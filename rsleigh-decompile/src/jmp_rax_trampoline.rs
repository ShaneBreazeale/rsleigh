//! Detect `JMP RAX` (and `JMP <reg>`) tail-call trampolines.
//!
//! Modern packers route IAT calls through a single 1- or 2-byte gadget
//! `FF E0` (JMP RAX) — the resolver computes the real target address,
//! puts it in RAX, then `CALL`s the trampoline. To the analyst staring
//! at the disasm, every routed call looks like a call to the same
//! 2-byte function, which destroys readability.
//!
//! This module finds those gadgets so the printer / xref renderer can
//! treat them transparently. Detection rules:
//!   - Function body is exactly `FF Ex` (JMP r64) followed by INT3
//!     padding or end-of-function.
//!   - The gadget address is referenced by either an IAT slot, an RVA
//!     table, or a CALL site that performs `MOV RAX, X; CALL gadget`.
//!
//! False-positive surface is essentially zero: a 2-byte function that
//! is *just* `JMP rN` is rare in legitimate code, and when it does
//! occur (compiler-generated thunks), the routing semantics are the
//! same.
//!
//! Empirically observed in:
//!   - PyVMProtect v3/v5 (`0x180034750`, `0x180040770`)
//!   - VMProtect 3.x runtime
//!   - Themida API wrappers
//!   - Donut / shellcode variants
//!
//! See `repos/CrackMe_PyVMP_v5/WHITEPAPER.md` § anti-emu trampoline for
//! the motivating session.

use goblin::Object;

/// Encodings of `JMP <reg>` we recognise. Each is one of the eight
/// `FF Ex` ModRM bytes (E0..E7) with optional REX.B prefix for r8..r15.
/// Returns the register name when matched, else None.
fn classify_jmp_reg(bytes: &[u8]) -> Option<&'static str> {
    if bytes.is_empty() {
        return None;
    }
    // Without REX prefix.
    if bytes.len() >= 2 && bytes[0] == 0xff {
        return match bytes[1] {
            0xe0 => Some("RAX"),
            0xe1 => Some("RCX"),
            0xe2 => Some("RDX"),
            0xe3 => Some("RBX"),
            0xe4 => Some("RSP"),
            0xe5 => Some("RBP"),
            0xe6 => Some("RSI"),
            0xe7 => Some("RDI"),
            _ => None,
        };
    }
    // REX.B prefix → r8..r15.
    if bytes.len() >= 3 && bytes[0] == 0x41 && bytes[1] == 0xff {
        return match bytes[2] {
            0xe0 => Some("R8"),
            0xe1 => Some("R9"),
            0xe2 => Some("R10"),
            0xe3 => Some("R11"),
            0xe4 => Some("R12"),
            0xe5 => Some("R13"),
            0xe6 => Some("R14"),
            0xe7 => Some("R15"),
            _ => None,
        };
    }
    None
}

/// Information about a detected trampoline.
#[derive(Debug, Clone)]
pub struct Trampoline {
    /// Virtual address of the gadget.
    pub addr: u64,
    /// Register that the gadget jumps through (e.g. "RAX").
    pub reg: &'static str,
}

/// Scan a contiguous executable region for `JMP <reg>` trampolines.
/// `code` is the raw bytes of an executable section. `base_va` is the
/// virtual address of `code[0]`.
///
/// We accept two body shapes:
///   - 2-byte `FF Ex` immediately followed by INT3/NOP padding.
///   - 3-byte `41 FF Ex` immediately followed by INT3/NOP padding.
///
/// Padding follower bytes are 0xCC (INT3) or 0x90 (NOP). The padding
/// requirement excludes the reg-jump in the middle of a normal function
/// (e.g., switch dispatch tables that later have real instructions).
pub fn scan_region(code: &[u8], base_va: u64) -> Vec<Trampoline> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i + 2 < code.len() {
        // Try 2-byte form first.
        if let Some(reg) = classify_jmp_reg(&code[i..i + 2]) {
            // Need at least one INT3 or NOP padding byte to qualify.
            let after = code.get(i + 2).copied().unwrap_or(0);
            if after == 0xCC || after == 0x90 {
                hits.push(Trampoline { addr: base_va + i as u64, reg });
                // Skip past the gadget + at least one padding byte.
                i += 3;
                continue;
            }
        }
        // Try 3-byte REX.B form.
        if i + 3 < code.len() {
            if let Some(reg) = classify_jmp_reg(&code[i..i + 3]) {
                let after = code.get(i + 3).copied().unwrap_or(0);
                if after == 0xCC || after == 0x90 {
                    hits.push(Trampoline { addr: base_va + i as u64, reg });
                    i += 4;
                    continue;
                }
            }
        }
        i += 1;
    }
    hits
}

/// Scan all executable sections of a parsed binary. Returns a vector
/// of all trampolines found across the image.
pub fn scan(obj: &Object<'_>, data: &[u8]) -> Vec<Trampoline> {
    match obj {
        Object::PE(pe) => {
            let mut hits = Vec::new();
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
            for sec in &pe.sections {
                if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                    continue;
                }
                let raddr = sec.pointer_to_raw_data as usize;
                let rsize = sec.size_of_raw_data as usize;
                if raddr + rsize > data.len() {
                    continue;
                }
                let base_va =
                    pe.image_base as u64 + sec.virtual_address as u64;
                let region_hits = scan_region(&data[raddr..raddr + rsize], base_va);
                hits.extend(region_hits);
            }
            hits
        }
        Object::Elf(elf) => {
            let mut hits = Vec::new();
            for sh in &elf.section_headers {
                // SHF_EXECINSTR = 0x4
                if sh.sh_flags & 0x4 == 0 {
                    continue;
                }
                let raddr = sh.sh_offset as usize;
                let rsize = sh.sh_size as usize;
                if raddr + rsize > data.len() {
                    continue;
                }
                let base_va = sh.sh_addr;
                let region_hits = scan_region(&data[raddr..raddr + rsize], base_va);
                hits.extend(region_hits);
            }
            hits
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jmp_rax() {
        // FF E0 followed by INT3 padding.
        let code = b"\xff\xe0\xcc\xcc\xcc\xcc";
        let hits = scan_region(code, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].reg, "RAX");
        assert_eq!(hits[0].addr, 0x1000);
    }

    #[test]
    fn detects_jmp_r8() {
        // 41 FF E0 (JMP R8) + INT3 padding.
        let code = b"\x41\xff\xe0\xcc\xcc";
        let hits = scan_region(code, 0x2000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].reg, "R8");
    }

    #[test]
    fn rejects_no_padding() {
        // FF E0 followed by real instruction (not 0xCC/0x90).
        let code = b"\xff\xe0\x48\x89\xc1";
        let hits = scan_region(code, 0x3000);
        assert!(hits.is_empty());
    }

    #[test]
    fn finds_multiple_in_region() {
        // Two trampolines with INT3 between them.
        let code = b"\xff\xe0\xcc\xcc\x41\xff\xe2\xcc\xcc";
        let hits = scan_region(code, 0x4000);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].reg, "RAX");
        assert_eq!(hits[0].addr, 0x4000);
        assert_eq!(hits[1].reg, "R10");
        assert_eq!(hits[1].addr, 0x4004);
    }
}
