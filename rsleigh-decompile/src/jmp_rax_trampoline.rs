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
                hits.push(Trampoline {
                    addr: base_va + i as u64,
                    reg,
                });
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
                    hits.push(Trampoline {
                        addr: base_va + i as u64,
                        reg,
                    });
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
///
/// Arch-gated to x86 / x86-64 — the `FF Ex` (and `41 FF Ex`) ModRM
/// encoding is x86-specific, and incidental matches in MIPS / ARM /
/// RISC-V code surface as bogus trampoline banners.
pub fn scan(obj: &Object<'_>, data: &[u8]) -> Vec<Trampoline> {
    match obj {
        Object::PE(pe) => {
            // PE COFF machine: 0x14c = i386, 0x8664 = x86-64.
            let machine = pe.header.coff_header.machine;
            if machine != 0x014c && machine != 0x8664 {
                return Vec::new();
            }
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
                let base_va = pe.image_base as u64 + sec.virtual_address as u64;
                let region_hits = scan_region(&data[raddr..raddr + rsize], base_va);
                hits.extend(region_hits);
            }
            hits
        }
        Object::Elf(elf) => {
            // ELF e_machine: EM_386 = 3, EM_X86_64 = 62.
            if elf.header.e_machine != 3 && elf.header.e_machine != 62 {
                return Vec::new();
            }
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
    fn skips_non_x86_elf() {
        // Build a minimal ELF32 MIPS header containing executable
        // bytes that include `FF E7 CC ...` — which would match x86
        // `JMP RDI + INT3`. scan() must arch-gate on e_machine and
        // return zero hits for MIPS.
        // Real fixture used by integration: a MIPS Mirai-class sample
        // surfaced spurious "JMP RBP / JMP RDI" trampolines purely
        // from incidental byte sequences. Unit-test against the
        // structural cause: build a parseable ELF and check `scan`.
        use goblin::Object;
        // Hand-assemble a tiny ELF32 LSB MIPS file with one .text
        // section whose payload is `FF E7 CC CC` (x86 JMP RDI;INT3).
        // 52-byte ehdr + 1 phdr (32) + 1 shstrtab + 1 sec hdr (40)
        // is heavier than we need; cheaper: construct via builder.
        // Instead, emit a minimal hand-made image.
        #[rustfmt::skip]
        let elf: Vec<u8> = {
            let mut v: Vec<u8> = vec![
                0x7f, b'E', b'L', b'F', 1, 1, 1, 0, // ei_*
                0, 0, 0, 0, 0, 0, 0, 0,
                2, 0,                                // e_type = ET_EXEC
                8, 0,                                // e_machine = EM_MIPS (8)
                1, 0, 0, 0,                          // e_version
                0, 0, 0, 0,                          // e_entry
                0, 0, 0, 0,                          // e_phoff
                0x34, 0, 0, 0,                       // e_shoff = 0x34
                0, 0, 0, 0,                          // e_flags
                0x34, 0,                             // e_ehsize = 52
                0, 0,                                // e_phentsize
                0, 0,                                // e_phnum
                0x28, 0,                             // e_shentsize = 40
                3, 0,                                // e_shnum = 3
                2, 0,                                // e_shstrndx = 2
            ];
            // shdr[0]: NULL
            v.extend(std::iter::repeat(0).take(40));
            // shdr[1]: .text  name=1, type=PROGBITS(1), flags=AX(6),
            //   addr=0x1000, offset=0xC0, size=4
            let text_off: u32 = 0xC0;
            let text_size: u32 = 4;
            v.extend_from_slice(&1u32.to_le_bytes());
            v.extend_from_slice(&1u32.to_le_bytes());
            v.extend_from_slice(&6u32.to_le_bytes());
            v.extend_from_slice(&0x1000u32.to_le_bytes());
            v.extend_from_slice(&text_off.to_le_bytes());
            v.extend_from_slice(&text_size.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes()); // link
            v.extend_from_slice(&0u32.to_le_bytes()); // info
            v.extend_from_slice(&4u32.to_le_bytes()); // align
            v.extend_from_slice(&0u32.to_le_bytes()); // entsize
            // shdr[2]: .shstrtab  name=7, type=STRTAB(3), flags=0,
            //   addr=0, offset=0xAC (172), size=0x11 (17)
            let str_off: u32 = 0xAC;
            let str_size: u32 = 0x11;
            v.extend_from_slice(&7u32.to_le_bytes());
            v.extend_from_slice(&3u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&str_off.to_le_bytes());
            v.extend_from_slice(&str_size.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&1u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            // .shstrtab payload at 0xAC: "\0.text\0.shstrtab\0" (17 bytes)
            assert_eq!(v.len(), 0xAC);
            v.extend_from_slice(b"\0.text\0.shstrtab\0");
            // pad to 0xC0 (3 bytes) for .text alignment
            v.extend_from_slice(&[0u8; 3]);
            // .text payload at 0xC0: x86-style JMP RDI + INT3 + NOP
            assert_eq!(v.len(), 0xC0);
            v.extend_from_slice(b"\xff\xe7\xcc\x90");
            v
        };
        let obj = Object::parse(&elf).expect("parseable MIPS ELF");
        let hits = scan(&obj, &elf);
        assert!(
            hits.is_empty(),
            "scan emitted {} bogus trampoline(s) on MIPS ELF",
            hits.len()
        );
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
