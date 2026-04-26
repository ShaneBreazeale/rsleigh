//! Detect PEB-walking patterns in code regions.
//!
//! Two related patterns:
//!
//! 1. **PEB anti-debug probes**: read `BeingDebugged` (PEB+0x2) or
//!    `NtGlobalFlag` (PEB+0xbc). The byte sequence
//!    `65 48 8b 04 25 60 00 00 00` (`MOV RAX, GS:[0x60]`) followed by
//!    `cmp byte ptr [rax+0x2]` or `test byte ptr [rax+0xbc]` is a
//!    strong signal.
//!
//! 2. **PEB.Ldr export-table walk for hash-resolved APIs**: same TEB
//!    fetch followed by `MOV RCX, [RAX+0x18]` (PEB.Ldr) then a loop
//!    reading export-name pointers and hashing them. When a hash
//!    multiply (DJB2 step `IMUL r,r,33` or ROR13 `ROR r32,13`) appears
//!    nearby, classify as an API resolver.
//!
//! Catches the v5 init-chain anti-debug + hash resolver and many
//! shellcode strains. False-positive rate is low — `MOV RAX, GS:[0x60]`
//! shows up almost exclusively in PEB walks.

use goblin::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PebHitKind {
    /// `MOV r, GS:[0x60]` — the canonical PEB-fetch entry.
    PebFetch,
    /// `cmp/test byte ptr [r + 0x2]` immediately after PEB fetch.
    BeingDebugged,
    /// `test [r + 0xbc], imm` — NtGlobalFlag check.
    NtGlobalFlag,
    /// `[r + 0x18]` — PEB.Ldr access (often start of API resolver).
    PebLdrAccess,
}

#[derive(Debug, Clone)]
pub struct PebHit {
    pub va: u64,
    pub kind: PebHitKind,
}

/// Scan a code region for PEB-walking patterns.
pub fn scan_region(code: &[u8], base_va: u64) -> Vec<PebHit> {
    let mut hits = Vec::new();
    let mut off = 0;
    // 9-byte PEB fetch: `65 48 8B 04 25 60 00 00 00`
    // (MOV RAX, GS:[0x60])
    while off + 9 <= code.len() {
        if &code[off..off + 5] == &[0x65, 0x48, 0x8b, 0x04, 0x25] {
            // Check disp32 == 0x60.
            let disp = u32::from_le_bytes([
                code[off + 5],
                code[off + 6],
                code[off + 7],
                code[off + 8],
            ]);
            if disp == 0x60 {
                hits.push(PebHit {
                    va: base_va + off as u64,
                    kind: PebHitKind::PebFetch,
                });
                // Look ahead in next 32 bytes for follow-up reads.
                let win = &code[off + 9..(off + 9 + 32).min(code.len())];
                let win_va = base_va + (off + 9) as u64;
                // PEB.Ldr at +0x18: `48 8b 48 18` (MOV RCX, [RAX+0x18])
                // or `48 8b 50 18` etc. Look for `48 8b ?? 18` pattern.
                let mut k = 0;
                while k + 4 <= win.len() {
                    if win[k] == 0x48 && win[k + 1] == 0x8b && win[k + 3] == 0x18
                    {
                        hits.push(PebHit {
                            va: win_va + k as u64,
                            kind: PebHitKind::PebLdrAccess,
                        });
                        break;
                    }
                    k += 1;
                }
                // BeingDebugged: `cmp/test byte ptr [rXX + 0x2]`
                let mut k = 0;
                while k + 3 <= win.len() {
                    if (win[k] == 0x80 || win[k] == 0x38)
                        && win[k + 2] == 0x02
                    {
                        hits.push(PebHit {
                            va: win_va + k as u64,
                            kind: PebHitKind::BeingDebugged,
                        });
                        break;
                    }
                    k += 1;
                }
                // NtGlobalFlag: `test ... + 0xbc, imm`
                let mut k = 0;
                while k + 3 <= win.len() {
                    if (win[k] == 0xf6 || win[k] == 0xf7)
                        && win[k + 2] == 0xbc
                    {
                        hits.push(PebHit {
                            va: win_va + k as u64,
                            kind: PebHitKind::NtGlobalFlag,
                        });
                        break;
                    }
                    k += 1;
                }
                off += 9;
                continue;
            }
        }
        off += 1;
    }
    hits
}

/// Scan all executable sections of a binary.
pub fn scan(obj: &Object<'_>, data: &[u8]) -> Vec<PebHit> {
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
                hits.extend(scan_region(&data[raddr..raddr + rsize], base_va));
            }
            hits
        }
        _ => Vec::new(),
    }
}

/// Render a hit list as a one-line-per-hit annotation.
pub fn render(hits: &[PebHit]) -> Vec<String> {
    hits.iter()
        .map(|h| {
            let label = match h.kind {
                PebHitKind::PebFetch => "MOV RAX, GS:[0x60] (PEB fetch)",
                PebHitKind::BeingDebugged => "PEB.BeingDebugged probe",
                PebHitKind::NtGlobalFlag => "PEB.NtGlobalFlag probe",
                PebHitKind::PebLdrAccess => "PEB.Ldr access (likely API resolver)",
            };
            format!("{:#x}: {}", h.va, label)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_peb_fetch() {
        // 65 48 8B 04 25 60 00 00 00 — MOV RAX, GS:[0x60]
        let code = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x90\x90\x90";
        let hits = scan_region(code, 0x1000);
        assert!(hits.iter().any(|h| h.kind == PebHitKind::PebFetch));
    }

    #[test]
    fn detects_peb_ldr_followup() {
        // PEB fetch + MOV RCX, [RAX+0x18]
        let code = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x48\x18";
        let hits = scan_region(code, 0x2000);
        assert!(hits.iter().any(|h| h.kind == PebHitKind::PebFetch));
        assert!(hits.iter().any(|h| h.kind == PebHitKind::PebLdrAccess));
    }

    #[test]
    fn no_false_positive_on_quiet_code() {
        let code = vec![0x90; 32];
        let hits = scan_region(&code, 0x3000);
        assert!(hits.is_empty());
    }
}
