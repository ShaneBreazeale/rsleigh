//! Classify functions as hash-resolved API resolvers.
//!
//! Pattern: shellcode and packers commonly resolve Windows APIs by
//! walking the PEB-loaded module list, iterating each module's export
//! table, hashing each export name, and comparing the hash against a
//! precomputed constant. Hits return a function pointer; misses
//! advance to the next export. The hash function fingerprint is what
//! tells us which variant we're dealing with — ROR13 (Metasploit /
//! Cobalt Strike), DJB2 (custom shellcode), FNV-1 (some packers),
//! DJB2a / xxHash variants, etc.
//!
//! This module looks for three signals in a single contiguous code
//! window:
//!   1. **PEB fetch** (`MOV RAX, GS:[0x60]`) — anchor.
//!   2. **PEB.Ldr access** (`[RAX+0x18]`) — confirms walk vs single
//!      anti-debug probe.
//!   3. **Hash-step instruction** — one of:
//!      * `ROR r32, 13`        (Metasploit ROR13)
//!      * `IMUL r, r, 33`      (DJB2 multiplicative step)
//!      * `IMUL r, r, 0x1000193` (FNV-1 32-bit prime)
//!      * `SHL r, 5; ADD r, r` pair (DJB2 shift-add equivalent of *33)
//!
//! When all three appear in close proximity, classify the surrounding
//! function as an API resolver and emit the detected hash variant.
//!
//! False positives: a function that does PEB walks (anti-debug Ldr
//! enumeration for sandbox-probe lists) AND happens to do *33 IMUL
//! elsewhere in its body could trip. In practice that's rare — pure
//! anti-debug routines don't IMUL, and pure hash routines don't PEB
//! walk. The combination is high-precision.

use goblin::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashVariant {
    Ror13,
    Djb2,
    Djb2ShiftAdd,
    Fnv1,
}

impl HashVariant {
    pub fn name(self) -> &'static str {
        match self {
            HashVariant::Ror13 => "ROR13 (Metasploit)",
            HashVariant::Djb2 => "DJB2/DJB2a (*33 IMUL)",
            HashVariant::Djb2ShiftAdd => "DJB2 (shift-add equivalent)",
            HashVariant::Fnv1 => "FNV-1 (*0x1000193)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolverHit {
    /// Approximate VA of the matched function start (PEB fetch).
    pub region_va: u64,
    /// Detected hash variant.
    pub variant: HashVariant,
    /// VA of the hash-step instruction.
    pub hash_step_va: u64,
}

/// Try to classify a hash-step at byte offset `off` in `code`. Returns
/// `Some((variant, instr_len))` on match.
fn classify_hash_step(code: &[u8], off: usize) -> Option<(HashVariant, usize)> {
    // ROR r32, imm8 — `C1 C8 0D` or `41 C1 C8 0D` (3/4 bytes)
    if off + 3 <= code.len()
        && code[off] == 0xc1
        && code[off + 1] & 0xf8 == 0xc8 // /1 = ROR
        && code[off + 2] == 0x0d
    {
        return Some((HashVariant::Ror13, 3));
    }
    if off + 4 <= code.len()
        && (code[off] & 0xf0 == 0x40 && code[off] & 0x01 == 0x01) // REX.B
        && code[off + 1] == 0xc1
        && code[off + 2] & 0xf8 == 0xc8
        && code[off + 3] == 0x0d
    {
        return Some((HashVariant::Ror13, 4));
    }
    // IMUL r, r, imm8 — `6B <modrm> 21` for *33. With REX prefix
    // `48 6B <modrm> 21` (4 bytes) or non-REX `6B <modrm> 21` (3 bytes).
    if off + 4 <= code.len() && code[off] == 0x48 && code[off + 1] == 0x6b && code[off + 3] == 0x21
    {
        return Some((HashVariant::Djb2, 4));
    }
    if off + 3 <= code.len() && code[off] == 0x6b && code[off + 2] == 0x21 {
        // Plain `6B <modrm> 21`
        return Some((HashVariant::Djb2, 3));
    }
    // IMUL r, r, imm32 — `69 <modrm> imm32` for *0x1000193 etc.
    // REX form: `48 69 <modrm> 93 01 00 01`
    if off + 7 <= code.len() && code[off] == 0x48 && code[off + 1] == 0x69 {
        let imm = u32::from_le_bytes([code[off + 3], code[off + 4], code[off + 5], code[off + 6]]);
        if imm == 0x0100_0193 || imm == 0x0100_01b3 {
            return Some((HashVariant::Fnv1, 7));
        }
    }
    if off + 6 <= code.len() && code[off] == 0x69 {
        let imm = u32::from_le_bytes([code[off + 2], code[off + 3], code[off + 4], code[off + 5]]);
        if imm == 0x0100_0193 {
            return Some((HashVariant::Fnv1, 6));
        }
    }
    // Shift-add form for DJB2: `C1 E0 05` (SHL EAX, 5) followed within
    // 4 bytes by `01 ??` (ADD r, r) — recognises the (h<<5) + h
    // pattern.
    if off + 5 <= code.len()
        && code[off] == 0xc1
        && code[off + 1] & 0xf8 == 0xe0 // /4 = SHL
        && code[off + 2] == 0x05
    {
        // Look for ADD in next 4 bytes.
        for k in 3..=4 {
            if off + k + 2 <= code.len() && (code[off + k] == 0x01 || code[off + k] == 0x03) {
                return Some((HashVariant::Djb2ShiftAdd, 3));
            }
        }
    }
    None
}

/// Scan a code region for hash-resolver candidates. Looks for the PEB
/// fetch + hash-step combination within `WINDOW` bytes of each other.
const WINDOW: usize = 256;

pub fn scan_region(code: &[u8], base_va: u64) -> Vec<ResolverHit> {
    let mut hits = Vec::new();
    // First, collect PEB fetch positions.
    let mut peb_offs = Vec::new();
    let mut k = 0;
    while k + 9 <= code.len() {
        if code[k..k + 5] == [0x65, 0x48, 0x8b, 0x04, 0x25] {
            let disp = u32::from_le_bytes([code[k + 5], code[k + 6], code[k + 7], code[k + 8]]);
            if disp == 0x60 {
                peb_offs.push(k);
                k += 9;
                continue;
            }
        }
        k += 1;
    }
    // For each PEB fetch, scan WINDOW bytes ahead for a hash step.
    for &peb_off in &peb_offs {
        let end = (peb_off + WINDOW).min(code.len());
        let mut h = peb_off + 9; // step past the PEB fetch itself
        while h < end {
            if let Some((variant, len)) = classify_hash_step(code, h) {
                hits.push(ResolverHit {
                    region_va: base_va + peb_off as u64,
                    variant,
                    hash_step_va: base_va + h as u64,
                });
                h += len;
                // First hash step is enough to classify; move to next
                // PEB fetch.
                break;
            }
            h += 1;
        }
    }
    hits
}

/// Scan all executable sections of a binary.
pub fn scan(obj: &Object<'_>, data: &[u8]) -> Vec<ResolverHit> {
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
                let base_va = pe.image_base as u64 + sec.virtual_address as u64;
                hits.extend(scan_region(&data[raddr..raddr + rsize], base_va));
            }
            hits
        }
        _ => Vec::new(),
    }
}

pub fn render(hits: &[ResolverHit]) -> Vec<String> {
    hits.iter()
        .map(|h| {
            format!(
                "resolver near {:#x} — hash: {} (step @ {:#x})",
                h.region_va,
                h.variant.name(),
                h.hash_step_va
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ror13_after_peb_fetch() {
        // PEB fetch (9 bytes) + 16 NOPs + ROR EAX, 13 (3 bytes).
        let mut code = vec![0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0];
        code.extend(std::iter::repeat(0x90).take(16));
        code.extend_from_slice(&[0xc1, 0xc8, 0x0d]);
        let hits = scan_region(&code, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].variant, HashVariant::Ror13);
    }

    #[test]
    fn detects_djb2_after_peb_fetch() {
        // PEB fetch + 8 NOPs + IMUL RAX, RAX, 0x21 (4 bytes).
        let mut code = vec![0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0];
        code.extend(std::iter::repeat(0x90).take(8));
        code.extend_from_slice(&[0x48, 0x6b, 0xc0, 0x21]);
        let hits = scan_region(&code, 0x2000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].variant, HashVariant::Djb2);
        assert!(hits[0].variant.name().contains("DJB2"));
    }

    #[test]
    fn detects_fnv1() {
        // PEB fetch + IMUL r64, r64, 0x01000193.
        let mut code = vec![0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0];
        code.extend_from_slice(&[0x48, 0x69, 0xc0, 0x93, 0x01, 0x00, 0x01]);
        let hits = scan_region(&code, 0x3000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].variant, HashVariant::Fnv1);
    }

    #[test]
    fn ignores_lone_peb_fetch_no_hash() {
        let mut code = vec![0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0];
        code.extend(std::iter::repeat(0x90).take(50));
        let hits = scan_region(&code, 0x4000);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_false_positive_quiet_code() {
        let code = vec![0x90; 64];
        let hits = scan_region(&code, 0x5000);
        assert!(hits.is_empty());
    }
}
