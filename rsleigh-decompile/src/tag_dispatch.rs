//! Type-tag dispatch chain extractor.
//!
//! VM packers and marshalled-data deserialisers often dispatch on a
//! single byte register (`DL`, `AL`) against a chain of CMPs:
//!
//! ```text
//!     CMP DL, 0x2f       ; tag = None
//!     JZ  none_handler
//!     CMP DL, 0x6e       ; tag = True
//!     JZ  true_handler
//!     CMP DL, 0xa4       ; tag = False
//!     JZ  false_handler
//!     ...
//! ```
//!
//! The constants are the type tags; the JZ targets are the per-tag
//! handlers; the fall-through after the final CMP is the "unknown
//! tag" path. This module walks a function looking for that pattern
//! and emits the tag → target map.
//!
//! In v5 we extracted this by hand for the const-pool resolver
//! (`0x180012ec0`); the chain had 10 tag cases (0x2f / 0x6e / 0xa4 /
//! 0x4b / 0x26 / 0xbc / 0x1e / 0x41 / 0x3d / 0xc8). Automating it
//! saves a few minutes per resolver and makes the data structure
//! programmatically accessible.

use goblin::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchDir {
    /// `JZ target` — equal → jump (target is the per-tag handler).
    Take,
    /// `JNZ target` — not-equal → skip (target is the next check/case).
    Skip,
}

#[derive(Debug, Clone)]
pub struct TagCase {
    /// VA of the CMP instruction.
    pub cmp_va: u64,
    /// Immediate value being compared.
    pub tag: u8,
    /// Branch target. For `Take`, this is the per-tag handler. For
    /// `Skip`, this is the fall-through label after the inline handler.
    pub target_va: u64,
    pub dir: BranchDir,
}

/// Scan a region for chained 1-byte CMP+JZ patterns and group them
/// when the same register is used. Encoding fragments accepted:
///
///   - `CMP DL, imm8`   →  `80 FA imm8` (3 bytes)
///   - `CMP AL, imm8`   →  `3C imm8` (2 bytes)
///   - `CMP r8, imm8` (general) → `80 F8..FF imm8` for AL..BH non-REX
///
/// And the matching JZ:
///   - `JZ rel8`        →  `74 rel8` (2 bytes)
///   - `JZ rel32`       →  `0F 84 rel32` (6 bytes)
pub fn scan_region(code: &[u8], base_va: u64) -> Vec<TagCase> {
    let mut cases = Vec::new();
    let mut k = 0;
    while k + 4 <= code.len() {
        // Find a CMP r8, imm8 candidate.
        let (tag, cmp_len) = if code[k] == 0x80
            && (code[k + 1] & 0xf8) == 0xf8
            && k + 3 <= code.len()
        {
            // 80 F8..FF imm8 = CMP AL/CL/DL/BL/AH/CH/DH/BH, imm8
            (code[k + 2], 3)
        } else if code[k] == 0x3c {
            // CMP AL, imm8
            (code[k + 1], 2)
        } else if code[k] == 0x41 && code[k + 1] == 0x80
            && (code[k + 2] & 0xf8) == 0xf8
            && k + 4 <= code.len()
        {
            // REX.B + CMP r8, imm8 (covers R8B..R15B)
            (code[k + 3], 4)
        } else {
            k += 1;
            continue;
        };
        // Expect JZ immediately after.
        let jz_off = k + cmp_len;
        if jz_off >= code.len() {
            break;
        }
        // JZ rel8 (74) or JNZ rel8 (75) — 2 bytes
        if jz_off + 2 <= code.len()
            && (code[jz_off] == 0x74 || code[jz_off] == 0x75)
        {
            let rel = code[jz_off + 1] as i8 as i64;
            let target = (base_va + (jz_off + 2) as u64).wrapping_add(rel as u64);
            let dir = if code[jz_off] == 0x74 {
                BranchDir::Take
            } else {
                BranchDir::Skip
            };
            cases.push(TagCase {
                cmp_va: base_va + k as u64,
                tag,
                target_va: target,
                dir,
            });
            k = jz_off + 2;
            continue;
        }
        // JZ rel32 (0F 84) or JNZ rel32 (0F 85) — 6 bytes
        if jz_off + 6 <= code.len()
            && code[jz_off] == 0x0f
            && (code[jz_off + 1] == 0x84 || code[jz_off + 1] == 0x85)
        {
            let rel = i32::from_le_bytes([
                code[jz_off + 2],
                code[jz_off + 3],
                code[jz_off + 4],
                code[jz_off + 5],
            ]) as i64;
            let target = (base_va + (jz_off + 6) as u64).wrapping_add(rel as u64);
            let dir = if code[jz_off + 1] == 0x84 {
                BranchDir::Take
            } else {
                BranchDir::Skip
            };
            cases.push(TagCase {
                cmp_va: base_va + k as u64,
                tag,
                target_va: target,
                dir,
            });
            k = jz_off + 6;
            continue;
        }
        // CMP without immediate JZ — not a dispatch chain link.
        k += 1;
    }
    cases
}

/// Extract dispatch chain starting at a function VA. Reads up to 0x600
/// bytes of code and looks for consecutive CMP+JZ pairs.
pub fn scan_function(
    obj: &Object<'_>,
    data: &[u8],
    func_va: u64,
) -> Vec<TagCase> {
    if let Object::PE(pe) = obj {
        for sec in &pe.sections {
            let svaddr = pe.image_base as u64 + sec.virtual_address as u64;
            let sv = sec.virtual_size as u64;
            if func_va >= svaddr && func_va < svaddr + sv {
                let raddr = sec.pointer_to_raw_data as usize;
                let rsize = sec.size_of_raw_data as usize;
                let off_in_section = (func_va - svaddr) as usize;
                if off_in_section < rsize {
                    let scan_len = (0x600).min(rsize - off_in_section);
                    return scan_region(
                        &data[raddr + off_in_section..raddr + off_in_section + scan_len],
                        func_va,
                    );
                }
            }
        }
    }
    Vec::new()
}

pub fn render(cases: &[TagCase]) -> Vec<String> {
    cases
        .iter()
        .map(|c| {
            let mnem = match c.dir {
                BranchDir::Take => "JZ",
                BranchDir::Skip => "JNZ",
            };
            format!(
                "{:#x}: CMP r8, {:#04x} → {} {:#x}",
                c.cmp_va, c.tag, mnem, c.target_va
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cmp_dl_jz_short() {
        // CMP DL, 0x2f (80 FA 2F) + JZ +5 (74 05)
        let code = b"\x80\xfa\x2f\x74\x05";
        let cases = scan_region(code, 0x1000);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].tag, 0x2f);
        assert_eq!(cases[0].dir, BranchDir::Take);
        assert_eq!(cases[0].target_va, 0x100a);
    }

    #[test]
    fn detects_cmp_dl_jnz_skip() {
        // CMP DL, 0x2f (80 FA 2F) + JNZ +5 (75 05) — skip pattern
        let code = b"\x80\xfa\x2f\x75\x05";
        let cases = scan_region(code, 0x1000);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].tag, 0x2f);
        assert_eq!(cases[0].dir, BranchDir::Skip);
    }

    #[test]
    fn detects_cmp_al_jz_long() {
        // CMP AL, 0xc8 (3C C8) + JZ rel32 +0x100
        let mut code = vec![0x3c, 0xc8, 0x0f, 0x84];
        code.extend_from_slice(&0x100_i32.to_le_bytes());
        let cases = scan_region(&code, 0x2000);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].tag, 0xc8);
        // base + 8 (jz_off + 6) + 0x100
        assert_eq!(cases[0].target_va, 0x2108);
    }

    #[test]
    fn extracts_chain() {
        // Two CMP+JZ pairs back to back.
        // CMP DL, 0x2f / JZ +0
        // CMP DL, 0x6e / JZ +0
        let code = b"\x80\xfa\x2f\x74\x00\x80\xfa\x6e\x74\x00";
        let cases = scan_region(code, 0x3000);
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].tag, 0x2f);
        assert_eq!(cases[1].tag, 0x6e);
    }

    #[test]
    fn ignores_cmp_without_jz() {
        // CMP DL, 0x2f followed by something else.
        let code = b"\x80\xfa\x2f\x90\x90";
        let cases = scan_region(code, 0x4000);
        assert!(cases.is_empty());
    }
}
