//! Raw-mode ARM32 / Cortex-M analysis helpers.
//!
//! Shared between `--raw arm`, `--xrefs <addr> --raw arm`, and
//! `--search --const <hex> --raw arm`. None of these have an ELF/PE
//! header to pull symbols or xrefs from, so we re-derive everything
//! from the byte stream:
//!
//! - **Function discovery**: Cortex-M vector table seeding + Thumb-2 BL
//!   pair scan + classic ARM BL scan.
//! - **MOVW/MOVT pairs**: 32-bit immediate construction. Required for
//!   string-load and large-constant xrefs on Thumb-2 firmware where
//!   most loads are MOVW Rd,#lo / MOVT Rd,#hi rather than literal-pool
//!   PC-relative LDR.
//! - **PC-relative literal-pool LDRs** (Thumb): `LDR Rt, [pc, #imm]`
//!   reads a u32 from the constant pool — also a constant-load site.
//! - **Direct call sites**: BL/BLX/B targets equal to a query address.

use std::collections::{BTreeMap, BTreeSet};

/// One MOVW/MOVT pair that builds a 32-bit immediate.
#[derive(Debug, Clone, Copy)]
pub struct MovwMovtPair {
    /// VA of the MOVW (low half) — pair is contiguous, MOVT follows immediately.
    pub addr: u64,
    /// Destination register (0..=15).
    pub rd: u8,
    /// Combined 32-bit immediate.
    pub value: u32,
}

/// One PC-relative literal-pool load (`LDR Rt, [pc, #imm]`).
#[derive(Debug, Clone, Copy)]
pub struct PcLiteralLoad {
    /// VA of the LDR instruction.
    pub addr: u64,
    /// Destination register.
    pub rt: u8,
    /// VA of the literal in the constant pool.
    pub literal_addr: u64,
    /// The 32-bit value at `literal_addr` (read from `data`).
    pub value: u32,
}

/// Discover function entry points in a raw ARM32 / Cortex-M blob.
///
/// Combines three sources:
/// 1. Cortex-M vector table (gated on first-word RAM-SP heuristic).
/// 2. Thumb-2 BL/BLX pair targets (halfword-aligned scan).
/// 3. Classic ARM-mode BL targets (4-byte aligned scan).
pub fn discover_functions(data: &[u8], base: u64) -> BTreeSet<u64> {
    let mut found = BTreeSet::new();
    found.insert(base);
    let code_end = base + data.len() as u64;

    // Cortex-M vector seed.
    if data.len() >= 8 {
        let sp_word = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        if (sp_word & 0xFF00_0000) == 0x2000_0000 {
            let scan_end = 0x400.min(data.len() & !3);
            for i in (4..scan_end).step_by(4) {
                let entry = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
                if (entry & 1) == 0 {
                    continue;
                }
                let canon = (entry as u64) & !1;
                if canon >= base && canon < code_end {
                    found.insert(entry as u64);
                }
            }
        }
    }

    // ARM-mode BL.
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
        if (word & 0x0F000000) == 0x0B000000 {
            let imm24 = word & 0x00FFFFFF;
            let offset = if imm24 & 0x800000 != 0 {
                ((imm24 | 0xFF000000) as i32) << 2
            } else {
                (imm24 as i32) << 2
            };
            let target = (base as i64 + i as i64 + 8 + offset as i64) as u64;
            if target >= base && target < code_end {
                found.insert(target);
            }
        }
    }

    // Thumb-2 BL / BLX.
    for i in (0..data.len().saturating_sub(3)).step_by(2) {
        let hw1 = u16::from_le_bytes([data[i], data[i + 1]]) as u32;
        let hw2 = u16::from_le_bytes([data[i + 2], data[i + 3]]) as u32;
        if (hw1 & 0xF800) != 0xF000 {
            continue;
        }
        let is_bl = (hw2 & 0xD000) == 0xD000;
        let is_blx = (hw2 & 0xD000) == 0xC000;
        if !is_bl && !is_blx {
            continue;
        }
        if let Some(target) = decode_thumb2_bl_target(base + i as u64, hw1, hw2, is_blx) {
            let canon = target & !1;
            if canon >= base && canon < code_end {
                found.insert(target);
            }
        }
    }

    found
}

/// Decode a Thumb-2 BL/BLX pair into its branch target (with Thumb LSB
/// set for BL; cleared and 4-byte-aligned for BLX).
fn decode_thumb2_bl_target(pc: u64, hw1: u32, hw2: u32, is_blx: bool) -> Option<u64> {
    let s = (hw1 >> 10) & 1;
    let j1 = (hw2 >> 13) & 1;
    let j2 = (hw2 >> 11) & 1;
    let i1 = (!(j1 ^ s)) & 1;
    let i2 = (!(j2 ^ s)) & 1;
    let imm10 = hw1 & 0x3FF;
    let imm11 = hw2 & 0x7FF;
    let mut offset: i32 = ((i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)) as i32;
    if s != 0 {
        offset |= 0xFF00_0000u32 as i32;
    }
    let raw = (pc as i64 + 4 + offset as i64) as u64;
    Some(if is_blx { raw & !0x3 } else { raw | 1 })
}

/// Find all BL/BLX call sites whose target equals `query` (with Thumb
/// LSB ignored on the comparison).
pub fn find_call_sites(data: &[u8], base: u64, query: u64) -> Vec<u64> {
    let mut sites = Vec::new();
    let code_end = base + data.len() as u64;
    let want = query & !1;

    // Thumb-2 BL/BLX.
    let mut i = 0;
    while i + 4 <= data.len() {
        let hw1 = u16::from_le_bytes([data[i], data[i + 1]]) as u32;
        let hw2 = u16::from_le_bytes([data[i + 2], data[i + 3]]) as u32;
        if (hw1 & 0xF800) == 0xF000 {
            let is_bl = (hw2 & 0xD000) == 0xD000;
            let is_blx = (hw2 & 0xD000) == 0xC000;
            if is_bl || is_blx {
                if let Some(t) = decode_thumb2_bl_target(base + i as u64, hw1, hw2, is_blx) {
                    if (t & !1) == want && (t & !1) >= base && (t & !1) < code_end {
                        sites.push(base + i as u64);
                    }
                }
            }
        }
        i += 2;
    }

    // ARM-mode BL.
    let mut j = 0;
    while j + 4 <= data.len() {
        let word = u32::from_le_bytes(data[j..j + 4].try_into().unwrap_or([0; 4]));
        if (word & 0x0F000000) == 0x0B000000 {
            let imm24 = word & 0x00FFFFFF;
            let offset = if imm24 & 0x800000 != 0 {
                ((imm24 | 0xFF000000) as i32) << 2
            } else {
                (imm24 as i32) << 2
            };
            let target = (base as i64 + j as i64 + 8 + offset as i64) as u64;
            if (target & !1) == want && (target & !1) >= base && (target & !1) < code_end {
                sites.push(base + j as u64);
            }
        }
        j += 4;
    }

    sites.sort();
    sites.dedup();
    sites
}

/// Decode a Thumb-2 MOVW (T3) or MOVT (T1) instruction's immediate +
/// destination register from the two halfwords. Returns
/// `Some((rd, imm16))` on match. Use `is_movt` flag to indicate whether
/// the encoding is MOVT.
fn decode_movw_movt(hw1: u32, hw2: u32, is_movt: bool) -> Option<(u8, u16)> {
    // MOVW (T3): 1111 0i10 0100 imm4 | 0iii dddd iiii iiii
    // MOVT (T1): 1111 0i10 1100 imm4 | 0iii dddd iiii iiii
    let want = if is_movt { 0xF2C0 } else { 0xF240 };
    if (hw1 & 0xFBF0) != want {
        return None;
    }
    if (hw2 & 0x8000) != 0 {
        return None;
    }
    let imm4 = hw1 & 0x000F;
    let i = (hw1 >> 10) & 1;
    let imm3 = (hw2 >> 12) & 0x7;
    let imm8 = hw2 & 0xFF;
    let imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;
    let rd = ((hw2 >> 8) & 0xF) as u8;
    Some((rd, imm16 as u16))
}

/// Find every MOVW Rd,#lo / MOVT Rd,#hi pair (immediate, contiguous,
/// matching Rd). Returns the combined 32-bit immediate per pair.
pub fn find_movw_movt_pairs(data: &[u8], base: u64) -> Vec<MovwMovtPair> {
    let mut pairs = Vec::new();
    let mut i = 0;
    while i + 8 <= data.len() {
        let hw1 = u16::from_le_bytes([data[i], data[i + 1]]) as u32;
        let hw2 = u16::from_le_bytes([data[i + 2], data[i + 3]]) as u32;
        let Some((rd_lo, lo)) = decode_movw_movt(hw1, hw2, false) else {
            i += 2;
            continue;
        };
        let hw3 = u16::from_le_bytes([data[i + 4], data[i + 5]]) as u32;
        let hw4 = u16::from_le_bytes([data[i + 6], data[i + 7]]) as u32;
        let Some((rd_hi, hi)) = decode_movw_movt(hw3, hw4, true) else {
            i += 2;
            continue;
        };
        if rd_lo != rd_hi {
            i += 2;
            continue;
        }
        pairs.push(MovwMovtPair {
            addr: base + i as u64,
            rd: rd_lo,
            value: ((hi as u32) << 16) | (lo as u32),
        });
        i += 8;
    }
    pairs
}

/// Find every Thumb PC-relative literal-pool load. Two encodings
/// covered: 16-bit `LDR Rt, [pc, #imm8*4]` (T1) and 32-bit
/// `LDR.W Rt, [pc, #imm12]` (T2). Returns one `PcLiteralLoad` per call.
pub fn find_pc_literal_loads(data: &[u8], base: u64) -> Vec<PcLiteralLoad> {
    let mut loads = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let hw1 = u16::from_le_bytes([data[i], data[i + 1]]) as u32;
        // T1: LDR Rt,[pc,#imm8*4]: 0100_1ttt_iiiiiiii (0x4800..0x4FFF)
        if (hw1 & 0xF800) == 0x4800 {
            let rt = ((hw1 >> 8) & 0x7) as u8;
            let imm8 = hw1 & 0xFF;
            // PC for this LDR is (instr_addr + 4) word-aligned.
            let pc_aligned = (base + i as u64 + 4) & !0x3;
            let lit_addr = pc_aligned + (imm8 as u64) * 4;
            if let Some(value) = read_u32_at(data, base, lit_addr) {
                loads.push(PcLiteralLoad {
                    addr: base + i as u64,
                    rt,
                    literal_addr: lit_addr,
                    value,
                });
            }
            i += 2;
            continue;
        }
        // T2: LDR.W Rt,[pc,#±imm12]: 11111000_U101_1111 | tttt_iiiiiiiiiiii
        // Check Rn==15 (PC). hw1 = 0xF8DF (U=1) or 0xF85F (U=0).
        if i + 4 > data.len() {
            i += 2;
            continue;
        }
        let is_u_pos = hw1 == 0xF8DF;
        let is_u_neg = hw1 == 0xF85F;
        if is_u_pos || is_u_neg {
            let hw2 = u16::from_le_bytes([data[i + 2], data[i + 3]]) as u32;
            let rt = ((hw2 >> 12) & 0xF) as u8;
            let imm12 = hw2 & 0xFFF;
            let pc_aligned = (base + i as u64 + 4) & !0x3;
            let lit_addr = if is_u_pos {
                pc_aligned + imm12 as u64
            } else {
                pc_aligned.wrapping_sub(imm12 as u64)
            };
            if let Some(value) = read_u32_at(data, base, lit_addr) {
                loads.push(PcLiteralLoad {
                    addr: base + i as u64,
                    rt,
                    literal_addr: lit_addr,
                    value,
                });
            }
            i += 4;
            continue;
        }
        i += 2;
    }
    loads
}

fn read_u32_at(data: &[u8], base: u64, va: u64) -> Option<u32> {
    if va < base {
        return None;
    }
    let off = (va - base) as usize;
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes(data[off..off + 4].try_into().ok()?))
}

/// Build a `va -> u32` map of every "constant-load site" detectable
/// statically: MOVW/MOVT pairs + PC-relative literal-pool loads.
/// Useful for `--search --const` and for follow-up xref
/// "what loads address X?" queries.
pub fn build_constant_load_map(data: &[u8], base: u64) -> BTreeMap<u64, u32> {
    let mut map = BTreeMap::new();
    for p in find_movw_movt_pairs(data, base) {
        map.insert(p.addr, p.value);
    }
    for l in find_pc_literal_loads(data, base) {
        map.insert(l.addr, l.value);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn movw_movt_pair_basic() {
        // MOVW r0, #0x1234 ; MOVT r0, #0x5678 (Thumb-2)
        // 0x1234 = 0001_0010_0011_0100 → imm4=0x1, i=0 (bit 11), imm3=0x2, imm8=0x34
        //   hw1 = 0xF240 | (0<<10) | 0x1 = 0xF241   (LE bytes 41 F2)
        //   hw2 = (0<<15) | (0x2<<12) | (0<<8) | 0x34 = 0x2034   (LE bytes 34 20)
        // 0x5678 = 0101_0110_0111_1000 → imm4=0x5, i=0 (bit 11), imm3=0x6, imm8=0x78
        //   hw1 = 0xF2C0 | (0<<10) | 0x5 = 0xF2C5   (LE bytes C5 F2)
        //   hw2 = (0<<15) | (0x6<<12) | (0<<8) | 0x78 = 0x6078   (LE bytes 78 60)
        let bytes: [u8; 8] = [0x41, 0xF2, 0x34, 0x20, 0xC5, 0xF2, 0x78, 0x60];
        let pairs = find_movw_movt_pairs(&bytes, 0x08000000);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].rd, 0);
        assert_eq!(pairs[0].value, 0x5678_1234);
    }

    #[test]
    fn discover_finds_vector_seed() {
        // Fake Cortex-M flash: SP=0x20020000, reset=0x08000401 (Thumb).
        let mut data = vec![0u8; 0x500];
        data[0..4].copy_from_slice(&0x2002_0000u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x0800_0401u32.to_le_bytes());
        let found = discover_functions(&data, 0x0800_0000);
        assert!(found.contains(&0x0800_0401));
    }

    #[test]
    fn thumb2_bl_target_decode_canon() {
        // BL with imm32 = +0x40 (target = pc + 4 + 0x40).
        // imm32[24] = S = 0
        // imm32[23] = I1 = 0, imm32[22] = I2 = 0
        // imm32[21:12] = imm10 = 0
        // imm32[11:1]  = imm11 = 0x20
        // J1 = !(I1 XOR S) = !(0 XOR 0) = 1
        // J2 = !(I2 XOR S) = 1
        // Encoding T1: hw1 = 11110_S_imm10 = 0xF000
        //              hw2 = 11_J1_1_J2_imm11
        //                  = 1111_1000_0010_0000 = 0xF820
        let hw1 = 0xF000u32;
        let hw2 = 0xF820u32;
        let target = decode_thumb2_bl_target(0x0800_0100, hw1, hw2, false).unwrap();
        // PC=0x0800_0100, +4 + 0x40 = 0x0800_0144, BL → Thumb LSB set
        assert_eq!(target, 0x0800_0145);
    }
}
