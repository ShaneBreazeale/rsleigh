//! Detect SHA-256 implementations via function-level constant tables.
//!
//! Single-constant matches (`crypto_constants::resolve(0x6a09e667)`)
//! are useful for inline annotation but don't tell us where the
//! algorithm *lives*. This module aggregates: when a function contains
//! all 8 SHA-256 H0 init constants OR ≥4 of the 64 K round constants,
//! it's almost certainly a SHA-256 init or round function.
//!
//! Output: list of `(function_va, kind)` tuples.

use goblin::Object;

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K_FIRST_16: [u32; 16] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256Kind {
    /// Function contains all 8 H0 init constants.
    Init,
    /// Function contains ≥4 K round constants.
    Round,
    /// Function contains some H0 + K mix.
    Mixed,
}

#[derive(Debug, Clone)]
pub struct Sha256Hit {
    pub region_va: u64,
    pub kind: Sha256Kind,
    pub h0_count: u8,
    pub k_count: u8,
}

/// Scan one contiguous code region in fixed-size windows. We look at
/// 0x600-byte windows (covers a typical SHA-256 init or compress
/// function body) and require dense constant presence to fire.
pub fn scan_region(code: &[u8], base_va: u64) -> Vec<Sha256Hit> {
    const WIN: usize = 0x600;
    const STRIDE: usize = 0x100;
    let mut hits = Vec::new();
    let mut off = 0;
    while off < code.len() {
        let end = (off + WIN).min(code.len());
        let window = &code[off..end];
        let mut h0 = 0u8;
        let mut k = 0u8;
        for c in SHA256_H0 {
            if find_constant(window, c) {
                h0 += 1;
            }
        }
        for c in SHA256_K_FIRST_16 {
            if find_constant(window, c) {
                k += 1;
            }
        }
        if h0 >= 6 || k >= 4 {
            let kind = match (h0 >= 6, k >= 4) {
                (true, true) => Sha256Kind::Mixed,
                (true, false) => Sha256Kind::Init,
                (false, true) => Sha256Kind::Round,
                _ => unreachable!(),
            };
            hits.push(Sha256Hit {
                region_va: base_va + off as u64,
                kind,
                h0_count: h0,
                k_count: k,
            });
            off += WIN; // skip past matched window
            continue;
        }
        off += STRIDE;
    }
    hits
}

fn find_constant(haystack: &[u8], needle: u32) -> bool {
    let needle_bytes = needle.to_le_bytes();
    haystack
        .windows(4)
        .any(|w| w == needle_bytes)
}

pub fn scan(obj: &Object<'_>, data: &[u8]) -> Vec<Sha256Hit> {
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

pub fn render(hits: &[Sha256Hit]) -> Vec<String> {
    hits.iter()
        .map(|h| {
            let kind = match h.kind {
                Sha256Kind::Init => "init (H0)",
                Sha256Kind::Round => "round (K)",
                Sha256Kind::Mixed => "init+round (combined)",
            };
            format!(
                "{:#x}: SHA-256 {} — H0={}/8 K={}/16",
                h.region_va, kind, h.h0_count, h.k_count
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_full_h0() {
        // Pack all 8 H0 constants into a window.
        let mut code = Vec::new();
        for c in SHA256_H0 {
            code.extend_from_slice(&c.to_le_bytes());
            code.extend_from_slice(&[0x90; 8]); // padding between
        }
        let hits = scan_region(&code, 0x1000);
        assert!(!hits.is_empty());
        assert!(matches!(hits[0].kind, Sha256Kind::Init | Sha256Kind::Mixed));
    }

    #[test]
    fn detects_partial_k() {
        // 4 K constants → round detection.
        let mut code = Vec::new();
        for c in &SHA256_K_FIRST_16[..4] {
            code.extend_from_slice(&c.to_le_bytes());
            code.extend_from_slice(&[0x90; 16]);
        }
        let hits = scan_region(&code, 0x2000);
        assert!(!hits.is_empty());
    }

    #[test]
    fn no_false_positive_on_quiet() {
        let code = vec![0x90; 0x600];
        let hits = scan_region(&code, 0x3000);
        assert!(hits.is_empty());
    }
}
