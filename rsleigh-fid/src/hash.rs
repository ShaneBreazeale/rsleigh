//! Hash quad: full body hash + specific (children-aware) hash + size.

use xxhash_rust::xxh3::xxh3_64;

/// Canonical hash tuple for one function.
/// - `full`: xxh3 over operand-masked body bytes
/// - `specific`: full combined with direct callee full-hashes
/// - `code_units`: instruction count (filter tiny stubs)
/// - `body_len`: raw byte length
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FidHashQuad {
    pub full: u64,
    pub specific: u64,
    pub code_units: u32,
    pub body_len: u32,
}

impl FidHashQuad {
    pub fn new(masked: &[u8], code_units: u32, callee_fulls: &[u64]) -> Self {
        let full = xxh3_64(masked);
        let mut buf = Vec::with_capacity(masked.len() + callee_fulls.len() * 8);
        buf.extend_from_slice(masked);
        for c in callee_fulls {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        let specific = xxh3_64(&buf);
        Self {
            full,
            specific,
            code_units,
            body_len: masked.len() as u32,
        }
    }
}
