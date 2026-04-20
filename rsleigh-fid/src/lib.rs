//! Function ID database — operand-masked body hashing for function
//! identification across stripped binaries. Ghidra FID semantic clone
//! with pure-Rust ingest/match pipeline.
//!
//! # Algorithm
//! 1. Disassemble function linearly.
//! 2. For each instruction: keep opcode + prefix bytes, zero operand slots
//!    (registers, immediates, displacements) per arch mask table.
//! 3. Hash masked byte stream with xxh3-64 → `full_hash`.
//! 4. Combine with hashes of direct call targets → `specific_hash`.
//! 5. Persist rows (full_hash, specific_hash, name, lib_id) in compact
//!    binary format; ship as gzipped blob for runtime match pass.

pub mod hash;
pub mod mask;
pub mod db;
pub mod ingest;

pub use db::{FidDb, FidEntry};
pub use hash::FidHashQuad;

/// Convenience: fingerprint a function body and return matching name(s)
/// from the database. Prefers `specific_hash` (callee-aware) matches;
/// falls back to `full_hash` if specific yields nothing.
///
/// Returns `None` if the body is too small to fingerprint, or if no
/// match exists. Returns `Some(&name)` when exactly one entry matches
/// (unambiguous rename). Multi-match caller should use `FidDb` directly
/// and apply additional disambiguation (e.g. library preference).
pub fn identify<'a>(
    arch: rsleigh_api::Architecture,
    body: &[u8],
    addr: u64,
    db: &'a FidDb,
) -> Option<&'a str> {
    let hq = ingest::fingerprint(arch, body, addr, |_| None)?;
    // Specific hash will only match when the callee graph lines up —
    // without cross-function fingerprints during match, fall back to full.
    let by_spec = db.match_specific(hq.specific);
    if by_spec.len() == 1 {
        return Some(&db.entries[by_spec[0]].name);
    }
    let by_full = db.match_full(hq.full);
    if by_full.len() == 1 {
        return Some(&db.entries[by_full[0]].name);
    }
    None
}
