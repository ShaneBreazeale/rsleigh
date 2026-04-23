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

/// Load all bundled FID databases matching the given architecture.
/// Returns a list of (library_name, db) pairs. Empty if no bundled
/// DBs ship for the architecture (e.g. ARM32, MIPS32, RISC-V today).
pub fn bundled_dbs(arch: rsleigh_api::Architecture) -> Vec<(&'static str, FidDb)> {
    let mut out = Vec::new();
    let blobs: &[(&str, &[u8])] = match arch {
        rsleigh_api::Architecture::X86_64 => &[
            ("glibc", include_bytes!("../data/glibc-x86_64.fidb")),
            ("libstdcxx", include_bytes!("../data/libstdcxx-x86_64.fidb")),
            ("musl", include_bytes!("../data/musl-x86_64.fidb")),
            ("zlib", include_bytes!("../data/zlib-x86_64.fidb")),
            ("openssl", include_bytes!("../data/openssl-x86_64.fidb")),
        ],
        rsleigh_api::Architecture::AArch64 => &[
            ("glibc", include_bytes!("../data/glibc-aarch64.fidb")),
            ("libstdcxx", include_bytes!("../data/libstdcxx-aarch64.fidb")),
            ("musl", include_bytes!("../data/musl-aarch64.fidb")),
            ("zlib", include_bytes!("../data/zlib-aarch64.fidb")),
            ("openssl", include_bytes!("../data/openssl-aarch64.fidb")),
        ],
        _ => &[],
    };
    for (name, bytes) in blobs {
        if let Ok(db) = FidDb::read(std::io::Cursor::new(bytes)) {
            out.push((*name, db));
        }
    }
    out
}

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
    // Accept multi-match when:
    //  - every hit has the identical name (weak-alias duplicates), OR
    //  - all hits are Itanium C++ ABI ctor/dtor variants of the same
    //    function (C1/C2 complete/base ctors, D0/D1/D2 dtors share a body
    //    by design). Prefer C1/D1 (complete-object) in that case.
    let resolve = |idxs: &[usize]| -> Option<&'a str> {
        if idxs.is_empty() {
            return None;
        }
        let first = &db.entries[idxs[0]].name;
        if idxs.iter().all(|i| &db.entries[*i].name == first) {
            return Some(first);
        }
        if idxs.iter().all(|i| is_cxx_abi_variant(&db.entries[*i].name, first)) {
            // Pick complete-object variant if present, else first.
            if let Some(i) = idxs.iter().find(|i| {
                let n = &db.entries[**i].name;
                n.contains("C1E") || n.contains("D1E")
            }) {
                return Some(&db.entries[*i].name);
            }
            return Some(first);
        }
        None
    };
    resolve(db.match_specific(hq.specific))
        .or_else(|| resolve(db.match_full(hq.full)))
}

/// Are `a` and `b` Itanium C++ ABI ctor/dtor variants of the same
/// function? Variants share a body by spec:
///   - `C1` (complete), `C2` (base), `C3` (allocating) ctors
///   - `D0` (deleting), `D1` (complete), `D2` (base) dtors
fn is_cxx_abi_variant(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // Extract (group, position) for each name. If both share group + prefix
    // + suffix, they are body-equivalent by ABI.
    let locate = |s: &str| -> Option<(char, usize)> {
        for &(ch, tag) in &[('C', "C1E"), ('C', "C2E"), ('C', "C3E"),
                            ('D', "D0E"), ('D', "D1E"), ('D', "D2E")] {
            if let Some(p) = s.find(tag) {
                return Some((ch, p));
            }
        }
        None
    };
    if let (Some((ga, pa)), Some((gb, pb))) = (locate(a), locate(b)) {
        if ga == gb && pa == pb && a[..pa] == b[..pb] && a[pa + 2..] == b[pb + 2..] {
            return true;
        }
    }
    false
}
