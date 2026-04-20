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
