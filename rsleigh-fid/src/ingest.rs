//! Build FID database rows from ELF/Mach-O/PE binaries using symbol tables.
//!
//! For each defined function symbol:
//!   1. Slice body bytes via symbol size (or stop at next function boundary).
//!   2. Linearly decode instructions through rsleigh-api.
//!   3. Mask operand bytes, concatenate, hash.
//!   4. Collect direct call targets (PcodeOp::CallInd skipped) for specific hash.

use pcode_ir::PcodeOp;
use rsleigh_api::{Architecture, Decoder};

use crate::hash::FidHashQuad;
use crate::mask::mask_instruction;

/// Minimum function size (bytes) worth hashing — below this, too many collisions.
pub const MIN_BODY_LEN: usize = 16;
/// Minimum code units (instructions) worth hashing.
pub const MIN_CODE_UNITS: u32 = 6;

/// Fingerprint one function body. Returns `None` if too small.
///
/// `direct_call_fulls` is an optional lookup: given a direct-call target
/// address, return the callee's `full` hash (for specific-hash computation).
/// If unavailable, pass `|_| None` and specific == full over an empty tail.
pub fn fingerprint<F>(
    arch: Architecture,
    body: &[u8],
    base_addr: u64,
    direct_call_fulls: F,
) -> Option<FidHashQuad>
where
    F: Fn(u64) -> Option<u64>,
{
    if body.len() < MIN_BODY_LEN {
        return None;
    }
    let mut decoder = Decoder::new(arch);
    let mut masked = Vec::with_capacity(body.len());
    let mut callees: Vec<u64> = Vec::new();
    let mut code_units: u32 = 0;
    let mut off = 0usize;
    while off < body.len() {
        let inst = match decoder.decode(&body[off..], base_addr + off as u64) {
            Ok(i) => i,
            Err(_) => break,
        };
        let ilen = inst.len as usize;
        if ilen == 0 || off + ilen > body.len() {
            break;
        }
        let m = mask_instruction(arch, &inst, &body[off..off + ilen]);
        masked.extend_from_slice(&m);
        for op in &inst.ops {
            if let PcodeOp::Call { dest } = op {
                if let Some(h) = direct_call_fulls(dest.offset) {
                    callees.push(h);
                }
            }
        }
        code_units += 1;
        off += ilen;
    }
    if code_units < MIN_CODE_UNITS {
        return None;
    }
    Some(FidHashQuad::new(&masked, code_units, &callees))
}
