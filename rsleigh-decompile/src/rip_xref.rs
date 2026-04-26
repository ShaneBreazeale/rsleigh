//! Find all RIP-relative references to a target address across multiple
//! instruction encodings.
//!
//! The classic mistake is to fix on a single instruction length (usually
//! 7-byte LEA, `48 8d 05 d32`) and miss every other encoding. Real x86-64
//! code emits `disp32` operands at all of these lengths:
//!   - 5 bytes — `MOV EAX, [RIP+d32]` (`8b 05 d32`), `LEA EAX, [RIP+d32]`
//!     (`8d 05 d32`), CALL/JMP rel32 (`e8/e9 d32`).
//!   - 6 bytes — `CALL [RIP+d32]` (`ff 15 d32`), `JMP [RIP+d32]`
//!     (`ff 25 d32`), `CMP r32, [RIP+d32]` (`3b 05 d32`).
//!   - 7 bytes — REX-prefixed forms (LEA r64, MOV r64, etc.).
//!   - 8-10 bytes — REX + ModRM with SIB or extra prefixes.
//!
//! Naive 7-byte-only sweeps drop ~50% of refs in real code. This module
//! tries a sliding window over multiple instruction lengths and reports
//! every hit, classified by leading-byte sequence so the caller can
//! filter (e.g., "only CALL sites").
//!
//! See `repos/CrackMe_PyVMP_v5/WHITEPAPER.md` § 8.6 for the motivating
//! session — we missed many resolver-internal refs initially because we
//! only matched 7-byte LEA.

/// One observed reference to a target.
#[derive(Debug, Clone)]
pub struct Xref {
    /// Virtual address of the referencing instruction.
    pub site_va: u64,
    /// Instruction length in bytes.
    pub instr_len: usize,
    /// Heuristic instruction kind based on leading bytes.
    pub kind: XrefKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    /// Direct relative call (`E8 d32`).
    CallRel,
    /// Direct relative jump (`E9 d32`).
    JmpRel,
    /// Indirect call through `[RIP+d32]` (`FF 15 d32`).
    CallMem,
    /// Indirect jump through `[RIP+d32]` (`FF 25 d32`).
    JmpMem,
    /// LEA/MOV/CMP-style data reference, REX-prefixed (7B+).
    DataRef,
    /// Short LEA/MOV without REX (5B forms).
    DataRefShort,
    /// Anything else that decoded as a disp32 to the target.
    Other,
}

/// Try every plausible disp32-bearing instruction starting at offset
/// `off`, returning Some(Xref) when any encoding's effective address
/// equals `target_va`.
fn try_match(
    code: &[u8],
    off: usize,
    base_va: u64,
    target_va: u64,
) -> Option<Xref> {
    // Each encoding: (leading prefix bytes, total instruction length).
    // The disp32 lives at `off + prefix_len`. The instruction's "next
    // RIP" used for RIP-relative computation is `off + total_len`.
    // Ordered longest prefix first. When two encodings can both match
    // the bytes at `off`, the longer (REX-prefixed) match wins so we
    // don't accidentally classify a 7-byte LEA's `8d 05 d32` tail as
    // a separate 6-byte LEA at off+1 on the next iteration.
    const ENCODINGS: &[(&[u8], usize, XrefKind)] = &[
        // 7-byte REX-prefixed forms
        (&[0x48, 0x8b, 0x05], 7, XrefKind::DataRef), // MOV r64, [RIP+d32]
        (&[0x48, 0x8d, 0x05], 7, XrefKind::DataRef), // LEA r64, [RIP+d32]
        (&[0x48, 0x89, 0x05], 7, XrefKind::DataRef), // MOV [RIP+d32], r64
        (&[0x48, 0x3b, 0x05], 7, XrefKind::DataRef), // CMP r64, [RIP+d32]
        (&[0x4c, 0x8b, 0x05], 7, XrefKind::DataRef),
        (&[0x4c, 0x8d, 0x05], 7, XrefKind::DataRef),
        // 6-byte indirect call/jump
        (&[0xff, 0x15], 6, XrefKind::CallMem),
        (&[0xff, 0x25], 6, XrefKind::JmpMem),
        // 6-byte non-REX MOV/LEA
        (&[0x8b, 0x05], 6, XrefKind::DataRefShort),
        (&[0x8d, 0x05], 6, XrefKind::DataRefShort),
        // 5-byte direct call/jump
        (&[0xe8], 5, XrefKind::CallRel),
        (&[0xe9], 5, XrefKind::JmpRel),
    ];

    for (prefix, total_len, kind) in ENCODINGS.iter() {
        if off + *total_len > code.len() {
            continue;
        }
        if &code[off..off + prefix.len()] != *prefix {
            continue;
        }
        // Read disp32 immediately after prefix.
        let d32_off = off + prefix.len();
        if d32_off + 4 > code.len() {
            continue;
        }
        let disp = i32::from_le_bytes([
            code[d32_off],
            code[d32_off + 1],
            code[d32_off + 2],
            code[d32_off + 3],
        ]);
        let next_rip = base_va.wrapping_add((off + *total_len) as u64);
        let effective = next_rip.wrapping_add(disp as i64 as u64);
        if effective == target_va {
            return Some(Xref {
                site_va: base_va.wrapping_add(off as u64),
                instr_len: *total_len,
                kind: *kind,
            });
        }
    }
    None
}

/// Scan a code region for all RIP-relative references to `target_va`.
/// Returns one `Xref` per match. Sliding-byte scan; on a match, advance
/// by the matched instruction's length so a longer encoding's tail
/// bytes don't get re-interpreted as a shorter instruction starting one
/// byte later (the classic 7-byte LEA / 6-byte LEA overlap).
pub fn scan(code: &[u8], base_va: u64, target_va: u64) -> Vec<Xref> {
    let mut hits = Vec::new();
    let mut off = 0;
    while off < code.len() {
        if let Some(xref) = try_match(code, off, base_va, target_va) {
            let len = xref.instr_len;
            hits.push(xref);
            off += len.max(1);
            continue;
        }
        off += 1;
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_call_rel32() {
        // CALL rel32 from 0x1000 → target 0x2005.
        // disp32 = 0x2005 - 0x1005 = 0x1000.
        let mut code = vec![0xe8];
        code.extend_from_slice(&0x1000_i32.to_le_bytes());
        let hits = scan(&code, 0x1000, 0x2005);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, XrefKind::CallRel);
    }

    #[test]
    fn matches_lea_rip() {
        // 48 8d 05 d32 — LEA RAX, [RIP+d32]
        // From base 0x1000, disp 0x100 → target 0x1107 (next RIP = 0x1007).
        let mut code = vec![0x48, 0x8d, 0x05];
        code.extend_from_slice(&0x100_i32.to_le_bytes());
        let hits = scan(&code, 0x1000, 0x1107);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, XrefKind::DataRef);
        assert_eq!(hits[0].instr_len, 7);
    }

    #[test]
    fn matches_call_indirect() {
        // FF 15 d32 — CALL [RIP+d32]
        let mut code = vec![0xff, 0x15];
        code.extend_from_slice(&0x10_i32.to_le_bytes());
        let hits = scan(&code, 0x1000, 0x1016);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, XrefKind::CallMem);
        assert_eq!(hits[0].instr_len, 6);
    }

    #[test]
    fn matches_short_data_ref() {
        // 8b 05 d32 — MOV EAX, [RIP+d32] (no REX)
        let mut code = vec![0x8b, 0x05];
        code.extend_from_slice(&0x20_i32.to_le_bytes());
        let hits = scan(&code, 0x1000, 0x1026);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, XrefKind::DataRefShort);
    }

    #[test]
    fn no_false_positive_on_random_bytes() {
        let code = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let hits = scan(&code, 0x1000, 0x2000);
        assert!(hits.is_empty());
    }
}
