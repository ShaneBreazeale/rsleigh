//! Regression: partial-register write must blend into parent, not clobber.
//!
//!   mov eax, 0x12345678   ; RAX low 4 bytes = 0x12345678 (zext to 8)
//!   mov al,  0x01         ; RAX low byte = 0x01 — must produce 0x12345601
//!   ret                   ; returns RAX
//!
//! Current SSA approximates the parent merge as a pure Zext of the new
//! sub-write, losing the high bytes of the prior value. Audit P1: the
//! merge must be `(parent_old & !mask) | Zext(new)` to preserve them.
//!
//! This test passes once the partial-register blend is fixed.

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{Expr, SsaCfg, SsaTerminator, VarId};
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn decode_x64(bytes: &[u8], base: u64) -> Vec<(u64, pcode_ir::Instruction)> {
    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = base + off as u64;
        match dec.decode(&bytes[off..], addr) {
            Ok(inst) => {
                let l = inst.len as usize;
                insts.push((addr, inst));
                off += l;
            }
            Err(_) => break,
        }
    }
    insts
}

/// Walk the Expr tree and collect every Const value reachable through
/// constant-foldable operators. Used to confirm the high-byte constant
/// 0x12345600 (or full 0x12345601) survives into the return expression.
fn collect_const_values(ssa: &SsaCfg, root: VarId) -> Vec<u64> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    let mut seen = std::collections::HashSet::new();
    while let Some(vid) = stack.pop() {
        if !seen.insert(vid.0) {
            continue;
        }
        let vdef = &ssa.vars[vid.0 as usize];
        match &vdef.expr {
            Expr::Const(v, _) => out.push(*v),
            Expr::Var(v) => stack.push(*v),
            Expr::BinOp(_, l, r) => {
                stack.push(*l);
                stack.push(*r);
            }
            Expr::UnaryOp(_, x) => stack.push(*x),
            Expr::Phi(inputs) => stack.extend(inputs.iter().copied()),
            _ => {}
        }
    }
    out
}

#[test]
fn partial_register_low_byte_write_preserves_high_bytes() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: &[u8] = &[
                0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
                0xb0, 0x01, // mov al, 0x01
                0xc3, // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            assert_eq!(insts.len(), 3, "decode produced {} instructions", insts.len());

            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
            fold_with_cc(&mut ssa, CallingConv::SysV);

            // Find the return terminator and walk its return value.
            let mut return_var: Option<VarId> = None;
            for block in &ssa.blocks {
                if let SsaTerminator::Return(Some(vid)) = &block.terminator {
                    return_var = Some(*vid);
                }
            }
            let rv = return_var.expect("function returns a value");

            let constants = collect_const_values(&ssa, rv);
            // The high-byte constant (0x12345600 — or any value containing the
            // high three bytes of 0x12345678 — must survive). After the fix the
            // expression collapses to a single Const(0x12345601) so that's the
            // strongest assertion. A pure-Zext bug leaves only Const(1).
            let preserved_high_bytes = constants.iter().any(|&c| {
                c == 0x12345601
                    || c == 0x12345600
                    || c == 0x12345678
                    || (c & 0xFFFF_FF00) == 0x12345600
            });
            assert!(
                preserved_high_bytes,
                "partial-register merge dropped the high bytes; \
                 return-expr constants = {:#x?} (want 0x12345601 or evidence of 0x12345600)",
                constants
            );
        })
        .unwrap();
    handle.join().unwrap();
}
