//! Tests for RSP-relative local variable naming.
//!
//! Plan: docs/superpowers/plans/2026-04-16-rsp-local-naming-plan.md
//! Spec: docs/superpowers/specs/2026-04-16-rsp-local-naming-design.md

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{BinOpKind, Expr};
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn decode_x64(bytes: &[u8], base: u64) -> Vec<(u64, Instruction)> {
    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = base + off as u64;
        match dec.decode(&bytes[off..], addr) {
            Ok(inst) => {
                let l = inst.len as usize;
                let is_ret = inst.ops.iter().any(|op| matches!(op, PcodeOp::Return { .. }));
                insts.push((addr, inst));
                off += l;
                if is_ret { break; }
            }
            Err(_) => break,
        }
    }
    insts
}

/// After fold, RSP register VarDefs (offset 32) should not be chained BinOps.
/// `sub rsp, 8; sub rsp, 0x2d` should produce a single RSP = RSP - 53, not
/// RSP = (RSP - 8) - 45.
#[test]
fn fold_collapses_chained_rsp_arithmetic() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: &[u8] = &[
                0x48, 0x83, 0xEC, 0x08,   // sub rsp, 8
                0x48, 0x83, 0xEC, 0x2D,   // sub rsp, 0x2d
                0xC3,                     // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
            fold_with_cc(&mut ssa, CallingConv::SysV);

            let rsp_reg_offset: u64 = 32;

            // Find all RSP-register VarDefs that are BinOp(Sub/Add, X, C)
            // For each, check that X is NOT itself a BinOp(_, RSP_unknown, _).
            // That would mean a chained subtraction was not collapsed.
            let rsp_unknown_ids: Vec<_> = ssa.vars.iter()
                .filter(|v| {
                    v.varnode.space == AddressSpaceId::Register
                        && v.varnode.offset == rsp_reg_offset
                        && matches!(v.expr, Expr::Unknown)
                })
                .map(|v| v.id)
                .collect();

            for vdef in &ssa.vars {
                // Only check RSP register writes (not flag computations or other regs)
                if vdef.varnode.space != AddressSpaceId::Register
                    || vdef.varnode.offset != rsp_reg_offset
                {
                    continue;
                }
                if let Expr::BinOp(_, outer_left, _) = vdef.expr {
                    let inner = &ssa.vars[outer_left.0 as usize];
                    if let Expr::BinOp(_, inner_left, _) = inner.expr {
                        if rsp_unknown_ids.contains(&inner_left) {
                            panic!(
                                "chained RSP arithmetic was NOT collapsed: RSP VarDef #{} still has nested BinOp with RSP at inner left (inner_left=VarId({}))",
                                vdef.id.0, inner_left.0
                            );
                        }
                    }
                }
            }
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Decompiling a function with RSP-relative stack accesses should produce `local_XX`
/// variable names, not raw `RSP ± N` expressions.
///
/// Function: multiply two parameters, storing them to stack slots and reloading.
///   sub rsp, 0x28
///   mov [rsp+0x20], rdi      ; param_0 → var_8  (0x28 - 0x20 = 8)
///   mov [rsp+0x18], rsi      ; param_1 → var_10 (0x28 - 0x18 = 0x10)
///   mov rax, [rsp+0x20]
///   imul rax, [rsp+0x18]
///   add rsp, 0x28
///   ret
#[test]
fn decompile_rsp_relative_access_uses_local_name() {
    use rsleigh_decompile::decompile_with_binary;
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: &[u8] = &[
                0x48, 0x83, 0xEC, 0x28,               // sub rsp, 0x28
                0x48, 0x89, 0x7C, 0x24, 0x20,         // mov [rsp+0x20], rdi
                0x48, 0x89, 0x74, 0x24, 0x18,         // mov [rsp+0x18], rsi
                0x48, 0x8B, 0x44, 0x24, 0x20,         // mov rax, [rsp+0x20]
                0x48, 0x0F, 0xAF, 0x44, 0x24, 0x18,   // imul rax, [rsp+0x18]
                0x48, 0x83, 0xC4, 0x28,               // add rsp, 0x28
                0xC3,                                 // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let out = decompile_with_binary(Architecture::X86_64, &insts, None, None);
            assert!(
                out.contains("local_"),
                "expected 'local_' variable name in output, got:\n{}",
                out
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
