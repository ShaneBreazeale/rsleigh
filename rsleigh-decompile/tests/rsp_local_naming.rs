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

/// After fold, no VarDef should have BinOp(_, BinOp(_, RSP_var, _), _) with RSP at inner left.
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

            let rsp_offset: u64 = 32;
            let rsp_id = ssa.vars.iter().find(|v| {
                v.varnode.space == AddressSpaceId::Register
                    && v.varnode.offset == rsp_offset
                    && matches!(v.expr, Expr::Unknown)
            }).map(|v| v.id);

            if let Some(rsp_id) = rsp_id {
                for vdef in &ssa.vars {
                    if let Expr::BinOp(_, outer_left, _) = vdef.expr {
                        let inner = &ssa.vars[outer_left.0 as usize];
                        if let Expr::BinOp(_, inner_left, _) = inner.expr {
                            assert_ne!(
                                inner_left, rsp_id,
                                "chained RSP arithmetic was NOT collapsed: VarDef #{} still has nested BinOp with RSP at inner left",
                                vdef.id.0
                            );
                        }
                    }
                }
            }
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Decompiling a minimal RSP-relative function should produce local_ names, not raw RSP arithmetic.
#[test]
fn decompile_rsp_relative_access_uses_local_name() {
    use rsleigh_decompile::decompile_with_binary;
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: &[u8] = &[
                0x48, 0x83, 0xEC, 0x40,         // sub rsp, 0x40
                0xC6, 0x44, 0x24, 0x10, 0x42,   // mov byte ptr [rsp+0x10], 0x42
                0xC3,                           // ret
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
