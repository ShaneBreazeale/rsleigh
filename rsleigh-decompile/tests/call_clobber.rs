//! Regression: after a Call terminator, caller-saved registers must be
//! invalidated so post-call reads resolve to fresh Expr::Unknown VarDefs.
//!
//! Spec: docs/superpowers/specs/2026-04-16-ssa-call-clobber-design.md

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::CallingConv;
use rsleigh_decompile::ir::Expr;
use rsleigh_decompile::ssa::build_ssa_with_cc;

/// Decode a tiny x86-64 sequence: set RAX to a LEA result, CALL an absolute
/// address, then read RAX. Post-call RAX must be a fresh Unknown, not the
/// pre-call LEA value.
fn decode(bytes: &[u8], base: u64) -> Vec<(u64, Instruction)> {
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

#[test]
fn post_call_rax_is_unknown_win64() {
    // lea rax, [rip+0x10]       48 8D 05 10 00 00 00
    // mov rcx, rax               48 89 C1
    // call rel32 (to +0x20)      E8 13 00 00 00    (returns to insn after call)
    // mov rdx, rax               48 89 C2
    let bytes: [u8; 18] = [
        0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC1,
        0xE8, 0x13, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC2,
    ];
    let insts = decode(&bytes, 0x1000);
    assert!(insts.len() >= 4, "expected >=4 instructions, got {}", insts.len());

    let cfg = build_cfg(&insts);
    let ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);

    // The "mov rdx, rax" instruction reads RAX post-call. Its source must be
    // a VarDef whose expr is Expr::Unknown (a fresh clobber), NOT the LEA
    // expression from before the call.
    let rdx_vn = Varnode { space: AddressSpaceId::Register, offset: 16, size: 8 };
    let rdx_var = ssa
        .vars
        .iter()
        .rev()
        .find(|v| v.varnode == rdx_vn)
        .expect("no RDX assignment found");

    // RDX = Var(RAX_post_call) where RAX_post_call has Expr::Unknown.
    let rax_src_id = match rdx_var.expr {
        Expr::Var(id) => id,
        ref other => panic!("expected RDX = Var(RAX), got {:?}", other),
    };
    let rax_src = &ssa.vars[rax_src_id.0 as usize];
    assert!(
        matches!(rax_src.expr, Expr::Unknown),
        "post-call RAX must be Expr::Unknown; got {:?}",
        rax_src.expr
    );
    assert!(
        rax_src.call_return,
        "post-call RAX must be marked call_return=true"
    );
}
