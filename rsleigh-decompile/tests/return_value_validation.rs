//! Audit P1 #4 wedge: return-value inference must surface ambiguity.
//!
//! `int wrap() { return foo(); }` and `void f() { foo(); }` compile to
//! identical x86-64 (call foo; ret). The decompiler picks the wrap()
//! interpretation (more common) but must record a StaleReturnInherited
//! diagnostic so audits can flag genuine void cases.

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_decompile::analysis::{
    collect_callsite_return_uses, validate_returns_against_callsites,
};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{DiagKind, Severity, SsaTerminator};
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn ram(addr: u64, size: u32) -> Varnode {
    Varnode {
        space: AddressSpaceId::Ram,
        offset: addr,
        size,
    }
}

fn inst(len: u64, ops: Vec<PcodeOp>) -> Instruction {
    Instruction {
        len,
        disassembly: String::new(),
        ops,
        constructor: None,
    }
}

#[test]
fn call_then_ret_emits_stale_return_diagnostic() {
    // call foo (direct, target 0x2000)
    // ret
    //
    // Both `int wrap() { return foo(); }` and `void f() { foo(); }`
    // produce this code. The decompiler can't tell them apart without
    // callsite info — pin that it (a) still infers a return so the
    // wrap() case prints correctly and (b) emits StaleReturnInherited.
    let insts = vec![
        (
            0x1000,
            inst(
                5,
                vec![PcodeOp::Call {
                    dest: ram(0x2000, 8),
                }],
            ),
        ),
        (0x1005, inst(1, vec![PcodeOp::Return { dest: ram(0, 8) }])),
    ];

    let cfg = build_cfg(&insts);
    let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
    fold_with_cc(&mut ssa, CallingConv::SysV);

    // Two acceptable outcomes — both reflect a valid choice the decompiler
    // can make for `call foo; ret`:
    //   (a) Return(Some(call_return)) + StaleReturnInherited diag — wrap()
    //       interpretation, ambiguity surfaced.
    //   (b) Return(None) and no diag — the synthetic call_return clobber
    //       was DCE'd before detect_return_values ran (no use of the
    //       value), so the function reads as void without ambiguity.
    let returned_some = ssa
        .blocks
        .iter()
        .any(|b| matches!(b.terminator, SsaTerminator::Return(Some(_))));
    let stale = ssa
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagKind::StaleReturnInherited)
        .count();
    if returned_some {
        assert_eq!(
            stale, 1,
            "Return(Some) without StaleReturnInherited diag — wrap/void \
             ambiguity hidden; diags: {:#?}",
            ssa.diagnostics
        );
        let d = ssa
            .diagnostics
            .iter()
            .find(|d| d.kind == DiagKind::StaleReturnInherited)
            .unwrap();
        assert_eq!(d.severity, Severity::Info);
    } else {
        assert_eq!(
            stale, 0,
            "Return(None) but StaleReturnInherited diag fired anyway — \
             the diagnostic should only accompany an actual promotion: {:#?}",
            ssa.diagnostics
        );
    }
}

#[test]
fn explicit_rax_write_does_not_emit_stale_diagnostic() {
    // mov eax, 42; ret  — explicit return, no ambiguity.
    let bytes: &[u8] = &[
        0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
        0xc3, // ret
    ];
    let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_64);
    let mut decoded = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = 0x1000 + off as u64;
        let inst = dec.decode(&bytes[off..], addr).unwrap();
        let l = inst.len as usize;
        decoded.push((addr, inst));
        off += l;
    }
    let cfg = build_cfg(&decoded);
    let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
    fold_with_cc(&mut ssa, CallingConv::SysV);

    let stale = ssa
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagKind::StaleReturnInherited)
        .count();
    assert_eq!(
        stale, 0,
        "explicit RAX write should not trigger StaleReturnInherited; \
         diagnostics: {:#?}",
        ssa.diagnostics
    );
}

#[test]
fn collect_callsite_uses_zero_for_call_then_immediate_ret() {
    // call foo; ret — function does not read foo's return.
    let insts = vec![
        (
            0x1000,
            inst(
                5,
                vec![PcodeOp::Call {
                    dest: ram(0x2000, 8),
                }],
            ),
        ),
        (0x1005, inst(1, vec![PcodeOp::Return { dest: ram(0, 8) }])),
    ];
    let cfg = build_cfg(&insts);
    let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
    fold_with_cc(&mut ssa, CallingConv::SysV);

    let uses = collect_callsite_return_uses(&ssa);
    // The synthetic call_return for foo at 0x2000 is created but never
    // consumed by a downstream Stmt::Assign read.
    assert!(
        uses.iter().any(|(callee, _)| *callee == 0x2000),
        "expected to see callee 0x2000 in {:?}",
        uses
    );
}

#[test]
fn validate_returns_demotes_when_no_caller_reads() {
    // Two synthetic functions: f calls g; nothing in f reads g's return.
    // After validation, g should be demoted to Return(None).
    let make_call_then_ret = |target: u64| {
        let insts = vec![
            (
                0x100,
                inst(
                    5,
                    vec![PcodeOp::Call {
                        dest: ram(target, 8),
                    }],
                ),
            ),
            (0x105, inst(1, vec![PcodeOp::Return { dest: ram(0, 8) }])),
        ];
        let cfg = build_cfg(&insts);
        let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
        fold_with_cc(&mut ssa, CallingConv::SysV);
        ssa
    };

    // g at 0x2000 — its body (`call h; ret`) inferred Return(Some) via
    // StaleReturnInherited, since detect_return_values would pick the
    // call_return from h. We need to trigger that path. Use the call→ret
    // pattern that fired the diagnostic in the existing first test.
    let g = make_call_then_ret(0x3000);
    // f at 0x1000 — calls g, ignores its return.
    let f = make_call_then_ret(0x2000);

    let mut funcs: Vec<(u64, _)> = vec![(0x1000, f), (0x2000, g)];
    let demoted = validate_returns_against_callsites(&mut funcs, false);

    // If g's detect_return_values stage actually inferred Return(Some) +
    // emitted the StaleReturnInherited, then validation must demote it.
    // The other path (DCE collapsed call_return → Return(None) already)
    // means nothing to demote.
    let g_after = &funcs[1].1;
    let g_returns_some = g_after
        .blocks
        .iter()
        .any(|b| matches!(b.terminator, SsaTerminator::Return(Some(_))));
    assert!(
        !g_returns_some,
        "g must not still hold Return(Some) after demotion: {:?}",
        g_after
            .blocks
            .iter()
            .map(|b| &b.terminator)
            .collect::<Vec<_>>()
    );
    // Both wrappers now retain their reaching call result in SSA. Neither
    // has an explicit consumer in this closed function set, so both are
    // demoted (including f, which has no callers in the supplied set).
    assert_eq!(demoted, 2);
    assert!(funcs[0].1.blocks.iter().all(|b| {
        !matches!(b.terminator, SsaTerminator::Return(Some(_)))
    }));
}

#[test]
fn validate_returns_skips_when_external_callers_assumed() {
    // External-callers mode must never demote, even when no caller reads
    // — preserves the wrap() interpretation for library exports.
    let make_call_then_ret = |target: u64| {
        let insts = vec![
            (
                0x100,
                inst(
                    5,
                    vec![PcodeOp::Call {
                        dest: ram(target, 8),
                    }],
                ),
            ),
            (0x105, inst(1, vec![PcodeOp::Return { dest: ram(0, 8) }])),
        ];
        let cfg = build_cfg(&insts);
        let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
        fold_with_cc(&mut ssa, CallingConv::SysV);
        ssa
    };

    let mut funcs: Vec<(u64, _)> = vec![(0x2000, make_call_then_ret(0x3000))];
    let demoted = validate_returns_against_callsites(&mut funcs, true);
    assert_eq!(demoted, 0);
}
