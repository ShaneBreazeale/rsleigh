//! Diagnostic channel surfaces approximations made during CFG/SSA build.
//!
//! Two cases pinned:
//!   1. A clean instruction stream produces an empty `diagnostics` vec.
//!   2. A jump to an address outside the decoded instruction set produces a
//!      `UnresolvedBranchTarget` warning.

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::CallingConv;
use rsleigh_decompile::ir::{DiagKind, Severity};
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
                insts.push((addr, inst));
                off += l;
            }
            Err(_) => break,
        }
    }
    insts
}

#[test]
fn clean_decode_emits_no_diagnostics() {
    // mov eax, 0x12345678; mov al, 1; ret — no branches, all ops covered.
    let bytes: &[u8] = &[
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0xb0, 0x01, // mov al, 1
        0xc3, // ret
    ];
    let insts = decode_x64(bytes, 0x1000);
    let cfg = build_cfg(&insts);
    assert!(
        cfg.diagnostics.is_empty(),
        "clean cfg leaked diagnostics: {:#?}",
        cfg.diagnostics
    );
    let ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
    assert!(
        ssa.diagnostics.is_empty(),
        "clean ssa leaked diagnostics: {:#?}",
        ssa.diagnostics
    );
}

#[test]
fn unresolved_indirect_call_emits_diagnostic() {
    // CallInd through a register that the resolver can't trace to a const.
    let inst = |len: u64, ops: Vec<PcodeOp>| Instruction {
        len,
        disassembly: String::new(),
        ops,
    };
    let dest = Varnode {
        space: AddressSpaceId::Register,
        offset: 8, // RCX or similar — no Load chain in this fixture
        size: 8,
    };
    let insts = vec![
        (0x1000, inst(2, vec![PcodeOp::CallInd { dest }])),
        (0x1002, inst(1, vec![PcodeOp::Return { dest: Varnode { space: AddressSpaceId::Ram, offset: 0, size: 8 } }])),
    ];
    let cfg = build_cfg(&insts);

    let unresolved = cfg
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagKind::UnresolvedIndirectCall)
        .count();
    assert_eq!(
        unresolved, 1,
        "expected one UnresolvedIndirectCall diagnostic, got {}: {:#?}",
        unresolved, cfg.diagnostics
    );
    let d = cfg
        .diagnostics
        .iter()
        .find(|d| d.kind == DiagKind::UnresolvedIndirectCall)
        .unwrap();
    assert_eq!(d.severity, Severity::Info);
    assert_eq!(d.addr, Some(0x1000));
}

#[test]
fn unresolved_branch_target_emits_diagnostic() {
    // Hand-built instruction stream: a Branch to an address that isn't a
    // leader. This is exactly the case the audit's branch-snap removal
    // exposed — the cfg now downgrades to Indirect AND records why.
    let inst = |len: u64, ops: Vec<PcodeOp>| Instruction {
        len,
        disassembly: String::new(),
        ops,
    };
    let insts = vec![
        (
            0x1000,
            inst(
                4,
                vec![PcodeOp::Branch {
                    dest: Varnode {
                        space: AddressSpaceId::Ram,
                        offset: 0x1006, // mid-instruction → not a leader
                        size: 8,
                    },
                }],
            ),
        ),
        (0x1004, inst(4, vec![])),
        (0x1008, inst(4, vec![])),
    ];
    let cfg = build_cfg(&insts);

    assert_eq!(
        cfg.diagnostics.len(),
        1,
        "expected exactly one diagnostic, got {:#?}",
        cfg.diagnostics
    );
    let d = &cfg.diagnostics[0];
    assert_eq!(d.severity, Severity::Warn);
    assert_eq!(d.kind, DiagKind::UnresolvedBranchTarget);
    assert_eq!(d.addr, Some(0x1000));
    assert!(
        d.detail.contains("0x1006"),
        "diagnostic detail missing target: {}",
        d.detail
    );

    // SSA inherits the cfg diagnostics.
    let ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
    assert_eq!(
        ssa.diagnostics.len(),
        1,
        "ssa did not inherit cfg diagnostics: {:#?}",
        ssa.diagnostics
    );
}
