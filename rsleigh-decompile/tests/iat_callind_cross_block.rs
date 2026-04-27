//! Cross-block IAT-via-register call resolution.
//!
//! Pattern: `mov rax, [rip+IAT]` in block A, branch to block B,
//! `call rax` in block B. Block-local resolver previously returned
//! `Indirect` because the Load lives in a different block. Resolver
//! now scans the function's full op stream when block-local search
//! fails, conservatively bailing on intervening Calls (which clobber
//! caller-saved regs).

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::ir::{CallTarget, Terminator};

fn vn(space: AddressSpaceId, offset: u64, size: u32) -> Varnode {
    Varnode {
        space,
        offset,
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
fn cross_block_iat_load_into_reg_resolves_to_direct_target() {
    let rax = vn(AddressSpaceId::Register, 0, 8);
    let tmp = vn(AddressSpaceId::Unique, 0x100, 8);
    let iat_slot = vn(AddressSpaceId::Const, 0x2000, 8);
    let branch_target = vn(AddressSpaceId::Ram, 0x1010, 8);
    let ret_dest = vn(AddressSpaceId::Ram, 0, 8);

    let insts = vec![
        (
            0x1000,
            inst(
                7,
                vec![
                    PcodeOp::Load {
                        out: tmp,
                        space: AddressSpaceId::Ram,
                        ptr: iat_slot,
                    },
                    PcodeOp::Copy {
                        out: rax,
                        input: tmp,
                    },
                ],
            ),
        ),
        (
            0x1007,
            inst(
                5,
                vec![PcodeOp::Branch {
                    dest: branch_target,
                }],
            ),
        ),
        (0x1010, inst(2, vec![PcodeOp::CallInd { dest: rax }])),
        (0x1012, inst(1, vec![PcodeOp::Return { dest: ret_dest }])),
    ];
    let cfg = build_cfg(&insts);

    let target = cfg
        .blocks
        .iter()
        .find_map(|b| match &b.terminator {
            Terminator::Call { target, .. } => Some(target.clone()),
            _ => None,
        })
        .expect("no Call terminator built");

    assert!(
        matches!(target, CallTarget::Direct(0x2000)),
        "cross-block IAT-via-rax not resolved: got {:?}",
        target
    );
}

#[test]
fn cross_block_clobbered_by_intervening_call_stays_indirect() {
    // Same shape, but an intervening Call between the IAT load and the
    // CallInd. RAX is caller-saved by SysV — must NOT resolve.
    let rax = vn(AddressSpaceId::Register, 0, 8);
    let tmp = vn(AddressSpaceId::Unique, 0x100, 8);
    let iat_slot = vn(AddressSpaceId::Const, 0x2000, 8);
    let other_call_dst = vn(AddressSpaceId::Ram, 0x4000, 8);
    let branch_target = vn(AddressSpaceId::Ram, 0x1020, 8);
    let ret_dest = vn(AddressSpaceId::Ram, 0, 8);

    let insts = vec![
        (
            0x1000,
            inst(
                7,
                vec![
                    PcodeOp::Load {
                        out: tmp,
                        space: AddressSpaceId::Ram,
                        ptr: iat_slot,
                    },
                    PcodeOp::Copy {
                        out: rax,
                        input: tmp,
                    },
                ],
            ),
        ),
        (
            0x1007,
            inst(
                5,
                vec![PcodeOp::Call {
                    dest: other_call_dst,
                }],
            ),
        ),
        (
            0x100c,
            inst(
                5,
                vec![PcodeOp::Branch {
                    dest: branch_target,
                }],
            ),
        ),
        (0x1020, inst(2, vec![PcodeOp::CallInd { dest: rax }])),
        (0x1022, inst(1, vec![PcodeOp::Return { dest: ret_dest }])),
    ];
    let cfg = build_cfg(&insts);

    // Find the second Call (CallInd resolution) — that's the one we care
    // about. It must remain Indirect.
    let callind_target = cfg
        .blocks
        .iter()
        .filter_map(|b| match &b.terminator {
            Terminator::Call { target, .. } => Some((b.addr, target.clone())),
            _ => None,
        })
        .find(|(addr, _)| *addr == 0x1020)
        .map(|(_, t)| t)
        .expect("no callind block found");

    assert!(
        matches!(callind_target, CallTarget::Indirect(_)),
        "intervening Call should clobber rax — got {:?}",
        callind_target
    );
}
