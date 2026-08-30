//! SSA predecessor roles must follow DFS edge classification, never BlockId
//! ordering. These graphs intentionally put headers/joins before their acyclic
//! predecessors in storage order.

use pcode_ir::{AddressSpaceId, PcodeOp, Varnode};
use rsleigh_decompile::fold::CallingConv;
use rsleigh_decompile::ir::{BasicBlock, BlockId, Cfg, Expr, SsaCfg, Stmt, Terminator, VarId};
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn reg(offset: u64) -> Varnode {
    Varnode {
        space: AddressSpaceId::Register,
        offset,
        size: 8,
    }
}

fn copy(addr: u64, out: Varnode, input: Varnode) -> (u64, PcodeOp) {
    (addr, PcodeOp::Copy { out, input })
}

fn assigned_var(ssa: &SsaCfg, block: BlockId, varnode: Varnode) -> VarId {
    ssa.blocks[block.0]
        .stmts
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Assign(id) if ssa.vars[id.0 as usize].varnode == varnode => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("block {:?} has no assignment for {:?}", block, varnode))
}

fn assert_copy_reads_phi(ssa: &SsaCfg, block: BlockId, source: Varnode, copy_out: Varnode) {
    let phi = ssa.blocks[block.0]
        .stmts
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Assign(id)
                if ssa.vars[id.0 as usize].varnode == source
                    && matches!(ssa.vars[id.0 as usize].expr, Expr::Phi(_)) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .expect("join/header Phi");
    let copied = assigned_var(ssa, block, copy_out);
    assert!(
        matches!(ssa.vars[copied.0 as usize].expr, Expr::Var(id) if id == phi),
        "copy did not read Phi {:?}: {:?}",
        phi,
        ssa.vars[copied.0 as usize].expr
    );
}

#[test]
fn layout_reversed_loop_relinks_from_acyclic_entry() {
    // DFS: B3(entry) -> B2(header) -> B1(latch) -> B2(back), then B2 -> B0.
    // Numeric ordering says B1 is forward and B3 is back; classification says
    // the opposite.
    let r0 = reg(0);
    let r1 = reg(8);
    let cfg = Cfg {
        blocks: vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x1000,
                ops: vec![],
                terminator: Terminator::Return,
            },
            BasicBlock {
                id: BlockId(1),
                addr: 0x1010,
                ops: vec![(
                    0x1010,
                    PcodeOp::IntAdd {
                        out: r0,
                        left: r0,
                        right: Varnode::constant(1, 8),
                    },
                )],
                terminator: Terminator::Branch(BlockId(2)),
            },
            BasicBlock {
                id: BlockId(2),
                addr: 0x1020,
                ops: vec![copy(0x1020, r1, r0)],
                terminator: Terminator::CBranch {
                    cond: Varnode::constant(1, 1),
                    taken: BlockId(1),
                    fallthrough: BlockId(0),
                },
            },
            BasicBlock {
                id: BlockId(3),
                addr: 0x1030,
                ops: vec![copy(0x1030, r0, Varnode::constant(0, 8))],
                terminator: Terminator::Branch(BlockId(2)),
            },
        ],
        entry: BlockId(3),
        diagnostics: vec![],
    };

    let ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
    assert_copy_reads_phi(&ssa, BlockId(2), r0, r1);
}

#[test]
fn tree_plus_cross_join_relinks_both_acyclic_inputs() {
    // DFS visits B0 -> B2 -> B1 first, then B0 -> B3 -> B1. B3 -> B1 is a
    // cross edge. Both predecessor IDs are greater than the join ID.
    let r0 = reg(0);
    let r1 = reg(8);
    let cfg = Cfg {
        blocks: vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x1000,
                ops: vec![],
                terminator: Terminator::CBranch {
                    cond: Varnode::constant(1, 1),
                    taken: BlockId(2),
                    fallthrough: BlockId(3),
                },
            },
            BasicBlock {
                id: BlockId(1),
                addr: 0x1010,
                ops: vec![copy(0x1010, r1, r0)],
                terminator: Terminator::Return,
            },
            BasicBlock {
                id: BlockId(2),
                addr: 0x1020,
                ops: vec![copy(0x1020, r0, Varnode::constant(11, 8))],
                terminator: Terminator::Branch(BlockId(1)),
            },
            BasicBlock {
                id: BlockId(3),
                addr: 0x1030,
                ops: vec![copy(0x1030, r0, Varnode::constant(22, 8))],
                terminator: Terminator::Branch(BlockId(1)),
            },
        ],
        entry: BlockId(0),
        diagnostics: vec![],
    };

    let ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
    assert_copy_reads_phi(&ssa, BlockId(1), r0, r1);
}
