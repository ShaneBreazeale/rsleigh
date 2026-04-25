//! Wedge for audit P1 #3 (memory model beyond stack): forward Store-of-const
//! through subsequent Load-of-same-const within a single basic block.
//!
//! Cross-block memory SSA stays out of scope (XL); intra-block global
//! forwarding is the smallest useful piece — pinning the test now lets the
//! data structure grow into cross-block reasoning later without breaking
//! the contract.

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::CallingConv;
use rsleigh_decompile::ir::{Expr, SsaTerminator, VarId};
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn ram(addr: u64, size: u32) -> Varnode {
    Varnode {
        space: AddressSpaceId::Ram,
        offset: addr,
        size,
    }
}

fn cnst(value: u64, size: u32) -> Varnode {
    Varnode {
        space: AddressSpaceId::Const,
        offset: value,
        size,
    }
}

fn rax() -> Varnode {
    Varnode {
        space: AddressSpaceId::Register,
        offset: 0,
        size: 8,
    }
}

fn unique(off: u64, size: u32) -> Varnode {
    Varnode {
        space: AddressSpaceId::Unique,
        offset: off,
        size,
    }
}

fn inst(len: u64, ops: Vec<PcodeOp>) -> Instruction {
    Instruction {
        len,
        disassembly: String::new(),
        ops,
    }
}

#[test]
fn store_then_load_of_same_global_addr_forwards_value() {
    // Synthetic three-instruction function:
    //   addr_unique = 0x4242                       (Copy const into a unique tmp)
    //   *(uint64_t*)addr_unique = 0xdeadbeef       (Store)
    //   rax = *(uint64_t*)addr_unique              (Load) — must yield the stored 0xdeadbeef
    //   return rax
    //
    // The pointer is the same Unique varnode for the Store and the Load, so
    // the SSA pass has full visibility that the addresses match. The forward
    // currently fails because only stack-frame slots are tracked.
    let addr = unique(0, 8);
    let val_node = cnst(0xdeadbeef, 8);
    let addr_const = cnst(0x4242, 8);

    let insts = vec![
        // Materialize the address into a unique tmp.
        (
            0x1000,
            inst(
                1,
                vec![PcodeOp::Copy {
                    out: addr,
                    input: addr_const,
                }],
            ),
        ),
        // Store the constant value through the tmp pointer.
        (
            0x1001,
            inst(
                1,
                vec![PcodeOp::Store {
                    space: AddressSpaceId::Ram,
                    ptr: addr,
                    val: val_node,
                }],
            ),
        ),
        // Load back through the same tmp pointer into RAX, then return.
        (
            0x1002,
            inst(
                1,
                vec![
                    PcodeOp::Load {
                        out: rax(),
                        space: AddressSpaceId::Ram,
                        ptr: addr,
                    },
                    PcodeOp::Return { dest: ram(0, 8) },
                ],
            ),
        ),
    ];

    let cfg = build_cfg(&insts);
    let ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);

    let mut return_var: Option<VarId> = None;
    for block in &ssa.blocks {
        if let SsaTerminator::Return(Some(vid)) = &block.terminator {
            return_var = Some(*vid);
        }
    }
    let rv = return_var.expect("function returns RAX");

    // Walk the return expression — must reach the stored Const(0xdeadbeef),
    // not a residual Expr::Load through the pointer.
    let mut stack = vec![rv];
    let mut seen = std::collections::HashSet::new();
    let mut found_stored = false;
    let mut saw_load = false;
    while let Some(vid) = stack.pop() {
        if !seen.insert(vid.0) {
            continue;
        }
        let vdef = &ssa.vars[vid.0 as usize];
        match &vdef.expr {
            Expr::Const(0xdeadbeef, _) => {
                found_stored = true;
            }
            Expr::Load(_) => {
                saw_load = true;
            }
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

    assert!(
        found_stored && !saw_load,
        "intra-block global forwarding failed: found_stored={} saw_load={}",
        found_stored,
        saw_load
    );
}
