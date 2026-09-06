use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_decompile::{
    cfg::build_cfg,
    fold::{fold_with_cc, CallingConv},
    ir::{Expr, SsaCfg},
    memory::{Access, Boundary},
    ssa::build_ssa_with_cc,
};

fn store(ptr: Varnode, value: u64, size: u32) -> PcodeOp {
    PcodeOp::Store {
        space: AddressSpaceId::Ram,
        ptr,
        val: Varnode::constant(value, size),
    }
}
fn load(ptr: Varnode, size: u32) -> PcodeOp {
    PcodeOp::Load {
        space: AddressSpaceId::Ram,
        ptr,
        out: Varnode::register(0, size),
    }
}
fn build(ops: Vec<PcodeOp>) -> SsaCfg {
    let instructions: Vec<_> = ops
        .into_iter()
        .enumerate()
        .map(|(i, op)| {
            (
                0x1000 + i as u64,
                Instruction {
                    len: 1,
                    disassembly: String::new(),
                    ops: vec![op],
                    constructor: None,
                },
            )
        })
        .collect();
    build_ssa_with_cc(&build_cfg(&instructions), CallingConv::SysV)
}
fn load_boundary(ssa: &SsaCfg) -> Option<Boundary> {
    ssa.vars
        .iter()
        .rev()
        .find_map(|v| match &v.memory {
            Some(Access::Load { boundary, .. }) => Some(*boundary),
            _ => None,
        })
        .expect("load metadata")
}

#[test]
fn stack_spill_reload_preserves_the_store_and_load_instructions_after_folding() {
    let rsp = Varnode::register(32, 8);
    let mut ssa = build(vec![store(rsp, 73, 8), load(rsp, 8)]);
    assert_eq!(load_boundary(&ssa), None);
    fold_with_cc(&mut ssa, CallingConv::SysV);
    let loaded = ssa
        .vars
        .iter()
        .find(|v| matches!(v.memory, Some(Access::Load { .. })))
        .unwrap();
    assert!(matches!(loaded.expr, Expr::Const(73, 8)));
    let addresses: Vec<_> = loaded
        .origins
        .operations
        .iter()
        .map(|o| o.instruction_address)
        .collect();
    assert!(addresses.contains(&0x1000) && addresses.contains(&0x1001));
    let Some(Access::Load {
        stores,
        boundary: None,
        ..
    }) = &loaded.memory
    else {
        panic!("resolved store");
    };
    assert_eq!(stores.len(), 1);
    assert!(matches!(
        ssa.var(stores[0]).memory,
        Some(Access::Store { .. })
    ));
}

#[test]
fn unknown_store_invalidates_both_stack_and_constant_locations() {
    for ptr in [Varnode::register(32, 8), Varnode::constant(0x5000, 8)] {
        let ssa = build(vec![
            store(ptr, 73, 8),
            store(Varnode::register(56, 8), 0, 8),
            load(ptr, 8),
        ]);
        assert_eq!(load_boundary(&ssa), Some(Boundary::AmbiguousAlias));
        assert!(ssa.vars.iter().any(|v| matches!(v.expr, Expr::Load(_))));
    }
}

#[test]
fn spilling_an_unresolved_read_preserves_its_alias_boundary() {
    let rsp = Varnode::register(32, 8);
    let mut ssa = build(vec![
        store(rsp, 73, 8),
        store(Varnode::register(56, 8), 0, 8),
        load(Varnode::constant(0x5000, 8), 8),
        PcodeOp::Store {
            space: AddressSpaceId::Ram,
            ptr: rsp,
            val: Varnode::register(0, 8),
        },
        load(rsp, 8),
    ]);
    let root = ssa
        .vars
        .iter()
        .rev()
        .find(|v| matches!(&v.memory, Some(Access::Load { stores, .. }) if !stores.is_empty()))
        .unwrap()
        .id;
    fold_with_cc(&mut ssa, CallingConv::SysV);
    let slice = rsleigh_decompile::slice::backward_slice(&ssa, root, 64, 16).unwrap();
    assert!(!slice.complete);
    assert!(slice
        .nodes
        .iter()
        .any(|node| node.boundary == Some("ambiguous_alias")));
}

#[test]
fn overlapping_writes_invalidate_but_disjoint_writes_preserve_a_value() {
    for (second, expected) in [(0x5004, Some(Boundary::OverlappingStore)), (0x5008, None)] {
        let ssa = build(vec![
            store(Varnode::constant(0x5000, 8), 73, 8),
            store(Varnode::constant(second, 8), 1, 4),
            load(Varnode::constant(0x5000, 8), 8),
        ]);
        assert_eq!(load_boundary(&ssa), expected);
    }
}

#[test]
fn call_and_user_operation_side_effects_stop_memory_forwarding() {
    let ptr = Varnode::constant(0x5000, 8);
    for effect in [
        PcodeOp::Call {
            dest: Varnode::ram(0x2000, 8),
        },
        PcodeOp::CallOther {
            out: None,
            func_id: 3,
            inputs: vec![],
        },
    ] {
        let ssa = build(vec![store(ptr, 73, 8), effect, load(ptr, 8)]);
        assert_eq!(load_boundary(&ssa), Some(Boundary::UnsupportedSideEffects));
    }
}

#[test]
fn a_path_without_a_store_cannot_inherit_another_paths_value() {
    let ptr = Varnode::constant(0x5000, 8);
    let ssa = build(vec![
        PcodeOp::CBranch {
            dest: Varnode::ram(0x1003, 8),
            cond: Varnode::register(8, 1),
        },
        store(ptr, 73, 8),
        PcodeOp::Branch {
            dest: Varnode::ram(0x1004, 8),
        },
        PcodeOp::Copy {
            out: Varnode::register(16, 8),
            input: Varnode::constant(0, 8),
        },
        load(ptr, 8),
    ]);
    assert!(load_boundary(&ssa).is_some());
}

#[test]
fn changed_frame_register_is_not_the_same_stack_slot() {
    let rsp = Varnode::register(32, 8);
    let ssa = build(vec![
        store(rsp, 73, 8),
        PcodeOp::IntSub {
            out: rsp,
            left: rsp,
            right: Varnode::constant(8, 8),
        },
        load(rsp, 8),
    ]);
    assert!(load_boundary(&ssa).is_some());
}

#[test]
fn loops_merge_only_known_reaching_stores_and_terminate() {
    let ptr = Varnode::constant(0x5000, 8);
    let ssa = build(vec![
        store(ptr, 11, 8),
        load(ptr, 8),
        store(ptr, 22, 8),
        PcodeOp::CBranch {
            dest: Varnode::ram(0x1001, 8),
            cond: Varnode::register(8, 1),
        },
        load(ptr, 8),
    ]);
    assert!(ssa.vars.len() < 100);
    for v in &ssa.vars {
        if let Some(Access::Load {
            stores, boundary, ..
        }) = &v.memory
        {
            // The loop header can conservatively remain unknown. A known
            // dependency must have explicit store definitions, never a guess.
            assert!(boundary.is_some() || !stores.is_empty());
        }
    }
}
