use pcode_ir::{Instruction, PcodeOp, Varnode};
use rsleigh_decompile::{
    fold::CallingConv,
    ir::{SsaCfg, SsaTerminator, VarId},
    provenance::OperationOrigin,
    slice::interprocedural::{self, Function, Limits},
};
use std::{collections::HashMap, rc::Rc};

struct Snapshot {
    ssa: SsaCfg,
    instructions: Vec<(u64, Instruction)>,
}
impl Function for Snapshot {
    fn ssa(&self) -> &SsaCfg {
        &self.ssa
    }
    fn operation(&self, origin: OperationOrigin) -> Option<&PcodeOp> {
        self.instructions
            .iter()
            .find(|(address, _)| *address == origin.instruction_address)?
            .1
            .ops
            .get(origin.operation_index)
    }
}
fn build(address: u64, ops: Vec<PcodeOp>) -> Rc<Snapshot> {
    let instructions: Vec<_> = ops
        .into_iter()
        .enumerate()
        .map(|(i, op)| {
            (
                address + i as u64,
                Instruction::new(1, String::new(), vec![op]),
            )
        })
        .collect();
    let ssa = rsleigh_decompile::folded_ssa(rsleigh_api::Architecture::X86_64, &instructions, None);
    Rc::new(Snapshot { ssa, instructions })
}
fn reg(offset: u64) -> Varnode {
    Varnode::register(offset, 8)
}
fn copy(offset: u64, value: u64) -> PcodeOp {
    PcodeOp::Copy {
        out: reg(offset),
        input: Varnode::constant(value, 8),
    }
}
fn call(address: u64) -> PcodeOp {
    PcodeOp::Call {
        dest: Varnode::ram(address, 8),
    }
}
fn ret() -> PcodeOp {
    PcodeOp::Return {
        dest: Varnode::ram(0, 8),
    }
}
fn root(snapshot: &Snapshot) -> VarId {
    snapshot
        .ssa
        .blocks
        .iter()
        .find_map(|b| {
            if let SsaTerminator::Return(Some(v)) = b.terminator {
                Some(v)
            } else {
                None
            }
        })
        .unwrap()
}
fn limits() -> Limits {
    Limits {
        max_nodes: 64,
        max_depth: 16,
        max_call_depth: 3,
        max_functions: 8,
        max_work: 100_000,
    }
}

#[test]
fn direct_helper_return_connects_callee_parameter_to_its_callers_argument() {
    let caller = build(0x1000, vec![copy(56, 17), call(0x2000), ret()]);
    let callee = build(
        0x2000,
        vec![
            PcodeOp::IntAdd {
                out: reg(0),
                left: reg(56),
                right: Varnode::constant(5, 8),
            },
            ret(),
        ],
    );
    // Reusing snapshots must not consume a new SSA construction allowance.
    let _budget = rsleigh_decompile::budget::Scope::new(rsleigh_decompile::budget::Limits {
        ssa_work: Some(0),
        ..Default::default()
    });
    let slice = interprocedural::backward(
        0x1000,
        root(&caller),
        caller,
        CallingConv::SysV,
        &HashMap::new(),
        limits(),
        |address| {
            assert_eq!(address, 0x2000);
            Ok(Rc::clone(&callee))
        },
    )
    .unwrap();
    assert!(slice.complete, "{slice:?}");
    assert_eq!(slice.contexts.len(), 2);
    assert!(slice
        .nodes
        .iter()
        .any(|n| n.function_address == 0x2000 && n.node.kind == "binary.Add"));
    assert!(slice
        .nodes
        .iter()
        .any(|n| n.context_id == 0 && n.node.constant == Some(17)));
    let parameter = slice
        .nodes
        .iter()
        .find(|n| n.links.iter().any(|l| l.kind == "argument_binding"))
        .unwrap();
    assert_eq!(parameter.context_id, 1);
    assert_eq!(parameter.links[0].target.context_id, 0);
    let call = slice.nodes.iter().find_map(|n| n.call.as_ref()).unwrap();
    assert_eq!(call.origin.instruction_address, 0x1001);
    assert_eq!(call.confidence, "direct");
    assert_eq!(rsleigh_decompile::budget::metrics().ssa_work, 0);
}

#[test]
fn two_calls_to_one_helper_keep_distinct_argument_bindings() {
    let caller = build(
        0x1000,
        vec![
            copy(56, 11),
            call(0x2000),
            PcodeOp::Copy {
                out: reg(24),
                input: reg(0),
            },
            copy(56, 22),
            call(0x2000),
            PcodeOp::IntAdd {
                out: reg(0),
                left: reg(24),
                right: reg(0),
            },
            ret(),
        ],
    );
    let callee = build(
        0x2000,
        vec![
            PcodeOp::Copy {
                out: reg(0),
                input: reg(56),
            },
            ret(),
        ],
    );
    let slice = interprocedural::backward(
        0x1000,
        root(&caller),
        caller,
        CallingConv::SysV,
        &HashMap::new(),
        limits(),
        |_| Ok(Rc::clone(&callee)),
    )
    .unwrap();
    assert!(slice.complete, "{slice:?}");
    assert_eq!(slice.contexts.len(), 3);
    let bindings: Vec<_> = slice
        .nodes
        .iter()
        .flat_map(|n| n.links.iter())
        .filter(|l| l.kind == "argument_binding")
        .map(|l| l.target)
        .collect();
    assert_eq!(bindings.len(), 2);
    assert_ne!(bindings[0], bindings[1]);
    let mut values: Vec<_> = bindings
        .iter()
        .map(|b| {
            slice
                .nodes
                .iter()
                .find(|n| n.context_id == b.context_id && n.node.var_id == b.var_id)
                .unwrap()
                .node
                .constant
                .unwrap()
        })
        .collect();
    values.sort();
    assert_eq!(values, vec![11, 22]);
}

#[test]
fn spilled_call_result_retains_its_helper_dependency() {
    let caller = build(
        0x1000,
        vec![
            call(0x2000),
            PcodeOp::Store {
                space: pcode_ir::AddressSpaceId::Ram,
                ptr: reg(32),
                val: reg(0),
            },
            PcodeOp::Load {
                space: pcode_ir::AddressSpaceId::Ram,
                ptr: reg(32),
                out: reg(0),
            },
            ret(),
        ],
    );
    let callee = build(0x2000, vec![copy(0, 37), ret()]);
    let slice = interprocedural::backward(
        0x1000,
        root(&caller),
        caller,
        CallingConv::SysV,
        &HashMap::new(),
        limits(),
        |_| Ok(Rc::clone(&callee)),
    )
    .unwrap();
    assert!(slice.complete, "{slice:?}");
    assert!(slice
        .nodes
        .iter()
        .any(|n| n.function_address == 0x2000 && n.node.constant == Some(37)));
}

#[test]
fn a_clobbered_argument_does_not_reuse_the_value_from_before_another_call() {
    let caller = build(
        0x1000,
        vec![copy(56, 11), call(0x3000), call(0x2000), ret()],
    );
    let callee = build(
        0x2000,
        vec![
            PcodeOp::Copy {
                out: reg(0),
                input: reg(56),
            },
            ret(),
        ],
    );
    let slice = interprocedural::backward(
        0x1000,
        root(&caller),
        caller,
        CallingConv::SysV,
        &HashMap::new(),
        limits(),
        |address| {
            assert_eq!(address, 0x2000);
            Ok(Rc::clone(&callee))
        },
    )
    .unwrap();
    assert!(!slice.complete, "{slice:?}");
    assert!(slice
        .nodes
        .iter()
        .any(|n| n.node.boundary == Some("missing_call_argument")), "{slice:?}");
    assert!(!slice.nodes.iter().any(|n| n.node.constant == Some(11)));
}

#[test]
fn recursion_and_each_traversal_limit_are_explicit() {
    let caller = build(0x1000, vec![call(0x2000), ret()]);
    let recursive = build(0x2000, vec![call(0x1000), ret()]);
    for (limits, expected) in [
        (limits(), "recursion_limit"),
        (
            Limits {
                max_call_depth: 0,
                ..limits()
            },
            "call_depth_limit",
        ),
        (
            Limits {
                max_functions: 1,
                ..limits()
            },
            "function_limit",
        ),
        (
            Limits {
                max_nodes: 1,
                ..limits()
            },
            "node_limit",
        ),
        (
            Limits {
                max_work: 0,
                ..limits()
            },
            "traversal_work_limit",
        ),
    ] {
        let slice = interprocedural::backward(
            0x1000,
            root(&caller),
            Rc::clone(&caller),
            CallingConv::SysV,
            &HashMap::new(),
            limits,
            |_| Ok(Rc::clone(&recursive)),
        )
        .unwrap();
        assert!(!slice.complete && slice.truncated);
        assert!(
            slice.stops.iter().any(|s| s == expected)
                || slice
                    .nodes
                    .iter()
                    .any(|n| n.node.boundary == Some(expected)),
            "expected {expected}: {slice:?}"
        );
        assert!(slice.metrics.functions_visited <= limits.max_functions);
        assert!(slice.metrics.traversal_work <= limits.max_work);
    }
}

#[test]
fn unknown_calls_missing_arguments_and_side_effects_stay_unknown() {
    let caller = build(0x1000, vec![copy(56, 11), call(0x2000), ret()]);
    for (callee, reason) in [
        (
            build(
                0x2000,
                vec![
                    PcodeOp::Copy {
                        out: reg(0),
                        input: reg(48),
                    },
                    ret(),
                ],
            ),
            "missing_call_argument",
        ),
        (
            build(
                0x2000,
                vec![
                    PcodeOp::Store {
                        space: pcode_ir::AddressSpaceId::Ram,
                        ptr: Varnode::constant(0x5000, 8),
                        val: Varnode::constant(9, 8),
                    },
                    copy(0, 3),
                    ret(),
                ],
            ),
            "unsupported_side_effects",
        ),
    ] {
        let slice = interprocedural::backward(
            0x1000,
            root(&caller),
            Rc::clone(&caller),
            CallingConv::SysV,
            &HashMap::new(),
            limits(),
            |_| Ok(Rc::clone(&callee)),
        )
        .unwrap();
        assert!(!slice.complete);
        assert!(
            slice.nodes.iter().any(|n| n.node.boundary == Some(reason)),
            "{slice:?}"
        );
    }
    let unknown = build(0x1000, vec![PcodeOp::CallInd { dest: reg(16) }, ret()]);
    let slice = interprocedural::backward(
        0x1000,
        root(&unknown),
        unknown,
        CallingConv::SysV,
        &HashMap::new(),
        limits(),
        |_| panic!("unknown target must not be loaded"),
    )
    .unwrap();
    assert!(!slice.complete);
    assert!(slice
        .nodes
        .iter()
        .any(|n| n.node.boundary == Some("unknown_call")));
}
