use pcode_ir::{Instruction, PcodeOp, Varnode};
use rsleigh_decompile::{
    cfg::build_cfg,
    fold::{fold_with_cc, CallingConv},
    ir::Expr,
    provenance::OperationOrigin,
    ssa::build_ssa_with_cc,
};

fn inst(address: u64, ops: Vec<PcodeOp>) -> (u64, Instruction) {
    (
        address,
        Instruction {
            len: 4,
            disassembly: String::new(),
            ops,
            constructor: None,
        },
    )
}

#[test]
fn constant_folding_preserves_both_instructions_and_raw_indices() {
    let eax = Varnode::register(0, 4);
    let input = vec![
        inst(
            0x1000,
            vec![PcodeOp::Copy {
                out: eax,
                input: Varnode::constant(5, 4),
            }],
        ),
        inst(
            0x1004,
            vec![
                PcodeOp::IntAdd {
                    out: Varnode::unique(0, 4),
                    left: eax,
                    right: Varnode::constant(7, 4),
                },
                PcodeOp::Copy {
                    out: eax,
                    input: Varnode::unique(0, 4),
                },
            ],
        ),
        inst(
            0x1008,
            vec![PcodeOp::Return {
                dest: Varnode::register(0x288, 4),
            }],
        ),
    ];
    let mut ssa = build_ssa_with_cc(&build_cfg(&input), CallingConv::Cdecl32);
    fold_with_cc(&mut ssa, CallingConv::Cdecl32);
    let value = ssa
        .vars
        .iter()
        .find(|v| v.varnode == eax && matches!(v.expr, Expr::Const(12, 4)))
        .unwrap();
    assert_eq!(
        value.origins.operations,
        vec![
            OperationOrigin {
                instruction_address: 0x1000,
                operation_index: 0
            },
            OperationOrigin {
                instruction_address: 0x1004,
                operation_index: 0
            },
            OperationOrigin {
                instruction_address: 0x1004,
                operation_index: 1
            },
        ]
    );
    assert!(!value.origins.truncated);
}

#[test]
fn removed_call_bookkeeping_does_not_renumber_call_evidence() {
    let esp = Varnode::register(16, 4);
    let input = vec![inst(
        0x1000,
        vec![
            PcodeOp::IntSub {
                out: esp,
                left: esp,
                right: Varnode::constant(4, 4),
            },
            PcodeOp::Store {
                space: pcode_ir::AddressSpaceId::Ram,
                ptr: esp,
                val: Varnode::constant(0x1004, 4),
            },
            PcodeOp::Call {
                dest: Varnode::ram(0x2000, 4),
            },
        ],
    )];
    let cfg = build_cfg(&input);
    assert!(cfg.blocks[0].ops.is_empty());
    let expected = OperationOrigin {
        instruction_address: 0x1000,
        operation_index: 2,
    };
    assert_eq!(cfg.blocks[0].terminator_origin, Some(expected));
    let ssa = build_ssa_with_cc(&cfg, CallingConv::Cdecl32);
    let result = ssa.vars.iter().find(|v| v.call_return).unwrap();
    assert_eq!(result.origins.operations, vec![expected]);
}

#[test]
fn conditional_select_merges_arms_and_marks_synthetic_expression() {
    let tmp = Varnode::unique(0, 4);
    let input = vec![inst(
        0x1000,
        vec![
            PcodeOp::Copy {
                out: tmp,
                input: Varnode::constant(3, 4),
            },
            PcodeOp::CBranch {
                dest: Varnode::constant(2, 4),
                cond: Varnode::register(0x200, 1),
            },
            PcodeOp::Copy {
                out: tmp,
                input: Varnode::constant(7, 4),
            },
            PcodeOp::Copy {
                out: Varnode::register(0, 4),
                input: tmp,
            },
        ],
    )];
    let ssa = build_ssa_with_cc(&build_cfg(&input), CallingConv::AArch64);
    let value = ssa
        .vars
        .iter()
        .find(|v| matches!(v.expr, Expr::Ternary(..)))
        .unwrap();
    assert!(value.origins.synthetic);
    assert_eq!(
        value
            .origins
            .operations
            .iter()
            .map(|o| o.operation_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let unknown = ssa
        .vars
        .iter()
        .find(|v| v.varnode == Varnode::register(0x200, 1))
        .unwrap();
    assert!(unknown.origins.operations.is_empty());
}

#[test]
fn raw_immediate_extensions_fold_with_output_width_and_keep_evidence() {
    for (signed, expected) in [(true, 0xffff_fffbu64), (false, 251)] {
        let eax = Varnode::register(0, 4);
        let input = Varnode::constant(251, 1);
        let op = if signed {
            PcodeOp::IntSext { out: eax, input }
        } else {
            PcodeOp::IntZext { out: eax, input }
        };
        let instructions = vec![inst(0x1000, vec![op])];
        let mut ssa = build_ssa_with_cc(&build_cfg(&instructions), CallingConv::Cdecl32);
        fold_with_cc(&mut ssa, CallingConv::Cdecl32);
        let value = ssa.vars.iter().find(|v| v.varnode == eax).unwrap();
        assert!(matches!(value.expr, Expr::Const(n, 4) if n == expected));
        assert_eq!(
            value.origins.operations,
            vec![OperationOrigin {
                instruction_address: 0x1000,
                operation_index: 0
            }]
        );
    }
}
