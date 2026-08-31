use pcode_ir::Varnode;
use rsleigh_decompile::deflatten::{
    detect_flattening, recover_edges, rewrite_cfg, FlatteningInfo, RecoveredEdge,
};
use rsleigh_decompile::ir::{
    BasicBlock, BinOpKind, BlockId, Cfg, Expr, InferredType, SsaBlock, SsaCfg, SsaTerminator, Stmt,
    Terminator, UnaryOpKind, VarDef, VarId,
};

fn block(id: usize, term: Terminator) -> BasicBlock {
    BasicBlock {
        id: BlockId(id),
        addr: 0x1000 + (id as u64 * 0x10),
        ops: Vec::new(),
        terminator: term,
    }
}

fn cfg(blocks: Vec<BasicBlock>) -> Cfg {
    Cfg {
        blocks,
        entry: BlockId(0),
        diagnostics: Vec::new(),
    }
}

fn var(id: u32, expr: Expr) -> VarDef {
    var_sized(id, expr, 8)
}

fn var_sized(id: u32, expr: Expr, size: u32) -> VarDef {
    VarDef {
        id: VarId(id),
        varnode: Varnode::ram(0x8000 + id as u64, size),
        expr,
        size,
        use_count: 0,
        param_name: None,
        call_return: false,
        inferred_type: InferredType::Unknown,
        display_type: None,
    }
}

fn ssa_block(id: usize, stmts: Vec<Stmt>, terminator: SsaTerminator) -> SsaBlock {
    SsaBlock {
        id: BlockId(id),
        addr: 0x1000 + (id as u64 * 0x10),
        stmts,
        terminator,
    }
}

fn state_vars() -> Vec<VarDef> {
    vec![
        var(0, Expr::Unknown),
        var(1, Expr::Const(1, 8)),
        var(2, Expr::Const(2, 8)),
        var(3, Expr::BinOp(BinOpKind::Eq, VarId(0), VarId(1))),
        var(4, Expr::Load(VarId(0))),
        var(5, Expr::Var(VarId(1))),
        var(6, Expr::UnaryOp(UnaryOpKind::Zext, VarId(5))),
    ]
}

fn width_lzcount_vars() -> Vec<VarDef> {
    vec![
        var_sized(0, Expr::Unknown, 1),
        var(1, Expr::UnaryOp(UnaryOpKind::Lzcount, VarId(0))),
        var(2, Expr::Const(7, 8)),
        var(3, Expr::BinOp(BinOpKind::Eq, VarId(1), VarId(2))),
        var(4, Expr::Load(VarId(0))),
        var(5, Expr::Const(1, 8)),
    ]
}

fn flattened_ssa(next_state: VarId) -> SsaCfg {
    SsaCfg {
        blocks: vec![
            ssa_block(0, Vec::new(), SsaTerminator::Branch(BlockId(2))),
            ssa_block(
                1,
                Vec::new(),
                SsaTerminator::CBranch {
                    cond: VarId(3),
                    taken: BlockId(3),
                    fallthrough: BlockId(4),
                },
            ),
            ssa_block(2, Vec::new(), SsaTerminator::Branch(BlockId(1))),
            ssa_block(
                3,
                vec![Stmt::Assign(next_state)],
                SsaTerminator::Branch(BlockId(2)),
            ),
            ssa_block(4, Vec::new(), SsaTerminator::Return(None)),
        ],
        vars: state_vars(),
        entry: BlockId(0),
        diagnostics: Vec::new(),
    }
}

#[test]
fn detects_loop_hub_and_rejects_convergence_sink() {
    let flattened = cfg(vec![
        block(0, Terminator::Branch(BlockId(2))),
        block(
            1,
            Terminator::CBranch {
                cond: Varnode::ram(0x9000, 1),
                taken: BlockId(3),
                fallthrough: BlockId(4),
            },
        ),
        block(2, Terminator::Branch(BlockId(1))),
        block(3, Terminator::Branch(BlockId(2))),
        block(4, Terminator::Branch(BlockId(2))),
    ]);

    let info = detect_flattening(&flattened).expect("loop hub should be detected");
    assert_eq!(info.predispatcher, BlockId(2));
    assert_eq!(info.dispatcher, BlockId(1));
    assert!(info.score >= 0.45);

    let convergence = cfg(vec![
        block(
            0,
            Terminator::CBranch {
                cond: Varnode::ram(0x9000, 1),
                taken: BlockId(2),
                fallthrough: BlockId(3),
            },
        ),
        block(1, Terminator::Return),
        block(2, Terminator::Branch(BlockId(1))),
        block(3, Terminator::Branch(BlockId(1))),
    ]);
    assert!(detect_flattening(&convergence).is_none());
}

#[test]
fn recovers_constant_and_environment_state_and_fails_closed_on_memory_state() {
    let flattened_cfg = cfg(vec![
        block(0, Terminator::Branch(BlockId(2))),
        block(
            1,
            Terminator::CBranch {
                cond: Varnode::ram(0x9000, 1),
                taken: BlockId(3),
                fallthrough: BlockId(4),
            },
        ),
        block(2, Terminator::Branch(BlockId(1))),
        block(3, Terminator::Branch(BlockId(2))),
        block(4, Terminator::Return),
    ]);
    let info = FlatteningInfo {
        predispatcher: BlockId(2),
        dispatcher: BlockId(1),
        score: 0.8,
        predecessor_count: 2,
        backbone_blocks: vec![BlockId(3), BlockId(4)],
    };
    let ssa = flattened_ssa(VarId(2));

    let edges = recover_edges(&flattened_cfg, &ssa, &info).expect("state update should resolve");
    assert_eq!(
        edges,
        vec![RecoveredEdge {
            from: BlockId(3),
            to: BlockId(4),
            condition: None
        }]
    );

    let rewritten = rewrite_cfg(&flattened_cfg, &edges, &info).expect("single edge rewrite");
    assert!(matches!(
        rewritten.blocks[3].terminator,
        Terminator::Branch(BlockId(4))
    ));

    let aliased = flattened_ssa(VarId(6));
    assert_eq!(
        recover_edges(&flattened_cfg, &aliased, &info),
        Some(vec![RecoveredEdge {
            from: BlockId(3),
            to: BlockId(3),
            condition: None,
        }])
    );

    let unresolved = flattened_ssa(VarId(4));
    assert!(recover_edges(&flattened_cfg, &unresolved, &info).is_none());

    let mut missing_substitution = flattened_ssa(VarId(2));
    missing_substitution.blocks[1].terminator = SsaTerminator::CBranch {
        cond: VarId(99),
        taken: BlockId(3),
        fallthrough: BlockId(4),
    };
    assert!(recover_edges(&flattened_cfg, &missing_substitution, &info).is_none());

    let overlap_cfg = cfg(vec![
        block(0, Terminator::Branch(BlockId(2))),
        block(
            1,
            Terminator::CBranch {
                cond: Varnode::ram(0x9000, 1),
                taken: BlockId(3),
                fallthrough: BlockId(4),
            },
        ),
        block(2, Terminator::Branch(BlockId(1))),
        block(3, Terminator::Branch(BlockId(4))),
        block(4, Terminator::Return),
        block(5, Terminator::Branch(BlockId(2))),
    ]);
    let overlap_info = FlatteningInfo {
        backbone_blocks: vec![BlockId(3), BlockId(4), BlockId(5)],
        ..info.clone()
    };
    let mut overlap_ssa = flattened_ssa(VarId(2));
    overlap_ssa.blocks[3].stmts.clear();
    overlap_ssa.blocks[3].terminator = SsaTerminator::Branch(BlockId(4));
    overlap_ssa.blocks.push(ssa_block(
        5,
        vec![Stmt::Assign(VarId(1))],
        SsaTerminator::Branch(BlockId(2)),
    ));
    assert!(recover_edges(&overlap_cfg, &overlap_ssa, &overlap_info).is_none());
}

#[test]
fn masks_substituted_dispatch_state_to_declared_width() {
    let flattened_cfg = cfg(vec![
        block(0, Terminator::Branch(BlockId(2))),
        block(
            1,
            Terminator::CBranch {
                cond: Varnode::ram(0x9000, 1),
                taken: BlockId(3),
                fallthrough: BlockId(4),
            },
        ),
        block(2, Terminator::Branch(BlockId(1))),
        block(3, Terminator::Branch(BlockId(2))),
        block(4, Terminator::Return),
    ]);
    let info = FlatteningInfo {
        predispatcher: BlockId(2),
        dispatcher: BlockId(1),
        score: 0.8,
        predecessor_count: 2,
        backbone_blocks: vec![BlockId(3), BlockId(4)],
    };
    let mut narrow_substitution = flattened_ssa(VarId(7));
    narrow_substitution.vars[0] = var_sized(0, Expr::Unknown, 1);
    narrow_substitution.vars.push(var(7, Expr::Const(0x100, 8)));
    narrow_substitution.blocks[1].terminator = SsaTerminator::CBranch {
        cond: VarId(0),
        taken: BlockId(3),
        fallthrough: BlockId(4),
    };

    assert_eq!(
        recover_edges(&flattened_cfg, &narrow_substitution, &info),
        Some(vec![RecoveredEdge {
            from: BlockId(3),
            to: BlockId(4),
            condition: None,
        }])
    );
}

#[test]
fn lzcount_uses_declared_input_width() {
    let flattened_cfg = cfg(vec![
        block(0, Terminator::Branch(BlockId(2))),
        block(
            1,
            Terminator::CBranch {
                cond: Varnode::ram(0x9000, 1),
                taken: BlockId(3),
                fallthrough: BlockId(4),
            },
        ),
        block(2, Terminator::Branch(BlockId(1))),
        block(3, Terminator::Branch(BlockId(2))),
        block(4, Terminator::Return),
    ]);
    let info = FlatteningInfo {
        predispatcher: BlockId(2),
        dispatcher: BlockId(1),
        score: 0.8,
        predecessor_count: 2,
        backbone_blocks: vec![BlockId(3), BlockId(4)],
    };
    let mut narrow_lzcount = flattened_ssa(VarId(5));
    narrow_lzcount.vars = width_lzcount_vars();

    assert_eq!(
        recover_edges(&flattened_cfg, &narrow_lzcount, &info),
        Some(vec![RecoveredEdge {
            from: BlockId(3),
            to: BlockId(3),
            condition: None,
        }])
    );
}

#[test]
#[ignore = "fixture oracle_manifest_pluto.json currently freezes intervals, not edge lists"]
fn pluto_fixture_requires_independent_edge_manifest() {
    let manifest = std::path::Path::new(
        "../../tools/protector_triage/tests/fixtures/build_ollvm/oracle_manifest_pluto.json",
    );
    assert!(
        manifest.exists(),
        "frozen Pluto oracle manifest is required for the landing gate"
    );
}
