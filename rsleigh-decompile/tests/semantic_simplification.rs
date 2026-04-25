//! Audit P2 #1 — semantic algebraic identities at the SSA layer.
//!
//! Three identities that previously lived only in `printer.rs`'s text
//! post-processor are now expressed as SSA folds. Pinning the contract
//! at the SSA layer makes them visible in `--ssa-json` and lets future
//! work retire the redundant text rewrites without losing the
//! simplification.

use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{
    BlockId, Expr, InferredType, SsaBlock, SsaCfg, SsaTerminator, UnaryOpKind, VarDef, VarId,
};

fn vd(id: u32, expr: Expr, size: u32) -> VarDef {
    VarDef {
        id: VarId(id),
        varnode: pcode_ir::Varnode {
            space: pcode_ir::AddressSpaceId::Unique,
            offset: id as u64,
            size,
        },
        expr,
        size,
        use_count: 0,
        param_name: None,
        call_return: false,
        inferred_type: InferredType::Unknown,
        display_type: None,
    }
}

fn run_fold(vars: Vec<VarDef>, return_id: u32) -> SsaCfg {
    let mut ssa = SsaCfg {
        blocks: vec![SsaBlock {
            id: BlockId(0),
            addr: 0x1000,
            stmts: vars
                .iter()
                .map(|v| rsleigh_decompile::ir::Stmt::Assign(v.id))
                .collect(),
            terminator: SsaTerminator::Return(Some(VarId(return_id))),
        }],
        vars,
        entry: BlockId(0),
        diagnostics: Vec::new(),
    };
    fold_with_cc(&mut ssa, CallingConv::SysV);
    ssa
}

#[test]
fn zero_minus_x_folds_to_neg_x() {
    // var0 = const(0, 4)
    // var1 = unknown (stand-in for x)
    // var2 = var0 - var1   →  must fold to UnaryOp(Neg, var1)
    let vars = vec![
        vd(0, Expr::Const(0, 4), 4),
        vd(1, Expr::Unknown, 4),
        vd(
            2,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Sub, VarId(0), VarId(1)),
            4,
        ),
    ];
    let ssa = run_fold(vars, 2);
    let v2 = &ssa.vars[2].expr;
    match v2 {
        Expr::UnaryOp(UnaryOpKind::Neg, inner) => {
            assert_eq!(inner.0, 1, "expected Neg(var1), got {:?}", v2);
        }
        other => panic!("expected UnaryOp(Neg, _), got {:?}", other),
    }
}

#[test]
fn x_times_one_folds_away_the_mult() {
    let vars = vec![
        vd(0, Expr::Const(42, 4), 4),
        vd(1, Expr::Const(1, 4), 4),
        vd(
            2,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Mult, VarId(0), VarId(1)),
            4,
        ),
    ];
    let ssa = run_fold(vars, 2);
    // After fold + constant propagation the multiply must collapse —
    // either to Var(0) (identity) or further to Const(42, _).
    let ok = matches!(
        ssa.vars[2].expr,
        Expr::Var(VarId(0)) | Expr::Const(42, _)
    );
    assert!(
        ok,
        "x*1 must collapse; got {:?}",
        ssa.vars[2].expr
    );
}

#[test]
fn x_times_zero_folds_to_zero() {
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(1, Expr::Const(0, 4), 4),
        vd(
            2,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Mult, VarId(0), VarId(1)),
            4,
        ),
    ];
    let ssa = run_fold(vars, 2);
    match ssa.vars[2].expr {
        Expr::Const(0, _) => {}
        ref other => panic!("expected Const(0, _), got {:?}", other),
    }
}

#[test]
fn neg_neg_x_folds_to_x() {
    // var0 = unknown (x)
    // var1 = -var0
    // var2 = -var1   →  must fold to Var(0)
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(1, Expr::UnaryOp(UnaryOpKind::Neg, VarId(0)), 4),
        vd(2, Expr::UnaryOp(UnaryOpKind::Neg, VarId(1)), 4),
    ];
    let ssa = run_fold(vars, 2);
    // After fold, var2 must NOT still be UnaryOp(Neg, _). The fold pass
    // either resolves to Var(0) or further inlines var0's expression
    // (Unknown), but the involutive double-Neg shape must be gone.
    assert!(
        !matches!(&ssa.vars[2].expr, Expr::UnaryOp(UnaryOpKind::Neg, _)),
        "Neg(Neg(x)) survived fold: {:?}",
        ssa.vars[2].expr
    );
}

#[test]
fn not_not_x_folds_away_double_negation() {
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(1, Expr::UnaryOp(UnaryOpKind::Not, VarId(0)), 4),
        vd(2, Expr::UnaryOp(UnaryOpKind::Not, VarId(1)), 4),
    ];
    let ssa = run_fold(vars, 2);
    assert!(
        !matches!(&ssa.vars[2].expr, Expr::UnaryOp(UnaryOpKind::Not, _)),
        "Not(Not(x)) survived fold: {:?}",
        ssa.vars[2].expr
    );
}

#[test]
fn boolnot_boolnot_x_folds_away_double_negation() {
    let vars = vec![
        vd(0, Expr::Unknown, 1),
        vd(1, Expr::UnaryOp(UnaryOpKind::BoolNot, VarId(0)), 1),
        vd(2, Expr::UnaryOp(UnaryOpKind::BoolNot, VarId(1)), 1),
    ];
    let ssa = run_fold(vars, 2);
    assert!(
        !matches!(&ssa.vars[2].expr, Expr::UnaryOp(UnaryOpKind::BoolNot, _)),
        "BoolNot(BoolNot(x)) survived fold: {:?}",
        ssa.vars[2].expr
    );
}

#[test]
fn x_div_one_folds_away_the_div() {
    let vars = vec![
        vd(0, Expr::Const(42, 4), 4),
        vd(1, Expr::Const(1, 4), 4),
        vd(
            2,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Div, VarId(0), VarId(1)),
            4,
        ),
    ];
    let ssa = run_fold(vars, 2);
    // x/1 must collapse — either to Var(0) or to a folded Const(42).
    let ok = matches!(
        ssa.vars[2].expr,
        Expr::Var(VarId(0)) | Expr::Const(42, _)
    );
    assert!(ok, "x/1 must collapse; got {:?}", ssa.vars[2].expr);
}

#[test]
fn x_rem_one_folds_to_zero() {
    let vars = vec![
        vd(0, Expr::Const(42, 4), 4),
        vd(1, Expr::Const(1, 4), 4),
        vd(
            2,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Rem, VarId(0), VarId(1)),
            4,
        ),
    ];
    let ssa = run_fold(vars, 2);
    match ssa.vars[2].expr {
        Expr::Const(0, _) => {}
        ref other => panic!("expected Const(0, _), got {:?}", other),
    }
}

#[test]
fn x_xor_all_ones_canonicalizes_to_not() {
    // var0 = unknown
    // var1 = -1 (4-byte: 0xFFFFFFFF)
    // var2 = var0 ^ var1   →  must fold to UnaryOp(Not, var0)
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(1, Expr::Const(0xFFFF_FFFF, 4), 4),
        vd(
            2,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Xor, VarId(0), VarId(1)),
            4,
        ),
    ];
    let ssa = run_fold(vars, 2);
    assert!(
        !matches!(
            &ssa.vars[2].expr,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Xor, _, _)
        ),
        "x ^ -1 must canonicalize away the Xor; got {:?}",
        ssa.vars[2].expr
    );
}

#[test]
fn x_eq_x_folds_to_one() {
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(
            1,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Eq, VarId(0), VarId(0)),
            1,
        ),
    ];
    let ssa = run_fold(vars, 1);
    match ssa.vars[1].expr {
        Expr::Const(1, _) => {}
        ref other => panic!("expected Const(1, _), got {:?}", other),
    }
}

#[test]
fn x_neq_x_folds_to_zero() {
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(
            1,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::NotEq, VarId(0), VarId(0)),
            1,
        ),
    ];
    let ssa = run_fold(vars, 1);
    match ssa.vars[1].expr {
        Expr::Const(0, _) => {}
        ref other => panic!("expected Const(0, _), got {:?}", other),
    }
}

#[test]
fn x_less_x_folds_to_zero() {
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(
            1,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Less, VarId(0), VarId(0)),
            1,
        ),
        vd(
            2,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::SLess, VarId(0), VarId(0)),
            1,
        ),
    ];
    let ssa = run_fold(vars, 1);
    match ssa.vars[1].expr {
        Expr::Const(0, _) => {}
        ref other => panic!("expected Const(0, _) for x < x, got {:?}", other),
    }
    match ssa.vars[2].expr {
        Expr::Const(0, _) => {}
        ref other => panic!("expected Const(0, _) for x <s x, got {:?}", other),
    }
}

#[test]
fn x_lesseq_x_folds_to_one() {
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(
            1,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::LessEq, VarId(0), VarId(0)),
            1,
        ),
        vd(
            2,
            Expr::BinOp(
                rsleigh_decompile::ir::BinOpKind::SLessEq,
                VarId(0),
                VarId(0),
            ),
            1,
        ),
    ];
    let ssa = run_fold(vars, 1);
    match ssa.vars[1].expr {
        Expr::Const(1, _) => {}
        ref other => panic!("expected Const(1, _) for x <= x, got {:?}", other),
    }
    match ssa.vars[2].expr {
        Expr::Const(1, _) => {}
        ref other => panic!("expected Const(1, _) for x <=s x, got {:?}", other),
    }
}

#[test]
fn x_minus_x_folds_to_zero() {
    // Idempotence check — the existing `x - x → 0` rule survives the new
    // `0 - x → -x` rule and isn't accidentally shadowed.
    let vars = vec![
        vd(0, Expr::Unknown, 4),
        vd(
            1,
            Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Sub, VarId(0), VarId(0)),
            4,
        ),
    ];
    let ssa = run_fold(vars, 1);
    match ssa.vars[1].expr {
        Expr::Const(0, _) => {}
        ref other => panic!("expected Const(0, _), got {:?}", other),
    }
}
