//! Z3-backed verifier for opaque-predicate candidates.
//!
//! Behind the `smt` cargo feature. Sampling in `opaque_pred` is fast
//! and catches the bulk of protector-style identities, but it is
//! probabilistic — a real solver removes the false-positive surface
//! entirely. Translates a `VarId` cone into Z3 bitvector terms and
//! asks `forall vars . cond` (encoded as `unsat (¬cond)`).
//!
//! Off by default. Enable with `--features smt`. Requires libz3 on
//! the system (`brew install z3` or `apt install libz3-dev`).

use crate::ir::{VarDef, VarId};
#[cfg(feature = "smt")]
use crate::ir::Expr;

/// Result of a Z3 check on one branch condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtVerdict {
    /// `forall vars . cond != 0` — branch always taken.
    Tautology,
    /// `forall vars . cond == 0` — branch never taken.
    Contradiction,
    /// Both branches reachable.
    Satisfiable,
    /// Translation hit an unsupported expression (Phi/Load/UserOp/Float).
    Unsupported,
    /// Solver timed out or returned Unknown.
    Unknown,
}

/// How the lowering treats `Expr` variants that aren't directly
/// translated (Phi, Load, Store, UserOp, ExprNew, ExprCPool, Ternary,
/// FieldAccess, Unknown).
///
/// `Symbolic` is the historical behaviour used by `verify_branch`:
/// any uncovered variant becomes a fresh symbolic bitvector so the
/// solver can quantify over it. That is correct when asking
/// "∀ inputs . cond holds?" — the unknown values represent
/// universally-quantified attacker control.
///
/// `RejectUnsupported` is the new behaviour required by the M1
/// taint-flow CVE finder: any uncovered variant immediately fails the
/// lowering with `None`. CVE proof outputs cannot afford silent
/// approximations; an unsupported lift must surface as
/// `SmtVerdict::Unsupported`, never as a SAT model whose evidence
/// rests on a free variable nobody constrained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerPolicy {
    /// Uncovered `Expr` -> fresh BV. Sound for ∀-quantified queries.
    Symbolic,
    /// Uncovered `Expr` -> None. Required for SAT-as-CVE-proof.
    RejectUnsupported,
}

#[cfg(feature = "smt")]
pub fn verify_branch(cond: VarId, vars: &[VarDef]) -> SmtVerdict {
    use std::collections::HashMap;
    use z3::ast::{Ast, Bool, BV};
    use z3::{Config, Context, SatResult, Solver};

    let mut cfg = Config::new();
    cfg.set_timeout_msec(5_000);
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let mut env: HashMap<u32, BV> = HashMap::new();
    let Some(c) = build(&ctx, cond, vars, &mut env, LowerPolicy::Symbolic) else {
        return SmtVerdict::Unsupported;
    };
    let zero = BV::from_u64(&ctx, 0, c.get_size());
    let truthy = c._eq(&zero).not();

    // Tautology check: assert ¬truthy; unsat ⇒ tautology.
    solver.push();
    solver.assert(&truthy.clone().not());
    let taut = matches!(solver.check(), SatResult::Unsat);
    solver.pop(1);
    if taut {
        return SmtVerdict::Tautology;
    }

    // Contradiction check: assert truthy; unsat ⇒ contradiction.
    solver.push();
    solver.assert(&truthy);
    let contra = matches!(solver.check(), SatResult::Unsat);
    solver.pop(1);
    if contra {
        return SmtVerdict::Contradiction;
    }

    // Both directions sat-able ⇒ real branch. (Solver::Unknown is
    // collapsed into Satisfiable here — it means "I couldn't disprove
    // either side within the timeout", which is the same downstream
    // signal as a genuinely-satisfiable branch: don't fold it.)
    SmtVerdict::Satisfiable
}

#[cfg(not(feature = "smt"))]
pub fn verify_branch(_cond: VarId, _vars: &[VarDef]) -> SmtVerdict {
    SmtVerdict::Unsupported
}

/// Lower `v` (and its transitive dependencies in `vars`) to a Z3
/// bitvector. `policy` controls behaviour for `Expr` variants the
/// translator does not directly handle — see `LowerPolicy`.
///
/// Returns `None` when:
///   - the cone references a `VarId` outside `vars`,
///   - a covered variant fails width/operand constraints, or
///   - `policy = RejectUnsupported` and the cone hits any
///     uncovered variant.
#[cfg(feature = "smt")]
pub fn lower<'c>(
    ctx: &'c z3::Context,
    v: VarId,
    vars: &[VarDef],
    env: &mut std::collections::HashMap<u32, z3::ast::BV<'c>>,
    policy: LowerPolicy,
) -> Option<z3::ast::BV<'c>> {
    build(ctx, v, vars, env, policy)
}

#[cfg(feature = "smt")]
fn build<'c>(
    ctx: &'c z3::Context,
    v: VarId,
    vars: &[VarDef],
    env: &mut std::collections::HashMap<u32, z3::ast::BV<'c>>,
    policy: LowerPolicy,
) -> Option<z3::ast::BV<'c>> {
    use crate::ir::{BinOpKind, UnaryOpKind};
    use z3::ast::{Ast, BV};

    if let Some(bv) = env.get(&v.0) {
        return Some(bv.clone());
    }
    let def = vars.get(v.0 as usize)?;
    let bits = bits_for(def.size);
    let bv = match &def.expr {
        Expr::Const(c, _) => BV::from_u64(ctx, *c, bits),
        Expr::Var(inner) => build(ctx, *inner, vars, env, policy)?,
        Expr::BinOp(kind, l, r) => {
            let a = build(ctx, *l, vars, env, policy)?;
            let b = build(ctx, *r, vars, env, policy)?;
            // Equalize widths by zero-extending the narrower side.
            let (a, b) = align(a, b);
            match kind {
                BinOpKind::Add => a.bvadd(&b),
                BinOpKind::Sub => a.bvsub(&b),
                BinOpKind::Mult => a.bvmul(&b),
                BinOpKind::And => a.bvand(&b),
                BinOpKind::Or => a.bvor(&b),
                BinOpKind::Xor => a.bvxor(&b),
                BinOpKind::Lsl => a.bvshl(&b),
                BinOpKind::Lsr => a.bvlshr(&b),
                BinOpKind::Asr => a.bvashr(&b),
                BinOpKind::Div => a.bvudiv(&b),
                BinOpKind::SDiv => a.bvsdiv(&b),
                BinOpKind::Rem => a.bvurem(&b),
                BinOpKind::SRem => a.bvsrem(&b),
                BinOpKind::Eq => bool_to_bv(ctx, &a._eq(&b)),
                BinOpKind::NotEq => bool_to_bv(ctx, &a._eq(&b).not()),
                BinOpKind::Less => bool_to_bv(ctx, &a.bvult(&b)),
                BinOpKind::LessEq => bool_to_bv(ctx, &a.bvule(&b)),
                BinOpKind::SLess => bool_to_bv(ctx, &a.bvslt(&b)),
                BinOpKind::SLessEq => bool_to_bv(ctx, &a.bvsle(&b)),
                _ => return None,
            }
        }
        Expr::UnaryOp(kind, inner) => {
            let a = build(ctx, *inner, vars, env, policy)?;
            match kind {
                UnaryOpKind::Neg => a.bvneg(),
                UnaryOpKind::Not => a.bvnot(),
                UnaryOpKind::BoolNot => bool_to_bv(ctx, &a._eq(&BV::from_u64(ctx, 0, a.get_size()))),
                UnaryOpKind::Zext => a.zero_ext(bits.saturating_sub(a.get_size())),
                UnaryOpKind::Sext => a.sign_ext(bits.saturating_sub(a.get_size())),
                UnaryOpKind::Trunc => a.extract(bits.saturating_sub(1), 0),
                _ => return None,
            }
        }
        // Uncovered variants: behaviour driven by policy.
        //   Symbolic           -> fresh BV; the caller is asking a
        //                          ∀-quantified question, treat the
        //                          unknown as universally controlled.
        //   RejectUnsupported  -> fail the lift; SAT proofs cannot
        //                          rest on unconstrained free vars.
        _ => match policy {
            LowerPolicy::Symbolic => {
                let fresh = BV::fresh_const(ctx, "v", bits);
                env.insert(v.0, fresh.clone());
                fresh
            }
            LowerPolicy::RejectUnsupported => return None,
        },
    };
    Some(bv)
}

#[cfg(feature = "smt")]
fn align<'c>(a: z3::ast::BV<'c>, b: z3::ast::BV<'c>) -> (z3::ast::BV<'c>, z3::ast::BV<'c>) {
    let (sa, sb) = (a.get_size(), b.get_size());
    if sa == sb {
        (a, b)
    } else if sa < sb {
        (a.zero_ext(sb - sa), b)
    } else {
        (a, b.zero_ext(sa - sb))
    }
}

#[cfg(feature = "smt")]
fn bool_to_bv<'c>(ctx: &'c z3::Context, b: &z3::ast::Bool<'c>) -> z3::ast::BV<'c> {
    use z3::ast::{Ast, BV};
    b.ite(&BV::from_u64(ctx, 1, 1), &BV::from_u64(ctx, 0, 1))
}

#[cfg_attr(not(feature = "smt"), allow(dead_code))]
fn bits_for(size: u32) -> u32 {
    match size {
        0 => 64,
        s if s >= 8 => 64,
        s => s * 8,
    }
}

#[cfg(all(test, feature = "smt"))]
mod tests {
    use super::*;
    use crate::ir::{BinOpKind, Expr, InferredType, VarDef, VarId};
    use pcode_ir::Varnode;

    fn mk(exprs: Vec<(Expr, u32)>) -> Vec<VarDef> {
        exprs
            .into_iter()
            .enumerate()
            .map(|(i, (e, size))| VarDef {
                id: VarId(i as u32),
                varnode: Varnode::constant(0, size),
                expr: e,
                size,
                use_count: 1,
                param_name: None,
                call_return: false,
                inferred_type: InferredType::Unknown,
                display_type: None,
            })
            .collect()
    }

    #[test]
    fn z3_proves_themida_identity() {
        // x*x - x*(x-1) - x == 0  ∀ x
        let vars = mk(vec![
            (Expr::Unknown, 8),
            (Expr::BinOp(BinOpKind::Mult, VarId(0), VarId(0)), 8),
            (Expr::Const(1, 8), 8),
            (Expr::BinOp(BinOpKind::Sub, VarId(0), VarId(2)), 8),
            (Expr::BinOp(BinOpKind::Mult, VarId(0), VarId(3)), 8),
            (Expr::BinOp(BinOpKind::Sub, VarId(1), VarId(4)), 8),
            (Expr::BinOp(BinOpKind::Sub, VarId(5), VarId(0)), 8),
            (Expr::Const(0, 8), 8),
            (Expr::BinOp(BinOpKind::Eq, VarId(6), VarId(7)), 1),
        ]);
        assert_eq!(verify_branch(VarId(8), &vars), SmtVerdict::Tautology);
    }

    #[test]
    fn z3_rejects_real_branch() {
        let vars = mk(vec![
            (Expr::Unknown, 8),
            (Expr::Const(0, 8), 8),
            (Expr::BinOp(BinOpKind::Eq, VarId(0), VarId(1)), 1),
        ]);
        assert_eq!(verify_branch(VarId(2), &vars), SmtVerdict::Satisfiable);
    }

    #[test]
    fn strict_policy_rejects_unknown() {
        // M1 invariant: under RejectUnsupported, a cone whose root
        // is `Expr::Unknown` must fail the lower (None), so the
        // caller cannot use a SAT result as CVE evidence.
        let vars = mk(vec![(Expr::Unknown, 8)]);
        let mut cfg = z3::Config::new();
        cfg.set_timeout_msec(1_000);
        let ctx = z3::Context::new(&cfg);
        let mut env = std::collections::HashMap::new();
        let r = lower(&ctx, VarId(0), &vars, &mut env, LowerPolicy::RejectUnsupported);
        assert!(r.is_none(), "Unknown leaked through strict lowering");
    }

    #[test]
    fn symbolic_policy_passes_unknown() {
        // The verifier path needs the legacy ∀-quantified semantic:
        // Unknown becomes a free BV.
        let vars = mk(vec![(Expr::Unknown, 8)]);
        let mut cfg = z3::Config::new();
        cfg.set_timeout_msec(1_000);
        let ctx = z3::Context::new(&cfg);
        let mut env = std::collections::HashMap::new();
        let r = lower(&ctx, VarId(0), &vars, &mut env, LowerPolicy::Symbolic);
        assert!(r.is_some(), "Symbolic policy regressed on Unknown");
    }

    #[test]
    fn strict_policy_rejects_load() {
        // Load is the canonical "M1 doesn't lower this yet" case.
        // Document the boundary now so a future Load lowering
        // surfaces in the test diff, not silently in production.
        let vars = mk(vec![
            (Expr::Const(0x1000, 8), 8),
            (Expr::Load(VarId(0)), 8),
        ]);
        let mut cfg = z3::Config::new();
        cfg.set_timeout_msec(1_000);
        let ctx = z3::Context::new(&cfg);
        let mut env = std::collections::HashMap::new();
        let r = lower(&ctx, VarId(1), &vars, &mut env, LowerPolicy::RejectUnsupported);
        assert!(r.is_none(), "Load leaked through strict lowering");
    }
}
