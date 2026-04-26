//! Opaque-predicate detector.
//!
//! Inspired by SMT-based unpacker techniques (e.g. "Thwarting Themida:
//! Unpacking Malware with SMT Solvers"). Where a real solver proves
//! `forall vars . cond` valid, we approximate by sampling: if the
//! conditional branch interprets to the same boolean over a wide spread
//! of random inputs to its free variables, treat it as opaque.
//!
//! Cheap, no `z3` system dep, false-negative-only when the branch is
//! genuinely opaque under a structure too narrow for random sampling
//! (rare for protector-style identities like `x*x - x*(x-1) - x == 0`,
//! which collapse for *every* input).
//!
//! Diagnostic-only for now: callers receive a list of suspect branches
//! and can wire that into fold/structure passes once confidence is high.

use crate::ir::{BinOpKind, BlockId, Expr, SsaCfg, SsaTerminator, UnaryOpKind, VarDef, VarId};
use std::collections::{HashMap, HashSet};

const SAMPLES: usize = 256;
const MAX_FREE_VARS: usize = 8;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchClass {
    AlwaysTaken,
    NeverTaken,
}

#[derive(Debug, Clone)]
pub struct OpaqueBranch {
    pub block: BlockId,
    pub block_addr: u64,
    pub cond: VarId,
    pub class: BranchClass,
    pub free_var_count: usize,
}

pub fn scan_opaque_branches(ssa: &SsaCfg) -> Vec<OpaqueBranch> {
    let mut out = Vec::new();
    for blk in &ssa.blocks {
        if let SsaTerminator::CBranch { cond, .. } = &blk.terminator {
            if let Some(class) = classify_branch(*cond, &ssa.vars) {
                let free = collect_free_vars(*cond, &ssa.vars);
                out.push(OpaqueBranch {
                    block: blk.id,
                    block_addr: blk.addr,
                    cond: *cond,
                    class,
                    free_var_count: free.len(),
                });
            }
        }
    }
    out
}

/// Classify a condition var as opaque-true / opaque-false / not opaque
/// by sampling `SAMPLES` random assignments to its leaf variables.
pub fn classify_branch(cond: VarId, vars: &[VarDef]) -> Option<BranchClass> {
    let free = collect_free_vars(cond, vars);
    if free.len() > MAX_FREE_VARS {
        return None;
    }
    // PRNG: SplitMix64. Deterministic so results are reproducible across
    // runs; we want stable diagnostics, not noise.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };

    let mut first: Option<u64> = None;
    let mut env: HashMap<u32, u64> = HashMap::new();
    // Always include some boundary values to catch identities that only
    // collapse at 0 / -1 / 1 alongside random sweep.
    let edge_envs: [u64; 4] = [0, 1, u64::MAX, 0x8000_0000_0000_0000];
    for trial in 0..SAMPLES + edge_envs.len() {
        env.clear();
        for (idx, v) in free.iter().enumerate() {
            let val = if trial < edge_envs.len() {
                edge_envs[trial].wrapping_add(idx as u64)
            } else {
                next()
            };
            env.insert(v.0, val);
        }
        let r = interp(cond, vars, &env, 0)?;
        let truthy = (r & 1) != 0;
        match first {
            None => first = Some(truthy as u64),
            Some(f) if f == truthy as u64 => {}
            _ => return None,
        }
    }
    Some(if first? != 0 {
        BranchClass::AlwaysTaken
    } else {
        BranchClass::NeverTaken
    })
}

/// Collect leaf vars: Load/Phi/UserOp/Unknown/FieldAccess/Ternary roots
/// and any var whose `expr` chain bottoms out in those. Const/BinOp/UnaryOp
/// recurse. Result is the symbolic input set we sample over.
fn collect_free_vars(root: VarId, vars: &[VarDef]) -> Vec<VarId> {
    let mut seen: HashSet<u32> = HashSet::new();
    let mut out = Vec::new();
    walk(root, vars, &mut seen, &mut out, 0);
    out
}

fn walk(v: VarId, vars: &[VarDef], seen: &mut HashSet<u32>, out: &mut Vec<VarId>, depth: usize) {
    if depth > MAX_DEPTH || !seen.insert(v.0) {
        return;
    }
    let Some(def) = vars.get(v.0 as usize) else {
        out.push(v);
        return;
    };
    match &def.expr {
        Expr::Const(_, _) => {}
        Expr::Var(inner) => walk(*inner, vars, seen, out, depth + 1),
        Expr::BinOp(_, l, r) => {
            walk(*l, vars, seen, out, depth + 1);
            walk(*r, vars, seen, out, depth + 1);
        }
        Expr::UnaryOp(_, inner) => walk(*inner, vars, seen, out, depth + 1),
        Expr::Load(_)
        | Expr::FieldAccess(_, _)
        | Expr::Phi(_)
        | Expr::Ternary(_, _, _)
        | Expr::UserOp { .. }
        | Expr::Unknown => out.push(v),
    }
}

fn interp(v: VarId, vars: &[VarDef], env: &HashMap<u32, u64>, depth: usize) -> Option<u64> {
    if depth > MAX_DEPTH {
        return None;
    }
    if let Some(&val) = env.get(&v.0) {
        return Some(val);
    }
    let def = vars.get(v.0 as usize)?;
    let mask = size_mask(def.size);
    let raw = match &def.expr {
        Expr::Const(c, _) => *c,
        Expr::Var(inner) => interp(*inner, vars, env, depth + 1)?,
        Expr::BinOp(kind, l, r) => {
            let a = interp(*l, vars, env, depth + 1)?;
            let b = interp(*r, vars, env, depth + 1)?;
            apply_binop(*kind, a, b, vars.get(l.0 as usize).map(|d| d.size).unwrap_or(8))?
        }
        Expr::UnaryOp(kind, inner) => {
            let a = interp(*inner, vars, env, depth + 1)?;
            let in_size = vars
                .get(inner.0 as usize)
                .map(|d| d.size)
                .unwrap_or(def.size);
            apply_unop(*kind, a, in_size, def.size)?
        }
        // Free vars must already be in env.
        _ => return None,
    };
    Some(raw & mask)
}

fn size_mask(size: u32) -> u64 {
    match size {
        0 => u64::MAX,
        s if s >= 8 => u64::MAX,
        s => (1u64 << (s * 8)).wrapping_sub(1),
    }
}

fn apply_binop(kind: BinOpKind, l: u64, r: u64, in_size: u32) -> Option<u64> {
    let m = size_mask(in_size);
    let l = l & m;
    let r = r & m;
    let bits = if in_size >= 8 { 64 } else { in_size * 8 };
    let sign_bit = if bits == 0 { 0 } else { 1u64 << (bits - 1) };
    let sext = |v: u64| -> i64 {
        if sign_bit != 0 && v & sign_bit != 0 {
            (v | !m) as i64
        } else {
            v as i64
        }
    };
    Some(match kind {
        BinOpKind::Add => l.wrapping_add(r),
        BinOpKind::Sub => l.wrapping_sub(r),
        BinOpKind::Mult => l.wrapping_mul(r),
        BinOpKind::Div => {
            if r == 0 {
                return None;
            } else {
                l / r
            }
        }
        BinOpKind::SDiv => {
            if r == 0 {
                return None;
            } else {
                (sext(l).wrapping_div(sext(r))) as u64
            }
        }
        BinOpKind::Rem => {
            if r == 0 {
                return None;
            } else {
                l % r
            }
        }
        BinOpKind::SRem => {
            if r == 0 {
                return None;
            } else {
                (sext(l).wrapping_rem(sext(r))) as u64
            }
        }
        BinOpKind::And => l & r,
        BinOpKind::Or => l | r,
        BinOpKind::Xor => l ^ r,
        BinOpKind::Lsl => l.wrapping_shl((r & 63) as u32),
        BinOpKind::Lsr => l.wrapping_shr((r & 63) as u32),
        BinOpKind::Asr => (sext(l).wrapping_shr((r & 63) as u32)) as u64,
        BinOpKind::Eq => (l == r) as u64,
        BinOpKind::NotEq => (l != r) as u64,
        BinOpKind::Less => (l < r) as u64,
        BinOpKind::LessEq => (l <= r) as u64,
        BinOpKind::SLess => (sext(l) < sext(r)) as u64,
        BinOpKind::SLessEq => (sext(l) <= sext(r)) as u64,
        BinOpKind::BoolAnd => (l & 1) & (r & 1),
        BinOpKind::BoolOr => (l & 1) | (r & 1),
        BinOpKind::BoolXor => (l & 1) ^ (r & 1),
        // Carry / float / signed-overflow — bail.
        _ => return None,
    })
}

fn apply_unop(kind: UnaryOpKind, v: u64, in_size: u32, out_size: u32) -> Option<u64> {
    let in_mask = size_mask(in_size);
    let bits = if in_size >= 8 { 64 } else { in_size * 8 };
    let sign_bit = if bits == 0 { 0 } else { 1u64 << (bits - 1) };
    Some(match kind {
        UnaryOpKind::Neg => (-(v as i64)) as u64,
        UnaryOpKind::Not => !v,
        UnaryOpKind::BoolNot => (v & 1) ^ 1,
        UnaryOpKind::Zext => v & in_mask,
        UnaryOpKind::Sext => {
            if sign_bit != 0 && v & sign_bit != 0 {
                v | !in_mask
            } else {
                v & in_mask
            }
        }
        UnaryOpKind::Trunc => v & size_mask(out_size),
        UnaryOpKind::Popcount => v.count_ones() as u64,
        UnaryOpKind::Lzcount => v.leading_zeros() as u64,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::InferredType;
    use pcode_ir::Varnode;

    fn mk_vars(exprs: Vec<(Expr, u32)>) -> Vec<VarDef> {
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
    fn detects_xor_self_zero() {
        // v0 = unknown; v1 = v0 ^ v0; v3 = (v1 == 0)  always true
        let vars = mk_vars(vec![
            (Expr::Unknown, 8),
            (Expr::BinOp(BinOpKind::Xor, VarId(0), VarId(0)), 8),
            (Expr::Const(0, 8), 8),
            (Expr::BinOp(BinOpKind::Eq, VarId(1), VarId(2)), 1),
        ]);
        assert_eq!(
            classify_branch(VarId(3), &vars),
            Some(BranchClass::AlwaysTaken)
        );
    }

    #[test]
    fn detects_themida_identity() {
        // x*x - x*(x-1) - x == 0  ∀ x
        let vars = mk_vars(vec![
            (Expr::Unknown, 8),                                    // 0: x
            (Expr::BinOp(BinOpKind::Mult, VarId(0), VarId(0)), 8), // 1: x*x
            (Expr::Const(1, 8), 8),                                // 2: 1
            (Expr::BinOp(BinOpKind::Sub, VarId(0), VarId(2)), 8),  // 3: x-1
            (Expr::BinOp(BinOpKind::Mult, VarId(0), VarId(3)), 8), // 4: x*(x-1)
            (Expr::BinOp(BinOpKind::Sub, VarId(1), VarId(4)), 8),  // 5: x*x - x*(x-1)
            (Expr::BinOp(BinOpKind::Sub, VarId(5), VarId(0)), 8),  // 6: ... - x
            (Expr::Const(0, 8), 8),                                // 7: 0
            (Expr::BinOp(BinOpKind::Eq, VarId(6), VarId(7)), 1),   // 8: == 0
        ]);
        assert_eq!(
            classify_branch(VarId(8), &vars),
            Some(BranchClass::AlwaysTaken)
        );
    }

    #[test]
    fn does_not_flag_real_branch() {
        // x == 0 — true only when x == 0
        let vars = mk_vars(vec![
            (Expr::Unknown, 8),
            (Expr::Const(0, 8), 8),
            (Expr::BinOp(BinOpKind::Eq, VarId(0), VarId(1)), 1),
        ]);
        assert_eq!(classify_branch(VarId(2), &vars), None);
    }

    #[test]
    fn detects_or_with_neg_one_always_nonzero() {
        // (x | -1) != 0  ∀ x
        let vars = mk_vars(vec![
            (Expr::Unknown, 8),
            (Expr::Const(u64::MAX, 8), 8),
            (Expr::BinOp(BinOpKind::Or, VarId(0), VarId(1)), 8),
            (Expr::Const(0, 8), 8),
            (Expr::BinOp(BinOpKind::NotEq, VarId(2), VarId(3)), 1),
        ]);
        assert_eq!(
            classify_branch(VarId(4), &vars),
            Some(BranchClass::AlwaysTaken)
        );
    }
}
