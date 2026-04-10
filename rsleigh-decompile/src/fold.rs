use pcode_ir::AddressSpaceId;
use crate::ir::*;

/// x86 flag register offsets (Ghidra register space).
const FLAG_OFFSETS: &[u64] = &[
    512, // CF
    513, // F1
    514, // PF
    518, // ZF
    519, // SF
    521, // DF
    523, // OF
];

/// RSP offset in x86 Ghidra register space.
const RSP_OFFSET: u64 = 32;
/// RBP offset
const _RBP_OFFSET: u64 = 40;
/// RIP offset
const RIP_OFFSET: u64 = 648;

/// Fold expressions: inline single-use temps, eliminate dead code, flags, and boilerplate.
pub fn fold(ssa: &mut SsaCfg) {
    for _round in 0..6 {
        let before = count_live_stmts(ssa);
        fold_once(ssa);
        recount_uses(ssa);
        eliminate_dead(ssa);
        recount_uses(ssa);
        let after = count_live_stmts(ssa);
        if before == after { break; }
    }
}

fn count_live_stmts(ssa: &SsaCfg) -> usize {
    ssa.blocks.iter().map(|b| b.stmts.len()).sum()
}

fn fold_once(ssa: &mut SsaCfg) {
    // Pass 1: Collapse trivial Phis
    for v in 0..ssa.vars.len() {
        if let Expr::Phi(inputs) = &ssa.vars[v].expr {
            if inputs.is_empty() { continue; }
            let first = inputs[0];
            if inputs.iter().all(|i| *i == first) {
                ssa.vars[v].expr = Expr::Var(first);
            }
        }
    }

    // Pass 2: Inline single-use vars into their consumers
    // Collect inlining candidates: single-use Unique or Const vars
    let inline_candidates: Vec<(VarId, Expr)> = (0..ssa.vars.len())
        .filter_map(|v| {
            let vdef = &ssa.vars[v];
            if vdef.use_count == 1 && vdef.varnode.space == AddressSpaceId::Unique {
                Some((vdef.id, vdef.expr.clone()))
            } else if matches!(vdef.expr, Expr::Const(_, _)) {
                // Always inline constants regardless of use count
                Some((vdef.id, vdef.expr.clone()))
            } else {
                None
            }
        })
        .collect();

    // Apply inlining: for each var's expr, replace Var(candidate) with candidate's expr
    for v in 0..ssa.vars.len() {
        let expr = ssa.vars[v].expr.clone();
        ssa.vars[v].expr = substitute_expr(&expr, &inline_candidates);
    }
}

fn substitute_expr(expr: &Expr, candidates: &[(VarId, Expr)]) -> Expr {
    match expr {
        Expr::Var(id) => {
            if let Some((_, replacement)) = candidates.iter().find(|(cid, _)| cid == id) {
                replacement.clone()
            } else {
                expr.clone()
            }
        }
        Expr::BinOp(kind, left, right) => {
            let l = resolve_var_id(left, candidates);
            let r = resolve_var_id(right, candidates);
            Expr::BinOp(*kind, l, r)
        }
        Expr::UnaryOp(kind, input) => {
            let i = resolve_var_id(input, candidates);
            Expr::UnaryOp(*kind, i)
        }
        Expr::Load(ptr) => {
            let p = resolve_var_id(ptr, candidates);
            Expr::Load(p)
        }
        _ => expr.clone(),
    }
}

/// If a VarId points to a constant, return a new VarId for that constant.
/// Otherwise return the original. (We don't actually create new vars here;
/// the printer handles the resolution.)
fn resolve_var_id(id: &VarId, _candidates: &[(VarId, Expr)]) -> VarId {
    *id
}

fn eliminate_dead(ssa: &mut SsaCfg) {
    for block in &mut ssa.blocks {
        block.stmts.retain(|stmt| {
            match stmt {
                Stmt::Assign(var_id) => {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    // Remove dead flag writes
                    if vdef.varnode.space == AddressSpaceId::Register
                        && FLAG_OFFSETS.contains(&vdef.varnode.offset)
                        && vdef.use_count == 0
                    {
                        return false;
                    }
                    // Remove dead unique writes
                    if vdef.varnode.space == AddressSpaceId::Unique && vdef.use_count == 0 {
                        return false;
                    }
                    // Remove RIP writes (return address management)
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RIP_OFFSET
                    {
                        return false;
                    }
                    true
                }
                Stmt::Store { addr, val } => {
                    // Remove push-return-address pattern:
                    // *(RSP) = const (where const looks like a return address)
                    let val_def = &ssa.vars[val.0 as usize];
                    let addr_def = &ssa.vars[addr.0 as usize];
                    if is_rsp_var(&addr_def.varnode) {
                        if let Expr::Const(_, _) = &val_def.expr {
                            // This is `push return_address` before a CALL — eliminate
                            return false;
                        }
                    }
                    true
                }
                _ => true,
            }
        });
    }
}

fn is_rsp_var(vn: &pcode_ir::Varnode) -> bool {
    vn.space == AddressSpaceId::Register && vn.offset == RSP_OFFSET
}

pub(crate) fn recount_uses(ssa: &mut SsaCfg) {
    let mut use_counts = vec![0u32; ssa.vars.len()];

    for v in 0..ssa.vars.len() {
        match &ssa.vars[v].expr {
            Expr::Var(id) => use_counts[id.0 as usize] += 1,
            Expr::BinOp(_, l, r) => {
                use_counts[l.0 as usize] += 1;
                use_counts[r.0 as usize] += 1;
            }
            Expr::UnaryOp(_, i) | Expr::Load(i) => use_counts[i.0 as usize] += 1,
            Expr::Phi(inputs) => {
                for i in inputs { use_counts[i.0 as usize] += 1; }
            }
            Expr::Const(_, _) | Expr::Unknown => {}
        }
    }
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, val } => {
                    use_counts[addr.0 as usize] += 1;
                    use_counts[val.0 as usize] += 1;
                }
                Stmt::Call { args, .. } => {
                    for a in args { use_counts[a.0 as usize] += 1; }
                }
                _ => {}
            }
        }
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => use_counts[cond.0 as usize] += 1,
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => use_counts[v.0 as usize] += 1,
            _ => {}
        }
    }

    for (i, count) in use_counts.into_iter().enumerate() {
        ssa.vars[i].use_count = count;
    }
}
