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

const _ZF_OFFSET: u64 = 518;
const _CF_OFFSET: u64 = 512;
const _SF_OFFSET: u64 = 519;

/// RSP offset in x86 Ghidra register space.
const RSP_OFFSET: u64 = 32;
const _RBP_OFFSET: u64 = 40;
/// RIP offset
const RIP_OFFSET: u64 = 648;
/// RAX offset (return value on x86-64)
pub const RAX_OFFSET: u64 = 0;

/// Fold expressions: inline single-use temps, eliminate dead code, flags, and boilerplate.
pub fn fold(ssa: &mut SsaCfg) {
    for _round in 0..6 {
        let before = count_live_stmts(ssa);
        fold_once(ssa);
        recount_uses(ssa);
        eliminate_dead(ssa);
        recount_uses(ssa);
        recover_conditions(ssa);
        detect_return_values(ssa);
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

    // Pass 2: Inline single-use Unique vars and all constants
    let inline_candidates: Vec<(VarId, Expr)> = (0..ssa.vars.len())
        .filter_map(|v| {
            let vdef = &ssa.vars[v];
            if vdef.use_count == 1 && vdef.varnode.space == AddressSpaceId::Unique {
                Some((vdef.id, vdef.expr.clone()))
            } else if matches!(vdef.expr, Expr::Const(_, _)) {
                Some((vdef.id, vdef.expr.clone()))
            } else {
                None
            }
        })
        .collect();

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
        _ => expr.clone(),
    }
}

fn eliminate_dead(ssa: &mut SsaCfg) {
    // Collect register writes per block to find overwrites-before-read
    for block in &mut ssa.blocks {
        // Track which registers have been read in remaining statements
        let mut read_after: std::collections::HashSet<(u64, u32)> = std::collections::HashSet::new();

        // First, collect all reads from terminators
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => {
                collect_var_reads(*cond, &ssa.vars, &mut read_after);
            }
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => {
                collect_var_reads(*v, &ssa.vars, &mut read_after);
            }
            _ => {}
        }

        // Walk statements in reverse to find dead writes
        let mut dead_indices = Vec::new();
        for i in (0..block.stmts.len()).rev() {
            match &block.stmts[i] {
                Stmt::Assign(var_id) => {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    let key = (vdef.varnode.offset, vdef.varnode.size);

                    // Remove dead flag writes
                    if vdef.varnode.space == AddressSpaceId::Register
                        && FLAG_OFFSETS.contains(&vdef.varnode.offset)
                        && vdef.use_count == 0
                    {
                        dead_indices.push(i);
                        continue;
                    }
                    // Remove dead unique writes
                    if vdef.varnode.space == AddressSpaceId::Unique && vdef.use_count == 0 {
                        dead_indices.push(i);
                        continue;
                    }
                    // Remove RIP writes
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RIP_OFFSET
                    {
                        dead_indices.push(i);
                        continue;
                    }
                    // Remove register writes that are overwritten before any read in same block.
                    // BUT: don't eliminate writes to argument registers (RDI, RSI, RDX, RCX, R8, R9)
                    // that precede a Call — they're setting up function arguments.
                    // x86-64 SysV ABI argument registers: RDI(56), RSI(48), RDX(16), RCX(8), R8(128), R9(136)
                    let is_arg_reg = matches!(vdef.varnode.offset, 56 | 48 | 16 | 8 | 128 | 136)
                        && vdef.varnode.space == AddressSpaceId::Register;
                    let precedes_call = block.stmts.get(i + 1..).map_or(false, |rest|
                        rest.iter().any(|s| matches!(s, Stmt::Call { .. })))
                        || matches!(block.terminator, SsaTerminator::Call { .. });
                    if vdef.varnode.space == AddressSpaceId::Register
                        && !read_after.contains(&key)
                        && vdef.use_count == 0
                        && !(is_arg_reg && precedes_call)
                    {
                        dead_indices.push(i);
                        continue;
                    }

                    // This statement is live — mark its inputs as read
                    collect_expr_reads(&vdef.expr, &ssa.vars, &mut read_after);
                }
                Stmt::Store { addr, val } => {
                    // Remove push-return-address pattern
                    let val_def = &ssa.vars[val.0 as usize];
                    let addr_def = &ssa.vars[addr.0 as usize];
                    if is_rsp_derived(&addr_def.varnode, &addr_def.expr, &ssa.vars) {
                        if let Expr::Const(_, _) = &val_def.expr {
                            dead_indices.push(i);
                            continue;
                        }
                    }
                    collect_var_reads(*addr, &ssa.vars, &mut read_after);
                    collect_var_reads(*val, &ssa.vars, &mut read_after);
                }
                Stmt::Call { args, .. } => {
                    for a in args {
                        collect_var_reads(*a, &ssa.vars, &mut read_after);
                    }
                }
            }
        }

        for i in dead_indices {
            block.stmts.remove(i);
        }
    }
}

fn collect_var_reads(id: VarId, vars: &[VarDef], reads: &mut std::collections::HashSet<(u64, u32)>) {
    let vdef = &vars[id.0 as usize];
    if vdef.varnode.space == AddressSpaceId::Register {
        reads.insert((vdef.varnode.offset, vdef.varnode.size));
    }
    collect_expr_reads(&vdef.expr, vars, reads);
}

fn collect_expr_reads(expr: &Expr, vars: &[VarDef], reads: &mut std::collections::HashSet<(u64, u32)>) {
    match expr {
        Expr::Var(id) => {
            let v = &vars[id.0 as usize];
            if v.varnode.space == AddressSpaceId::Register {
                reads.insert((v.varnode.offset, v.varnode.size));
            }
        }
        Expr::BinOp(_, l, r) => {
            collect_var_reads(*l, vars, reads);
            collect_var_reads(*r, vars, reads);
        }
        Expr::UnaryOp(_, i) | Expr::Load(i) => {
            collect_var_reads(*i, vars, reads);
        }
        Expr::Phi(inputs) => {
            for i in inputs { collect_var_reads(*i, vars, reads); }
        }
        _ => {}
    }
}

fn is_rsp_derived(vn: &pcode_ir::Varnode, expr: &Expr, vars: &[VarDef]) -> bool {
    if vn.space == AddressSpaceId::Register && vn.offset == RSP_OFFSET {
        return true;
    }
    match expr {
        Expr::Var(id) => {
            let v = &vars[id.0 as usize];
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
        }
        Expr::BinOp(_, l, _) => {
            let v = &vars[l.0 as usize];
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
        }
        _ => false,
    }
}

/// Recover high-level conditions from flag variables.
/// Replace CBranch(flag_var) with CBranch(comparison_var) by tracing
/// the flag back to the comparison that produced it.
fn recover_conditions(ssa: &mut SsaCfg) {
    // Collect replacements first to avoid borrow conflict
    let mut replacements: Vec<(usize, VarId)> = Vec::new();
    for (bi, block) in ssa.blocks.iter().enumerate() {
        if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
            let vdef = &ssa.vars[cond.0 as usize];
            if vdef.varnode.space == AddressSpaceId::Register
                && FLAG_OFFSETS.contains(&vdef.varnode.offset)
            {
                if let Some(new_cond) = trace_flag_condition(*cond, &ssa.vars) {
                    replacements.push((bi, new_cond));
                }
            }
        }
    }
    for (bi, new_cond) in replacements {
        if let SsaTerminator::CBranch { taken, fallthrough, .. } = ssa.blocks[bi].terminator {
            ssa.blocks[bi].terminator = SsaTerminator::CBranch {
                cond: new_cond, taken, fallthrough,
            };
        }
    }
}

/// Trace a flag variable back to the comparison that produced it.
/// Returns a new VarId with a comparison expression, or None.
fn trace_flag_condition(flag_id: VarId, vars: &[VarDef]) -> Option<VarId> {
    let vdef = &vars[flag_id.0 as usize];

    match &vdef.expr {
        // Already a comparison — use it directly
        Expr::BinOp(BinOpKind::Eq | BinOpKind::NotEq | BinOpKind::Less
            | BinOpKind::LessEq | BinOpKind::SLess | BinOpKind::SLessEq, _, _) =>
        {
            Some(flag_id)
        }
        // Flag was set by a Var reference — trace through one level
        Expr::Var(inner_id) => {
            let inner = &vars[inner_id.0 as usize];
            match &inner.expr {
                Expr::BinOp(BinOpKind::Eq | BinOpKind::NotEq | BinOpKind::Less
                    | BinOpKind::LessEq | BinOpKind::SLess | BinOpKind::SLessEq, _, _) =>
                {
                    Some(*inner_id)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Detect return values: if a block ends with Return and RAX/X0 was recently written,
/// set the return value.
fn detect_return_values(ssa: &mut SsaCfg) {
    for block in &mut ssa.blocks {
        if let SsaTerminator::Return(ref mut ret_val) = block.terminator {
            if ret_val.is_some() { continue; }
            // Search backwards for the last RAX write
            for stmt in block.stmts.iter().rev() {
                if let Stmt::Assign(var_id) = stmt {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RAX_OFFSET
                        && vdef.varnode.size == 8
                    {
                        *ret_val = Some(*var_id);
                        break;
                    }
                }
            }
        }
    }
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
