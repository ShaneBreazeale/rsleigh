use pcode_ir::AddressSpaceId;
use crate::ir::*;

/// x86 flag register offsets (Ghidra register space).
const FLAG_OFFSETS: &[u64] = &[512, 513, 514, 518, 519, 521, 523];

const RSP_OFFSET: u64 = 32;
const RIP_OFFSET: u64 = 648;
pub const RAX_OFFSET: u64 = 0;

/// x86-64 SysV ABI argument register offsets.
const ARG_REG_OFFSETS: &[u64] = &[56, 48, 16, 8, 128, 136]; // RDI, RSI, RDX, RCX, R8, R9

/// Fold expressions: inline temps, eliminate dead code, recover conditions.
pub fn fold(ssa: &mut SsaCfg) {
    for _round in 0..8 {
        let before = count_live_stmts(ssa);
        fold_once(ssa);
        recount_uses(ssa);
        eliminate_dead(ssa);
        recount_uses(ssa);
        recover_conditions(ssa);
        detect_return_values(ssa);
        collect_call_arguments(ssa);
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

    // Pass 2: Algebraic simplification
    for v in 0..ssa.vars.len() {
        let expr = ssa.vars[v].expr.clone();
        ssa.vars[v].expr = simplify_expr(expr, &ssa.vars);
    }

    // Pass 3: Inline single-use Unique vars and all constants
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

    // Pass 4: Multi-level register copy propagation
    propagate_register_copies(ssa);
}

fn simplify_expr(expr: Expr, vars: &[VarDef]) -> Expr {
    match &expr {
        // x & x → x (TEST instruction)
        Expr::BinOp(BinOpKind::And, left, right) => {
            // Check both VarId equality AND varnode equality (same register, different VarId)
            if left == right || same_varnode(*left, *right, vars) {
                Expr::Var(*left)
            } else {
                expr
            }
        }
        // x ^ x → 0
        Expr::BinOp(BinOpKind::Xor, left, right) if left == right || same_varnode(*left, *right, vars) => {
            Expr::Const(0, vars[left.0 as usize].size)
        }
        // x + 0 → x, 0 + x → x, x | 0 → x
        Expr::BinOp(BinOpKind::Or | BinOpKind::Add, left, right) => {
            if is_const_zero(*right, vars) { Expr::Var(*left) }
            else if is_const_zero(*left, vars) { Expr::Var(*right) }
            else { expr }
        }
        // x - 0 → x
        Expr::BinOp(BinOpKind::Sub, left, right) if is_const_zero(*right, vars) => {
            Expr::Var(*left)
        }
        _ => expr,
    }
}

/// Check if two VarIds refer to the same register (same offset+size).
fn same_varnode(a: VarId, b: VarId, vars: &[VarDef]) -> bool {
    let va = &vars[a.0 as usize];
    let vb = &vars[b.0 as usize];
    va.varnode.space == AddressSpaceId::Register
        && vb.varnode.space == AddressSpaceId::Register
        && va.varnode.offset == vb.varnode.offset
        && va.varnode.size == vb.varnode.size
}

fn is_const_zero(id: VarId, vars: &[VarDef]) -> bool {
    matches!(&vars[id.0 as usize].expr, Expr::Const(0, _))
}

/// Multi-level register copy propagation:
/// RAX = var_8; RAX = RAX + 1 → RAX = var_8 + 1
/// Also handles chains: RAX = X; RAX = RAX op Y; RAX = RAX op Z
fn propagate_register_copies(ssa: &mut SsaCfg) {
    for bi in 0..ssa.blocks.len() {
        // Build a map: for each register, track the most recent assignment's expression
        let mut reg_expr: std::collections::HashMap<(u64, u32), (VarId, Expr)> = std::collections::HashMap::new();
        let mut replacements: Vec<(usize, Expr)> = Vec::new();

        let stmts = &ssa.blocks[bi].stmts;
        for i in 0..stmts.len() {
            if let Stmt::Assign(var_id) = &stmts[i] {
                let vdef = &ssa.vars[var_id.0 as usize];
                if vdef.varnode.space != AddressSpaceId::Register { continue; }
                let key = (vdef.varnode.offset, vdef.varnode.size);

                if let Expr::BinOp(kind, left, right) = &vdef.expr {
                    let left_var = &ssa.vars[left.0 as usize];
                    // Is the left operand the same register?
                    if left_var.varnode.space == AddressSpaceId::Register
                        && left_var.varnode.offset == vdef.varnode.offset
                        && left_var.use_count <= 1
                    {
                        // Look up what that register was previously assigned to
                        if let Some((prev_id, prev_expr)) = reg_expr.get(&key) {
                            match prev_expr {
                                Expr::Var(_src) | Expr::Load(_src) => {
                                    let src_id = match prev_expr {
                                        Expr::Var(s) => *s,
                                        Expr::Load(_s) => *prev_id, // keep the load as-is
                                        _ => unreachable!(),
                                    };
                                    replacements.push((i, Expr::BinOp(*kind, src_id, *right)));
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Track this assignment
                reg_expr.insert(key, (*var_id, vdef.expr.clone()));
            }
        }

        for (idx, new_expr) in replacements {
            if let Stmt::Assign(var_id) = &ssa.blocks[bi].stmts[idx] {
                ssa.vars[var_id.0 as usize].expr = new_expr;
            }
        }
    }
}

fn substitute_expr(expr: &Expr, candidates: &[(VarId, Expr)]) -> Expr {
    match expr {
        Expr::Var(id) => {
            candidates.iter().find(|(cid, _)| cid == id)
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| expr.clone())
        }
        _ => expr.clone(),
    }
}

fn eliminate_dead(ssa: &mut SsaCfg) {
    for block in &mut ssa.blocks {
        let mut read_after: std::collections::HashSet<(u64, u32)> = std::collections::HashSet::new();

        // Collect reads from terminators
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => {
                collect_var_reads(*cond, &ssa.vars, &mut read_after);
            }
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => {
                collect_var_reads(*v, &ssa.vars, &mut read_after);
            }
            SsaTerminator::Call { args, .. } => {
                for a in args { collect_var_reads(*a, &ssa.vars, &mut read_after); }
            }
            _ => {}
        }

        let mut dead_indices = Vec::new();
        for i in (0..block.stmts.len()).rev() {
            match &block.stmts[i] {
                Stmt::Assign(var_id) => {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    let key = (vdef.varnode.offset, vdef.varnode.size);

                    // Dead flags
                    if vdef.varnode.space == AddressSpaceId::Register
                        && FLAG_OFFSETS.contains(&vdef.varnode.offset)
                        && vdef.use_count == 0
                    { dead_indices.push(i); continue; }

                    // Dead uniques
                    if vdef.varnode.space == AddressSpaceId::Unique && vdef.use_count == 0 {
                        dead_indices.push(i); continue;
                    }

                    // RIP writes
                    if vdef.varnode.space == AddressSpaceId::Register && vdef.varnode.offset == RIP_OFFSET {
                        dead_indices.push(i); continue;
                    }

                    // Dead register writes (not read before overwrite)
                    // BUT preserve argument registers before calls
                    let is_arg_reg = ARG_REG_OFFSETS.contains(&vdef.varnode.offset)
                        && vdef.varnode.space == AddressSpaceId::Register;
                    let precedes_call = block.stmts.get(i + 1..).map_or(false, |rest|
                        rest.iter().any(|s| matches!(s, Stmt::Call { .. })))
                        || matches!(block.terminator, SsaTerminator::Call { .. });
                    if vdef.varnode.space == AddressSpaceId::Register
                        && !read_after.contains(&key)
                        && vdef.use_count == 0
                        && !(is_arg_reg && precedes_call)
                    { dead_indices.push(i); continue; }

                    collect_expr_reads(&vdef.expr, &ssa.vars, &mut read_after);
                }
                Stmt::Store { addr, val } => {
                    let val_def = &ssa.vars[val.0 as usize];
                    let addr_def = &ssa.vars[addr.0 as usize];
                    if is_rsp_derived(&addr_def.varnode, &addr_def.expr, &ssa.vars) {
                        if let Expr::Const(_, _) = &val_def.expr {
                            dead_indices.push(i); continue;
                        }
                    }
                    collect_var_reads(*addr, &ssa.vars, &mut read_after);
                    collect_var_reads(*val, &ssa.vars, &mut read_after);
                }
                Stmt::Call { args, .. } => {
                    for a in args { collect_var_reads(*a, &ssa.vars, &mut read_after); }
                }
            }
        }
        // Remove in reverse order so indices stay valid
        dead_indices.sort_unstable();
        dead_indices.dedup();
        for &i in dead_indices.iter().rev() {
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
        Expr::UnaryOp(_, i) | Expr::Load(i) => collect_var_reads(*i, vars, reads),
        Expr::Phi(inputs) => { for i in inputs { collect_var_reads(*i, vars, reads); } }
        _ => {}
    }
}

fn is_rsp_derived(vn: &pcode_ir::Varnode, expr: &Expr, vars: &[VarDef]) -> bool {
    if vn.space == AddressSpaceId::Register && vn.offset == RSP_OFFSET { return true; }
    match expr {
        Expr::Var(id) | Expr::BinOp(_, id, _) => {
            let v = &vars[id.0 as usize];
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
        }
        _ => false,
    }
}

// ---- Condition Recovery ----

/// Recover high-level conditions from flag variables.
/// Handles: ZF (from TEST/CMP → IntEq), SF==OF (JGE/JL from CMP → IntSLess).
fn recover_conditions(ssa: &mut SsaCfg) {
    // First pass: collect what we need without borrowing ssa mutably
    let mut to_recover: Vec<(usize, VarId)> = Vec::new();
    for (bi, block) in ssa.blocks.iter().enumerate() {
        if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
            let vdef = &ssa.vars[cond.0 as usize];
            if vdef.varnode.space == AddressSpaceId::Register
                && FLAG_OFFSETS.contains(&vdef.varnode.offset)
            {
                to_recover.push((bi, *cond));
            }
        }
    }

    // Second pass: try to recover each condition
    for (bi, cond_id) in to_recover {
        if let Some(new_cond) = try_recover_condition(cond_id, bi, ssa) {
            if let SsaTerminator::CBranch { taken, fallthrough, .. } = ssa.blocks[bi].terminator {
                ssa.blocks[bi].terminator = SsaTerminator::CBranch {
                    cond: new_cond, taken, fallthrough,
                };
            }
        }
    }
}

fn try_recover_condition(cond_id: VarId, block_idx: usize, ssa: &mut SsaCfg) -> Option<VarId> {
    let vdef = &ssa.vars[cond_id.0 as usize];

    // If already a comparison, use it
    if let Expr::BinOp(kind, _, _) = &vdef.expr {
        if is_comparison(*kind) { return Some(cond_id); }
    }

    // If it's a flag, trace back
    if vdef.varnode.space != AddressSpaceId::Register { return None; }
    if !FLAG_OFFSETS.contains(&vdef.varnode.offset) { return None; }

    let flag_offset = vdef.varnode.offset;

    // Direct comparison expression on the flag
    if let Expr::BinOp(kind, _, _) = &vdef.expr {
        if is_comparison(*kind) { return Some(cond_id); }
    }

    // Trace through Var indirection
    if let Expr::Var(inner_id) = &vdef.expr {
        let inner = &ssa.vars[inner_id.0 as usize];
        if let Expr::BinOp(kind, _, _) = &inner.expr {
            if is_comparison(*kind) { return Some(*inner_id); }
        }
    }

    // ZF from IntEq: trace to find what was compared
    if flag_offset == 518 { // ZF
        // Look in this block's stmts for the ZF assignment
        // ZF is typically set by IntEq(result, 0) after a SUB/AND
        if let Expr::BinOp(BinOpKind::Eq, _left, _right) = &vdef.expr {
            return Some(cond_id); // Already IntEq — good
        }
    }

    // SF == OF pattern (JGE/JL): search the block for SF and OF definitions,
    // then find the SUB/CMP that produced them
    // SF and OF are set by the same SUB instruction. SF = IntSLess(result, 0),
    // OF = IntSCarry(left, right). The original comparison is left >= right (JGE)
    // or left < right (JL).
    if flag_offset == 519 || flag_offset == 523 { // SF or OF
        // Search backward in the same block for a SUB that set flags
        let block = &ssa.blocks[block_idx];
        for stmt in block.stmts.iter().rev() {
            if let Stmt::Assign(vid) = stmt {
                let v = &ssa.vars[vid.0 as usize];
                // Find a SUB operation (from CMP instruction)
                if let Expr::BinOp(BinOpKind::Sub, left, right) = &v.expr {
                    // Create a new SLess comparison: left < right
                    let new_var = ssa.new_var(
                        vdef.varnode,
                        Expr::BinOp(BinOpKind::SLess, *left, *right),
                        1,
                    );
                    return Some(new_var);
                }
            }
        }
    }

    None
}

fn is_comparison(kind: BinOpKind) -> bool {
    matches!(kind, BinOpKind::Eq | BinOpKind::NotEq | BinOpKind::Less
        | BinOpKind::LessEq | BinOpKind::SLess | BinOpKind::SLessEq)
}

// ---- Return Values ----

fn detect_return_values(ssa: &mut SsaCfg) {
    for block in &mut ssa.blocks {
        if let SsaTerminator::Return(ref mut ret_val) = block.terminator {
            if ret_val.is_some() { continue; }
            for stmt in block.stmts.iter().rev() {
                if let Stmt::Assign(var_id) = stmt {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RAX_OFFSET
                        && vdef.varnode.size >= 4
                    {
                        *ret_val = Some(*var_id);
                        break;
                    }
                }
            }
        }
    }
}

// ---- Call Arguments ----

/// Collect argument register writes before each Call and attach them.
fn collect_call_arguments(ssa: &mut SsaCfg) {
    for bi in 0..ssa.blocks.len() {
        // Check if block ends with a Call terminator
        let call_info = match &ssa.blocks[bi].terminator {
            SsaTerminator::Call { target, fallthrough, .. } => {
                Some((target.clone(), *fallthrough))
            }
            _ => None,
        };

        if let Some((target, fallthrough)) = call_info {
            // Collect argument register VarIds from the block's statements
            let mut args: Vec<(u64, VarId)> = Vec::new();
            for stmt in &ssa.blocks[bi].stmts {
                if let Stmt::Assign(var_id) = stmt {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.varnode.space == AddressSpaceId::Register
                        && ARG_REG_OFFSETS.contains(&vdef.varnode.offset)
                    {
                        // Remove any previous assignment to same register
                        args.retain(|(off, _)| *off != vdef.varnode.offset);
                        args.push((vdef.varnode.offset, *var_id));
                    }
                }
            }

            if !args.is_empty() {
                // Sort by ABI order: RDI, RSI, RDX, RCX, R8, R9
                args.sort_by_key(|(off, _)| {
                    ARG_REG_OFFSETS.iter().position(|o| o == off).unwrap_or(99)
                });
                let arg_ids: Vec<VarId> = args.iter().map(|(_, v)| *v).collect();
                ssa.blocks[bi].terminator = SsaTerminator::Call {
                    target,
                    args: arg_ids,
                    fallthrough,
                };
            }
        }

        // Also check for Call statements within the block
        for si in 0..ssa.blocks[bi].stmts.len() {
            if let Stmt::Call { target, args, out } = &ssa.blocks[bi].stmts[si] {
                if !args.is_empty() { continue; } // Already has args
                let target = target.clone();
                let out = *out;
                // Look backward for arg register writes
                let mut call_args: Vec<(u64, VarId)> = Vec::new();
                for j in (0..si).rev() {
                    if let Stmt::Assign(var_id) = &ssa.blocks[bi].stmts[j] {
                        let vdef = &ssa.vars[var_id.0 as usize];
                        if vdef.varnode.space == AddressSpaceId::Register
                            && ARG_REG_OFFSETS.contains(&vdef.varnode.offset)
                        {
                            if !call_args.iter().any(|(off, _)| *off == vdef.varnode.offset) {
                                call_args.push((vdef.varnode.offset, *var_id));
                            }
                        }
                    }
                    // Stop at previous call or branch
                    if matches!(&ssa.blocks[bi].stmts[j], Stmt::Call { .. }) { break; }
                }
                if !call_args.is_empty() {
                    call_args.sort_by_key(|(off, _)| {
                        ARG_REG_OFFSETS.iter().position(|o| o == off).unwrap_or(99)
                    });
                    let arg_ids: Vec<VarId> = call_args.iter().map(|(_, v)| *v).collect();
                    ssa.blocks[bi].stmts[si] = Stmt::Call { target, args: arg_ids, out };
                }
            }
        }
    }
}

// ---- Use counting ----

pub(crate) fn recount_uses(ssa: &mut SsaCfg) {
    let mut use_counts = vec![0u32; ssa.vars.len()];
    for v in 0..ssa.vars.len() {
        match &ssa.vars[v].expr {
            Expr::Var(id) => use_counts[id.0 as usize] += 1,
            Expr::BinOp(_, l, r) => { use_counts[l.0 as usize] += 1; use_counts[r.0 as usize] += 1; }
            Expr::UnaryOp(_, i) | Expr::Load(i) => use_counts[i.0 as usize] += 1,
            Expr::Phi(inputs) => { for i in inputs { use_counts[i.0 as usize] += 1; } }
            Expr::Const(_, _) | Expr::Unknown => {}
        }
    }
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, val } => { use_counts[addr.0 as usize] += 1; use_counts[val.0 as usize] += 1; }
                Stmt::Call { args, .. } => { for a in args { use_counts[a.0 as usize] += 1; } }
                _ => {}
            }
        }
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => use_counts[cond.0 as usize] += 1,
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => use_counts[v.0 as usize] += 1,
            SsaTerminator::Call { args, .. } => { for a in args { use_counts[a.0 as usize] += 1; } }
            _ => {}
        }
    }
    for (i, count) in use_counts.into_iter().enumerate() {
        ssa.vars[i].use_count = count;
    }
}
