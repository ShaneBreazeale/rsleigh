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
    // Collect ALL CBranch conditions — not just flag registers.
    // Compound conditions from Jcc (like JG) produce BoolAnd/BoolNot in Unique space.
    let mut to_recover: Vec<(usize, VarId)> = Vec::new();
    for (bi, block) in ssa.blocks.iter().enumerate() {
        if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
            let vdef = &ssa.vars[cond.0 as usize];
            // Accept: flag registers, Unique-space compound expressions, anything not already a comparison
            let dominated_by_flags = is_flag_derived(*cond, ssa);
            let already_comparison = matches!(&vdef.expr, Expr::BinOp(k, _, _) if is_comparison(*k));
            if dominated_by_flags && !already_comparison {
                to_recover.push((bi, *cond));
            }
        }
    }

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

/// Check if a VarId's expression tree references any flag registers.
fn is_flag_derived(id: VarId, ssa: &SsaCfg) -> bool {
    is_flag_derived_depth(id, ssa, 5)
}

fn is_flag_derived_depth(id: VarId, ssa: &SsaCfg, depth: u32) -> bool {
    if depth == 0 { return false; }
    let vdef = &ssa.vars[id.0 as usize];
    if vdef.varnode.space == AddressSpaceId::Register && FLAG_OFFSETS.contains(&vdef.varnode.offset) {
        return true;
    }
    match &vdef.expr {
        Expr::Var(inner) => is_flag_derived_depth(*inner, ssa, depth - 1),
        Expr::BinOp(_, l, r) => {
            is_flag_derived_depth(*l, ssa, depth - 1) || is_flag_derived_depth(*r, ssa, depth - 1)
        }
        Expr::UnaryOp(_, i) => is_flag_derived_depth(*i, ssa, depth - 1),
        _ => false,
    }
}

fn try_recover_condition(cond_id: VarId, block_idx: usize, ssa: &mut SsaCfg) -> Option<VarId> {
    let vdef = &ssa.vars[cond_id.0 as usize];

    // If already a comparison, use it
    if let Expr::BinOp(kind, _, _) = &vdef.expr {
        if is_comparison(*kind) { return Some(cond_id); }
    }

    // Detect compound flag patterns from x86 Jcc instructions:
    // JG:  BoolAnd(BoolNot(ZF), IntEq(OF, SF))  → left > right (signed)
    // JGE: IntEq(OF, SF)                         → left >= right (signed)
    // JL:  BoolXor/NotEq(OF, SF)                 → left < right (signed)
    // JE:  ZF                                     → left == right
    // JNE: BoolNot(ZF)                            → left != right
    // JA:  BoolAnd(BoolNot(CF), BoolNot(ZF))     → left > right (unsigned)
    // JB:  CF                                     → left < right (unsigned)

    // Try to find CMP/SUB operands from this block
    let (cmp_left, cmp_right) = find_cmp_operands(block_idx, ssa)?;

    // Classify the condition expression and determine operand order
    let classified = classify_jcc_condition(cond_id, ssa);

    if let Some((kind, swap)) = classified {
        let (left, right) = if swap { (cmp_right, cmp_left) } else { (cmp_left, cmp_right) };
        let new_var = ssa.new_var(
            ssa.vars[cond_id.0 as usize].varnode,
            Expr::BinOp(kind, left, right),
            1,
        );
        return Some(new_var);
    }

    // Fallback: check if it's a simple flag with a direct comparison expr
    let vdef = &ssa.vars[cond_id.0 as usize];
    if let Expr::Var(inner_id) = &vdef.expr {
        let inner = &ssa.vars[inner_id.0 as usize];
        if let Expr::BinOp(kind, _, _) = &inner.expr {
            if is_comparison(*kind) { return Some(*inner_id); }
        }
    }
    if let Expr::BinOp(kind, _, _) = &vdef.expr {
        if is_comparison(*kind) { return Some(cond_id); }
    }

    None
}

/// Find the CMP/SUB/TEST operands by tracing from the flag definitions.
/// Looks for the SUB/AND that produced the result used by ZF/SF flags.
fn find_cmp_operands(block_idx: usize, ssa: &SsaCfg) -> Option<(VarId, VarId)> {
    let block = &ssa.blocks[block_idx];

    // Strategy: find ZF assignment (IntEq(result, 0)), then trace `result` back
    // to the SUB/AND that produced it.
    for stmt in block.stmts.iter().rev() {
        if let Stmt::Assign(vid) = stmt {
            let v = &ssa.vars[vid.0 as usize];
            // ZF = IntEq(sub_result, 0) — the sub_result comes from CMP's SUB
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 518 {
                if let Expr::BinOp(BinOpKind::Eq, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        // Trace result_id back to a SUB or AND
                        return trace_to_cmp(*result_id, ssa);
                    }
                }
            }
            // Also check: IntSLess(result, 0) for SF
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 519 {
                if let Expr::BinOp(BinOpKind::SLess, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp(*result_id, ssa);
                    }
                }
            }
            // IntCarry/IntSCarry for CF/OF — trace their operands directly
            if v.varnode.space == AddressSpaceId::Register
                && (v.varnode.offset == 512 || v.varnode.offset == 523) // CF or OF
            {
                if let Expr::BinOp(BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow
                    | BinOpKind::Less, left, right) = &v.expr
                {
                    return Some((*left, *right));
                }
            }
        }
    }
    None
}

/// Trace a SUB/AND result variable back to find the CMP operands.
fn trace_to_cmp(result_id: VarId, ssa: &SsaCfg) -> Option<(VarId, VarId)> {
    let v = &ssa.vars[result_id.0 as usize];
    match &v.expr {
        Expr::BinOp(BinOpKind::Sub, left, right) => Some((*left, *right)),
        Expr::BinOp(BinOpKind::And, left, right) => Some((*left, *right)),
        Expr::Var(inner) => trace_to_cmp(*inner, ssa), // one level of indirection
        _ => None,
    }
}

/// Classify a Jcc condition expression into a comparison kind.
/// Returns (comparison_kind, swap_operands).
/// swap_operands=true means use (right, left) instead of (left, right) from CMP.
fn classify_jcc_condition(cond_id: VarId, ssa: &SsaCfg) -> Option<(BinOpKind, bool)> {
    let vdef = &ssa.vars[cond_id.0 as usize];

    match &vdef.expr {
        // ZF directly → JE → a == b
        _ if is_flag_ref(cond_id, 518, ssa) => Some((BinOpKind::Eq, false)),

        // BoolNot(ZF) → JNE → a != b
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_flag_ref(*inner, 518, ssa) => {
            Some((BinOpKind::NotEq, false))
        }

        // CF directly → JB → a < b (unsigned)
        _ if is_flag_ref(cond_id, 512, ssa) => Some((BinOpKind::Less, false)),

        // BoolNot(CF) → JAE → a >= b (unsigned) = !(a < b) = b <= a? No: use LessEq swapped
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_flag_ref(*inner, 512, ssa) => {
            Some((BinOpKind::LessEq, true)) // a >= b = b <= a
        }

        // IntEq(OF, SF) → JGE → a >= b (signed) = b <= a (signed)
        Expr::BinOp(BinOpKind::Eq, left, right)
            if is_flag_ref(*left, 523, ssa) && is_flag_ref(*right, 519, ssa) =>
        {
            Some((BinOpKind::SLessEq, true)) // a >= b = b <= a
        }

        // SF directly or through Var → if it's IntSLess → JL → a < b (signed)
        _ if is_flag_ref(cond_id, 519, ssa) => {
            // SF set = result was negative = a < b for CMP
            Some((BinOpKind::SLess, false))
        }

        // BoolAnd(BoolNot(ZF), IntEq(OF, SF)) → JG → a > b (signed) = b < a
        Expr::BinOp(BinOpKind::BoolAnd, left, right) => {
            let left_def = &ssa.vars[left.0 as usize];
            let right_def = &ssa.vars[right.0 as usize];

            let left_is_not_zf = matches!(&left_def.expr,
                Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_flag_ref(*inner, 518, ssa));
            let right_is_sf_eq_of = matches!(&right_def.expr,
                Expr::BinOp(BinOpKind::Eq, a, b)
                    if is_flag_ref(*a, 523, ssa) && is_flag_ref(*b, 519, ssa));

            if left_is_not_zf && right_is_sf_eq_of {
                // JG: a > b = b < a (swap operands, use SLess)
                Some((BinOpKind::SLess, true))
            } else {
                // BoolAnd(BoolNot(CF), BoolNot(ZF)) → JA → a > b (unsigned) = b < a
                let left_is_not_cf = matches!(&left_def.expr,
                    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_flag_ref(*inner, 512, ssa));
                let right_is_not_zf = matches!(&right_def.expr,
                    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_flag_ref(*inner, 518, ssa));

                if left_is_not_cf && right_is_not_zf {
                    Some((BinOpKind::Less, true)) // JA: a > b unsigned = b < a
                } else if left_is_not_zf {
                    // Partial match — at least it's a JNE variant
                    Some((BinOpKind::NotEq, false))
                } else {
                    None
                }
            }
        }

        _ => None,
    }
}

/// Check if a VarId refers to (or resolves to) a specific flag register.
fn is_flag_ref(id: VarId, flag_offset: u64, ssa: &SsaCfg) -> bool {
    let v = &ssa.vars[id.0 as usize];
    if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == flag_offset {
        return true;
    }
    // Check one level of Var indirection
    if let Expr::Var(inner) = &v.expr {
        let inner_v = &ssa.vars[inner.0 as usize];
        if inner_v.varnode.space == AddressSpaceId::Register && inner_v.varnode.offset == flag_offset {
            return true;
        }
    }
    false
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
