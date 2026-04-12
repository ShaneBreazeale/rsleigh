use pcode_ir::AddressSpaceId;
use crate::ir::*;

/// Flag register offsets (Ghidra register space).
/// x86: CF=512, F1=513, PF=514, ZF=518, SF=519, DF=521, OF=523
/// ARM64: NG=256, ZR=257, CY=258, OV=259, tmpNG=263, tmpZR=264, tmpCY=261, tmpOV=262
const FLAG_OFFSETS: &[u64] = &[
    512, 513, 514, 518, 519, 521, 523,       // x86
    256, 257, 258, 259, 261, 262, 263, 264,   // ARM64
];

const RSP_OFFSET: u64 = 32;   // x86-64 RSP
const ESP_OFFSET: u64 = 16;   // x86-32 ESP
const RIP_OFFSET: u64 = 648;
pub const RAX_OFFSET: u64 = 0;

/// x86-64 SysV ABI argument register offsets (Linux, macOS, BSD).
const SYSV_ARG_REGS: &[u64] = &[56, 48, 16, 8, 128, 136]; // RDI, RSI, RDX, RCX, R8, R9

/// Windows x64 ABI argument register offsets.
const WIN64_ARG_REGS: &[u64] = &[8, 16, 128, 136]; // RCX, RDX, R8, R9

/// Active argument register offsets — set by fold_with_cc() based on binary format.
/// Uses thread_local to avoid unsafe static mut.
std::thread_local! {
    static ARG_REG_OFFSETS_TLS: std::cell::RefCell<&'static [u64]> = const { std::cell::RefCell::new(SYSV_ARG_REGS) };
}

fn arg_reg_offsets() -> &'static [u64] {
    ARG_REG_OFFSETS_TLS.with(|r| *r.borrow())
}

/// Calling convention detected from binary format.
#[derive(Clone, Copy, PartialEq)]
pub enum CallingConv {
    SysV,     // Linux, macOS, BSD — RDI, RSI, RDX, RCX, R8, R9
    Win64,    // Windows x64 — RCX, RDX, R8, R9
    Cdecl32,  // x86-32 cdecl — stack-based
}

/// Fold expressions: inline temps, eliminate dead code, recover conditions.
pub fn fold(ssa: &mut SsaCfg) {
    fold_with_cc(ssa, CallingConv::SysV);
}

/// Fold with explicit calling convention.
pub fn fold_with_cc(ssa: &mut SsaCfg, cc: CallingConv) {
    // Set the thread-local arg register offsets based on calling convention
    ARG_REG_OFFSETS_TLS.with(|r| {
        *r.borrow_mut() = match cc {
            CallingConv::SysV => SYSV_ARG_REGS,
            CallingConv::Win64 => WIN64_ARG_REGS,
            CallingConv::Cdecl32 => &[],
        };
    });
    // Collect call arguments FIRST, before any optimization.
    // Arg register writes (RCX/RDX for Win64, RDI/RSI for SysV) have use_count=0
    // because the Call terminator doesn't reference them by VarId. If we run
    // fold_once or eliminate_dead first, these assignments get removed.
    collect_call_arguments(ssa);
    recount_uses(ssa);

    for _round in 0..8 {
        let before = count_live_stmts(ssa);
        fold_once(ssa);
        recount_uses(ssa);
        propagate_register_constants(ssa);
        propagate_call_returns(ssa);
        recount_uses(ssa);
        eliminate_dead(ssa);
        recount_uses(ssa);
        recover_conditions(ssa);
        detect_return_values(ssa);
        recount_uses(ssa);
        name_parameters(ssa);
        let after = count_live_stmts(ssa);
        if before == after { break; }
    }
    // Type inference runs once after folding is stable
    infer_types(ssa);
    // Recognize struct field access patterns after all folding is done
    recognize_field_access(ssa);
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
        // x & x → x (TEST instruction), x & 0 → 0, const & mask noop
        Expr::BinOp(BinOpKind::And, left, right) => {
            if left == right || same_varnode(*left, *right, vars) {
                Expr::Var(*left)
            } else if is_const_zero(*right, vars) {
                Expr::Const(0, vars[left.0 as usize].size)
            } else if is_const_zero(*left, vars) {
                Expr::Const(0, vars[right.0 as usize].size)
            } else if is_const_mask_noop(*left, *right, vars) {
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
            // x | -1 → -1 (all bits set)
            else if is_const_all_ones(*right, vars) { Expr::Var(*right) }
            else if is_const_all_ones(*left, vars) { Expr::Var(*left) }
            else { expr }
        }
        // x - 0 → x
        Expr::BinOp(BinOpKind::Sub, left, right) if is_const_zero(*right, vars) => {
            Expr::Var(*left)
        }
        // x * 1 → x, x * 0 → 0
        Expr::BinOp(BinOpKind::Mult, left, right) => {
            if is_const_one(*right, vars) { Expr::Var(*left) }
            else if is_const_one(*left, vars) { Expr::Var(*right) }
            else if is_const_zero(*right, vars) { Expr::Const(0, vars[left.0 as usize].size) }
            else if is_const_zero(*left, vars) { Expr::Const(0, vars[right.0 as usize].size) }
            else { expr }
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

fn is_const_one(id: VarId, vars: &[VarDef]) -> bool {
    matches!(&vars[id.0 as usize].expr, Expr::Const(1, _))
}

/// Check if `val & mask` == `val` (AND is a no-op because val fits within mask).
fn is_const_mask_noop(val_id: VarId, mask_id: VarId, vars: &[VarDef]) -> bool {
    if let (Expr::Const(val, _), Expr::Const(mask, _)) = (&vars[val_id.0 as usize].expr, &vars[mask_id.0 as usize].expr) {
        *val & *mask == *val && *val != 0
    } else {
        false
    }
}

fn is_const_all_ones(id: VarId, vars: &[VarDef]) -> bool {
    if let Expr::Const(val, sz) = &vars[id.0 as usize].expr {
        let mask = if *sz >= 8 { u64::MAX } else { (1u64 << (*sz * 8)) - 1 };
        *val == mask
    } else {
        false
    }
}

/// Propagate constants from register writes to Unknown versions at the same offset.
/// Only propagates to non-parameter, non-argument registers that aren't heavily used
/// (which would indicate they're loop variables, not constants).
fn propagate_register_constants(ssa: &mut SsaCfg) {
    // Collect all register constants: offset → (value, size)
    let mut reg_consts: std::collections::HashMap<u64, (u64, u32)> = std::collections::HashMap::new();
    for v in &ssa.vars {
        if v.varnode.space == AddressSpaceId::Register && v.param_name.is_none() {
            if let Expr::Const(val, sz) = &v.expr {
                reg_consts.insert(v.varnode.offset, (*val, *sz));
            }
        }
    }

    // Propagate to Unknown vars at the same register offset
    // Only target non-parameter, low-use Unknown vars
    for v in &mut ssa.vars {
        if v.varnode.space == AddressSpaceId::Register && matches!(&v.expr, Expr::Unknown)
            && v.param_name.is_none()
            && v.use_count <= 2  // Low use count = likely a constant setup, not a loop var
            && !FLAG_OFFSETS.contains(&v.varnode.offset)
            && v.varnode.offset != RSP_OFFSET
            && v.varnode.offset != RIP_OFFSET
            && v.varnode.offset != 40 // RBP
        {
            if let Some(&(val, _const_sz)) = reg_consts.get(&v.varnode.offset) {
                let mask = match v.varnode.size {
                    1 => 0xFF, 2 => 0xFFFF, 4 => 0xFFFFFFFF, _ => u64::MAX,
                };
                v.expr = Expr::Const(val & mask, v.varnode.size);
            }
        }
    }
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
                        if let Some((prev_id, _prev_expr)) = reg_expr.get(&key) {
                            // Substitute the previous assignment's VarId as the left operand
                            // This handles: EAX = X; EAX = EAX + Y → EAX = X + Y
                            replacements.push((i, Expr::BinOp(*kind, *prev_id, *right)));
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

                    // Dead CARRY/SCARRY/SBORROW operations (multi-precision arithmetic flags)
                    if vdef.use_count == 0 {
                        if matches!(&vdef.expr,
                            Expr::BinOp(BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow, _, _))
                        {
                            dead_indices.push(i); continue;
                        }
                    }

                    // RIP writes
                    if vdef.varnode.space == AddressSpaceId::Register && vdef.varnode.offset == RIP_OFFSET {
                        dead_indices.push(i); continue;
                    }

                    // Dead register writes (not read before overwrite)
                    // BUT preserve argument registers before calls
                    // BUT preserve registers in loop bodies (back-edge blocks)
                    // because the SSA may not have connected loop-carried variables
                    let is_arg_reg = arg_reg_offsets().contains(&vdef.varnode.offset)
                        && vdef.varnode.space == AddressSpaceId::Register;
                    let precedes_call = block.stmts.get(i + 1..).map_or(false, |rest|
                        rest.iter().any(|s| matches!(s, Stmt::Call { .. })))
                        || matches!(block.terminator, SsaTerminator::Call { .. });
                    // Check if this block branches back to an earlier block (loop body)
                    let is_loop_body = match &block.terminator {
                        SsaTerminator::CBranch { taken, fallthrough, .. } =>
                            taken.0 <= block.id.0 || fallthrough.0 <= block.id.0,
                        SsaTerminator::Branch(b) => b.0 <= block.id.0,
                        _ => false,
                    };
                    // Also check if this block's successor is a loop header
                    let is_pre_loop = match &block.terminator {
                        SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) =>
                            b.0 < block.id.0,
                        _ => false,
                    };
                    // Preserve non-flag register writes in loop bodies — they may be
                    // loop accumulators (count += bit, total += arr[i]) whose use_count
                    // is 0 due to incomplete phi resolution in the SSA builder.
                    let preserve_in_loop = (is_loop_body || is_pre_loop)
                        && vdef.varnode.space == AddressSpaceId::Register
                        && !FLAG_OFFSETS.contains(&vdef.varnode.offset)
                        && vdef.varnode.offset != RIP_OFFSET
                        && vdef.varnode.offset != RSP_OFFSET
                        && vdef.varnode.offset != ESP_OFFSET;
                    if vdef.varnode.space == AddressSpaceId::Register
                        && !read_after.contains(&key)
                        && vdef.use_count == 0
                        && !(is_arg_reg && precedes_call)
                        && !preserve_in_loop
                    { dead_indices.push(i); continue; }

                    let mut visited = std::collections::HashSet::new();
                    collect_expr_reads_inner(&vdef.expr, &ssa.vars, &mut read_after, &mut visited);
                }
                Stmt::Store { addr, val } => {
                    let val_def = &ssa.vars[val.0 as usize];
                    let addr_def = &ssa.vars[addr.0 as usize];
                    if is_rsp_derived(&addr_def.varnode, &addr_def.expr, &ssa.vars)
                        || is_esp_derived(&addr_def.varnode, &addr_def.expr, &ssa.vars)
                    {
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
    let mut visited = std::collections::HashSet::new();
    collect_var_reads_inner(id, vars, reads, &mut visited);
}

fn collect_var_reads_inner(id: VarId, vars: &[VarDef], reads: &mut std::collections::HashSet<(u64, u32)>, visited: &mut std::collections::HashSet<u32>) {
    if !visited.insert(id.0) { return; } // cycle detection
    let vdef = &vars[id.0 as usize];
    if vdef.varnode.space == AddressSpaceId::Register {
        reads.insert((vdef.varnode.offset, vdef.varnode.size));
    }
    collect_expr_reads_inner(&vdef.expr, vars, reads, visited);
}

fn collect_expr_reads_inner(expr: &Expr, vars: &[VarDef], reads: &mut std::collections::HashSet<(u64, u32)>, visited: &mut std::collections::HashSet<u32>) {
    match expr {
        Expr::Var(id) => {
            let v = &vars[id.0 as usize];
            if v.varnode.space == AddressSpaceId::Register {
                reads.insert((v.varnode.offset, v.varnode.size));
            }
        }
        Expr::BinOp(_, l, r) => {
            collect_var_reads_inner(*l, vars, reads, visited);
            collect_var_reads_inner(*r, vars, reads, visited);
        }
        Expr::UnaryOp(_, i) | Expr::Load(i) => collect_var_reads_inner(*i, vars, reads, visited),
        Expr::Phi(inputs) => { for i in inputs { collect_var_reads_inner(*i, vars, reads, visited); } }
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

fn is_esp_derived(vn: &pcode_ir::Varnode, expr: &Expr, vars: &[VarDef]) -> bool {
    if vn.space == AddressSpaceId::Register && vn.offset == ESP_OFFSET && vn.size == 4 { return true; }
    match expr {
        Expr::Var(id) | Expr::BinOp(_, id, _) => {
            let v = &vars[id.0 as usize];
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == ESP_OFFSET && v.varnode.size == 4
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
            let dominated_by_flags = is_flag_derived(*cond, ssa);
            // A comparison is only "already recovered" if its operands are NOT flags
            let already_comparison = if let Expr::BinOp(k, l, r) = &vdef.expr {
                is_comparison(*k) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa)
            } else { false };
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

    // If already a comparison with non-flag operands, use it
    if let Expr::BinOp(kind, l, r) = &vdef.expr {
        if is_comparison(*kind) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
            return Some(cond_id);
        }
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
    let cmp_result = find_cmp_operands(block_idx, ssa)
        // Fallback: trace through the condition's SSA expression tree directly.
        // Flag assignments may have been eliminated by dead code elimination,
        // but the VarIds still exist. Trace from the condition variable through
        // its expression tree to find the underlying CMP/TEST operands.
        .or_else(|| trace_cond_to_cmp(cond_id, ssa, 8));
    let (cmp_left, cmp_right) = cmp_result?;

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

    // Fallback: check if it's a simple flag with a direct comparison expr (non-flag operands)
    let vdef = &ssa.vars[cond_id.0 as usize];
    if let Expr::Var(inner_id) = &vdef.expr {
        let inner = &ssa.vars[inner_id.0 as usize];
        if let Expr::BinOp(kind, l, r) = &inner.expr {
            if is_comparison(*kind) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
                return Some(*inner_id);
            }
        }
    }
    if let Expr::BinOp(kind, l, r) = &vdef.expr {
        if is_comparison(*kind) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
            return Some(cond_id);
        }
    }

    None
}

/// Trace the condition variable's SSA expression tree to find CMP/TEST operands.
/// This handles the case where flag assignments have been inlined/eliminated by
/// earlier fold passes but the VarIds still exist.
fn trace_cond_to_cmp(cond_id: VarId, ssa: &SsaCfg, depth: u32) -> Option<(VarId, VarId)> {
    if depth == 0 { return None; }
    let vdef = &ssa.vars[cond_id.0 as usize];
    match &vdef.expr {
        // SF = IntSLess(result, 0)
        Expr::BinOp(BinOpKind::SLess, result_id, zero_id) => {
            let zero = &ssa.vars[zero_id.0 as usize];
            if matches!(&zero.expr, Expr::Const(0, _)) {
                return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
            }
            None
        }
        // CF = Carry/Less(left, right)
        Expr::BinOp(BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow
            | BinOpKind::Less, left, right) => {
            Some((*left, *right))
        }
        // BoolNot(inner) → trace inner
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) => trace_cond_to_cmp(*inner, ssa, depth - 1),
        // Var(inner) → follow
        Expr::Var(inner) => trace_cond_to_cmp(*inner, ssa, depth - 1),
        // Compound: BoolAnd/BoolOr → trace both sides for CMP operands
        Expr::BinOp(BinOpKind::BoolAnd | BinOpKind::BoolOr, left, right) => {
            trace_cond_to_cmp(*left, ssa, depth - 1)
                .or_else(|| trace_cond_to_cmp(*right, ssa, depth - 1))
        }
        // Eq/NotEq: could be ZF=IntEq(result,0) or IntEq(OF,SF)
        Expr::BinOp(BinOpKind::Eq | BinOpKind::NotEq, left, right) => {
            // Check if right is Const(0) — this is ZF = IntEq(result, 0)
            let rdef = &ssa.vars[right.0 as usize];
            if matches!(&rdef.expr, Expr::Const(0, _)) {
                if let Some(result) = trace_to_cmp_with_zero(*left, ssa, Some(*right)) {
                    return Some(result);
                }
                // Can't trace further — use (result, 0) directly.
                // This handles TEST of computed values like IDIV remainder.
                return Some((*left, *right));
            }
            // Otherwise trace through (e.g., IntEq(OF, SF) for JGE)
            trace_cond_to_cmp(*left, ssa, depth - 1)
                .or_else(|| trace_cond_to_cmp(*right, ssa, depth - 1))
        }
        _ => None,
    }
}

/// Find the CMP/SUB/TEST operands by tracing from the flag definitions.
/// Searches the specified block first, then all blocks as fallback.
fn find_cmp_operands(block_idx: usize, ssa: &SsaCfg) -> Option<(VarId, VarId)> {
    // Try the specified block first
    if let Some(result) = find_cmp_in_block(block_idx, ssa) {
        return Some(result);
    }
    // Fallback: search all blocks (for cases where the CMP is in a predecessor)
    for bi in (0..ssa.blocks.len()).rev() {
        if bi == block_idx { continue; }
        if let Some(result) = find_cmp_in_block(bi, ssa) {
            return Some(result);
        }
    }
    None
}

fn find_cmp_in_block(block_idx: usize, ssa: &SsaCfg) -> Option<(VarId, VarId)> {
    let block = &ssa.blocks[block_idx];
    for stmt in block.stmts.iter().rev() {
        if let Stmt::Assign(vid) = stmt {
            let v = &ssa.vars[vid.0 as usize];
            // ZF = IntEq(sub_result, 0)
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 518 {
                if let Expr::BinOp(BinOpKind::Eq, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            // SF = IntSLess(result, 0)
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 519 {
                if let Expr::BinOp(BinOpKind::SLess, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            // CF/OF (x86) or CY/OV (ARM64) — trace operands directly
            if v.varnode.space == AddressSpaceId::Register
                && matches!(v.varnode.offset, 512 | 523 | 258 | 259 | 261 | 262)
            {
                if let Expr::BinOp(BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow
                    | BinOpKind::Less, left, right) = &v.expr
                {
                    return Some((*left, *right));
                }
            }
            // ARM64: NG/ZR from tmp flag writes
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 257 { // ZR (ARM64)
                if let Expr::BinOp(BinOpKind::Eq, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 256 { // NG (ARM64)
                if let Expr::BinOp(BinOpKind::SLess, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
        }
    }
    None
}

/// Trace a SUB/AND/NEG result variable back to find the CMP operands.
/// Uses zero_id for IntNeg(x) → (0, x) and TEST same-register → (x, 0).
fn trace_to_cmp_with_zero(result_id: VarId, ssa: &SsaCfg, zero_id: Option<VarId>) -> Option<(VarId, VarId)> {
    let v = &ssa.vars[result_id.0 as usize];
    match &v.expr {
        Expr::BinOp(BinOpKind::Sub, left, right) => {
            Some((resolve_cmp_operand(*left, ssa), resolve_cmp_operand(*right, ssa)))
        }
        Expr::BinOp(BinOpKind::And, left, right) => {
            // TEST a, b → AND(a, b). ZF = (a & b == 0).
            // When both operands are the same (TEST a, a), compare a against 0.
            // When different, compare (a & b) result against 0.
            let l = resolve_cmp_operand(*left, ssa);
            let r = resolve_cmp_operand(*right, ssa);
            if let Some(z) = zero_id {
                // For TEST: compare the operand (or result) against zero
                if ssa.vars[l.0 as usize].varnode == ssa.vars[r.0 as usize].varnode {
                    Some((l, z))
                } else {
                    // Different operands: use the result itself vs zero
                    Some((result_id, z))
                }
            } else {
                Some((l, r))
            }
        }
        // IntNeg(x) is equivalent to Sub(0, x)
        Expr::UnaryOp(UnaryOpKind::Neg, inner) => {
            if let Some(z) = zero_id {
                Some((z, resolve_cmp_operand(*inner, ssa)))
            } else {
                None
            }
        }
        Expr::Var(inner) => trace_to_cmp_with_zero(*inner, ssa, zero_id),
        _ => None,
    }
}

/// Resolve a CMP operand through register copies to find the underlying value.
/// REG = Var(other_reg) → follow; REG = Load(stack) → use the Load.
fn resolve_cmp_operand(id: VarId, ssa: &SsaCfg) -> VarId {
    resolve_cmp_operand_depth(id, ssa, 8)
}

fn resolve_cmp_operand_depth(id: VarId, ssa: &SsaCfg, depth: u32) -> VarId {
    if depth == 0 { return id; }
    let v = &ssa.vars[id.0 as usize];
    // Follow register-to-register copies
    if v.varnode.space == AddressSpaceId::Register {
        if let Expr::Var(src) = &v.expr {
            let sv = &ssa.vars[src.0 as usize];
            // If source is a stack Load or has a param name, prefer it
            if matches!(&sv.expr, Expr::Load(_)) || sv.param_name.is_some() {
                return *src;
            }
            // If source is another register, follow one more level
            if sv.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(inner) = &sv.expr {
                    let iv = &ssa.vars[inner.0 as usize];
                    if matches!(&iv.expr, Expr::Load(_)) || iv.param_name.is_some() {
                        return *inner;
                    }
                }
                if let Expr::Load(_) = &sv.expr { return *src; }
            }
            return *src;
        }
        if let Expr::Load(_) = &v.expr { return id; }
    }
    // Follow Unique space vars
    if v.varnode.space == AddressSpaceId::Unique {
        if let Expr::Var(src) = &v.expr {
            return resolve_cmp_operand_depth(*src, ssa, depth - 1);
        }
    }
    id
}

/// Classify a Jcc condition expression into a comparison kind.
/// Returns (comparison_kind, swap_operands).
/// swap_operands=true means use (right, left) instead of (left, right) from CMP.
fn classify_jcc_condition(cond_id: VarId, ssa: &SsaCfg) -> Option<(BinOpKind, bool)> {
    let vdef = &ssa.vars[cond_id.0 as usize];

    // General BoolNot unwrapping: !cond → invert the inner condition
    if let Expr::UnaryOp(UnaryOpKind::BoolNot, inner) = &vdef.expr {
        if let Some((kind, swap)) = classify_jcc_condition(*inner, ssa) {
            let inverted = match kind {
                BinOpKind::Eq => BinOpKind::NotEq,
                BinOpKind::NotEq => BinOpKind::Eq,
                BinOpKind::Less => BinOpKind::LessEq,   // !(a < b) = a >= b = b <= a
                BinOpKind::LessEq => BinOpKind::Less,    // !(a <= b) = a > b = b < a
                BinOpKind::SLess => BinOpKind::SLessEq,  // !(a < b) = a >= b = b <= a
                BinOpKind::SLessEq => BinOpKind::SLess,  // !(a <= b) = a > b = b < a
                _ => return None,
            };
            // Invert: !(a < b) = b <= a, so swap stays the same but the kind flips.
            // But !(a < b) = a >= b = b <= a. With swap, the operands are already swapped.
            // We need: invert the comparison and flip swap.
            return Some((inverted, !swap));
        }
    }

    // Helper: check ZF (x86=518) or ZR (ARM64=257)
    let is_zf = |id: VarId| is_flag_ref(id, 518, ssa) || is_flag_ref(id, 257, ssa);
    // Helper: check CF (x86=512) or CY (ARM64=258)
    let is_cf = |id: VarId| is_flag_ref(id, 512, ssa) || is_flag_ref(id, 258, ssa);
    // Helper: check OF (x86=523) or OV (ARM64=259)
    let is_of = |id: VarId| is_flag_ref(id, 523, ssa) || is_flag_ref(id, 259, ssa);
    // Helper: check SF (x86=519) or NG (ARM64=256)
    let is_sf = |id: VarId| is_flag_ref(id, 519, ssa) || is_flag_ref(id, 256, ssa);

    match &vdef.expr {
        // ZF/ZR directly → JE/BEQ → a == b
        _ if is_zf(cond_id) => Some((BinOpKind::Eq, false)),

        // BoolNot(ZF/ZR) → JNE/BNE → a != b
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner) => {
            Some((BinOpKind::NotEq, false))
        }

        // CF/CY directly → JB/BLO → a < b (unsigned)
        _ if is_cf(cond_id) => Some((BinOpKind::Less, false)),

        // BoolNot(CF/CY) → JAE/BHS → a >= b (unsigned) = b <= a
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_cf(*inner) => {
            Some((BinOpKind::LessEq, true))
        }

        // IntEq(OF, SF) or IntEq(OV, NG) → JGE/BGE → a >= b (signed) = b <= a
        Expr::BinOp(BinOpKind::Eq, left, right)
            if (is_of(*left) && is_sf(*right)) || (is_sf(*left) && is_of(*right)) =>
        {
            Some((BinOpKind::SLessEq, true))
        }

        // NotEq(OF, SF) or NotEq(SBORROW, SLess) → JL → a < b (signed)
        Expr::BinOp(BinOpKind::NotEq, left, right)
            if (is_of(*left) && is_sf(*right)) || (is_sf(*left) && is_of(*right)) =>
        {
            Some((BinOpKind::SLess, false))
        }

        // SF/NG directly → JL/BLT → a < b (signed)
        _ if is_sf(cond_id) => {
            Some((BinOpKind::SLess, false))
        }

        // BoolOr(CF, ZF) → JBE → a <= b (unsigned)
        Expr::BinOp(BinOpKind::BoolOr, left, right)
            if (is_cf(*left) && is_zf(*right)) || (is_zf(*left) && is_cf(*right)) =>
        {
            Some((BinOpKind::LessEq, false))
        }

        // BoolOr(ZF, NotEq(OF, SF)) → JLE → a <= b (signed)
        Expr::BinOp(BinOpKind::BoolOr, left, right) => {
            let left_def = &ssa.vars[left.0 as usize];
            let right_def = &ssa.vars[right.0 as usize];
            // ZF || (OF != SF) → JLE
            let zf_or_sfneqof =
                (is_zf(*left) && matches!(&right_def.expr,
                    Expr::BinOp(BinOpKind::NotEq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b))))
                || (is_zf(*right) && matches!(&left_def.expr,
                    Expr::BinOp(BinOpKind::NotEq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b))));
            if zf_or_sfneqof {
                Some((BinOpKind::SLessEq, false))
            } else {
                None
            }
        }

        // BoolAnd(BoolNot(ZF/ZR), IntEq(OF/OV, SF/NG)) → JG/BGT → a > b = b < a
        Expr::BinOp(BinOpKind::BoolAnd, left, right) => {
            let left_def = &ssa.vars[left.0 as usize];
            let right_def = &ssa.vars[right.0 as usize];

            let left_is_not_zf = matches!(&left_def.expr,
                Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));
            let right_is_sf_eq_of = matches!(&right_def.expr,
                Expr::BinOp(BinOpKind::Eq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b)));

            if left_is_not_zf && right_is_sf_eq_of {
                Some((BinOpKind::SLess, true)) // JG/BGT: a > b = b < a
            } else {
                let left_is_not_cf = matches!(&left_def.expr,
                    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_cf(*inner));
                let right_is_not_zf = matches!(&right_def.expr,
                    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));

                if left_is_not_cf && right_is_not_zf {
                    Some((BinOpKind::Less, true)) // JA/BHI: unsigned b < a
                } else if left_is_not_zf {
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
    // Also check x86-32 EAX (offset 0, size 4) and ARM64 x0/w0 (offset 0)
    let ret_reg_offset = RAX_OFFSET;

    for bi in 0..ssa.blocks.len() {
        if let SsaTerminator::Return(ref ret_val) = ssa.blocks[bi].terminator {
            if ret_val.is_some() { continue; }
        } else { continue; }

        // Look backwards in this block for RAX/EAX assignment
        let mut found = None;
        for stmt in ssa.blocks[bi].stmts.iter().rev() {
            if let Stmt::Assign(var_id) = stmt {
                let vdef = &ssa.vars[var_id.0 as usize];
                if vdef.varnode.space == AddressSpaceId::Register
                    && vdef.varnode.offset == ret_reg_offset
                    && vdef.varnode.size >= 4
                {
                    found = Some(*var_id);
                    break;
                }
            }
        }

        // If not found in this block, check predecessors (handles CMOV patterns
        // where the return register was set in a preceding conditional block)
        if found.is_none() {
            for pred_bi in 0..ssa.blocks.len() {
                if pred_bi == bi { continue; }
                let flows_to_bi = match &ssa.blocks[pred_bi].terminator {
                    SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) => b.0 == bi,
                    SsaTerminator::CBranch { taken, fallthrough, .. } => taken.0 == bi || fallthrough.0 == bi,
                    SsaTerminator::Call { fallthrough, .. } => fallthrough.0 == bi,
                    _ => false,
                };
                if !flows_to_bi { continue; }

                for stmt in ssa.blocks[pred_bi].stmts.iter().rev() {
                    if let Stmt::Assign(var_id) = stmt {
                        let vdef = &ssa.vars[var_id.0 as usize];
                        if vdef.varnode.space == AddressSpaceId::Register
                            && vdef.varnode.offset == ret_reg_offset
                            && vdef.varnode.size >= 4
                        {
                            found = Some(*var_id);
                            break;
                        }
                    }
                }
                if found.is_some() { break; }
            }
        }

        if let Some(var_id) = found {
            if let SsaTerminator::Return(ref mut ret_val) = ssa.blocks[bi].terminator {
                *ret_val = Some(var_id);
            }
        }
    }
}

// ---- Call Arguments ----

/// Collect argument register writes (x86-64) or stack pushes (x86-32) before each Call.
/// For x86-32, also removes consumed Store/ESP-decrement statements.
fn collect_call_arguments(ssa: &mut SsaCfg) {
    // Use the calling convention set by fold_with_cc, not heuristic detection.
    let is_x86_32 = arg_reg_offsets().is_empty();

    for bi in 0..ssa.blocks.len() {
        // Collect all indices to remove for this block (from multiple calls)
        let mut all_consumed: Vec<usize> = Vec::new();

        // Check if block ends with a Call terminator
        let call_info = match &ssa.blocks[bi].terminator {
            SsaTerminator::Call { target, fallthrough, .. } => {
                Some((target.clone(), *fallthrough))
            }
            _ => None,
        };

        if let Some((target, fallthrough)) = call_info {
            let n_stmts = ssa.blocks[bi].stmts.len();
            let args = if is_x86_32 {
                let (args, consumed) = collect_stack_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, n_stmts);
                if !args.is_empty() { all_consumed.extend(consumed); }
                args
            } else {
                collect_reg_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, n_stmts)
            };

            if !args.is_empty() {
                ssa.blocks[bi].terminator = SsaTerminator::Call {
                    target,
                    args,
                    fallthrough,
                };
            }
        }

        // Also check for Call statements within the block
        // Process in reverse order so consumed indices from earlier calls don't shift
        let call_indices: Vec<usize> = (0..ssa.blocks[bi].stmts.len())
            .filter(|si| matches!(&ssa.blocks[bi].stmts[*si],
                Stmt::Call { args, .. } if args.is_empty()))
            .collect();

        for &si in call_indices.iter().rev() {
            let args = if is_x86_32 {
                let (args, consumed) = collect_stack_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, si);
                if !args.is_empty() { all_consumed.extend(consumed); }
                args
            } else {
                collect_reg_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, si)
            };

            if !args.is_empty() {
                if let Stmt::Call { target, out, .. } = &ssa.blocks[bi].stmts[si] {
                    let target = target.clone();
                    let out = *out;
                    ssa.blocks[bi].stmts[si] = Stmt::Call { target, args, out };
                }
            }
        }

        // Remove consumed arg Store + ESP-decrement statements (reverse order for stable indices)
        all_consumed.sort_unstable();
        all_consumed.dedup();
        for &i in all_consumed.iter().rev() {
            if i < ssa.blocks[bi].stmts.len() {
                ssa.blocks[bi].stmts.remove(i);
            }
        }
    }
}

/// Collect x86-64 register-based arguments before a call (original logic).
fn collect_reg_args_from_block(stmts: &[Stmt], vars: &[VarDef], up_to: usize) -> Vec<VarId> {
    let arg_offsets = arg_reg_offsets();
    if arg_offsets.is_empty() { return Vec::new(); }
    let mut args: Vec<(u64, VarId)> = Vec::new();
    for j in (0..up_to).rev() {
        if let Stmt::Assign(var_id) = &stmts[j] {
            let vdef = safe_var(vars, *var_id);
            if vdef.varnode.space == AddressSpaceId::Register
                && arg_offsets.contains(&vdef.varnode.offset)
            {
                if !args.iter().any(|(off, _)| *off == vdef.varnode.offset) {
                    args.push((vdef.varnode.offset, *var_id));
                }
            }
        }
        if matches!(&stmts[j], Stmt::Call { .. }) { break; }
    }
    args.sort_by_key(|(off, _)| {
        arg_reg_offsets().iter().position(|o| o == off).unwrap_or(99)
    });
    args.into_iter().map(|(_, v)| v).collect()
}

/// Collect x86-32 stack-pushed arguments before a call.
///
/// Scans backward from `up_to` for Store { addr: ESP-derived, val } patterns.
/// Arguments are pushed right-to-left (cdecl), so first push = last arg.
/// Returns (args in correct call order, indices of consumed statements to remove).
fn collect_stack_args_from_block(stmts: &[Stmt], vars: &[VarDef], up_to: usize) -> (Vec<VarId>, Vec<usize>) {
    let mut pushed_values: Vec<VarId> = Vec::new();
    let mut consumed_indices: Vec<usize> = Vec::new();
    let mut i = up_to;

    while i > 0 {
        i -= 1;
        match &stmts[i] {
            Stmt::Store { addr, val } => {
                let addr_def = &vars[addr.0 as usize];
                if is_esp_var(addr_def, vars) {
                    pushed_values.push(*val);
                    consumed_indices.push(i);
                    continue;
                }
                // Non-ESP store — could be a memory write between pushes, skip
                continue;
            }
            Stmt::Assign(v) => {
                let vdef = &vars[v.0 as usize];
                // Skip (and mark for removal) ESP writes (IntSub ESP, 4) — PUSH boilerplate
                if vdef.varnode.space == AddressSpaceId::Register
                    && vdef.varnode.offset == ESP_OFFSET
                    && vdef.varnode.size == 4
                {
                    consumed_indices.push(i);
                    continue;
                }
                // Skip flag writes
                if FLAG_OFFSETS.contains(&vdef.varnode.offset) {
                    continue;
                }
                // Skip Unique-space temporaries (address computation, etc.)
                if vdef.varnode.space == AddressSpaceId::Unique {
                    consumed_indices.push(i);
                    continue;
                }
                // Other register writes between pushes — these could be thiscall
                // ECX setup or general register preparation. Stop scanning.
                break;
            }
            Stmt::Call { .. } => break, // Previous call — stop
        }
    }

    // Arguments pushed right-to-left: first pushed = last argument
    // We collected bottom-up, so reverse for correct order
    pushed_values.reverse();
    (pushed_values, consumed_indices)
}

/// Check if a VarDef is ESP-derived (direct ESP or computed from ESP via IntSub).
fn is_esp_var(vdef: &VarDef, vars: &[VarDef]) -> bool {
    if vdef.varnode.space == AddressSpaceId::Register
        && vdef.varnode.offset == ESP_OFFSET
        && vdef.varnode.size == 4
    {
        return true;
    }
    // Check Unique-space vars that are computed from ESP
    if vdef.varnode.space == AddressSpaceId::Unique {
        match &vdef.expr {
            Expr::BinOp(BinOpKind::Sub, left, _) | Expr::BinOp(BinOpKind::Add, left, _) => {
                let left_def = &vars[left.0 as usize];
                return left_def.varnode.space == AddressSpaceId::Register
                    && left_def.varnode.offset == ESP_OFFSET
                    && left_def.varnode.size == 4;
            }
            Expr::Var(v) => {
                let inner = &vars[v.0 as usize];
                return inner.varnode.space == AddressSpaceId::Register
                    && inner.varnode.offset == ESP_OFFSET
                    && inner.varnode.size == 4;
            }
            _ => {}
        }
    }
    false
}

// ---- Type inference ----

/// Infer types for all SSA variables from operation context.
///
/// Three phases:
/// 1. **Seed** — mark variables whose defining expression directly implies a type
///    (float ops, signed ops, comparisons, load/store addresses)
/// 2. **Forward propagation** — propagate types through Copy/Var chains and extensions
/// 3. **Backward propagation** — propagate types from uses (e.g., if a var is used in
///    SDiv, mark it signed even if its definition didn't imply it)
fn infer_types(ssa: &mut SsaCfg) {
    let n = ssa.vars.len();

    // Phase 1: Seed types from defining expressions
    for vi in 0..n {
        let ty = seed_type_from_expr(&ssa.vars[vi].expr, &ssa.vars);
        if ty != InferredType::Unknown {
            ssa.vars[vi].inferred_type = ty;
        }
    }

    // Mark Store addresses as pointers
    for bi in 0..ssa.blocks.len() {
        for stmt in &ssa.blocks[bi].stmts {
            if let Stmt::Store { addr, .. } = stmt {
                let cur = ssa.vars[addr.0 as usize].inferred_type;
                ssa.vars[addr.0 as usize].inferred_type = cur.merge(InferredType::Pointer);
            }
        }
    }

    // Mark Load pointer operands as pointers (from Expr::Load(ptr_var))
    for vi in 0..n {
        match ssa.vars[vi].expr {
            Expr::Load(ptr) => {
                let cur = ssa.vars[ptr.0 as usize].inferred_type;
                ssa.vars[ptr.0 as usize].inferred_type = cur.merge(InferredType::Pointer);
            }
            Expr::FieldAccess(base, _) => {
                let cur = ssa.vars[base.0 as usize].inferred_type;
                ssa.vars[base.0 as usize].inferred_type = cur.merge(InferredType::Pointer);
            }
            _ => {}
        }
    }

    // Phase 2: Forward propagation (2 rounds)
    for _ in 0..2 {
        for vi in 0..n {
            let expr = ssa.vars[vi].expr.clone();
            let propagated = forward_propagate_type(&expr, &ssa.vars);
            if propagated != InferredType::Unknown && ssa.vars[vi].inferred_type == InferredType::Unknown {
                ssa.vars[vi].inferred_type = propagated;
            }
        }
    }

    // Phase 3: Backward propagation — mark operands of typed operations
    for vi in 0..n {
        let ty = ssa.vars[vi].inferred_type;
        if ty == InferredType::Unknown { continue; }

        match ssa.vars[vi].expr.clone() {
            Expr::BinOp(_, left, right) => {
                backward_propagate(ssa, left, ty);
                backward_propagate(ssa, right, ty);
            }
            Expr::UnaryOp(_, input) => {
                // For Sext/Zext, the input inherits the signedness
                backward_propagate(ssa, input, ty);
            }
            Expr::Var(v) => {
                backward_propagate(ssa, v, ty);
            }
            _ => {}
        }
    }

    // Mark size-1 comparison results as Bool
    for vi in 0..n {
        if ssa.vars[vi].size == 1 {
            if let Expr::BinOp(kind, _, _) = &ssa.vars[vi].expr {
                match kind {
                    BinOpKind::Eq | BinOpKind::NotEq
                    | BinOpKind::Less | BinOpKind::LessEq
                    | BinOpKind::SLess | BinOpKind::SLessEq
                    | BinOpKind::FloatEq | BinOpKind::FloatNotEq
                    | BinOpKind::FloatLess | BinOpKind::FloatLessEq
                    | BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow
                    | BinOpKind::BoolAnd | BinOpKind::BoolOr | BinOpKind::BoolXor => {
                        ssa.vars[vi].inferred_type = InferredType::Bool;
                    }
                    _ => {}
                }
            }
            if let Expr::UnaryOp(UnaryOpKind::BoolNot | UnaryOpKind::FloatNan, _) = &ssa.vars[vi].expr {
                ssa.vars[vi].inferred_type = InferredType::Bool;
            }
        }
    }
}

/// Seed the type of a variable from its defining expression.
fn seed_type_from_expr(expr: &Expr, _vars: &[VarDef]) -> InferredType {
    match expr {
        // Float operations
        Expr::BinOp(kind, _, _) => match kind {
            BinOpKind::FloatAdd | BinOpKind::FloatSub
            | BinOpKind::FloatMult | BinOpKind::FloatDiv => InferredType::Float,
            BinOpKind::FloatEq | BinOpKind::FloatNotEq
            | BinOpKind::FloatLess | BinOpKind::FloatLessEq => InferredType::Bool,
            // Signed operations
            BinOpKind::SDiv | BinOpKind::SRem => InferredType::Signed,
            BinOpKind::SLess | BinOpKind::SLessEq => InferredType::Bool,
            // Unsigned operations
            BinOpKind::Div | BinOpKind::Rem => InferredType::Unsigned,
            BinOpKind::Less | BinOpKind::LessEq => InferredType::Bool,
            // Comparisons
            BinOpKind::Eq | BinOpKind::NotEq => InferredType::Bool,
            // Boolean logic
            BinOpKind::BoolAnd | BinOpKind::BoolOr | BinOpKind::BoolXor => InferredType::Bool,
            _ => InferredType::Unknown,
        },
        Expr::UnaryOp(kind, _) => match kind {
            // Float unary ops
            UnaryOpKind::FloatNeg | UnaryOpKind::FloatAbs | UnaryOpKind::FloatSqrt
            | UnaryOpKind::FloatCeil | UnaryOpKind::FloatFloor | UnaryOpKind::FloatRound
            | UnaryOpKind::Int2Float | UnaryOpKind::Float2Float => InferredType::Float,
            UnaryOpKind::FloatNan => InferredType::Bool,
            // Trunc: float→int
            UnaryOpKind::Trunc => InferredType::Signed,
            // Sign extension implies signed source
            UnaryOpKind::Sext | UnaryOpKind::Neg => InferredType::Signed,
            // Zero extension implies unsigned source
            UnaryOpKind::Zext => InferredType::Unsigned,
            // Arithmetic shift right implies signed
            // (mapped from IntAsr)
            UnaryOpKind::BoolNot => InferredType::Bool,
            _ => InferredType::Unknown,
        },
        _ => InferredType::Unknown,
    }
}

/// Propagate type forward from the defining expression's operands.
fn forward_propagate_type(expr: &Expr, vars: &[VarDef]) -> InferredType {
    match expr {
        // Copy/Var inherits the source type
        Expr::Var(v) => vars[v.0 as usize].inferred_type,
        // Arithmetic on floats produces float
        Expr::BinOp(BinOpKind::Add | BinOpKind::Sub | BinOpKind::Mult, left, right) => {
            let lt = vars[left.0 as usize].inferred_type;
            let rt = vars[right.0 as usize].inferred_type;
            if lt == InferredType::Float || rt == InferredType::Float {
                InferredType::Float
            } else if lt == InferredType::Signed || rt == InferredType::Signed {
                InferredType::Signed
            } else {
                InferredType::Unknown
            }
        }
        // Sext preserves signed, Zext preserves unsigned
        Expr::UnaryOp(UnaryOpKind::Sext, input) => {
            let it = vars[input.0 as usize].inferred_type;
            if it == InferredType::Unknown { InferredType::Signed } else { it }
        }
        Expr::UnaryOp(UnaryOpKind::Zext, input) => {
            let it = vars[input.0 as usize].inferred_type;
            if it == InferredType::Unknown { InferredType::Unsigned } else { it }
        }
        // Neg implies signed result
        Expr::UnaryOp(UnaryOpKind::Neg, _) => InferredType::Signed,
        // Load result: unknown (the pointee type isn't known without more analysis)
        _ => InferredType::Unknown,
    }
}

/// Backward-propagate a type to an operand variable (if it's still Unknown).
fn backward_propagate(ssa: &mut SsaCfg, var: VarId, ty: InferredType) {
    let cur = ssa.vars[var.0 as usize].inferred_type;
    if cur == InferredType::Unknown {
        // Don't propagate Bool backward (comparisons don't make operands bool)
        // Don't propagate Pointer backward (pointer arithmetic doesn't make operands pointers)
        match ty {
            InferredType::Signed | InferredType::Float => {
                ssa.vars[var.0 as usize].inferred_type = ty;
            }
            _ => {}
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
            Expr::UnaryOp(_, i) | Expr::Load(i) | Expr::FieldAccess(i, _) => use_counts[i.0 as usize] += 1,
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

// ---- Pass: Save/Restore Elimination ----
// Detect the pattern:  A = X; [call]; Y = A
// ---- Pass: Forward Substitution Within Blocks ----
// Scan each block linearly. Track what each register currently holds (its
// "value" — a VarId pointing to the original source). When a register is
// read, substitute the source. This is safe because we only look within
// one block and we invalidate on any write.
//
// Example: EAX = var_8; var_c = EAX → var_c = var_8 (because EAX holds var_8)
//          Later: EAX = var_c → EAX = var_8 (because var_c holds var_8)

#[allow(dead_code)]
fn forward_substitute_block(ssa: &mut SsaCfg) {
    for bi in 0..ssa.blocks.len() {
        // Map: (register offset, size) → the VarId of the value it currently holds
        let mut reg_value: std::collections::HashMap<(u64, u32), VarId> = std::collections::HashMap::new();
        // Map: VarId (stack/unique) → the VarId of its source value
        let mut alias_map: std::collections::HashMap<u32, VarId> = std::collections::HashMap::new();

        let stmts = &ssa.blocks[bi].stmts;
        let mut replacements: Vec<(u32, Expr)> = Vec::new();

        for stmt in stmts {
            match stmt {
                Stmt::Assign(var_id) => {
                    let vdef = &ssa.vars[var_id.0 as usize];

                    if vdef.varnode.space == AddressSpaceId::Register {
                        match &vdef.expr {
                            // REG = Var(src) — register gets a new value
                            Expr::Var(src_id) => {
                                let src = &ssa.vars[src_id.0 as usize];
                                if src.varnode.space == AddressSpaceId::Register {
                                    // REG = OTHER_REG: look up what OTHER_REG holds
                                    let key = (src.varnode.offset, src.varnode.size);
                                    if let Some(original) = reg_value.get(&key) {
                                        // Substitute: instead of REG = OTHER_REG,
                                        // use REG = original_source
                                        replacements.push((var_id.0, Expr::Var(*original)));
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *original);
                                    } else {
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *src_id);
                                    }
                                } else {
                                    // REG = stack_var/unique: look up what the stack var holds
                                    if let Some(original) = alias_map.get(&src_id.0) {
                                        replacements.push((var_id.0, Expr::Var(*original)));
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *original);
                                    } else {
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *src_id);
                                    }
                                }
                            }
                            Expr::Load(_) => {
                                // REG = Load(addr) — register gets a loaded value
                                // Invalidate this register's tracked value
                                let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                reg_value.remove(&my_key);
                            }
                            _ => {
                                // REG = expr — register gets a computed value
                                let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                reg_value.remove(&my_key);
                            }
                        }
                    } else {
                        // Non-register assignment (stack var, unique)
                        // Track what it holds for later substitution
                        if let Expr::Var(src_id) = &vdef.expr {
                            let src = &ssa.vars[src_id.0 as usize];
                            if src.varnode.space == AddressSpaceId::Register {
                                let key = (src.varnode.offset, src.varnode.size);
                                if let Some(original) = reg_value.get(&key) {
                                    // stack_var = REG where REG holds original
                                    // → stack_var = original
                                    replacements.push((var_id.0, Expr::Var(*original)));
                                    alias_map.insert(var_id.0, *original);
                                } else {
                                    alias_map.insert(var_id.0, *src_id);
                                }
                            }
                        }
                    }
                }
                Stmt::Store { .. } => {
                    // Stores don't affect register tracking
                }
                Stmt::Call { .. } => {
                    // Calls invalidate ALL register values (callee may clobber)
                    reg_value.clear();
                }
            }
        }

        // Also invalidate on Call terminators
        if matches!(&ssa.blocks[bi].terminator, SsaTerminator::Call { .. }) {
            // Already handled — reg_value would be cleared if we had more stmts
        }

        // Apply replacements
        for (var_idx, new_expr) in replacements {
            ssa.vars[var_idx as usize].expr = new_expr;
        }
    }
}

// where A is a stack variable used only for the save+restore.
// Replace Y's expression with X directly, eliminating the roundtrip.
// Also: A = X; ... ; B = A where B has same register as X → B = X

#[allow(dead_code)]
fn eliminate_save_restore(ssa: &mut SsaCfg) {
    // First: look for the specific pattern REG = stack_var where
    // stack_var.expr = Var(same_REG) — this is a restore.
    // Replace the restore's expr to point directly at the original register value.
    for v in 0..ssa.vars.len() {
        let vdef = &ssa.vars[v];
        if vdef.varnode.space != AddressSpaceId::Register { continue; }
        // Is this REG = Var(stack_var)?
        let src_id = match &vdef.expr {
            Expr::Var(id) => Some(*id),
            _ => None,
        };
        let Some(src_id) = src_id else { continue };
        let src = &ssa.vars[src_id.0 as usize];
        // Is the source a stack variable (stored to RBP-offset)?
        // In our SSA, stack vars have Unique space or are intermediate
        // Check if the source was defined as Var(original_reg) where original_reg
        // is the same register we're writing to
        if let Expr::Var(orig_id) = &src.expr {
            let orig = &ssa.vars[orig_id.0 as usize];
            if orig.varnode.space == AddressSpaceId::Register
                && orig.varnode.offset == vdef.varnode.offset
                && orig.varnode.size == vdef.varnode.size
            {
                // Save/restore detected: REG = X; stack = REG; ... ; REG = stack
                // Replace this var's expr with Var(orig_id) to skip the stack roundtrip
                // But we can't do it here because we'd need to modify ssa.vars while reading it.
                // Collect for later.
            }
        }
    }

    // Collect and apply save/restore eliminations (Var chains)
    let mut sr_replacements: Vec<(usize, VarId)> = Vec::new();
    for v in 0..ssa.vars.len() {
        let vdef = &ssa.vars[v];
        if vdef.varnode.space != AddressSpaceId::Register { continue; }
        if let Expr::Var(src_id) = &vdef.expr {
            let src = &ssa.vars[src_id.0 as usize];
            if let Expr::Var(orig_id) = &src.expr {
                let orig = &ssa.vars[orig_id.0 as usize];
                if orig.varnode.space == AddressSpaceId::Register
                    && orig.varnode.offset == vdef.varnode.offset
                    && orig.varnode.size == vdef.varnode.size
                    && src.use_count <= 2
                {
                    sr_replacements.push((v, *orig_id));
                }
            }
        }
    }
    // Disabled — too aggressive, eliminates legitimate assignments
    // for (v, orig_id) in &sr_replacements {
    //     ssa.vars[*v].expr = Expr::Var(*orig_id);
    // }

    // Memory save/restore: within each block, match Store(addr, reg_val)
    // followed by Load(same_addr) → same register. Only match within the
    // SAME block to avoid cross-block aliasing issues.
    for bi in 0..ssa.blocks.len() {
        let mut store_map: std::collections::HashMap<u64, VarId> = std::collections::HashMap::new();

        // Collect stores in this block
        for stmt in &ssa.blocks[bi].stmts {
            if let Stmt::Store { addr, val } = stmt {
                if let Some(offset) = compute_rbp_offset(*addr, &ssa.vars) {
                    let stored = &ssa.vars[val.0 as usize];
                    // Only track stores of register values (save patterns)
                    if stored.varnode.space == AddressSpaceId::Register {
                        store_map.insert(offset, *val);
                    }
                }
            }
        }

        if store_map.is_empty() { continue; }

        // Find Load assignments in this block that match a store
        let mut load_replacements: Vec<(u32, VarId)> = Vec::new();
        for stmt in &ssa.blocks[bi].stmts {
            if let Stmt::Assign(var_id) = stmt {
                let vdef = &ssa.vars[var_id.0 as usize];
                if vdef.varnode.space != AddressSpaceId::Register { continue; }
                if let Expr::Load(addr_id) = &vdef.expr {
                    if let Some(offset) = compute_rbp_offset(*addr_id, &ssa.vars) {
                        if let Some(stored_val) = store_map.get(&offset) {
                            let stored = &ssa.vars[stored_val.0 as usize];
                            // Only replace if stored value was the same register
                            if stored.varnode.offset == vdef.varnode.offset {
                                load_replacements.push((var_id.0, *stored_val));
                            }
                        }
                    }
                }
            }
        }
        // Disabled for now — needs more precise matching
        // for (var_idx, stored_val) in load_replacements {
        //     ssa.vars[var_idx as usize].expr = Expr::Var(stored_val);
        // }
    }
}

/// Compute the RBP-relative offset for an address var, if it's RBP + const.
#[allow(dead_code)]
fn compute_rbp_offset(addr_id: VarId, vars: &[VarDef]) -> Option<u64> {
    let v = &vars[addr_id.0 as usize];
    match &v.expr {
        Expr::BinOp(BinOpKind::Add, base_id, off_id) => {
            let base = &vars[base_id.0 as usize];
            if base.varnode.space == AddressSpaceId::Register && base.varnode.offset == 40 {
                // RBP + const
                if let Expr::Const(val, _) = &vars[off_id.0 as usize].expr {
                    return Some(*val);
                }
            }
            // One level of indirection on base
            if let Expr::Var(inner) = &base.expr {
                let inner_v = &vars[inner.0 as usize];
                if inner_v.varnode.space == AddressSpaceId::Register && inner_v.varnode.offset == 40 {
                    if let Expr::Const(val, _) = &vars[off_id.0 as usize].expr {
                        return Some(*val);
                    }
                }
            }
            None
        }
        Expr::Var(inner) => compute_rbp_offset(*inner, vars),
        _ => None,
    }
}

// ---- Pass: Return Value Propagation ----
// After a Call (terminator or statement), the first read of RAX/EAX (x86)
// or x0/w0 (ARM64) is the call's return value. Replace the assignment
// with a synthetic "call_return" expression so the printer can inline it.

fn propagate_call_returns(ssa: &mut SsaCfg) {
    for bi in 0..ssa.blocks.len() {
        // Check if this block has a Call terminator
        let has_call_term = matches!(&ssa.blocks[bi].terminator, SsaTerminator::Call { .. });

        // For Call terminators: the fallthrough block's first RAX assignment is the return value
        if has_call_term {
            let fallthrough = match &ssa.blocks[bi].terminator {
                SsaTerminator::Call { fallthrough, .. } => Some(*fallthrough),
                _ => None,
            };
            if let Some(ft) = fallthrough {
                if ft.0 < ssa.blocks.len() {
                    // Find the first RAX/EAX assignment in the fallthrough block
                    for stmt in &ssa.blocks[ft.0].stmts {
                        if let Stmt::Assign(var_id) = stmt {
                            let vdef = &ssa.vars[var_id.0 as usize];
                            if vdef.varnode.space == AddressSpaceId::Register
                                && (vdef.varnode.offset == RAX_OFFSET)
                                && matches!(&vdef.expr, Expr::Unknown)
                            {
                                ssa.vars[var_id.0 as usize].call_return = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // For Call statements within a block: the next RAX assignment is the return value
        let stmts = &ssa.blocks[bi].stmts;
        let mut after_call = false;
        for i in 0..stmts.len() {
            if matches!(&stmts[i], Stmt::Call { .. }) {
                after_call = true;
                continue;
            }
            if after_call {
                if let Stmt::Assign(var_id) = &stmts[i] {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RAX_OFFSET
                    {
                        ssa.vars[var_id.0 as usize].call_return = true;
                        after_call = false;
                    }
                }
            }
        }
    }
}

// ---- Pass: Copy Chain Collapse ----
// If A = B (register copy) and A is only used once in an expression,
// replace that use with B directly. This collapses:
//   EAX = var_8; var_c = EAX  →  var_c = var_8
//   ECX = EAX (after call)    →  ECX = call_return

#[allow(dead_code)]
fn collapse_copy_chains(ssa: &mut SsaCfg) {
    // Build a map: VarId → its Var(source) if it's a safe copy to collapse.
    // Only collapse register copies where the source is a stack variable (Unique load)
    // or constant — NOT register-to-register copies, since the source register
    // might be overwritten between the copy and the use.
    let copy_map: Vec<Option<VarId>> = (0..ssa.vars.len())
        .map(|v| {
            let vdef = &ssa.vars[v];
            if vdef.call_return { return None; }
            if vdef.use_count <= 1 && vdef.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(src) = &vdef.expr {
                    let src_def = &ssa.vars[src.0 as usize];
                    if src_def.call_return { return None; }
                    // Only collapse if source is a stack var, constant, or Unique
                    // (not another register that might get overwritten)
                    if src_def.varnode.space != AddressSpaceId::Register {
                        return Some(*src);
                    }
                    // Also collapse if source has a param name (stable identity)
                    if src_def.param_name.is_some() {
                        return Some(*src);
                    }
                }
            }
            None
        })
        .collect();

    // Substitute: for each var whose expr references a copy source, replace with the source
    for v in 0..ssa.vars.len() {
        let expr = ssa.vars[v].expr.clone();
        ssa.vars[v].expr = substitute_copies(&expr, &copy_map);
    }
}

#[allow(dead_code)]
fn substitute_copies(expr: &Expr, copy_map: &[Option<VarId>]) -> Expr {
    match expr {
        Expr::Var(id) => {
            if let Some(Some(src)) = copy_map.get(id.0 as usize) {
                // Follow the chain one level
                if let Some(Some(src2)) = copy_map.get(src.0 as usize) {
                    Expr::Var(*src2)
                } else {
                    Expr::Var(*src)
                }
            } else {
                expr.clone()
            }
        }
        Expr::BinOp(kind, left, right) => {
            let l = resolve_copy(*left, copy_map);
            let r = resolve_copy(*right, copy_map);
            Expr::BinOp(*kind, l, r)
        }
        Expr::UnaryOp(kind, input) => {
            let i = resolve_copy(*input, copy_map);
            Expr::UnaryOp(*kind, i)
        }
        Expr::Load(ptr) => {
            let p = resolve_copy(*ptr, copy_map);
            Expr::Load(p)
        }
        _ => expr.clone(),
    }
}

#[allow(dead_code)]
fn resolve_copy(id: VarId, copy_map: &[Option<VarId>]) -> VarId {
    if let Some(Some(src)) = copy_map.get(id.0 as usize) {
        if let Some(Some(src2)) = copy_map.get(src.0 as usize) {
            *src2
        } else {
            *src
        }
    } else {
        id
    }
}

// ---- Pass: Parameter Naming ----
// In the entry block, assignments from argument registers (RDI, RSI, etc.)
// to stack variables are parameter setup. Name them param_0, param_1, etc.

fn name_parameters(ssa: &mut SsaCfg) {
    if ssa.blocks.is_empty() { return; }
    let entry = ssa.entry.0;
    if entry >= ssa.blocks.len() { return; }

    let mut param_idx = 0u32;
    let mut named_offsets = std::collections::HashSet::new();
    let mut to_name: Vec<(usize, String, u64)> = Vec::new();

    // Pass 1: Collect params from Unknown expressions (unoptimized code)
    let stmts: Vec<Stmt> = ssa.blocks[entry].stmts.clone();
    for stmt in &stmts {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = &ssa.vars[var_id.0 as usize];
            if let Expr::Unknown = &vdef.expr {
                if vdef.varnode.space == AddressSpaceId::Register
                    && arg_reg_offsets().contains(&vdef.varnode.offset)
                    && !named_offsets.contains(&vdef.varnode.offset)
                {
                    to_name.push((var_id.0 as usize, format!("param_{}", param_idx), vdef.varnode.offset));
                    named_offsets.insert(vdef.varnode.offset);
                    param_idx += 1;
                }
            }
        }
        if let Stmt::Store { val, .. } = stmt {
            let vdef = &ssa.vars[val.0 as usize];
            if vdef.param_name.is_none() {
                if let Expr::Unknown = &vdef.expr {
                    if vdef.varnode.space == AddressSpaceId::Register
                        && arg_reg_offsets().contains(&vdef.varnode.offset)
                        && !named_offsets.contains(&vdef.varnode.offset)
                    {
                        to_name.push((val.0 as usize, format!("param_{}", param_idx), vdef.varnode.offset));
                        named_offsets.insert(vdef.varnode.offset);
                        param_idx += 1;
                    }
                }
            }
        }
    }
    for (v, name, _) in &to_name {
        ssa.vars[*v].param_name = Some(name.clone());
    }

    // Pass 2: For optimized code, also check for arg registers used as function inputs
    // that weren't marked Unknown. Scan ALL vars for arg register reads that have no
    // prior definition in the function (i.e., they come from the caller).
    if param_idx == 0 {
        let mut to_name: Vec<(usize, String)> = Vec::new();
        for &offset in arg_reg_offsets().iter() {
            if named_offsets.contains(&offset) { continue; }
            for v in 0..ssa.vars.len() {
                let vdef = &ssa.vars[v];
                if vdef.varnode.space == AddressSpaceId::Register
                    && vdef.varnode.offset == offset
                    && vdef.param_name.is_none()
                {
                    if matches!(&vdef.expr, Expr::Unknown | Expr::Phi(_)) {
                        to_name.push((v, format!("param_{}", param_idx)));
                        named_offsets.insert(offset);
                        param_idx += 1;
                        break;
                    }
                }
            }
        }
        for (v, name) in to_name {
            ssa.vars[v].param_name = Some(name);
        }
    }

    // Pass 3: x86-32 cdecl stack parameters from positive EBP offsets.
    // In cdecl with frame pointer: EBP+8 = param_0, EBP+12 = param_1, etc.
    // Scan all vars for Load(EBP + positive_offset) patterns.
    if arg_reg_offsets().is_empty() && param_idx == 0 {
        const EBP_OFFSET_32: u64 = 20;
        const RBP_OFFSET_64: u64 = 40;
        let mut ebp_params: std::collections::BTreeMap<u64, Vec<usize>> = std::collections::BTreeMap::new();

        for v in 0..ssa.vars.len() {
            let vdef = &ssa.vars[v];
            if vdef.param_name.is_some() { continue; }
            // Look for Load(ptr) where ptr is EBP/RBP + positive_const
            if let Expr::Load(ptr_id) = &vdef.expr {
                let ptr = &ssa.vars[ptr_id.0 as usize];
                if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &ptr.expr {
                    let base = &ssa.vars[base_id.0 as usize];
                    let off = &ssa.vars[off_id.0 as usize];
                    if base.varnode.space == AddressSpaceId::Register
                        && (base.varnode.offset == EBP_OFFSET_32 || base.varnode.offset == RBP_OFFSET_64)
                    {
                        if let Expr::Const(off_val, _) = &off.expr {
                            // EBP+8 = param_0, EBP+12 = param_1, ...
                            if *off_val >= 8 && *off_val < 0x80 && *off_val % 4 == 0 {
                                ebp_params.entry(*off_val).or_default().push(v);
                            }
                        }
                    }
                }
            }
        }

        // Name the detected parameters
        for (off_val, var_indices) in &ebp_params {
            let pidx = (off_val - 8) / 4;
            let name = format!("param_{}", pidx);
            for &vi in var_indices {
                if ssa.vars[vi].param_name.is_none() {
                    ssa.vars[vi].param_name = Some(name.clone());
                }
            }
        }
    }

    // Pass 4: x86-32 thiscall ECX detection.
    // In MSVC thiscall, ECX holds `this`. If ECX (offset 8, size 4) has Expr::Unknown
    // in the entry block, it's a parameter read without prior write.
    if arg_reg_offsets().is_empty() {
        const ECX_OFFSET: u64 = 8;
        let has_ecx_param = ssa.vars.iter().any(|v| v.param_name.as_deref() == Some("this"));
        if !has_ecx_param {
            for v in 0..ssa.vars.len() {
                let vdef = &ssa.vars[v];
                if vdef.varnode.space == AddressSpaceId::Register
                    && vdef.varnode.offset == ECX_OFFSET
                    && vdef.varnode.size == 4
                    && vdef.param_name.is_none()
                    && matches!(&vdef.expr, Expr::Unknown)
                    && vdef.use_count > 0
                {
                    ssa.vars[v].param_name = Some("this".to_string());
                    break;
                }
            }
        }
    }
}

/// Recognize struct field access patterns.
/// Converts Load(BinOp(Add, base, Const(offset))) → FieldAccess(base, offset)
/// when the base is a pointer (parameter, Load result, or another FieldAccess)
/// and the offset is a small aligned value typical of struct fields.
fn recognize_field_access(ssa: &mut SsaCfg) {
    // Collect pointer-typed variables: parameters, Load results, and anything
    // already typed as Pointer.
    let mut pointer_vars: std::collections::HashSet<VarId> = std::collections::HashSet::new();
    for v in &ssa.vars {
        if v.param_name.is_some() {
            pointer_vars.insert(v.id);
        }
        if v.inferred_type == InferredType::Pointer {
            pointer_vars.insert(v.id);
        }
        if matches!(&v.expr, Expr::Load(_)) {
            pointer_vars.insert(v.id);
        }
    }

    // Find Load(BinOp(Add, base, Const(offset))) patterns
    let mut replacements: Vec<(usize, VarId, u64)> = Vec::new();
    for v in 0..ssa.vars.len() {
        let vdef = &ssa.vars[v];
        if let Expr::Load(ptr_id) = &vdef.expr {
            let ptr_def = safe_var(&ssa.vars, *ptr_id);
            if let Expr::BinOp(BinOpKind::Add, base, offset_var) = &ptr_def.expr {
                let offset_def = safe_var(&ssa.vars, *offset_var);
                if let Expr::Const(offset_val, _) = &offset_def.expr {
                    // Only convert if:
                    // 1. Offset is non-zero (offset 0 is just a plain deref)
                    // 2. Offset is within reasonable struct size (< 4096 bytes)
                    // 3. Base looks like a pointer (parameter, load, or known pointer)
                    if *offset_val > 0 && *offset_val < 4096 {
                        let base_def = safe_var(&ssa.vars, *base);

                        // Skip stack frame accesses: EBP+offset in x86-32 is a parameter
                        // or local variable, not a struct field. EBP offset = 20, ESP offset = 28.
                        let is_stack_frame = base_def.varnode.space == AddressSpaceId::Register
                            && (base_def.varnode.offset == 20 || base_def.varnode.offset == 28)
                            && base_def.varnode.size == 4;
                        if is_stack_frame { continue; }

                        let base_is_pointer = pointer_vars.contains(base)
                            || base_def.param_name.is_some()
                            || matches!(&base_def.expr, Expr::Load(_) | Expr::FieldAccess(_, _))
                            || base_def.inferred_type == InferredType::Pointer;

                        // Also check if base is a register that was a parameter
                        let base_is_reg_param = base_def.varnode.space == AddressSpaceId::Register
                            && (base_def.param_name.is_some()
                                || matches!(&base_def.expr, Expr::Var(src) if safe_var(&ssa.vars, *src).param_name.is_some()));

                        if base_is_pointer || base_is_reg_param {
                            replacements.push((v, *base, *offset_val));
                        }
                    }
                }
            }
        }
    }

    for (var_idx, base, offset) in replacements {
        ssa.vars[var_idx].expr = Expr::FieldAccess(base, offset);
    }
}

/// Apply parameter names and types from the function signature database to call arguments.
///
/// For each call whose target resolves to a known function name (via `import_map`),
/// rename argument variables from generic "param_N" names to the signature's parameter names
/// and propagate parameter types when not already inferred.
pub fn apply_signature_names(ssa: &mut SsaCfg, import_map: &std::collections::HashMap<u64, String>) {
    // Collect (VarId, new_name, new_type) triples to apply after iteration.
    let mut renames: Vec<(VarId, String, InferredType)> = Vec::new();

    for block in &ssa.blocks {
        // Helper closure: given a call target and args, collect renames
        let mut process_call = |target: &CallTarget, args: &[VarId]| {
            let addr = match target {
                CallTarget::Direct(a) => *a,
                CallTarget::Indirect(_) => return,
            };
            let name = match import_map.get(&addr) {
                Some(n) => n.as_str(),
                None => return,
            };
            let sig = match crate::signatures::lookup(name) {
                Some(s) => s,
                None => return,
            };
            for (i, arg_id) in args.iter().enumerate() {
                if let Some(param) = sig.params.get(i) {
                    let var = &ssa.vars[arg_id.0 as usize];
                    // Only propagate type from signature — don't rename.
                    // Renaming via param_name would corrupt the function signature
                    // (the printer collects all vars with param_name for the sig line).
                    // Instead, the printer uses signatures::lookup() directly for
                    // call-site argument comments/naming.
                    let ty = param.ty.to_inferred();
                    if ty != InferredType::Unknown && var.inferred_type == InferredType::Unknown {
                        renames.push((*arg_id, String::new(), ty));
                    }
                }
            }
        };

        for stmt in &block.stmts {
            if let Stmt::Call { target, args, .. } = stmt {
                process_call(target, args);
            }
        }
        if let SsaTerminator::Call { target, args, .. } = &block.terminator {
            process_call(target, args);
        }
    }

    // Apply collected renames
    for (var_id, new_name, new_type) in renames {
        let var = &mut ssa.vars[var_id.0 as usize];
        if !new_name.is_empty() {
            var.param_name = Some(new_name);
            if var.inferred_type == InferredType::Unknown && new_type != InferredType::Unknown {
                var.inferred_type = new_type;
            }
        } else if new_type != InferredType::Unknown && var.inferred_type == InferredType::Unknown {
            var.inferred_type = new_type;
        }
    }
}

/// Propagate return types from the function signature database to call output variables.
///
/// For each call whose target resolves to a known function, set the return variable's
/// inferred type from the signature when not already inferred.
pub fn propagate_signature_return_types(ssa: &mut SsaCfg, import_map: &std::collections::HashMap<u64, String>) {
    let mut type_updates: Vec<(VarId, InferredType)> = Vec::new();

    for block in &ssa.blocks {
        // Stmt::Call with out variable
        for stmt in &block.stmts {
            if let Stmt::Call { target, out: Some(out_id), .. } = stmt {
                if let CallTarget::Direct(addr) = target {
                    if let Some(name) = import_map.get(addr) {
                        if let Some(sig) = crate::signatures::lookup(name) {
                            let ret_ty = sig.ret.to_inferred();
                            if ret_ty != InferredType::Unknown {
                                let var = &ssa.vars[out_id.0 as usize];
                                if var.inferred_type == InferredType::Unknown {
                                    type_updates.push((*out_id, ret_ty));
                                }
                            }
                        }
                    }
                }
            }
        }

        // SsaTerminator::Call — find call_return var in fallthrough block
        if let SsaTerminator::Call { target, fallthrough, .. } = &block.terminator {
            if let CallTarget::Direct(addr) = target {
                if let Some(name) = import_map.get(addr) {
                    if let Some(sig) = crate::signatures::lookup(name) {
                        let ret_ty = sig.ret.to_inferred();
                        if ret_ty != InferredType::Unknown {
                            // Find the first call_return var in the fallthrough block
                            let ft_idx = fallthrough.0;
                            if ft_idx < ssa.blocks.len() {
                                let ft_block = &ssa.blocks[ft_idx];
                                for stmt in &ft_block.stmts {
                                    if let Stmt::Assign(var_id) = stmt {
                                        let var = &ssa.vars[var_id.0 as usize];
                                        if var.call_return && var.inferred_type == InferredType::Unknown {
                                            type_updates.push((*var_id, ret_ty));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for (var_id, ty) in type_updates {
        ssa.vars[var_id.0 as usize].inferred_type = ty;
    }
}
