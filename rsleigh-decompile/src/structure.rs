use std::collections::HashSet;
use crate::ir::*;
use crate::dominators::{compute_dominators, compute_post_dominators};

/// Scan the statements of `block_id` for the first `call_return=true` var
/// with `use_count > 0`. SSA VarId uniqueness ensures each call_return var
/// appears in exactly one block, so a global consumed set is safe.
fn find_call_return_in_block(ssa: &SsaCfg, block_id: BlockId) -> Option<VarId> {
    if block_id.0 >= ssa.blocks.len() {
        return None;
    }
    for stmt in &ssa.blocks[block_id.0].stmts {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = ssa.var(*var_id);
            if vdef.call_return && vdef.use_count > 0 {
                return Some(*var_id);
            }
        }
    }
    None
}

/// Recover structured control flow from SSA CFG.
pub fn recover_structure(ssa: &SsaCfg, cfg: &Cfg) -> Vec<StructuredStmt> {
    if cfg.blocks.is_empty() {
        return vec![];
    }

    let dom = compute_dominators(cfg);
    let pdom = compute_post_dominators(cfg);

    // Identify back-edges (loop headers)
    let mut back_edges: Vec<(BlockId, BlockId)> = Vec::new(); // (source, target=header)
    for block in &cfg.blocks {
        for succ in cfg.successors(block.id) {
            if dominates(&dom, succ, block.id) {
                back_edges.push((block.id, succ));
            }
        }
    }

    let mut emitted = vec![false; cfg.blocks.len()];
    let mut result = Vec::new();
    let mut consumed: HashSet<VarId> = HashSet::new();

    emit_region(ssa, cfg, &dom, &pdom, &back_edges, cfg.entry,
                &mut emitted, &mut result, 0, None, &mut consumed);

    // Post-pass: convert if-else chains on the same variable into switch/case
    collapse_if_else_to_switch(&mut result, ssa);

    // Post-pass: flatten if-return patterns to reduce nesting
    // if (cond) { ...; return X; } else { REST } → if (cond) { ...; return X; } REST
    flatten_if_return(&mut result);

    // Post-pass: convert gotos to break/continue where possible
    eliminate_gotos(&mut result, ssa, cfg);

    result
}

/// Maximum recursion depth for structure recovery.
/// Prevents stack overflow on deeply nested or pathological CFGs.
const MAX_STRUCTURE_DEPTH: usize = 256;

/// Check if a statement list unconditionally returns (every path ends with Return).
/// If so, wrapping it in a do-while is misleading because the condition is dead code.
fn body_always_returns(stmts: &[StructuredStmt]) -> bool {
    match stmts.last() {
        Some(StructuredStmt::Return(_)) => true,
        Some(StructuredStmt::IfElse { then_body, else_body, .. }) => {
            body_always_returns(then_body) && body_always_returns(else_body)
        }
        _ => false,
    }
}

/// Context for loop-aware goto elimination.
/// Tracks the current loop header address and exit address.
struct LoopCtx {
    header_addr: u64,
    exit_addr: u64,
}

fn emit_region(
    ssa: &SsaCfg,
    cfg: &Cfg,
    dom: &[BlockId],
    pdom: &[BlockId],
    back_edges: &[(BlockId, BlockId)],
    start: BlockId,
    emitted: &mut Vec<bool>,
    out: &mut Vec<StructuredStmt>,
    depth: usize,
    _loop_ctx: Option<&LoopCtx>,
    consumed: &mut HashSet<VarId>,
) {
    if depth >= MAX_STRUCTURE_DEPTH {
        out.push(StructuredStmt::Goto(0)); // bail on too-deep nesting
        return;
    }
    let mut current = start;

    loop {
        if current.0 >= cfg.blocks.len() || emitted[current.0] {
            break;
        }
        emitted[current.0] = true;

        let block = &ssa.blocks[current.0];

        // Check if this block is a loop header
        let is_loop_header = back_edges.iter().any(|(_, header)| *header == current);

        // For self-loops (block branches back to itself), emit statements
        // INSIDE the while body, not before it.
        let is_self_loop = is_loop_header && match &block.terminator {
            SsaTerminator::CBranch { taken, fallthrough, .. } =>
                *taken == current || *fallthrough == current,
            _ => false,
        };

        if !is_self_loop {
            // Normal block: emit statements before control flow
            emit_block_stmts(block, out, consumed);
        }

        match &block.terminator {
            SsaTerminator::Return(ret_val) => {
                out.push(StructuredStmt::Return(*ret_val));
                break;
            }
            SsaTerminator::Fallthrough(next) | SsaTerminator::Branch(next) => {
                // Check if this fallthrough/call block is a loop header.
                if is_loop_header {
                    // Check if this is a do-while: header has no condition,
                    // the back-edge source has the condition (post-tested).
                    let back_source = back_edges.iter()
                        .find(|(_, header)| *header == current)
                        .map(|(src, _)| *src);

                    if let Some(back_src) = back_source {
                        if back_src.0 < ssa.blocks.len() {
                            // The back-edge source might be the CBranch block itself,
                            // or it might be a block that falls through to the CBranch.
                            // Check both the direct back-edge source and its successors.
                            let back_block = &ssa.blocks[back_src.0];
                            let latch_block = if matches!(&back_block.terminator, SsaTerminator::CBranch { .. }) {
                                Some(back_src)
                            } else if let SsaTerminator::Fallthrough(next) | SsaTerminator::Branch(next) = &back_block.terminator {
                                if matches!(&ssa.blocks[next.0].terminator, SsaTerminator::CBranch { .. }) {
                                    Some(*next)
                                } else { None }
                            } else { None };

                            if let Some(latch) = latch_block {
                            if let SsaTerminator::CBranch { cond, taken, fallthrough } = &ssa.blocks[latch.0].terminator {
                                // The back-edge goes to `current` (header).
                                // One branch goes to header (loop continues), the other exits.
                                let (exit, negate) = if *taken == current {
                                    (*fallthrough, false)
                                } else if *fallthrough == current {
                                    (*taken, true)
                                } else {
                                    // Not a clean do-while, fall through to regular handling
                                    (BlockId(0), false)
                                };

                                if (*taken == current || *fallthrough == current) && exit.0 < cfg.blocks.len() {
                                    // This IS a do-while pattern. Emit:
                                    // do { body } while (cond);
                                    let mut body = Vec::new();

                                    // Mark exit block as emitted to bound the loop body
                                    let exit_was_emitted = if exit.0 < emitted.len() { emitted[exit.0] } else { true };
                                    if exit.0 < emitted.len() { emitted[exit.0] = true; }

                                    // Mark back-edge source as emitted to prevent it
                                    // from being emitted inside the body twice
                                    let back_was_emitted = emitted[back_src.0];

                                    emit_region(ssa, cfg, dom, pdom, back_edges, *next, emitted, &mut body, depth + 1, None, consumed);

                                    // If the back-edge source wasn't emitted as part of the body,
                                    // emit its statements now (they're part of the loop body)
                                    if !back_was_emitted && !emitted[back_src.0] {
                                        emitted[back_src.0] = true;
                                        emit_block_stmts(&ssa.blocks[back_src.0], &mut body, consumed);
                                    }

                                    if exit.0 < emitted.len() { emitted[exit.0] = exit_was_emitted; }

                                    // If the body unconditionally returns, the while
                                    // condition is dead code — emit as straight-line.
                                    if body_always_returns(&body) {
                                        out.extend(body);
                                    } else {
                                        out.push(StructuredStmt::DoWhile {
                                            cond: *cond,
                                            negate,
                                            body,
                                        });
                                    }
                                    current = exit;
                                    continue;
                                }
                            }
                            }
                        }
                    }

                    // Not a do-while; try the existing while-with-condition-in-next-block pattern
                    let next_block = &ssa.blocks[next.0];
                    if let SsaTerminator::CBranch { cond, taken, fallthrough } = &next_block.terminator {
                        if !emitted[next.0] {
                            emitted[next.0] = true;
                            // Emit the next block's statements (e.g., the condition check)
                            emit_block_stmts(next_block, out, consumed);

                            let (body_start, exit, negate) = if can_reach(cfg, *taken, current, emitted)
                                || can_reach_limited(cfg, *taken, current, cfg.blocks.len())
                            {
                                (*taken, *fallthrough, false)
                            } else {
                                (*fallthrough, *taken, true)
                            };

                            let mut body = Vec::new();
                            let exit_was_emitted = emitted[exit.0];
                            emitted[exit.0] = true;
                            emit_region(ssa, cfg, dom, pdom, back_edges, body_start, emitted, &mut body, depth + 1, None, consumed);
                            emitted[exit.0] = exit_was_emitted;
                            out.push(StructuredStmt::While { cond: *cond, negate, body });
                            current = exit;
                            continue;
                        }
                    }
                }
                current = *next;
            }
            SsaTerminator::CBranch { cond, taken, fallthrough } => {
                // Check if this is a loop header
                if is_loop_header {
                    let back_source = back_edges.iter()
                        .find(|(_, header)| *header == current)
                        .map(|(src, _)| *src);

                    // Do-while detection: header terminator is CBranch
                    // (an inner conditional inside the loop body), the
                    // back-edge comes from a DIFFERENT CBranch block that
                    // tests loop exit. Emit body = header stmts + nested
                    // if-else from header's CBranch successors + latch
                    // stmts; cond = latch's CBranch.
                    if let Some(back_src) = back_source {
                        if back_src != current && back_src.0 < ssa.blocks.len() {
                            let latch = &ssa.blocks[back_src.0];
                            if let SsaTerminator::CBranch {
                                cond: latch_cond,
                                taken: latch_taken,
                                fallthrough: latch_fall,
                            } = &latch.terminator
                            {
                                let (exit, dw_negate) = if *latch_taken == current {
                                    (*latch_fall, false)
                                } else if *latch_fall == current {
                                    (*latch_taken, true)
                                } else {
                                    (BlockId(0), false)
                                };
                                if (*latch_taken == current || *latch_fall == current)
                                    && exit.0 < cfg.blocks.len()
                                {
                                    let mut body = Vec::new();
                                    // 1. Emit header block's statements.
                                    emit_block_stmts(&ssa.blocks[current.0], &mut body, consumed);
                                    // 2. Header's CBranch → nested if inside body.
                                    //    Protect exit + latch from recursion overrun.
                                    let exit_was_emitted = emitted[exit.0];
                                    emitted[exit.0] = true;
                                    let back_was_emitted = emitted[back_src.0];
                                    emitted[back_src.0] = true;
                                    // Post-dominator of header is latch (= back_src)
                                    // for this shape; protect it so recursion stops.
                                    let h_taken = *taken;
                                    let h_fall = *fallthrough;
                                    let h_cond = *cond;
                                    let merge = back_src;
                                    let mut then_body = Vec::new();
                                    let mut else_body = Vec::new();
                                    if h_taken != merge {
                                        emit_region(ssa, cfg, dom, pdom, back_edges,
                                                    h_taken, emitted, &mut then_body,
                                                    depth + 1, None, consumed);
                                    }
                                    if h_fall != merge {
                                        emit_region(ssa, cfg, dom, pdom, back_edges,
                                                    h_fall, emitted, &mut else_body,
                                                    depth + 1, None, consumed);
                                    }
                                    body.push(StructuredStmt::IfElse {
                                        cond: h_cond,
                                        then_body,
                                        else_body,
                                    });
                                    // 3. Emit latch's statements (its CBranch is the loop cond).
                                    if !back_was_emitted {
                                        emit_block_stmts(&ssa.blocks[back_src.0], &mut body, consumed);
                                    }
                                    emitted[exit.0] = exit_was_emitted;
                                    emitted[back_src.0] = true;
                                    emitted[current.0] = true;
                                    if body_always_returns(&body) {
                                        out.extend(body);
                                    } else {
                                        out.push(StructuredStmt::DoWhile {
                                            cond: *latch_cond,
                                            negate: dw_negate,
                                            body,
                                        });
                                    }
                                    current = exit;
                                    continue;
                                }
                            }
                        }
                    }

                    let (body_start, exit, negate) = if can_reach(cfg, *taken, current, emitted)
                        || back_source.is_some()
                            && can_reach_limited(cfg, *taken, back_source.unwrap(), cfg.blocks.len())
                    {
                        (*taken, *fallthrough, false)
                    } else {
                        (*fallthrough, *taken, true)
                    };

                    let mut body = Vec::new();
                    // For self-loops, the block's statements ARE the loop body.
                    // But Phi nodes should be emitted BEFORE the while (as initialization),
                    // not inside the body — otherwise the text post-processor folds them
                    // into the accumulator expression, destroying the loop semantics.
                    if is_self_loop {
                        for stmt in &block.stmts {
                            if let Stmt::Assign(var_id) = stmt {
                                if matches!(&ssa.vars[var_id.0 as usize].expr, Expr::Phi(_)) {
                                    // Emit Phi as initialization before the while
                                    out.push(StructuredStmt::Assign { lhs: *var_id, rhs: *var_id });
                                } else {
                                    // Emit non-Phi stmts inside the while body
                                    body.push(StructuredStmt::Assign { lhs: *var_id, rhs: *var_id });
                                }
                            } else {
                                // Store/Call — always inside loop body
                                match stmt {
                                    Stmt::Store { addr, val } => {
                                        body.push(StructuredStmt::Store { addr: *addr, val: *val });
                                    }
                                    Stmt::Call { target, args, out: call_out } => {
                                        body.push(StructuredStmt::Call {
                                            target: target.clone(),
                                            args: args.clone(),
                                            out: *call_out,
                                        });
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    // Mark exit block as emitted to bound the loop body
                    let exit_was_emitted = emitted[exit.0];
                    emitted[exit.0] = true;
                    emit_region(ssa, cfg, dom, pdom, back_edges, body_start, emitted, &mut body, depth + 1, None, consumed);
                    emitted[exit.0] = exit_was_emitted;

                    out.push(StructuredStmt::While {
                        cond: *cond,
                        negate,
                        body,
                    });
                    current = exit;
                    continue;
                }

                // if/else: check if taken and fallthrough reconverge.
                // The post-dominator is the merge point; bound branch recursion
                // at it by temporarily marking it emitted. Without this guard,
                // branch bodies over-run into post-merge code, collapsing
                // sibling ifs into nested form.
                let merge = pdom[current.0];

                let mut then_body = Vec::new();
                let mut else_body = Vec::new();

                let merge_valid = merge.0 < emitted.len();
                let merge_was_emitted = if merge_valid { emitted[merge.0] } else { true };
                if merge_valid { emitted[merge.0] = true; }

                if *taken != merge {
                    emit_region(ssa, cfg, dom, pdom, back_edges, *taken, emitted, &mut then_body, depth + 1, None, consumed);
                }
                if *fallthrough != merge {
                    emit_region(ssa, cfg, dom, pdom, back_edges, *fallthrough, emitted, &mut else_body, depth + 1, None, consumed);
                }

                if merge_valid { emitted[merge.0] = merge_was_emitted; }

                if else_body.is_empty() {
                    out.push(StructuredStmt::IfElse {
                        cond: *cond,
                        then_body,
                        else_body: vec![],
                    });
                } else {
                    out.push(StructuredStmt::IfElse {
                        cond: *cond,
                        then_body,
                        else_body,
                    });
                }

                // Continue at merge point
                current = merge;
            }
            SsaTerminator::Call { target, args, out: term_out, fallthrough } => {
                // Resolve the call return: use the terminator's out if set, otherwise
                // check the fallthrough block's first call_return=true stmt.
                let call_out = term_out.or_else(|| find_call_return_in_block(ssa, *fallthrough));
                if let Some(v) = call_out {
                    consumed.insert(v);
                }

                // Check if this call block is a loop header — try do-while first
                if is_loop_header {
                    let back_source = back_edges.iter()
                        .find(|(_, header)| *header == current)
                        .map(|(src, _)| *src);

                    // Do-while: back-edge source has CBranch (post-tested loop)
                    if let Some(back_src) = back_source {
                        if back_src.0 < ssa.blocks.len() {
                            let back_block = &ssa.blocks[back_src.0];
                            if let SsaTerminator::CBranch { cond, taken, fallthrough: back_fall } = &back_block.terminator {
                                let (exit, negate) = if *taken == current {
                                    (*back_fall, false)
                                } else if *back_fall == current {
                                    (*taken, true)
                                } else {
                                    (BlockId(0), false)
                                };

                                if (*taken == current || *back_fall == current) && exit.0 < cfg.blocks.len() {
                                    // Emit the call as part of the loop body
                                    let mut body = Vec::new();
                                    body.push(StructuredStmt::Call {
                                        target: target.clone(),
                                        args: args.clone(),
                                        out: call_out,
                                    });

                                    let exit_was_emitted = if exit.0 < emitted.len() { emitted[exit.0] } else { true };
                                    if exit.0 < emitted.len() { emitted[exit.0] = true; }
                                    let back_was_emitted = emitted[back_src.0];

                                    emit_region(ssa, cfg, dom, pdom, back_edges, *fallthrough, emitted, &mut body, depth + 1, None, consumed);

                                    if !back_was_emitted && !emitted[back_src.0] {
                                        emitted[back_src.0] = true;
                                        emit_block_stmts(&ssa.blocks[back_src.0], &mut body, consumed);
                                    }

                                    if exit.0 < emitted.len() { emitted[exit.0] = exit_was_emitted; }

                                    if body_always_returns(&body) {
                                        out.extend(body);
                                    } else {
                                        out.push(StructuredStmt::DoWhile {
                                            cond: *cond,
                                            negate,
                                            body,
                                        });
                                    }
                                    current = exit;
                                    continue;
                                }
                            }
                        }
                    }

                    // Not a do-while — try while pattern
                    out.push(StructuredStmt::Call {
                        target: target.clone(),
                        args: args.clone(),
                        out: call_out,
                    });
                    let next_block = &ssa.blocks[fallthrough.0];
                    if let SsaTerminator::CBranch { cond, taken, fallthrough: fall } = &next_block.terminator {
                        if !emitted[fallthrough.0] {
                            emitted[fallthrough.0] = true;
                            emit_block_stmts(next_block, out, consumed);
                            let (body_start, exit, negate) = if can_reach(cfg, *taken, current, emitted)
                                || can_reach_limited(cfg, *taken, current, cfg.blocks.len())
                            {
                                (*taken, *fall, false)
                            } else {
                                (*fall, *taken, true)
                            };
                            let mut body = Vec::new();
                            let exit_was_emitted = emitted[exit.0];
                            emitted[exit.0] = true;
                            emit_region(ssa, cfg, dom, pdom, back_edges, body_start, emitted, &mut body, depth + 1, None, consumed);
                            emitted[exit.0] = exit_was_emitted;
                            out.push(StructuredStmt::While { cond: *cond, negate, body });
                            current = exit;
                            continue;
                        }
                    }
                } else {
                    out.push(StructuredStmt::Call {
                        target: target.clone(),
                        args: args.clone(),
                        out: call_out,
                    });
                }
                current = *fallthrough;
            }
            SsaTerminator::Indirect(_v) => {
                out.push(StructuredStmt::Goto(0)); // Can't resolve indirect
                break;
            }
        }
    }
}

fn emit_block_stmts(block: &SsaBlock, out: &mut Vec<StructuredStmt>, consumed: &HashSet<VarId>) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Assign(var_id) => {
                if consumed.contains(var_id) {
                    continue;
                }
                out.push(StructuredStmt::Assign { lhs: *var_id, rhs: *var_id });
            }
            Stmt::Store { addr, val } => {
                out.push(StructuredStmt::Store { addr: *addr, val: *val });
            }
            Stmt::Call { target, args, out: call_out } => {
                out.push(StructuredStmt::Call {
                    target: target.clone(),
                    args: args.clone(),
                    out: *call_out,
                });
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Post-pass: collapse if-else chains on the same variable into switch
// ──────────────────────────────────────────────────────────────────────

/// Try to extract the variable and constant from a condition VarId.
/// Returns (var_being_tested, constant_value, is_eq).
/// Handles both `var == const` (is_eq=true) and `var != const` (is_eq=false).
/// Traces through Var() indirection to find the original variable.
fn extract_eq_const(cond: VarId, ssa: &SsaCfg) -> Option<(VarId, i64, bool)> {
    let vdef = ssa.var(cond);
    let (is_eq, left, right) = match &vdef.expr {
        Expr::BinOp(BinOpKind::Eq, l, r) => (true, *l, *r),
        Expr::BinOp(BinOpKind::NotEq, l, r) => (false, *l, *r),
        _ => return None,
    };
    let rv = ssa.var(right);
    if let Expr::Const(val, sz) = &rv.expr {
        let signed = sign_extend(*val, *sz);
        return Some((resolve_to_source(left, ssa), signed, is_eq));
    }
    let lv = ssa.var(left);
    if let Expr::Const(val, sz) = &lv.expr {
        let signed = sign_extend(*val, *sz);
        return Some((resolve_to_source(right, ssa), signed, is_eq));
    }
    None
}

/// Extract (base_register_offset, constant_offset) from an address expression.
/// Matches patterns like BinOp(Add, reg, const) which is typical for stack access.
fn extract_base_offset(ptr: VarId, ssa: &SsaCfg) -> Option<(u64, u64)> {
    let vdef = ssa.var(ptr);
    if let Expr::BinOp(BinOpKind::Add | BinOpKind::Sub, base, off) = &vdef.expr {
        let base_def = ssa.var(*base);
        let off_def = ssa.var(*off);
        if base_def.varnode.space == pcode_ir::AddressSpaceId::Register {
            if let Expr::Const(c, _) = &off_def.expr {
                return Some((base_def.varnode.offset, *c));
            }
        }
        // Also handle: base is a Var(reg)
        if let Expr::Var(inner) = &base_def.expr {
            let inner_def = ssa.var(*inner);
            if inner_def.varnode.space == pcode_ir::AddressSpaceId::Register {
                if let Expr::Const(c, _) = &off_def.expr {
                    return Some((inner_def.varnode.offset, *c));
                }
            }
        }
    }
    None
}

/// Trace a VarId through Var() copies and Zext/Sext to find the source variable.
/// Returns the deepest non-trivial VarId.
fn resolve_to_source(id: VarId, ssa: &SsaCfg) -> VarId {
    let mut cur = id;
    for _ in 0..8 { // max depth
        let vdef = ssa.var(cur);
        match &vdef.expr {
            Expr::Var(inner) => cur = *inner,
            Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, inner) => cur = *inner,
            _ => break,
        }
    }
    cur
}

fn sign_extend(val: u64, size: u32) -> i64 {
    match size {
        1 => val as i8 as i64,
        2 => val as i16 as i64,
        4 => val as i32 as i64,
        _ => val as i64,
    }
}

/// Check if two VarIds refer to the same underlying variable.
/// They match if they're the same id, or if they're both loads from the same
/// stack location, or copies of the same source register.
fn same_test_var(a: VarId, b: VarId, ssa: &SsaCfg) -> bool {
    if a == b { return true; }
    let va = ssa.var(a);
    let vb = ssa.var(b);
    // Same register
    if va.varnode.space == pcode_ir::AddressSpaceId::Register
        && vb.varnode.space == pcode_ir::AddressSpaceId::Register
        && va.varnode.offset == vb.varnode.offset
        && va.varnode.size == vb.varnode.size
    {
        return true;
    }
    // Both are Var() pointing to the same source
    if let (Expr::Var(sa), Expr::Var(sb)) = (&va.expr, &vb.expr) {
        if sa == sb { return true; }
        return same_test_var(*sa, *sb, ssa);
    }
    // Both are loads — check if they load from the same address
    if let (Expr::Load(pa), Expr::Load(pb)) = (&va.expr, &vb.expr) {
        if same_test_var(*pa, *pb, ssa) { return true; }
        // Check if both are Load(base + offset) with same base and offset
        if let Some(off_a) = extract_base_offset(*pa, ssa) {
            if let Some(off_b) = extract_base_offset(*pb, ssa) {
                if off_a == off_b { return true; }
            }
        }
    }
    // Both are param_name with same name
    if va.param_name.is_some() && va.param_name == vb.param_name {
        return true;
    }
    false
}

/// Flatten if-return patterns to reduce nesting depth.
/// When an if-block ends with return/break/goto and has an else-block,
/// move the else-block contents out to the parent level.
fn flatten_if_return(stmts: &mut Vec<StructuredStmt>) {
    let mut i = 0;
    while i < stmts.len() {
        // Recurse first into nested bodies
        match &mut stmts[i] {
            StructuredStmt::IfElse { then_body, else_body, .. } => {
                flatten_if_return(then_body);
                flatten_if_return(else_body);
            }
            StructuredStmt::While { body, .. } | StructuredStmt::DoWhile { body, .. } => {
                flatten_if_return(body);
            }
            StructuredStmt::Switch { cases, default, .. } => {
                for (_, body) in cases.iter_mut() { flatten_if_return(body); }
                flatten_if_return(default);
            }
            _ => {}
        }

        // Check: if (cond) { ...; return; } else { BODY }
        // → if (cond) { ...; return; } BODY
        if let StructuredStmt::IfElse { then_body, else_body, .. } = &stmts[i] {
            let then_ends_with_exit = matches!(then_body.last(),
                Some(StructuredStmt::Return(_)) | Some(StructuredStmt::Break)
                | Some(StructuredStmt::Continue) | Some(StructuredStmt::Goto(_)));
            if then_ends_with_exit && !else_body.is_empty() {
                // Move else_body contents after the if
                let else_stmts = else_body.clone();
                // Clear the else body
                if let StructuredStmt::IfElse { else_body, .. } = &mut stmts[i] {
                    else_body.clear();
                }
                // Insert else stmts after the if
                for (j, s) in else_stmts.into_iter().enumerate() {
                    stmts.insert(i + 1 + j, s);
                }
            }
        }
        i += 1;
    }
}

/// Collapse if-else chains testing the same variable into switch/case.
fn collapse_if_else_to_switch(stmts: &mut Vec<StructuredStmt>, ssa: &SsaCfg) {
    let mut i = 0;
    while i < stmts.len() {
        // Try to collapse BEFORE recursing into nested bodies,
        // so we can catch the full if-else chain before inner IfElses
        // are independently processed.

        // Try to collapse this if-else into a switch
        if let StructuredStmt::IfElse { cond, .. } = &stmts[i] {
            if let Some((test_var, _, _)) = extract_eq_const(*cond, ssa) {
                // Walk the if-else chain collecting cases
                let mut cases: Vec<(Vec<i64>, Vec<StructuredStmt>)> = Vec::new();
                let mut default = Vec::new();
                let collected = collect_switch_cases(&stmts[i], test_var, ssa, &mut cases, &mut default);

                // Only convert if we collected at least 3 cases
                if collected && cases.len() >= 3 {
                    stmts[i] = StructuredStmt::Switch {
                        expr: test_var,
                        cases,
                        default,
                    };
                }
            }
        }

        // Recurse into nested bodies AFTER switch collapse attempt
        match &mut stmts[i] {
            StructuredStmt::IfElse { then_body, else_body, .. } => {
                collapse_if_else_to_switch(then_body, ssa);
                collapse_if_else_to_switch(else_body, ssa);
            }
            StructuredStmt::While { body, .. } | StructuredStmt::DoWhile { body, .. } => {
                collapse_if_else_to_switch(body, ssa);
            }
            StructuredStmt::Switch { cases, default, .. } => {
                for (_, body) in cases.iter_mut() {
                    collapse_if_else_to_switch(body, ssa);
                }
                collapse_if_else_to_switch(default, ssa);
            }
            _ => {}
        }

        i += 1;
    }
}

/// Recursively collect cases from a chain of if-else-if testing the same variable.
/// Returns true if the chain was successfully collected.
///
/// Handles two patterns:
/// 1. `if (x == N) { case_body } else { next_check }` — case body in then
/// 2. `if (x != N) { next_check } else { case_body }` — case body in else (inverted)
fn collect_switch_cases(
    stmt: &StructuredStmt,
    test_var: VarId,
    ssa: &SsaCfg,
    cases: &mut Vec<(Vec<i64>, Vec<StructuredStmt>)>,
    default: &mut Vec<StructuredStmt>,
) -> bool {
    if let StructuredStmt::IfElse { cond, then_body, else_body } = stmt {
        if let Some((var, val, is_eq)) = extract_eq_const(*cond, ssa) {
            if same_test_var(var, test_var, ssa) {
                // For `==`: case body is in then_body, chain continues in else_body
                // For `!=`: case body is in else_body, chain continues in then_body
                let (case_body, chain_body) = if is_eq {
                    (then_body, else_body)
                } else {
                    (else_body, then_body)
                };

                cases.push((vec![val], case_body.clone()));

                // Check if the chain body contains another if-else on the same var.
                // Allow leading non-IfElse statements (assignments, stores) before it.
                let next_if = chain_body.iter().enumerate().find(|(_, s)|
                    matches!(s, StructuredStmt::IfElse { .. }));
                if let Some((_, next_stmt)) = next_if {
                    if let StructuredStmt::IfElse { cond: next_cond, .. } = next_stmt {
                        if let Some((next_var, _, _)) = extract_eq_const(*next_cond, ssa) {
                            if same_test_var(next_var, test_var, ssa) {
                                return collect_switch_cases(next_stmt, test_var, ssa, cases, default);
                            }
                        }
                    }
                }

                // Chain body is the default case
                if !chain_body.is_empty() {
                    *default = chain_body.clone();
                }
                return true;
            }
        }
    }
    false
}

// ──────────────────────────────────────────────────────────────────────
// Post-pass: convert gotos to break/continue
// ──────────────────────────────────────────────────────────────────────

fn eliminate_gotos(stmts: &mut Vec<StructuredStmt>, ssa: &SsaCfg, cfg: &Cfg) {
    eliminate_gotos_inner(stmts, ssa, cfg, None);
}

fn eliminate_gotos_inner(stmts: &mut Vec<StructuredStmt>, ssa: &SsaCfg, cfg: &Cfg, loop_ctx: Option<&LoopCtx>) {
    // First: collect info we need from stmts without holding mutable borrows
    let len = stmts.len();
    let mut loop_infos: Vec<Option<LoopCtx>> = Vec::new();
    for i in 0..len {
        match &stmts[i] {
            StructuredStmt::While { body, .. } | StructuredStmt::DoWhile { body, .. } => {
                let header_addr = body.first().map(|s| stmt_addr(s, ssa)).unwrap_or(0);
                let exit_addr = if i + 1 < len {
                    stmt_addr(&stmts[i + 1], ssa)
                } else {
                    0
                };
                loop_infos.push(Some(LoopCtx { header_addr, exit_addr }));
            }
            _ => {
                loop_infos.push(None);
            }
        }
    }

    // Now do the mutable pass
    for i in 0..len {
        match &mut stmts[i] {
            StructuredStmt::While { body, .. } | StructuredStmt::DoWhile { body, .. } => {
                if let Some(ref ctx) = loop_infos[i] {
                    eliminate_gotos_inner(body, ssa, cfg, Some(ctx));
                }
            }
            StructuredStmt::IfElse { then_body, else_body, .. } => {
                eliminate_gotos_inner(then_body, ssa, cfg, loop_ctx);
                eliminate_gotos_inner(else_body, ssa, cfg, loop_ctx);
            }
            StructuredStmt::Switch { cases, default, .. } => {
                for (_, body) in cases.iter_mut() {
                    eliminate_gotos_inner(body, ssa, cfg, loop_ctx);
                }
                eliminate_gotos_inner(default, ssa, cfg, loop_ctx);
            }
            StructuredStmt::Goto(addr) => {
                if let Some(ctx) = loop_ctx {
                    if *addr == ctx.header_addr && ctx.header_addr != 0 {
                        stmts[i] = StructuredStmt::Continue;
                    } else if *addr == ctx.exit_addr && ctx.exit_addr != 0 {
                        stmts[i] = StructuredStmt::Break;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Try to get a representative address for a statement (for goto resolution).
fn stmt_addr(stmt: &StructuredStmt, ssa: &SsaCfg) -> u64 {
    match stmt {
        StructuredStmt::Assign { lhs, .. } => {
            let vdef = ssa.var(*lhs);
            // Use the instruction address encoded in the varnode
            vdef.varnode.offset
        }
        StructuredStmt::Label(addr) | StructuredStmt::Goto(addr) => *addr,
        _ => 0,
    }
}

/// Check if `from` can reach `target` without going through already-emitted blocks.
fn can_reach(cfg: &Cfg, from: BlockId, target: BlockId, _emitted: &[bool]) -> bool {
    can_reach_limited(cfg, from, target, cfg.blocks.len())
}

/// Check if `from` can reach `target` within `limit` steps.
fn can_reach_limited(cfg: &Cfg, from: BlockId, target: BlockId, limit: usize) -> bool {
    if from == target { return true; }
    let mut visited = vec![false; cfg.blocks.len()];
    let mut stack = vec![from];
    let mut steps = 0;
    while let Some(node) = stack.pop() {
        if steps > limit { return false; }
        steps += 1;
        if node.0 >= cfg.blocks.len() || visited[node.0] { continue; }
        visited[node.0] = true;
        for succ in cfg.successors(node) {
            if succ == target { return true; }
            stack.push(succ);
        }
    }
    false
}

/// Check if `a` dominates `b` in the dominator tree.
fn dominates(dom: &[BlockId], a: BlockId, b: BlockId) -> bool {
    if a == b {
        return true;
    }
    let mut cur = b;
    for _ in 0..dom.len() {
        let d = dom[cur.0];
        if d == a {
            return true;
        }
        if d == cur {
            return false; // reached root
        }
        cur = d;
    }
    false
}
