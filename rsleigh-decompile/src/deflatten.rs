//! Static OLLVM-style control-flow deflattening.
//!
//! The detection shape is a clean Rust port of the Rolf Rolles/Miasm
//! dominator/back-edge heuristic used by the Apache-2.0
//! `IDA_Ollvm-unflattener` reference. This module stays analysis-only: it
//! rewrites rsleigh's in-memory CFG for an opt-in decompile path and never
//! patches binary text.

use crate::ir::{
    BasicBlock, BinOpKind, BlockId, Cfg, Expr, SsaCfg, SsaTerminator, Stmt, Terminator,
    UnaryOpKind, VarDef, VarId,
};
use std::collections::{HashMap, HashSet};

const MIN_FLATTENING_SCORE: f64 = 0.45;
const MIN_PREDISPATCHER_PREDS: usize = 2;
const MAX_DISPATCH_WALK: usize = 128;
const MAX_CONST_EVAL_DEPTH: usize = 32;

#[derive(Debug, Clone)]
pub struct FlatteningInfo {
    pub predispatcher: BlockId,
    pub dispatcher: BlockId,
    pub score: f64,
    pub predecessor_count: usize,
    pub backbone_blocks: Vec<BlockId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveredEdge {
    pub from: BlockId,
    pub to: BlockId,
    /// `Some(true)`/`Some(false)` preserves the original conditional arm when
    /// the source block still has a real conditional terminator. `None` is an
    /// unconditional recovered edge.
    pub condition: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct DeflattenReport {
    pub info: FlatteningInfo,
    pub recovered_edges: Vec<RecoveredEdge>,
    pub reason: Option<String>,
}

pub fn detect_flattening(cfg: &Cfg) -> Option<FlatteningInfo> {
    if cfg.blocks.len() < 4 || cfg.entry.0 >= cfg.blocks.len() {
        return None;
    }

    let reachable = reachable_from(cfg, cfg.entry);
    let preds = cfg.predecessors();
    let dominators = compute_dominators(cfg, &reachable, &preds);

    let mut best: Option<FlatteningInfo> = None;
    for block in &cfg.blocks {
        let id = block.id;
        if id.0 >= preds.len() || !reachable.contains(&id) {
            continue;
        }
        let pred_count = preds[id.0].len();
        if pred_count < MIN_PREDISPATCHER_PREDS || !block_in_cycle(cfg, id) {
            continue;
        }
        let succs = cfg.successors(id);
        if succs.len() != 1 {
            continue;
        }
        let dominated_count = reachable
            .iter()
            .filter(|node| dominators[node.0].contains(&id))
            .count();
        let score = dominated_count as f64 / reachable.len().max(1) as f64;
        if score < MIN_FLATTENING_SCORE {
            continue;
        }
        let dispatcher = succs[0];
        let backbone_blocks = find_backbone_blocks(cfg, id, dispatcher, &preds);
        if backbone_blocks.len() < 2 {
            continue;
        }
        let info = FlatteningInfo {
            predispatcher: id,
            dispatcher,
            score,
            predecessor_count: pred_count,
            backbone_blocks,
        };
        let replace = best
            .as_ref()
            .map(|old| (info.predecessor_count, info.score) > (old.predecessor_count, old.score))
            .unwrap_or(true);
        if replace {
            best = Some(info);
        }
    }
    best
}

pub fn recover_edges(cfg: &Cfg, ssa: &SsaCfg, info: &FlatteningInfo) -> Option<Vec<RecoveredEdge>> {
    if cfg.blocks.len() != ssa.blocks.len() || info.dispatcher.0 >= ssa.blocks.len() {
        return None;
    }

    let state_var = discover_dispatch_state_var(ssa, info.dispatcher)?;
    let backbone: HashSet<BlockId> = info.backbone_blocks.iter().copied().collect();
    let mut edges = Vec::new();

    for &block in &info.backbone_blocks {
        if block == info.predispatcher || block == info.dispatcher || block.0 >= ssa.blocks.len() {
            continue;
        }
        if let Some(mut explicit) = explicit_non_dispatch_edges(ssa, block, info) {
            edges.append(&mut explicit);
            continue;
        }
        let Some(next_state) = block_next_state_value(&ssa.blocks[block.0], &ssa.vars) else {
            continue;
        };
        let target = resolve_dispatch_target_for_state(ssa, info, state_var, next_state)?;
        if backbone.contains(&target) || is_function_exit(ssa, target) {
            edges.push(RecoveredEdge {
                from: block,
                to: target,
                condition: None,
            });
        }
    }

    edges.sort_by_key(edge_sort_key);
    edges.dedup();
    if edges.is_empty() {
        None
    } else {
        Some(edges)
    }
}

pub fn rewrite_cfg(cfg: &Cfg, edges: &[RecoveredEdge], info: &FlatteningInfo) -> Option<Cfg> {
    let mut blocks = clone_blocks(&cfg.blocks);
    let mut by_source: HashMap<BlockId, Vec<RecoveredEdge>> = HashMap::new();
    for edge in edges {
        if edge.from.0 >= blocks.len() || edge.to.0 >= blocks.len() {
            return None;
        }
        by_source.entry(edge.from).or_default().push(*edge);
    }

    for (from, mut out_edges) in by_source {
        out_edges.sort_by_key(edge_sort_key);
        out_edges.dedup();
        match out_edges.as_slice() {
            [edge] => {
                blocks[from.0].terminator = match &blocks[from.0].terminator {
                    Terminator::Call { target, .. } => Terminator::Call {
                        target: target.clone(),
                        fallthrough: edge.to,
                    },
                    _ => Terminator::Branch(edge.to),
                };
            }
            [a, b] => {
                let (taken, fallthrough) = match (a.condition, b.condition) {
                    (Some(true), Some(false)) => (a.to, b.to),
                    (Some(false), Some(true)) => (b.to, a.to),
                    _ => return None,
                };
                let cond = match &blocks[from.0].terminator {
                    Terminator::CBranch { cond, .. } => cond.clone(),
                    _ => return None,
                };
                blocks[from.0].terminator = Terminator::CBranch {
                    cond,
                    taken,
                    fallthrough,
                };
            }
            _ => return None,
        }
    }

    // Bypass the dispatcher loop. Keeping block IDs stable is more important
    // than physically removing vector entries because SSA indexes by BlockId.
    if info.predispatcher.0 < blocks.len() {
        blocks[info.predispatcher.0].terminator = Terminator::Return;
    }
    if info.dispatcher.0 < blocks.len() {
        blocks[info.dispatcher.0].terminator = Terminator::Return;
    }

    Some(Cfg {
        blocks,
        entry: cfg.entry,
        diagnostics: cfg.diagnostics.clone(),
    })
}

pub fn deflatten_cfg(cfg: &Cfg, ssa: &SsaCfg) -> Option<(Cfg, DeflattenReport)> {
    let info = detect_flattening(cfg)?;
    let edges = recover_edges(cfg, ssa, &info)?;
    let rewritten = rewrite_cfg(cfg, &edges, &info)?;
    let report = DeflattenReport {
        info,
        recovered_edges: edges,
        reason: None,
    };
    Some((rewritten, report))
}

fn reachable_from(cfg: &Cfg, start: BlockId) -> HashSet<BlockId> {
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(node) = stack.pop() {
        if node.0 >= cfg.blocks.len() || !seen.insert(node) {
            continue;
        }
        stack.extend(cfg.successors(node));
    }
    seen
}

fn compute_dominators(
    cfg: &Cfg,
    reachable: &HashSet<BlockId>,
    preds: &[Vec<BlockId>],
) -> Vec<HashSet<BlockId>> {
    let all: HashSet<BlockId> = reachable.iter().copied().collect();
    let mut doms = vec![HashSet::new(); cfg.blocks.len()];
    for block in &cfg.blocks {
        if !reachable.contains(&block.id) {
            continue;
        }
        if block.id == cfg.entry {
            doms[block.id.0].insert(block.id);
        } else {
            doms[block.id.0] = all.clone();
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in &cfg.blocks {
            let id = block.id;
            if id == cfg.entry || !reachable.contains(&id) || id.0 >= preds.len() {
                continue;
            }
            let mut next: Option<HashSet<BlockId>> = None;
            for pred in preds[id.0].iter().filter(|p| reachable.contains(p)) {
                next = Some(match next {
                    Some(acc) => acc.intersection(&doms[pred.0]).copied().collect(),
                    None => doms[pred.0].clone(),
                });
            }
            let mut next = next.unwrap_or_default();
            next.insert(id);
            if next != doms[id.0] {
                doms[id.0] = next;
                changed = true;
            }
        }
    }
    doms
}

fn block_in_cycle(cfg: &Cfg, node: BlockId) -> bool {
    for succ in cfg.successors(node) {
        if succ == node {
            return true;
        }
        let seen = reachable_from(cfg, succ);
        if seen.contains(&node) {
            return true;
        }
    }
    false
}

fn find_backbone_blocks(
    cfg: &Cfg,
    predispatcher: BlockId,
    dispatcher: BlockId,
    preds: &[Vec<BlockId>],
) -> Vec<BlockId> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |b: BlockId, out: &mut Vec<BlockId>| {
        if b != predispatcher && b != dispatcher && seen.insert(b) {
            out.push(b);
        }
    };

    if predispatcher.0 < preds.len() {
        for &pred in &preds[predispatcher.0] {
            add(pred, &mut out);
            walk_up_linear_splits(cfg, preds, pred, &mut add, &mut out);
        }
    }
    for block in &cfg.blocks {
        if cfg.successors(block.id).is_empty() {
            add(block.id, &mut out);
            walk_up_linear_splits(cfg, preds, block.id, &mut add, &mut out);
        }
    }
    if dispatcher.0 < preds.len() {
        for &pred in &preds[dispatcher.0] {
            if pred != predispatcher {
                add(pred, &mut out);
                walk_up_linear_splits(cfg, preds, pred, &mut add, &mut out);
            }
        }
    }
    out.sort_by_key(|b| b.0);
    out
}

fn walk_up_linear_splits<F: FnMut(BlockId, &mut Vec<BlockId>)>(
    cfg: &Cfg,
    preds: &[Vec<BlockId>],
    start: BlockId,
    add: &mut F,
    out: &mut Vec<BlockId>,
) {
    let mut current = start;
    for _ in 0..MAX_DISPATCH_WALK {
        if current.0 >= preds.len() || preds[current.0].len() != 1 {
            break;
        }
        let pred = preds[current.0][0];
        if pred.0 >= cfg.blocks.len() || ends_in_control_branch(&cfg.blocks[pred.0].terminator) {
            break;
        }
        add(pred, out);
        current = pred;
    }
}

fn ends_in_control_branch(term: &Terminator) -> bool {
    matches!(
        term,
        Terminator::Branch(_) | Terminator::CBranch { .. } | Terminator::Indirect(_)
    )
}

fn discover_dispatch_state_var(ssa: &SsaCfg, dispatcher: BlockId) -> Option<VarId> {
    let mut current = dispatcher;
    let mut seen = HashSet::new();
    for _ in 0..MAX_DISPATCH_WALK {
        if current.0 >= ssa.blocks.len() || !seen.insert(current) {
            return None;
        }
        match &ssa.blocks[current.0].terminator {
            SsaTerminator::CBranch { cond, .. } => {
                let leaves = symbolic_leaves(*cond, &ssa.vars);
                return leaves.first().copied().or(Some(*cond));
            }
            SsaTerminator::Branch(next) | SsaTerminator::Fallthrough(next) => current = *next,
            SsaTerminator::Indirect(v) => return Some(*v),
            _ => return None,
        }
    }
    None
}

fn edge_sort_key(edge: &RecoveredEdge) -> (usize, usize, u8) {
    let condition = match edge.condition {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    (edge.from.0, edge.to.0, condition)
}

fn explicit_non_dispatch_edges(
    ssa: &SsaCfg,
    block: BlockId,
    info: &FlatteningInfo,
) -> Option<Vec<RecoveredEdge>> {
    let term = &ssa.blocks.get(block.0)?.terminator;
    let is_dispatch = |b: BlockId| b == info.predispatcher || b == info.dispatcher;
    match term {
        SsaTerminator::Branch(to) | SsaTerminator::Fallthrough(to) if !is_dispatch(*to) => {
            Some(vec![RecoveredEdge {
                from: block,
                to: *to,
                condition: None,
            }])
        }
        SsaTerminator::CBranch {
            taken, fallthrough, ..
        } if !is_dispatch(*taken) && !is_dispatch(*fallthrough) => Some(vec![
            RecoveredEdge {
                from: block,
                to: *taken,
                condition: Some(true),
            },
            RecoveredEdge {
                from: block,
                to: *fallthrough,
                condition: Some(false),
            },
        ]),
        _ => None,
    }
}

fn block_next_state_value(block: &crate::ir::SsaBlock, vars: &[VarDef]) -> Option<u64> {
    let env = HashMap::new();
    for stmt in block.stmts.iter().rev() {
        if let Stmt::Assign(v) = stmt {
            if let Some(value) = interp_const(*v, vars, &env) {
                return Some(value);
            }
        }
    }
    None
}

fn resolve_dispatch_target_for_state(
    ssa: &SsaCfg,
    info: &FlatteningInfo,
    state_var: VarId,
    state: u64,
) -> Option<BlockId> {
    let mut env = HashMap::new();
    env.insert(state_var.0, state);
    let mut current = info.dispatcher;
    let mut seen = HashSet::new();
    for _ in 0..MAX_DISPATCH_WALK {
        if current.0 >= ssa.blocks.len() || !seen.insert(current) {
            return None;
        }
        if is_residual_unconditional_backbone_overlap(ssa, info, current) {
            return None;
        }
        match &ssa.blocks[current.0].terminator {
            SsaTerminator::CBranch {
                cond,
                taken,
                fallthrough,
            } => {
                let cond_value = interp_const(*cond, &ssa.vars, &env)?;
                let next = if cond_value != 0 {
                    *taken
                } else {
                    *fallthrough
                };
                if next == info.predispatcher {
                    return None;
                }
                if next == info.dispatcher || is_dispatch_chain_block(ssa, next, state_var, info) {
                    current = next;
                } else {
                    return Some(next);
                }
            }
            SsaTerminator::Branch(next) | SsaTerminator::Fallthrough(next) => {
                if *next == info.predispatcher {
                    return None;
                }
                if *next == info.dispatcher || is_dispatch_chain_block(ssa, *next, state_var, info)
                {
                    current = *next;
                } else {
                    return Some(*next);
                }
            }
            SsaTerminator::Return(_) => return Some(current),
            _ => return None,
        }
    }
    None
}

fn interp_const(v: VarId, vars: &[VarDef], env: &HashMap<u32, u64>) -> Option<u64> {
    interp_const_inner(v, vars, env, 0)
}

fn interp_const_inner(
    v: VarId,
    vars: &[VarDef],
    env: &HashMap<u32, u64>,
    depth: usize,
) -> Option<u64> {
    if depth > MAX_CONST_EVAL_DEPTH {
        return None;
    }
    let def = vars.get(v.0 as usize)?;
    if let Some(&value) = env.get(&v.0) {
        return Some(value & const_size_mask(def.size));
    }

    let raw = match &def.expr {
        Expr::Const(value, _) => *value,
        Expr::Var(inner) => interp_const_inner(*inner, vars, env, depth + 1)?,
        Expr::BinOp(kind, left, right) => {
            let left_value = interp_const_inner(*left, vars, env, depth + 1)?;
            let right_value = interp_const_inner(*right, vars, env, depth + 1)?;
            let input_size = vars.get(left.0 as usize)?.size;
            apply_const_binop(*kind, left_value, right_value, input_size)?
        }
        Expr::UnaryOp(kind, inner) => {
            let value = interp_const_inner(*inner, vars, env, depth + 1)?;
            let input_size = vars
                .get(inner.0 as usize)
                .map(|inner_def| inner_def.size)
                .unwrap_or(def.size);
            apply_const_unop(*kind, value, input_size, def.size)?
        }
        Expr::Load(_)
        | Expr::FieldAccess(_, _)
        | Expr::Phi(_)
        | Expr::Ternary(_, _, _)
        | Expr::UserOp { .. }
        | Expr::Unknown => return None,
    };
    Some(raw & const_size_mask(def.size))
}

fn const_size_mask(size: u32) -> u64 {
    match size {
        0 => u64::MAX,
        size if size >= 8 => u64::MAX,
        size => (1u64 << (size * 8)).wrapping_sub(1),
    }
}

fn apply_const_binop(kind: BinOpKind, left: u64, right: u64, size: u32) -> Option<u64> {
    let mask = const_size_mask(size);
    let left = left & mask;
    let right = right & mask;
    let bits = if size >= 8 { 64 } else { size * 8 };
    let sign_bit = if bits == 0 { 0 } else { 1u64 << (bits - 1) };
    let signed = |value: u64| -> i64 {
        if sign_bit != 0 && value & sign_bit != 0 {
            (value | !mask) as i64
        } else {
            value as i64
        }
    };

    Some(match kind {
        BinOpKind::Add => left.wrapping_add(right),
        BinOpKind::Sub => left.wrapping_sub(right),
        BinOpKind::Mult => left.wrapping_mul(right),
        BinOpKind::Div => {
            if right == 0 {
                return None;
            }
            left / right
        }
        BinOpKind::SDiv => {
            if right == 0 {
                return None;
            }
            signed(left).wrapping_div(signed(right)) as u64
        }
        BinOpKind::Rem => {
            if right == 0 {
                return None;
            }
            left % right
        }
        BinOpKind::SRem => {
            if right == 0 {
                return None;
            }
            signed(left).wrapping_rem(signed(right)) as u64
        }
        BinOpKind::And => left & right,
        BinOpKind::Or => left | right,
        BinOpKind::Xor => left ^ right,
        BinOpKind::Lsl => left.wrapping_shl((right & 63) as u32),
        BinOpKind::Lsr => left.wrapping_shr((right & 63) as u32),
        BinOpKind::Asr => signed(left).wrapping_shr((right & 63) as u32) as u64,
        BinOpKind::Eq => (left == right) as u64,
        BinOpKind::NotEq => (left != right) as u64,
        BinOpKind::Less => (left < right) as u64,
        BinOpKind::LessEq => (left <= right) as u64,
        BinOpKind::SLess => (signed(left) < signed(right)) as u64,
        BinOpKind::SLessEq => (signed(left) <= signed(right)) as u64,
        BinOpKind::BoolAnd => (left & 1) & (right & 1),
        BinOpKind::BoolOr => (left & 1) | (right & 1),
        BinOpKind::BoolXor => (left & 1) ^ (right & 1),
        _ => return None,
    })
}

fn apply_const_unop(
    kind: UnaryOpKind,
    value: u64,
    input_size: u32,
    output_size: u32,
) -> Option<u64> {
    let input_mask = const_size_mask(input_size);
    let bits = if input_size >= 8 { 64 } else { input_size * 8 };
    let sign_bit = if bits == 0 { 0 } else { 1u64 << (bits - 1) };

    Some(match kind {
        UnaryOpKind::Neg => (value as i64).wrapping_neg() as u64,
        UnaryOpKind::Not => !value,
        UnaryOpKind::BoolNot => (value & 1) ^ 1,
        UnaryOpKind::Zext => value & input_mask,
        UnaryOpKind::Sext => {
            if sign_bit != 0 && value & sign_bit != 0 {
                value | !input_mask
            } else {
                value & input_mask
            }
        }
        UnaryOpKind::Trunc => value & const_size_mask(output_size),
        UnaryOpKind::Popcount => value.count_ones() as u64,
        UnaryOpKind::Lzcount => {
            if bits == 0 {
                return None;
            }
            (value & input_mask).leading_zeros() as u64 - (64 - bits) as u64
        }
        _ => return None,
    })
}

fn is_residual_unconditional_backbone_overlap(
    ssa: &SsaCfg,
    info: &FlatteningInfo,
    block: BlockId,
) -> bool {
    if !info.backbone_blocks.contains(&block) {
        return false;
    }
    let Some(block) = ssa.blocks.get(block.0) else {
        return true;
    };
    match &block.terminator {
        SsaTerminator::Branch(next) | SsaTerminator::Fallthrough(next) => {
            *next != info.predispatcher && *next != info.dispatcher
        }
        _ => false,
    }
}

fn is_dispatch_chain_block(
    ssa: &SsaCfg,
    block: BlockId,
    state_var: VarId,
    info: &FlatteningInfo,
) -> bool {
    let Some(block) = ssa.blocks.get(block.0) else {
        return false;
    };
    match &block.terminator {
        SsaTerminator::CBranch { cond, .. } => {
            symbolic_leaves(*cond, &ssa.vars).contains(&state_var)
        }
        SsaTerminator::Branch(next) | SsaTerminator::Fallthrough(next) => {
            !info.backbone_blocks.contains(&block.id)
                || (*next != info.predispatcher && *next != info.dispatcher)
        }
        _ => false,
    }
}

fn symbolic_leaves(root: VarId, vars: &[VarDef]) -> Vec<VarId> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    collect_symbolic_leaves(root, vars, &mut seen, &mut out, 0);
    out.sort_by_key(|v| v.0);
    out.dedup();
    out
}

fn collect_symbolic_leaves(
    v: VarId,
    vars: &[VarDef],
    seen: &mut HashSet<VarId>,
    out: &mut Vec<VarId>,
    depth: usize,
) {
    if depth > 32 || !seen.insert(v) {
        return;
    }
    let Some(def) = vars.get(v.0 as usize) else {
        out.push(v);
        return;
    };
    match &def.expr {
        Expr::Const(_, _) => {}
        Expr::Var(inner) | Expr::UnaryOp(_, inner) | Expr::Load(inner) => {
            collect_symbolic_leaves(*inner, vars, seen, out, depth + 1)
        }
        Expr::BinOp(_, l, r) => {
            collect_symbolic_leaves(*l, vars, seen, out, depth + 1);
            collect_symbolic_leaves(*r, vars, seen, out, depth + 1);
        }
        Expr::Ternary(c, t, f) => {
            collect_symbolic_leaves(*c, vars, seen, out, depth + 1);
            collect_symbolic_leaves(*t, vars, seen, out, depth + 1);
            collect_symbolic_leaves(*f, vars, seen, out, depth + 1);
        }
        Expr::Phi(inputs) => {
            for input in inputs {
                collect_symbolic_leaves(*input, vars, seen, out, depth + 1);
            }
        }
        Expr::FieldAccess(base, _) => collect_symbolic_leaves(*base, vars, seen, out, depth + 1),
        Expr::UserOp { .. } | Expr::Unknown => out.push(v),
    }
}

fn is_function_exit(ssa: &SsaCfg, block: BlockId) -> bool {
    ssa.blocks
        .get(block.0)
        .map(|b| matches!(b.terminator, SsaTerminator::Return(_)))
        .unwrap_or(false)
}

fn clone_blocks(blocks: &[BasicBlock]) -> Vec<BasicBlock> {
    blocks
        .iter()
        .map(|block| BasicBlock {
            id: block.id,
            addr: block.addr,
            ops: block.ops.clone(),
            terminator: block.terminator.clone(),
        })
        .collect()
}
