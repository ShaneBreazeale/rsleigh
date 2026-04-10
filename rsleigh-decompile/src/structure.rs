use crate::ir::*;
use crate::dominators::{compute_dominators, compute_post_dominators};

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

    emit_region(ssa, cfg, &dom, &pdom, &back_edges, cfg.entry,
                &mut emitted, &mut result);

    result
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
) {
    let mut current = start;

    loop {
        if current.0 >= cfg.blocks.len() || emitted[current.0] {
            break;
        }
        emitted[current.0] = true;

        let block = &ssa.blocks[current.0];

        // Emit statements for this block
        emit_block_stmts(block, out);

        // Check if this block is a loop header
        let is_loop_header = back_edges.iter().any(|(_, header)| *header == current);

        match &block.terminator {
            SsaTerminator::Return(ret_val) => {
                out.push(StructuredStmt::Return(*ret_val));
                break;
            }
            SsaTerminator::Fallthrough(next) | SsaTerminator::Branch(next) => {
                current = *next;
            }
            SsaTerminator::CBranch { cond, taken, fallthrough } => {
                // Check if this is a loop header
                if is_loop_header {
                    // Determine which branch goes to the loop body vs exit.
                    // The body is the successor that eventually leads back to this header.
                    // The exit is the other successor.
                    let back_source = back_edges.iter()
                        .find(|(_, header)| *header == current)
                        .map(|(src, _)| *src);

                    let (body_start, exit, negate) = if can_reach(cfg, *taken, current, emitted)
                        || back_source.is_some()
                            && can_reach_limited(cfg, *taken, back_source.unwrap(), cfg.blocks.len())
                    {
                        (*taken, *fallthrough, false)
                    } else {
                        (*fallthrough, *taken, true)
                    };

                    let mut body = Vec::new();
                    emit_region(ssa, cfg, dom, pdom, back_edges, body_start, emitted, &mut body);

                    if negate {
                        // The condition was for the exit, so negate for the loop
                        out.push(StructuredStmt::While {
                            cond: *cond, // printer will handle negation via context
                            body,
                        });
                    } else {
                        out.push(StructuredStmt::While {
                            cond: *cond,
                            body,
                        });
                    }
                    current = exit;
                    continue;
                }

                // if/else: check if taken and fallthrough reconverge
                let merge = pdom[current.0];

                let mut then_body = Vec::new();
                let mut else_body = Vec::new();

                if *taken != merge {
                    emit_region(ssa, cfg, dom, pdom, back_edges, *taken, emitted, &mut then_body);
                }
                if *fallthrough != merge {
                    emit_region(ssa, cfg, dom, pdom, back_edges, *fallthrough, emitted, &mut else_body);
                }

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
            SsaTerminator::Call { target, args, fallthrough } => {
                out.push(StructuredStmt::Call {
                    target: target.clone(),
                    args: args.clone(),
                    out: None,
                });
                current = *fallthrough;
            }
            SsaTerminator::Indirect(_v) => {
                out.push(StructuredStmt::Goto(0)); // Can't resolve indirect
                break;
            }
        }
    }
}

fn emit_block_stmts(block: &SsaBlock, out: &mut Vec<StructuredStmt>) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Assign(var_id) => {
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
