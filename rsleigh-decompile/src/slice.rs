//! Bounded backward traversal of a post-fold SSA snapshot.
//! This is expression dependence, not a memory-alias or reachability proof.
use crate::ir::{Expr, SsaCfg, SsaTerminator, Stmt, VarId};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

pub const MAX_NODES: usize = 256;
pub const MAX_DEPTH: usize = 32;
pub const MAX_INPUTS: usize = 2048;

#[derive(Debug, Serialize)]
pub struct SliceInput {
    pub var_id: u32,
    /// None means the target node is included. Otherwise this edge stops here.
    pub stop_reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SliceNode {
    pub var_id: u32,
    pub depth: usize,
    /// Definition sites retained by folding; empty for entry values or removed assignments.
    pub block_ids: Vec<usize>,
    pub kind: String,
    pub size: u32,
    pub constant: Option<u64>,
    pub parameter: Option<String>,
    pub inputs: Vec<SliceInput>,
    pub inputs_total: usize,
    pub boundary: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SliceBlock {
    pub id: usize,
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct BackwardSlice {
    pub root: u32,
    pub nodes: Vec<SliceNode>,
    pub blocks: Vec<SliceBlock>,
    pub truncated: bool,
    /// False if any boundary remains unresolved, including memory and calls.
    pub complete: bool,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_inputs: usize,
}

pub fn backward_slice(
    ssa: &SsaCfg,
    root: VarId,
    max_nodes: usize,
    max_depth: usize,
) -> Result<BackwardSlice, String> {
    if root.0 as usize >= ssa.vars.len() {
        return Err(format!("SSA variable {} does not exist", root.0));
    }
    if max_nodes == 0 {
        return Err("max_nodes must be positive".into());
    }
    let max_nodes = max_nodes.min(MAX_NODES);
    let max_depth = max_depth.min(MAX_DEPTH);
    let mut definitions: HashMap<VarId, BTreeSet<usize>> = HashMap::new();
    let mut call_outputs = HashSet::new();
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign(v) => {
                    definitions.entry(*v).or_default().insert(block.id.0);
                }
                Stmt::Call { out: Some(v), .. } => {
                    call_outputs.insert(*v);
                    definitions.entry(*v).or_default().insert(block.id.0);
                }
                _ => {}
            }
        }
        if let SsaTerminator::Call { out: Some(v), .. } = &block.terminator {
            call_outputs.insert(*v);
            definitions.entry(*v).or_default().insert(block.id.0);
        }
    }
    let mut seen = HashSet::from([root]);
    let mut queue = VecDeque::from([(root, 0)]);
    let mut nodes = Vec::new();
    let mut blocks = BTreeSet::new();
    let mut edges = 0;
    let mut truncated = false;
    let mut complete = true;
    while let Some((id, depth)) = queue.pop_front() {
        let v = &ssa.vars[id.0 as usize];
        let (kind, dependencies, boundary) = match &v.expr {
            Expr::Var(a) => ("var".into(), vec![*a], None),
            Expr::Const(_, _) => ("constant".into(), vec![], None),
            Expr::BinOp(op, a, b) => (format!("binary.{op:?}"), vec![*a, *b], None),
            Expr::UnaryOp(op, a) => (format!("unary.{op:?}"), vec![*a], None),
            Expr::Phi(inputs) => ("phi".into(), inputs.clone(), None),
            Expr::Ternary(c, a, b) => ("ternary".into(), vec![*c, *a, *b], None),
            Expr::Load(a) => ("load".into(), vec![*a], Some("unmodeled_memory")),
            Expr::FieldAccess(a, _) => ("field_access".into(), vec![*a], Some("unmodeled_memory")),
            Expr::UserOp { inputs, .. } => {
                ("user_op".into(), inputs.clone(), Some("unmodeled_user_op"))
            }
            Expr::Unknown if v.param_name.is_some() => {
                ("parameter".into(), vec![], Some("external_input"))
            }
            Expr::Unknown => ("unknown".into(), vec![], Some("unknown_value")),
        };
        let boundary = if v.call_return || call_outputs.contains(&id) {
            Some("unmodeled_call")
        } else {
            boundary
        };
        if boundary.is_some() {
            complete = false;
        }
        let inputs_total = dependencies.len();
        let mut inputs = Vec::new();
        for input in dependencies.into_iter().take(MAX_INPUTS - edges) {
            edges += 1;
            let stop_reason = if let Some(reason) = boundary {
                Some(reason)
            } else if input.0 as usize >= ssa.vars.len() {
                Some("missing_variable")
            } else if seen.contains(&input) {
                None
            } else if depth >= max_depth {
                truncated = true;
                Some("depth_limit")
            } else if seen.len() >= max_nodes {
                truncated = true;
                Some("node_limit")
            } else {
                seen.insert(input);
                queue.push_back((input, depth + 1));
                None
            };
            if stop_reason.is_some() {
                complete = false;
            }
            inputs.push(SliceInput {
                var_id: input.0,
                stop_reason,
            });
        }
        if inputs.len() < inputs_total {
            truncated = true;
            complete = false;
        }
        let mut block_ids = Vec::new();
        if let Some(sites) = definitions.get(&id) {
            for site in sites {
                if blocks.contains(site) || blocks.len() < MAX_NODES {
                    blocks.insert(*site);
                    block_ids.push(*site);
                } else {
                    truncated = true;
                    complete = false;
                }
            }
        }
        nodes.push(SliceNode {
            var_id: id.0,
            depth,
            block_ids,
            kind,
            size: v.size,
            constant: if let Expr::Const(value, _) = v.expr {
                Some(value)
            } else {
                None
            },
            parameter: v.param_name.as_ref().map(|s| s.chars().take(256).collect()),
            inputs,
            inputs_total,
            boundary,
        });
    }
    let blocks = blocks
        .into_iter()
        .filter_map(|id| {
            ssa.blocks
                .iter()
                .find(|b| b.id.0 == id)
                .map(|b| SliceBlock {
                    id,
                    address: format!("0x{:x}", b.addr),
                })
        })
        .collect();
    Ok(BackwardSlice {
        root: root.0,
        nodes,
        blocks,
        truncated,
        complete,
        max_nodes,
        max_depth,
        max_inputs: MAX_INPUTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::*;
    use pcode_ir::Varnode;
    fn graph(expressions: Vec<Expr>) -> SsaCfg {
        let vars: Vec<_> = expressions
            .into_iter()
            .enumerate()
            .map(|(id, expr)| VarDef {
                id: VarId(id as u32),
                varnode: Varnode::unique(id as u64, 8),
                expr,
                size: 8,
                use_count: 0,
                param_name: None,
                call_return: false,
                inferred_type: InferredType::Unknown,
                display_type: None,
            })
            .collect();
        SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vars.iter().map(|v| Stmt::Assign(v.id)).collect(),
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: vec![],
        }
    }
    #[test]
    fn follows_both_phi_arms_and_terminates_cycles() {
        let ssa = graph(vec![
            Expr::Phi(vec![VarId(1), VarId(2)]),
            Expr::Const(7, 8),
            Expr::Var(VarId(0)),
        ]);
        let slice = backward_slice(&ssa, VarId(0), 10, 10).unwrap();
        assert_eq!(
            slice.nodes.iter().map(|n| n.var_id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(slice.nodes[0].inputs.len(), 2);
        assert_eq!(slice.nodes[1].constant, Some(7));
        assert_eq!(slice.blocks[0].address, "0x1000");
        assert!(slice.complete);
        assert!(!slice.truncated);
    }
    #[test]
    fn stops_at_memory_calls_and_unknowns() {
        let mut ssa = graph(vec![
            Expr::Load(VarId(1)),
            Expr::Const(9, 8),
            Expr::Var(VarId(1)),
            Expr::Unknown,
        ]);
        ssa.vars[2].call_return = true;
        for (root, reason) in [
            (0, "unmodeled_memory"),
            (2, "unmodeled_call"),
            (3, "unknown_value"),
        ] {
            let slice = backward_slice(&ssa, VarId(root), 10, 10).unwrap();
            assert_eq!(slice.nodes.len(), 1);
            assert_eq!(slice.nodes[0].boundary, Some(reason));
            assert!(!slice.complete);
            assert!(!slice.truncated);
        }
    }
    #[test]
    fn node_depth_and_input_limits_are_explicit() {
        let ssa = graph(vec![
            Expr::Phi(vec![VarId(1), VarId(2)]),
            Expr::Var(VarId(2)),
            Expr::Const(1, 8),
        ]);
        for (nodes, depth, reason) in [(1, 10, "node_limit"), (10, 0, "depth_limit")] {
            let slice = backward_slice(&ssa, VarId(0), nodes, depth).unwrap();
            assert_eq!(slice.nodes.len(), 1);
            assert!(slice.truncated);
            assert_eq!(slice.nodes[0].inputs[0].stop_reason, Some(reason));
        }
        let ssa = graph(vec![Expr::Phi(vec![VarId(0); MAX_INPUTS + 1])]);
        let slice = backward_slice(&ssa, VarId(0), 10, 10).unwrap();
        assert_eq!(slice.nodes[0].inputs.len(), MAX_INPUTS);
        assert!(slice.truncated);
        assert!(backward_slice(&ssa, VarId(1), 10, 10).is_err());
        assert!(backward_slice(&ssa, VarId(0), 0, 10).is_err());
    }
    #[test]
    fn dangling_dependencies_are_reported() {
        let ssa = graph(vec![Expr::Var(VarId(99))]);
        let slice = backward_slice(&ssa, VarId(0), 10, 10).unwrap();
        assert_eq!(
            slice.nodes[0].inputs[0].stop_reason,
            Some("missing_variable")
        );
        assert!(!slice.complete);
    }
}
