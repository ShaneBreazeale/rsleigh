//! Bounded, context-sensitive expression dependencies across direct helper calls.
use super::{backward_slice, SliceBlock, SliceNode, MAX_DEPTH, MAX_INPUTS, MAX_NODES};
use crate::{
    callgraph::{dependency_call, DependencyCall},
    fold::CallingConv,
    function_summary::{dependency_summary, DependencySummary},
    ir::{SsaCfg, VarId},
    provenance::OperationOrigin,
};
use pcode_ir::PcodeOp;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    rc::Rc,
};

pub trait Function {
    fn ssa(&self) -> &SsaCfg;
    fn operation(&self, origin: OperationOrigin) -> Option<&PcodeOp>;
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Limits {
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_call_depth: usize,
    pub max_functions: usize,
    pub max_work: usize,
}
impl Limits {
    pub fn bounded(self) -> Self {
        Self {
            max_nodes: self.max_nodes.min(MAX_NODES),
            max_depth: self.max_depth.min(MAX_DEPTH),
            max_call_depth: self.max_call_depth.min(8),
            max_functions: self.max_functions.min(32),
            max_work: self.max_work.min(1_000_000),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Reference {
    pub context_id: usize,
    pub var_id: u32,
}
#[derive(Debug, Serialize)]
pub struct Link {
    pub kind: &'static str,
    pub target: Reference,
    pub stop_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct Node {
    #[serde(flatten)]
    pub node: SliceNode,
    pub context_id: usize,
    pub function_address: u64,
    pub links: Vec<Link>,
    pub call: Option<DependencyCall>,
}
#[derive(Debug, Serialize)]
pub struct Context {
    pub id: usize,
    pub function_address: u64,
    pub caller_context: Option<usize>,
    pub call_origin: Option<OperationOrigin>,
    pub call_depth: usize,
}
#[derive(Debug, Serialize)]
pub struct Block {
    #[serde(flatten)]
    pub block: SliceBlock,
    pub context_id: usize,
}
#[derive(Debug, Default, Serialize)]
pub struct Metrics {
    pub functions_visited: usize,
    pub contexts_created: usize,
    pub traversal_work: usize,
}
#[derive(Debug, Serialize)]
pub struct Slice {
    pub root: u32,
    pub root_context: usize,
    pub nodes: Vec<Node>,
    pub blocks: Vec<Block>,
    pub contexts: Vec<Context>,
    pub complete: bool,
    pub truncated: bool,
    pub limits: Limits,
    pub metrics: Metrics,
    pub stops: Vec<String>,
}

struct Frame<F> {
    function: Rc<F>,
    caller_arguments: HashMap<usize, Reference>,
}

fn charge(result: &mut Slice, amount: usize) -> bool {
    if amount
        > result
            .limits
            .max_work
            .saturating_sub(result.metrics.traversal_work)
    {
        if !result.stops.iter().any(|s| s == "traversal_work_limit") {
            result.stops.push("traversal_work_limit".into());
        }
        result.truncated = true;
        return false;
    }
    result.metrics.traversal_work += amount;
    true
}

/// `load` must return snapshots for the same binary/build/options. The caller
/// owns caching and decoding budgets; this layer bounds traversal separately.
pub fn backward<F: Function>(
    address: u64,
    root: VarId,
    function: Rc<F>,
    cc: CallingConv,
    imports: &HashMap<u64, String>,
    limits: Limits,
    mut load: impl FnMut(u64) -> Result<Rc<F>, String>,
) -> Result<Slice, String> {
    let limits = limits.bounded();
    if limits.max_nodes == 0 || limits.max_functions == 0 {
        return Err("node and function limits must be positive".into());
    }
    let mut result = Slice {
        root: root.0,
        root_context: 0,
        nodes: vec![],
        blocks: vec![],
        contexts: vec![Context {
            id: 0,
            function_address: address,
            caller_context: None,
            call_origin: None,
            call_depth: 0,
        }],
        complete: false,
        truncated: false,
        limits,
        metrics: Metrics::default(),
        stops: vec![],
    };
    let mut frames = vec![Frame {
        function,
        caller_arguments: HashMap::new(),
    }];
    let mut summaries: HashMap<u64, DependencySummary> = HashMap::new();
    let mut functions = HashSet::from([address]);
    let mut visited = HashSet::new();
    let mut jobs = VecDeque::from([(
        Reference {
            context_id: 0,
            var_id: root.0,
        },
        0,
    )]);
    let mut inputs_used = 0;
    let mut block_seen = HashSet::new();
    let attempt =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
            while let Some((reference, depth)) = jobs.pop_front() {
                if visited.contains(&reference) {
                    continue;
                }
                if depth > limits.max_depth || result.nodes.len() >= limits.max_nodes {
                    result.truncated = true;
                    result.stops.push(
                        if depth > limits.max_depth {
                            "depth_limit"
                        } else {
                            "node_limit"
                        }
                        .into(),
                    );
                    continue;
                }
                let context_id = reference.context_id;
                let address = result.contexts[context_id].function_address;
                let function = Rc::clone(&frames[context_id].function);
                let ssa = function.ssa();
                // Account for scans needed by summaries and the local slice before
                // running them. Traversal work includes variables, statements,
                // nodes, edges, and function admissions; decode/SSA work is separate.
                let scan_work = ssa
                    .vars
                    .len()
                    .saturating_add(ssa.blocks.iter().map(|b| 1 + b.stmts.len()).sum::<usize>());
                if !charge(&mut result, scan_work) {
                    break;
                }
                summaries
                    .entry(address)
                    .or_insert_with(|| crate::budget::traversal(|| dependency_summary(ssa, cc)));
                let local = backward_slice(
                    ssa,
                    VarId(reference.var_id),
                    limits.max_nodes - result.nodes.len(),
                    limits.max_depth - depth,
                )?;
                result.truncated |= local.truncated;
                for block in local.blocks {
                    if block_seen.insert((context_id, block.id)) {
                        if result.blocks.len() < MAX_NODES {
                            result.blocks.push(Block { block, context_id });
                        } else {
                            result.truncated = true;
                            result.stops.push("block_limit".into());
                        }
                    }
                }
                for mut node in local.nodes {
                    let reference = Reference {
                        context_id,
                        var_id: node.var_id,
                    };
                    if !visited.insert(reference) {
                        continue;
                    }
                    if !charge(&mut result, 1 + node.inputs.len()) {
                        break;
                    }
                    node.depth += depth;
                    let available = MAX_INPUTS.saturating_sub(inputs_used);
                    if node.inputs.len() > available {
                        node.inputs.truncate(available);
                        result.truncated = true;
                        result.stops.push("input_limit".into());
                    }
                    inputs_used += node.inputs.len();
                    let slot = summaries[&address]
                        .parameters
                        .get(&VarId(node.var_id))
                        .copied();
                    let mut output = Node {
                        node,
                        context_id,
                        function_address: address,
                        links: vec![],
                        call: None,
                    };
                    if let Some(slot) = slot.filter(|_| context_id != 0) {
                        if let Some(&actual) = frames[context_id].caller_arguments.get(&slot) {
                            output.node.boundary = None;
                            // A bound stack parameter is supplied by the caller;
                            // its address is not another data dependency to follow.
                            output.node.inputs.clear();
                            output.node.inputs_total = 0;
                            output.links.push(Link {
                                kind: "argument_binding",
                                target: actual,
                                stop_reason: None,
                            });
                            jobs.push_back((actual, output.node.depth + 1));
                        } else {
                            output.node.boundary = Some("missing_call_argument");
                        }
                    } else if output.node.boundary == Some("unmodeled_call") {
                        match crate::budget::traversal(|| {
                            dependency_call(ssa, VarId(output.node.var_id), cc, imports, |origin| {
                                function.operation(origin)
                            })
                        }) {
                            Err(reason) => output.node.boundary = Some(reason),
                            Ok(call) => {
                                let target = call.target_address;
                                let mut reason = if call.import.is_some() {
                                    Some("external_call")
                                } else if target.is_none() {
                                    Some("unknown_call")
                                } else {
                                    None
                                };
                                if reason.is_none() && result.nodes.len() + 1 >= limits.max_nodes {
                                    reason = Some("node_limit");
                                }
                                let next_depth = result.contexts[context_id].call_depth + 1;
                                if reason.is_none() && next_depth > limits.max_call_depth {
                                    reason = Some("call_depth_limit");
                                }
                                let mut ancestor = Some(context_id);
                                while let Some(id) = ancestor {
                                    if target == Some(result.contexts[id].function_address)
                                        && reason.is_none()
                                    {
                                        reason = Some("recursion_limit");
                                    }
                                    ancestor = result.contexts[id].caller_context;
                                }
                                if let Some(target) = target.filter(|_| reason.is_none()) {
                                    if !functions.contains(&target)
                                        && functions.len() >= limits.max_functions
                                    {
                                        reason = Some("function_limit");
                                    } else if !charge(&mut result, 1) {
                                        reason = Some("traversal_work_limit");
                                    } else {
                                        functions.insert(target);
                                        match load(target) {
                                            Err(error) => {
                                                result.stops.push(error);
                                                reason = Some("function_unavailable");
                                            }
                                            Ok(callee) => {
                                                functions.insert(target);
                                                let callee_ssa = callee.ssa();
                                                let cost = callee_ssa.vars.len().saturating_add(
                                                    callee_ssa
                                                        .blocks
                                                        .iter()
                                                        .map(|b| 1 + b.stmts.len())
                                                        .sum::<usize>(),
                                                );
                                                if !charge(&mut result, cost) {
                                                    reason = Some("traversal_work_limit");
                                                } else {
                                                    let summary = summaries
                                                        .entry(target)
                                                        .or_insert_with(|| {
                                                            crate::budget::traversal(|| {
                                                                dependency_summary(callee_ssa, cc)
                                                            })
                                                        });
                                                    if summary.unsupported_side_effects {
                                                        reason = Some("unsupported_side_effects");
                                                    } else if summary.returns.is_empty() {
                                                        reason = Some("unsupported_return");
                                                    } else if result.contexts.len()
                                                        >= limits.max_nodes
                                                    {
                                                        reason = Some("context_limit");
                                                    } else {
                                                        let id = result.contexts.len();
                                                        result.contexts.push(Context {
                                                            id,
                                                            function_address: target,
                                                            caller_context: Some(context_id),
                                                            call_origin: Some(call.origin),
                                                            call_depth: next_depth,
                                                        });
                                                        frames.push(Frame {
                                                            function: callee,
                                                            caller_arguments: call
                                                                .arguments
                                                                .iter()
                                                                .map(|(&slot, value)| {
                                                                    (
                                                                        slot,
                                                                        Reference {
                                                                            context_id,
                                                                            var_id: value.0,
                                                                        },
                                                                    )
                                                                })
                                                                .collect(),
                                                        });
                                                        for &ret in &summary.returns {
                                                            let to = Reference {
                                                                context_id: id,
                                                                var_id: ret.0,
                                                            };
                                                            output.links.push(Link {
                                                                kind: "call_return",
                                                                target: to,
                                                                stop_reason: None,
                                                            });
                                                            jobs.push_back((
                                                                to,
                                                                output.node.depth + 1,
                                                            ));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if reason.is_some_and(|r| {
                                    matches!(
                                        r,
                                        "call_depth_limit"
                                            | "recursion_limit"
                                            | "function_limit"
                                            | "traversal_work_limit"
                                            | "context_limit"
                                            | "node_limit"
                                    )
                                }) {
                                    result.truncated = true;
                                }
                                output.node.boundary = reason;
                                output.call = Some(call);
                            }
                        }
                    }
                    if !charge(&mut result, output.links.len()) {
                        output.node.boundary = Some("traversal_work_limit");
                    }
                    let available = MAX_INPUTS.saturating_sub(inputs_used);
                    if output.links.len() > available {
                        output.links.truncate(available);
                        output.node.boundary = Some("input_limit");
                        result.truncated = true;
                    }
                    inputs_used += output.links.len();
                    result.nodes.push(output);
                    if inputs_used >= MAX_INPUTS {
                        result.truncated = true;
                        result.stops.push("input_limit".into());
                        break;
                    }
                }
            }
            Ok(())
        }));
    match attempt {
        Ok(result) => result?,
        Err(_) if crate::budget::stopped().is_some() => {
            result.stops.push("execution_limit".into());
            result.truncated = true;
        }
        Err(_) => return Err("dependency traversal panicked".into()),
    }
    let included: HashSet<_> = result
        .nodes
        .iter()
        .map(|n| Reference {
            context_id: n.context_id,
            var_id: n.node.var_id,
        })
        .collect();
    for node in &mut result.nodes {
        for input in &mut node.node.inputs {
            if input.stop_reason.is_none()
                && !included.contains(&Reference {
                    context_id: node.context_id,
                    var_id: input.var_id,
                })
            {
                input.stop_reason = Some("traversal_limit");
            }
        }
        for link in &mut node.links {
            if !included.contains(&link.target) {
                link.stop_reason = Some("traversal_limit");
            }
        }
    }
    result.metrics.functions_visited = functions.len();
    result.metrics.contexts_created = result.contexts.len();
    result.complete = !result.truncated
        && result.stops.is_empty()
        && result.nodes.iter().all(|n| {
            n.node.boundary.is_none()
                && n.node.inputs.iter().all(|i| i.stop_reason.is_none())
                && n.links.iter().all(|l| l.stop_reason.is_none())
        });
    Ok(result)
}
