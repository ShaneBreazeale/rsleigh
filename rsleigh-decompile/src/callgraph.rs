//! Static call graph + Tarjan SCC for inter-procedural taint
//! analysis (smt-backend v2).
//!
//! v0/v1 of `--smt-explore` operated per-function: the path
//! collector walked one SSA at a time and bailed at any call. v2
//! propagates taint across function boundaries by computing a
//! per-function summary (`smt_explore::FunctionSummary`) bottom-up
//! over the call graph. This module owns the call-graph
//! construction, cycle handling, and reverse-topological iteration
//! order summary generation depends on.
//!
//! Call edges come from the SSA's `Stmt::Call` and
//! `SsaTerminator::Call` `target` field. `CallTarget::Direct(addr)`
//! resolves to either a known FuncId (intra-binary call) or an
//! import name (libc / system call). `CallTarget::Indirect` either
//! resolves through `smt_explore::resolve_indirect_target` or stays
//! opaque.
//!
//! SCCs with more than one node represent recursion. v2 treats them
//! as opaque single nodes — no summary, no inter-procedural
//! propagation across the cycle. That's a known precision loss; v3
//! may compute fixed-point summaries over an SCC.

use std::collections::HashMap;

/// Stable identifier for one function in the call graph. Wraps the
/// function's entry-point virtual address so callers can join back
/// to the SSA / disasm pipeline without an additional translation
/// table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FuncId(pub u64);

/// What a Call edge points at.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CalleeRef {
    /// Intra-binary call to a function in this graph.
    Direct(FuncId),
    /// Library / kernel-level call surfaced by the import map.
    /// Carries the resolved name (`"recv"`, `"strcpy"`, etc.) and
    /// the imports-map address that surfaced it.
    Import { name: String, addr: u64 },
    /// Indirect call we couldn't resolve. Treated as a black box
    /// for summary generation.
    Indirect,
}

/// Edge from caller → callee. Caller is implicit in the
/// `CallGraph::edges` keying; this struct just carries the callee
/// plus per-edge metadata the summary builder may need (call-site
/// PC, arg list, return-value VarId).
#[derive(Debug, Clone)]
pub struct CallEdge {
    pub callee: CalleeRef,
    /// Address of the calling instruction (PC of the BL/CALL).
    /// Useful for grouping multiple calls to the same callee.
    pub call_site: u64,
}

/// Static call graph over a set of functions. Built once per
/// binary, consumed by the summary builder.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// Every function in the explored set. The graph may have
    /// edges to functions NOT in `funcs` (e.g. library imports);
    /// those are surfaced as `CalleeRef::Import` and don't get
    /// FuncId entries.
    pub funcs: Vec<FuncId>,
    /// Per-caller edge list, keyed by FuncId.
    pub edges: HashMap<FuncId, Vec<CallEdge>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function(&mut self, id: FuncId) {
        if !self.funcs.contains(&id) {
            self.funcs.push(id);
            self.edges.entry(id).or_default();
        }
    }

    pub fn add_edge(&mut self, caller: FuncId, edge: CallEdge) {
        self.edges.entry(caller).or_default().push(edge);
    }

    /// Direct-call successors of `id`. Drops Import / Indirect
    /// edges — they're not in the graph's FuncId space.
    pub fn direct_successors(&self, id: FuncId) -> Vec<FuncId> {
        let mut out = Vec::new();
        if let Some(edges) = self.edges.get(&id) {
            for e in edges {
                if let CalleeRef::Direct(target) = e.callee {
                    if !out.contains(&target) {
                        out.push(target);
                    }
                }
            }
        }
        out
    }
}

/// Strongly connected components of the direct-call subgraph.
/// `components` is a Vec<Vec<FuncId>>; each inner Vec is one SCC.
/// Trivial SCCs (single node, no self-loop) are still emitted as a
/// 1-element Vec so the consumer can iterate uniformly.
///
/// Order: REVERSE TOPOLOGICAL on the condensation — leaves first,
/// roots last. This is the order the summary builder needs.
#[derive(Debug)]
pub struct Sccs {
    pub components: Vec<Vec<FuncId>>,
}

impl Sccs {
    /// True if the SCC containing `id` has more than one member,
    /// or is a single node with a self-loop. v2 treats these as
    /// opaque — no summary computed.
    pub fn is_recursive(&self, id: FuncId, graph: &CallGraph) -> bool {
        for scc in &self.components {
            if scc.contains(&id) {
                if scc.len() > 1 {
                    return true;
                }
                // Self-loop check
                if let Some(edges) = graph.edges.get(&id) {
                    return edges
                        .iter()
                        .any(|e| matches!(e.callee, CalleeRef::Direct(t) if t == id));
                }
                return false;
            }
        }
        false
    }
}

/// Compute SCCs of the call graph's direct-call subgraph using
/// Tarjan's algorithm. Output ordering = reverse topological (leaf
/// SCCs first), so a bottom-up summary builder can iterate
/// `components` in order.
pub fn tarjan_sccs(graph: &CallGraph) -> Sccs {
    let mut state = TarjanState {
        index_counter: 0,
        stack: Vec::new(),
        indices: HashMap::new(),
        lowlinks: HashMap::new(),
        on_stack: HashMap::new(),
        components: Vec::new(),
    };
    for id in &graph.funcs {
        if !state.indices.contains_key(id) {
            tarjan_visit(*id, graph, &mut state);
        }
    }
    // Tarjan emits SCCs in reverse topological order naturally
    // (leaves first), which is exactly what summary generation
    // needs. No further sorting required.
    Sccs {
        components: state.components,
    }
}

struct TarjanState {
    index_counter: u32,
    stack: Vec<FuncId>,
    indices: HashMap<FuncId, u32>,
    lowlinks: HashMap<FuncId, u32>,
    on_stack: HashMap<FuncId, bool>,
    components: Vec<Vec<FuncId>>,
}

fn tarjan_visit(id: FuncId, graph: &CallGraph, state: &mut TarjanState) {
    state.indices.insert(id, state.index_counter);
    state.lowlinks.insert(id, state.index_counter);
    state.index_counter += 1;
    state.stack.push(id);
    state.on_stack.insert(id, true);

    for succ in graph.direct_successors(id) {
        if !state.indices.contains_key(&succ) {
            tarjan_visit(succ, graph, state);
            let succ_low = state.lowlinks[&succ];
            let cur_low = state.lowlinks[&id];
            state.lowlinks.insert(id, cur_low.min(succ_low));
        } else if *state.on_stack.get(&succ).unwrap_or(&false) {
            let succ_idx = state.indices[&succ];
            let cur_low = state.lowlinks[&id];
            state.lowlinks.insert(id, cur_low.min(succ_idx));
        }
    }

    if state.lowlinks[&id] == state.indices[&id] {
        let mut component = Vec::new();
        loop {
            let w = state.stack.pop().expect("non-empty stack at SCC root");
            state.on_stack.insert(w, false);
            component.push(w);
            if w == id {
                break;
            }
        }
        state.components.push(component);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_from_edges(edges: &[(u64, u64)]) -> CallGraph {
        let mut g = CallGraph::new();
        let mut seen = std::collections::HashSet::new();
        for &(a, b) in edges {
            seen.insert(a);
            seen.insert(b);
        }
        let mut sorted: Vec<u64> = seen.into_iter().collect();
        sorted.sort();
        for a in sorted {
            g.add_function(FuncId(a));
        }
        for &(a, b) in edges {
            g.add_edge(
                FuncId(a),
                CallEdge {
                    callee: CalleeRef::Direct(FuncId(b)),
                    call_site: 0,
                },
            );
        }
        g
    }

    #[test]
    fn linear_chain_yields_n_singletons() {
        // a → b → c → d. Four singletons in reverse-topo order.
        let g = graph_from_edges(&[(1, 2), (2, 3), (3, 4)]);
        let sccs = tarjan_sccs(&g);
        assert_eq!(sccs.components.len(), 4);
        // Leaves first: 4, then 3, then 2, then 1.
        assert_eq!(sccs.components[0], vec![FuncId(4)]);
        assert_eq!(sccs.components[3], vec![FuncId(1)]);
        for c in &sccs.components {
            assert!(!sccs.is_recursive(c[0], &g));
        }
    }

    #[test]
    fn diamond_collapses_to_singletons() {
        // a → b, a → c, b → d, c → d.
        let g = graph_from_edges(&[(1, 2), (1, 3), (2, 4), (3, 4)]);
        let sccs = tarjan_sccs(&g);
        assert_eq!(sccs.components.len(), 4);
        // Leaf 4 must come before its parents.
        let leaf_idx = sccs
            .components
            .iter()
            .position(|c| c.contains(&FuncId(4)))
            .unwrap();
        let root_idx = sccs
            .components
            .iter()
            .position(|c| c.contains(&FuncId(1)))
            .unwrap();
        assert!(leaf_idx < root_idx, "leaf 4 must precede root 1");
    }

    #[test]
    fn self_loop_is_recursive() {
        // a → a only.
        let g = graph_from_edges(&[(1, 1)]);
        let sccs = tarjan_sccs(&g);
        assert_eq!(sccs.components.len(), 1);
        assert_eq!(sccs.components[0], vec![FuncId(1)]);
        assert!(sccs.is_recursive(FuncId(1), &g));
    }

    #[test]
    fn mutual_recursion_collapses_to_one_scc() {
        // a → b → a (mutual recursion). One SCC of two members.
        let g = graph_from_edges(&[(1, 2), (2, 1)]);
        let sccs = tarjan_sccs(&g);
        assert_eq!(sccs.components.len(), 1);
        assert_eq!(sccs.components[0].len(), 2);
        assert!(sccs.is_recursive(FuncId(1), &g));
        assert!(sccs.is_recursive(FuncId(2), &g));
    }

    #[test]
    fn three_node_cycle_collapses() {
        // a → b → c → a.
        let g = graph_from_edges(&[(1, 2), (2, 3), (3, 1)]);
        let sccs = tarjan_sccs(&g);
        assert_eq!(sccs.components.len(), 1);
        assert_eq!(sccs.components[0].len(), 3);
        for f in [1u64, 2, 3] {
            assert!(sccs.is_recursive(FuncId(f), &g));
        }
    }

    #[test]
    fn separate_components_emit_separately() {
        // Two disjoint 2-node cycles: {1↔2} and {3↔4}.
        let g = graph_from_edges(&[(1, 2), (2, 1), (3, 4), (4, 3)]);
        let sccs = tarjan_sccs(&g);
        assert_eq!(sccs.components.len(), 2);
        for scc in &sccs.components {
            assert_eq!(scc.len(), 2);
        }
    }

    #[test]
    fn import_edges_dont_create_funcid() {
        // Adding an Import callee shouldn't pollute funcs.
        let mut g = CallGraph::new();
        g.add_function(FuncId(1));
        g.add_edge(
            FuncId(1),
            CallEdge {
                callee: CalleeRef::Import {
                    name: "recv".to_string(),
                    addr: 0x1000,
                },
                call_site: 0x2000,
            },
        );
        assert_eq!(g.funcs, vec![FuncId(1)]);
        assert!(g.direct_successors(FuncId(1)).is_empty());
    }
}
