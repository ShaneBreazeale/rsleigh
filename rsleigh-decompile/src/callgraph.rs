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

/// Build a `CallGraph` over a set of (FuncId, SSA) pairs. For each
/// function, walks every Stmt::Call and SsaTerminator::Call,
/// classifying the target as `Direct` / `Import` / `Indirect`.
///
/// `funcs` is the explored set: an edge to a FuncId NOT in `funcs`
/// is dropped (only intra-binary direct calls produce `Direct`
/// edges). Direct calls to addresses that match `imports` produce
/// `Import` edges; the import takes priority over direct because
/// PLT stub addresses live in the imports map but their bodies
/// (the stubs) aren't typically in the explored set.
pub fn build_call_graph(
    funcs: &[(FuncId, &crate::ir::SsaCfg)],
    imports: &HashMap<u64, String>,
) -> CallGraph {
    let mut g = CallGraph::new();
    let func_set: std::collections::HashSet<FuncId> =
        funcs.iter().map(|(id, _)| *id).collect();

    for (id, _) in funcs {
        g.add_function(*id);
    }

    for (caller_id, ssa) in funcs {
        for block in &ssa.blocks {
            for stmt in &block.stmts {
                if let crate::ir::Stmt::Call { target, .. } = stmt {
                    if let Some(edge) = classify_edge(target, &ssa.vars, imports, &func_set) {
                        g.add_edge(*caller_id, edge);
                    }
                }
            }
            if let crate::ir::SsaTerminator::Call { target, .. } = &block.terminator {
                if let Some(edge) = classify_edge(target, &ssa.vars, imports, &func_set) {
                    g.add_edge(*caller_id, edge);
                }
            }
        }
    }

    g
}

fn classify_edge(
    target: &crate::ir::CallTarget,
    vars: &[crate::ir::VarDef],
    imports: &HashMap<u64, String>,
    func_set: &std::collections::HashSet<FuncId>,
) -> Option<CallEdge> {
    let resolved = match target {
        crate::ir::CallTarget::Direct(addr) => Some(*addr),
        crate::ir::CallTarget::Indirect(vn) => resolve_via_vars(vn, vars, imports),
    };
    let edge = match resolved {
        Some(addr) => {
            if let Some(name) = imports.get(&addr) {
                CallEdge {
                    callee: CalleeRef::Import {
                        name: name.clone(),
                        addr,
                    },
                    call_site: 0,
                }
            } else if func_set.contains(&FuncId(addr)) {
                CallEdge {
                    callee: CalleeRef::Direct(FuncId(addr)),
                    call_site: 0,
                }
            } else {
                // Direct call to an address outside the explored
                // function set and outside imports — typically a
                // discovered-but-not-explored callee. v2 records
                // it as an opaque Indirect for now (could become a
                // ToBeExplored variant in v3).
                CallEdge {
                    callee: CalleeRef::Indirect,
                    call_site: 0,
                }
            }
        }
        None => CallEdge {
            callee: CalleeRef::Indirect,
            call_site: 0,
        },
    };
    Some(edge)
}

/// Lightweight stand-in for smt_explore::resolve_indirect_target.
/// Same algorithm — walk Var-chains and Load(Const) edges — but
/// returns the raw address regardless of imports membership so the
/// caller can decide between Direct/Import classification. Bounded
/// depth to avoid pathological IRs.
fn resolve_via_vars(
    target_vn: &pcode_ir::Varnode,
    vars: &[crate::ir::VarDef],
    imports: &HashMap<u64, String>,
) -> Option<u64> {
    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut stack: Vec<u32> = vars
        .iter()
        .rev()
        .filter(|d| d.varnode == *target_vn)
        .map(|d| d.id.0)
        .collect();
    while let Some(id) = stack.pop() {
        if !visited.insert(id) || visited.len() > 32 {
            continue;
        }
        let Some(def) = vars.get(id as usize) else {
            continue;
        };
        match &def.expr {
            crate::ir::Expr::Const(c, _) => {
                let candidate = c & 0x0FFF_FFFF;
                if imports.contains_key(c) {
                    return Some(*c);
                }
                if imports.contains_key(&candidate) {
                    return Some(candidate);
                }
                return Some(*c);
            }
            crate::ir::Expr::Var(inner) => stack.push(inner.0),
            crate::ir::Expr::Load(addr_var) => {
                if let Some(addr_def) = vars.get(addr_var.0 as usize) {
                    if let crate::ir::Expr::Const(slot, _) = addr_def.expr {
                        if imports.contains_key(&slot) {
                            return Some(slot);
                        }
                        let masked = slot & 0x0FFF_FFFF;
                        if imports.contains_key(&masked) {
                            return Some(masked);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
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

    use crate::ir::{
        BlockId, CallTarget, Diagnostic, Expr, InferredType, SsaBlock, SsaCfg,
        SsaTerminator, Stmt, VarDef, VarId,
    };
    use pcode_ir::Varnode;

    fn mk_var(id: u32, expr: Expr) -> VarDef {
        VarDef {
            id: VarId(id),
            varnode: Varnode::constant(0, 8),
            expr,
            size: 8,
            use_count: 1,
            param_name: None,
            call_return: false,
            inferred_type: InferredType::Unknown,
            display_type: None,
        }
    }

    fn ssa_with_terminator_call(target: CallTarget, vars: Vec<VarDef>) -> SsaCfg {
        SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0,
                stmts: vec![],
                terminator: SsaTerminator::Call {
                    target,
                    args: vec![],
                    out: None,
                    fallthrough: BlockId(1),
                },
            }, SsaBlock {
                id: BlockId(1),
                addr: 0x10,
                stmts: vec![],
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        }
    }

    #[test]
    fn build_emits_direct_edge_within_funcset() {
        // Function 0x1000 calls 0x2000 (also in func set) → Direct edge.
        let ssa_a = ssa_with_terminator_call(
            CallTarget::Direct(0x2000),
            vec![mk_var(0, Expr::Const(0, 8))],
        );
        let ssa_b = ssa_with_terminator_call(
            CallTarget::Direct(0x3000),
            vec![mk_var(0, Expr::Const(0, 8))],
        );
        let funcs = vec![
            (FuncId(0x1000), &ssa_a),
            (FuncId(0x2000), &ssa_b),
        ];
        let imports: HashMap<u64, String> = HashMap::new();
        let g = build_call_graph(&funcs, &imports);

        let edges_a = g.edges.get(&FuncId(0x1000)).unwrap();
        assert_eq!(edges_a.len(), 1);
        assert!(matches!(edges_a[0].callee, CalleeRef::Direct(FuncId(0x2000))));
        assert_eq!(g.direct_successors(FuncId(0x1000)), vec![FuncId(0x2000)]);
    }

    #[test]
    fn build_emits_import_edge_when_target_in_imports() {
        // Direct(0x125d8) where imports[0x125d8] = "recvfrom" → Import.
        let ssa = ssa_with_terminator_call(
            CallTarget::Direct(0x125d8),
            vec![mk_var(0, Expr::Const(0, 8))],
        );
        let funcs = vec![(FuncId(0x1000), &ssa)];
        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "recvfrom".to_string());
        let g = build_call_graph(&funcs, &imports);

        let edges = g.edges.get(&FuncId(0x1000)).unwrap();
        assert_eq!(edges.len(), 1);
        match &edges[0].callee {
            CalleeRef::Import { name, addr } => {
                assert_eq!(name, "recvfrom");
                assert_eq!(*addr, 0x125d8);
            }
            other => panic!("expected Import, got {other:?}"),
        }
    }

    #[test]
    fn build_classifies_unknown_direct_as_indirect() {
        // Direct(0x9000) where 0x9000 isn't in funcs and isn't an
        // import → Indirect (opaque). Future v3 may add a
        // ToBeExplored variant.
        let ssa = ssa_with_terminator_call(
            CallTarget::Direct(0x9000),
            vec![mk_var(0, Expr::Const(0, 8))],
        );
        let funcs = vec![(FuncId(0x1000), &ssa)];
        let imports: HashMap<u64, String> = HashMap::new();
        let g = build_call_graph(&funcs, &imports);

        let edges = g.edges.get(&FuncId(0x1000)).unwrap();
        assert!(matches!(edges[0].callee, CalleeRef::Indirect));
    }

    #[test]
    fn build_handles_ssa_with_no_calls() {
        let ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0,
                stmts: vec![],
                terminator: SsaTerminator::Return(None),
            }],
            vars: vec![mk_var(0, Expr::Const(0, 8))],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let funcs = vec![(FuncId(0x1000), &ssa)];
        let imports: HashMap<u64, String> = HashMap::new();
        let g = build_call_graph(&funcs, &imports);
        assert_eq!(g.funcs, vec![FuncId(0x1000)]);
        assert!(g.edges.get(&FuncId(0x1000)).unwrap().is_empty());
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
