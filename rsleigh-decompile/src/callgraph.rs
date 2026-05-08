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
    build_call_graph_with_image(funcs, imports, None)
}

/// Same as `build_call_graph` but with an optional `ImageView` so
/// vtable / function-pointer-table indirect calls can be resolved
/// to multiple synthetic Direct edges (v4.W9). When `image` is
/// `None` behaviour is identical to the legacy entrypoint.
pub fn build_call_graph_with_image(
    funcs: &[(FuncId, &crate::ir::SsaCfg)],
    imports: &HashMap<u64, String>,
    image: Option<ImageView<'_>>,
) -> CallGraph {
    const VTABLE_CAP: usize = 64;

    let mut g = CallGraph::new();
    let func_set: std::collections::HashSet<FuncId> =
        funcs.iter().map(|(id, _)| *id).collect();

    for (id, _) in funcs {
        g.add_function(*id);
    }

    for (caller_id, ssa) in funcs {
        // Per-caller dedup against (call_site, callee). Avoids
        // emitting multiple identical edges when both a stmt and
        // a terminator reference the same target, or when the
        // vtable resolver returns an entry already present from a
        // direct call elsewhere in the function.
        let mut seen: std::collections::HashSet<(u64, CalleeRef)> =
            std::collections::HashSet::new();
        for block in &ssa.blocks {
            for stmt in &block.stmts {
                if let crate::ir::Stmt::Call { target, .. } = stmt {
                    let edges = classify_edges(
                        target,
                        &ssa.vars,
                        imports,
                        &func_set,
                        image,
                        VTABLE_CAP,
                    );
                    for e in edges {
                        let key = (e.call_site, e.callee.clone());
                        if seen.insert(key) {
                            g.add_edge(*caller_id, e);
                        }
                    }
                }
            }
            if let crate::ir::SsaTerminator::Call { target, .. } = &block.terminator {
                let edges = classify_edges(
                    target,
                    &ssa.vars,
                    imports,
                    &func_set,
                    image,
                    VTABLE_CAP,
                );
                for e in edges {
                    let key = (e.call_site, e.callee.clone());
                    if seen.insert(key) {
                        g.add_edge(*caller_id, e);
                    }
                }
            }
        }
    }

    g
}

fn classify_edges(
    target: &crate::ir::CallTarget,
    vars: &[crate::ir::VarDef],
    imports: &HashMap<u64, String>,
    func_set: &std::collections::HashSet<FuncId>,
    image: Option<ImageView<'_>>,
    vtable_cap: usize,
) -> Vec<CallEdge> {
    let classify_addr = |addr: u64| -> CalleeRef {
        if let Some(name) = imports.get(&addr) {
            CalleeRef::Import {
                name: name.clone(),
                addr,
            }
        } else if func_set.contains(&FuncId(addr)) {
            CalleeRef::Direct(FuncId(addr))
        } else {
            CalleeRef::Indirect
        }
    };

    let resolved = match target {
        crate::ir::CallTarget::Direct(addr) => Some(*addr),
        crate::ir::CallTarget::Indirect(vn) => resolve_via_vars(vn, vars, imports),
    };
    if let Some(addr) = resolved {
        return vec![CallEdge {
            callee: classify_addr(addr),
            call_site: 0,
        }];
    }

    // Indirect with no scalar resolution — try the vtable resolver
    // when an image is available.
    if let (crate::ir::CallTarget::Indirect(vn), Some(img)) = (target, image) {
        let entries = resolve_vtable_targets(vn, vars, img, vtable_cap);
        if !entries.is_empty() {
            return entries
                .into_iter()
                .map(|addr| CallEdge {
                    callee: classify_addr(addr),
                    call_site: 0,
                })
                .collect();
        }
    }

    vec![CallEdge {
        callee: CalleeRef::Indirect,
        call_site: 0,
    }]
}

/// View over a binary's loaded segments, used to read constant
/// pointer tables (vtables / function-pointer dispatch arrays)
/// while resolving indirect calls. Segments use the same
/// `(va, size, file_offset)` schema as the rest of the CLI; data
/// is the raw image bytes.
#[derive(Clone, Copy)]
pub struct ImageView<'a> {
    pub data: &'a [u8],
    pub segs: &'a [(u64, u64, u64)],
    /// Pointer width: 4 (32-bit) or 8 (64-bit).
    pub ptr_size: u8,
}

impl<'a> ImageView<'a> {
    fn va_to_offset(&self, va: u64) -> Option<usize> {
        for (seg_va, size, file_off) in self.segs {
            if va >= *seg_va && va < seg_va.saturating_add(*size) {
                let delta = va - *seg_va;
                let off = file_off.saturating_add(delta) as usize;
                return Some(off);
            }
        }
        None
    }

    /// Little-endian pointer read at `va`. Returns None when `va`
    /// is outside any mapped segment or runs off the image.
    pub fn read_ptr(&self, va: u64) -> Option<u64> {
        let off = self.va_to_offset(va)?;
        match self.ptr_size {
            4 => self
                .data
                .get(off..off + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64),
            8 => self.data.get(off..off + 8).map(|b| {
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }),
            _ => None,
        }
    }
}

/// Resolve an indirect call shaped like a vtable / function-pointer
/// dispatch table dereference and enumerate its entries.
///
/// Two patterns are recognised:
///
///   * Function-pointer table (single indirection):
///     `Load(Add(Const(table_va), idx * stride))`
///
///   * C++ vtable through object slot (two indirections):
///     `Load(Add(Load(Const(slot_va)), idx * stride))`,
///     where `*slot_va` resolves to `vtable_va` at link time.
///
/// `idx * stride` accepts either `Mult(_, Const(stride))` or
/// `Lsl(_, Const(log2_stride))`; `stride` must equal `ptr_size`.
///
/// Enumerates up to `cap` entries; stops on a NULL slot or a
/// pointer that falls outside any mapped segment. Duplicates are
/// suppressed.
pub fn resolve_vtable_targets(
    target_vn: &pcode_ir::Varnode,
    vars: &[crate::ir::VarDef],
    image: ImageView<'_>,
    cap: usize,
) -> Vec<u64> {
    use crate::ir::{BinOpKind, Expr};

    fn drill_var<'b>(
        mut def: Option<&'b crate::ir::VarDef>,
        vars: &'b [crate::ir::VarDef],
    ) -> Option<&'b crate::ir::VarDef> {
        let mut budget = 16usize;
        while let Some(d) = def {
            match &d.expr {
                Expr::Var(inner) => {
                    if budget == 0 {
                        return None;
                    }
                    budget -= 1;
                    def = vars.get(inner.0 as usize);
                }
                _ => break,
            }
        }
        def
    }

    let target_def = match drill_var(
        vars.iter().rev().find(|d| d.varnode == *target_vn),
        vars,
    ) {
        Some(d) => d,
        None => return Vec::new(),
    };
    let outer_addr = match &target_def.expr {
        Expr::Load(v) => v.0,
        _ => return Vec::new(),
    };
    let outer_addr_def = match drill_var(vars.get(outer_addr as usize), vars) {
        Some(d) => d,
        None => return Vec::new(),
    };
    let (lhs_id, rhs_id) = match outer_addr_def.expr {
        Expr::BinOp(BinOpKind::Add, a, b) => (a.0, b.0),
        _ => return Vec::new(),
    };

    let stride = image.ptr_size as u64;

    // One side must be the table base; the other must be a scaled
    // index whose stride matches the pointer width.
    let resolve_table_base = |id: u32| -> Option<u64> {
        let d = drill_var(vars.get(id as usize), vars)?;
        match &d.expr {
            Expr::Const(c, _) => Some(*c),
            Expr::Load(inner) => {
                let inner_def = drill_var(vars.get(inner.0 as usize), vars)?;
                if let Expr::Const(slot_va, _) = inner_def.expr {
                    image.read_ptr(slot_va)
                } else {
                    None
                }
            }
            _ => None,
        }
    };
    let is_index_term = |id: u32| -> bool {
        let Some(d) = drill_var(vars.get(id as usize), vars) else {
            return false;
        };
        match d.expr {
            Expr::BinOp(BinOpKind::Mult, _, k) => {
                matches!(vars.get(k.0 as usize).map(|x| &x.expr),
                    Some(Expr::Const(c, _)) if *c == stride)
            }
            Expr::BinOp(BinOpKind::Lsl, _, k) => {
                let log2 = match stride {
                    4 => 2,
                    8 => 3,
                    _ => return false,
                };
                matches!(vars.get(k.0 as usize).map(|x| &x.expr),
                    Some(Expr::Const(c, _)) if *c == log2)
            }
            _ => false,
        }
    };

    let table_va = if is_index_term(rhs_id) {
        resolve_table_base(lhs_id)
    } else if is_index_term(lhs_id) {
        resolve_table_base(rhs_id)
    } else {
        None
    };
    let Some(table_va) = table_va else {
        return Vec::new();
    };

    let mut out: Vec<u64> = Vec::new();
    for i in 0..cap as u64 {
        let entry_va = table_va.wrapping_add(i * stride);
        match image.read_ptr(entry_va) {
            Some(0) => break,
            Some(p) => {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
            None => break,
        }
    }
    out
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

    fn mk_var_with_vn(id: u32, expr: Expr, vn: pcode_ir::Varnode) -> VarDef {
        let mut d = mk_var(id, expr);
        d.varnode = vn;
        d
    }

    #[test]
    fn vtable_resolver_enumerates_funcptr_table() {
        // table at va=0x4000, size 32 bytes (4 entries × 8). entries
        // = [0x1000, 0x2000, 0x3000, 0]. ptr-size 8.
        let mut data = vec![0u8; 0x40];
        for (i, fp) in [0x1000u64, 0x2000, 0x3000, 0].iter().enumerate() {
            data[i * 8..i * 8 + 8].copy_from_slice(&fp.to_le_bytes());
        }
        let segs: Vec<(u64, u64, u64)> = vec![(0x4000, 0x40, 0)];
        let image = ImageView {
            data: &data,
            segs: &segs,
            ptr_size: 8,
        };

        // Build SSA: target = Load(Add(Const(0x4000), Mult(idx, Const(8))))
        let target_vn = Varnode::register(0x100, 8);
        let vars = vec![
            mk_var(0, Expr::Const(0x4000, 8)),         // 0: table base
            mk_var(1, Expr::Const(8, 8)),              // 1: stride
            mk_var(2, Expr::Const(7, 8)),              // 2: idx (any)
            mk_var(3, Expr::BinOp(crate::ir::BinOpKind::Mult, VarId(2), VarId(1))), // 3: idx*stride
            mk_var(4, Expr::BinOp(crate::ir::BinOpKind::Add, VarId(0), VarId(3))),  // 4: addr
            mk_var_with_vn(5, Expr::Load(VarId(4)), target_vn.clone()),             // 5: target
        ];

        let out = resolve_vtable_targets(&target_vn, &vars, image, 64);
        assert_eq!(out, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn vtable_resolver_handles_lsl_index() {
        // target = Load(Add(idx<<3, Const(0x4000))) — operands flipped.
        let mut data = vec![0u8; 0x10];
        data[0..8].copy_from_slice(&0xdeadbeefu64.to_le_bytes());
        let segs: Vec<(u64, u64, u64)> = vec![(0x4000, 0x10, 0)];
        let image = ImageView {
            data: &data,
            segs: &segs,
            ptr_size: 8,
        };
        let target_vn = Varnode::register(0x200, 8);
        let vars = vec![
            mk_var(0, Expr::Const(0x4000, 8)),
            mk_var(1, Expr::Const(3, 8)), // log2(8)
            mk_var(2, Expr::Const(0, 8)), // idx
            mk_var(3, Expr::BinOp(crate::ir::BinOpKind::Lsl, VarId(2), VarId(1))),
            mk_var(4, Expr::BinOp(crate::ir::BinOpKind::Add, VarId(3), VarId(0))),
            mk_var_with_vn(5, Expr::Load(VarId(4)), target_vn.clone()),
        ];
        let out = resolve_vtable_targets(&target_vn, &vars, image, 64);
        assert_eq!(out, vec![0xdeadbeef]);
    }

    #[test]
    fn vtable_resolver_two_indirection_through_slot() {
        // slot_va = 0x3000 holds vtable_va = 0x5000.
        // vtable: [0xAA, 0xBB, 0].
        let mut data = vec![0u8; 0x60];
        // segment 1 is slot at 0x3000 → file_off 0
        data[0..8].copy_from_slice(&0x5000u64.to_le_bytes());
        // segment 2 is vtable at 0x5000 → file_off 0x10
        data[0x10..0x18].copy_from_slice(&0xAAu64.to_le_bytes());
        data[0x18..0x20].copy_from_slice(&0xBBu64.to_le_bytes());
        // 0x20..0x28 left zero
        let segs: Vec<(u64, u64, u64)> = vec![
            (0x3000, 0x10, 0),
            (0x5000, 0x40, 0x10),
        ];
        let image = ImageView {
            data: &data,
            segs: &segs,
            ptr_size: 8,
        };
        let target_vn = Varnode::register(0x300, 8);
        let vars = vec![
            mk_var(0, Expr::Const(0x3000, 8)),       // slot const
            mk_var(1, Expr::Load(VarId(0))),         // vtable ptr
            mk_var(2, Expr::Const(8, 8)),
            mk_var(3, Expr::Const(2, 8)),
            mk_var(4, Expr::BinOp(crate::ir::BinOpKind::Mult, VarId(3), VarId(2))),
            mk_var(5, Expr::BinOp(crate::ir::BinOpKind::Add, VarId(1), VarId(4))),
            mk_var_with_vn(6, Expr::Load(VarId(5)), target_vn.clone()),
        ];
        let out = resolve_vtable_targets(&target_vn, &vars, image, 64);
        assert_eq!(out, vec![0xAA, 0xBB]);
    }

    #[test]
    fn build_with_image_emits_synthetic_direct_edges_per_vtable_entry() {
        // table at 0x4000 = [0x2000, 0x3000, 0]. Both entries are
        // also explored functions, so each becomes a Direct edge.
        let mut data = vec![0u8; 0x40];
        data[0..8].copy_from_slice(&0x2000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        let segs: Vec<(u64, u64, u64)> = vec![(0x4000, 0x40, 0)];
        let image = ImageView {
            data: &data,
            segs: &segs,
            ptr_size: 8,
        };

        let target_vn = Varnode::register(0x600, 8);
        let vars = vec![
            mk_var(0, Expr::Const(0x4000, 8)),
            mk_var(1, Expr::Const(8, 8)),
            mk_var(2, Expr::Const(0, 8)),
            mk_var(3, Expr::BinOp(crate::ir::BinOpKind::Mult, VarId(2), VarId(1))),
            mk_var(4, Expr::BinOp(crate::ir::BinOpKind::Add, VarId(0), VarId(3))),
            mk_var_with_vn(5, Expr::Load(VarId(4)), target_vn.clone()),
        ];
        let ssa = SsaCfg {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    addr: 0,
                    stmts: vec![],
                    terminator: SsaTerminator::Call {
                        target: CallTarget::Indirect(target_vn),
                        args: vec![],
                        out: None,
                        fallthrough: BlockId(1),
                    },
                },
                SsaBlock {
                    id: BlockId(1),
                    addr: 0x10,
                    stmts: vec![],
                    terminator: SsaTerminator::Return(None),
                },
            ],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let stub_b = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x2000,
                stmts: vec![],
                terminator: SsaTerminator::Return(None),
            }],
            vars: vec![],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let stub_c = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x3000,
                stmts: vec![],
                terminator: SsaTerminator::Return(None),
            }],
            vars: vec![],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let funcs = vec![
            (FuncId(0x1000), &ssa),
            (FuncId(0x2000), &stub_b),
            (FuncId(0x3000), &stub_c),
        ];
        let imports: HashMap<u64, String> = HashMap::new();
        let g = build_call_graph_with_image(&funcs, &imports, Some(image));

        let edges = g.edges.get(&FuncId(0x1000)).unwrap();
        let direct: Vec<FuncId> = edges
            .iter()
            .filter_map(|e| match e.callee {
                CalleeRef::Direct(f) => Some(f),
                _ => None,
            })
            .collect();
        assert!(direct.contains(&FuncId(0x2000)));
        assert!(direct.contains(&FuncId(0x3000)));
        assert_eq!(direct.len(), 2);
    }

    #[test]
    fn build_with_image_falls_back_to_indirect_when_no_match() {
        // Indirect target with no var trail and no vtable shape →
        // legacy Indirect classification, image present or not.
        let target_vn = Varnode::register(0x700, 8);
        let ssa = SsaCfg {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    addr: 0,
                    stmts: vec![],
                    terminator: SsaTerminator::Call {
                        target: CallTarget::Indirect(target_vn),
                        args: vec![],
                        out: None,
                        fallthrough: BlockId(1),
                    },
                },
                SsaBlock {
                    id: BlockId(1),
                    addr: 0x10,
                    stmts: vec![],
                    terminator: SsaTerminator::Return(None),
                },
            ],
            vars: vec![],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let funcs = vec![(FuncId(0x1000), &ssa)];
        let imports: HashMap<u64, String> = HashMap::new();
        let data: Vec<u8> = vec![];
        let segs: Vec<(u64, u64, u64)> = vec![];
        let image = ImageView {
            data: &data,
            segs: &segs,
            ptr_size: 8,
        };
        let g = build_call_graph_with_image(&funcs, &imports, Some(image));
        let edges = g.edges.get(&FuncId(0x1000)).unwrap();
        assert_eq!(edges.len(), 1);
        assert!(matches!(edges[0].callee, CalleeRef::Indirect));
    }

    #[test]
    fn vtable_resolver_caps_entries() {
        // Table of 100 non-null pointers; cap=8 limits output.
        let mut data = vec![0u8; 100 * 8];
        for i in 0..100 {
            let v = (0x1000 + i as u64) * 0x10;
            data[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        let segs: Vec<(u64, u64, u64)> = vec![(0x4000, 100 * 8, 0)];
        let image = ImageView {
            data: &data,
            segs: &segs,
            ptr_size: 8,
        };
        let target_vn = Varnode::register(0x400, 8);
        let vars = vec![
            mk_var(0, Expr::Const(0x4000, 8)),
            mk_var(1, Expr::Const(8, 8)),
            mk_var(2, Expr::Const(0, 8)),
            mk_var(3, Expr::BinOp(crate::ir::BinOpKind::Mult, VarId(2), VarId(1))),
            mk_var(4, Expr::BinOp(crate::ir::BinOpKind::Add, VarId(0), VarId(3))),
            mk_var_with_vn(5, Expr::Load(VarId(4)), target_vn.clone()),
        ];
        let out = resolve_vtable_targets(&target_vn, &vars, image, 8);
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn vtable_resolver_rejects_wrong_stride() {
        // Stride 4 in SSA but ptr_size 8 → should not match.
        let segs: Vec<(u64, u64, u64)> = vec![(0x4000, 0x40, 0)];
        let data = vec![0u8; 0x40];
        let image = ImageView {
            data: &data,
            segs: &segs,
            ptr_size: 8,
        };
        let target_vn = Varnode::register(0x500, 8);
        let vars = vec![
            mk_var(0, Expr::Const(0x4000, 8)),
            mk_var(1, Expr::Const(4, 8)), // wrong stride
            mk_var(2, Expr::Const(0, 8)),
            mk_var(3, Expr::BinOp(crate::ir::BinOpKind::Mult, VarId(2), VarId(1))),
            mk_var(4, Expr::BinOp(crate::ir::BinOpKind::Add, VarId(0), VarId(3))),
            mk_var_with_vn(5, Expr::Load(VarId(4)), target_vn.clone()),
        ];
        let out = resolve_vtable_targets(&target_vn, &vars, image, 64);
        assert!(out.is_empty());
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
