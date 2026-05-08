//! Per-function taint summaries for inter-procedural SMT analysis
//! (smt-backend v2).
//!
//! v0/v1 of `--smt-explore` could only identify Source→Sink pairs
//! when both calls lived in the same function. Real router-firmware
//! flows are inter-procedural: `recv() in handler() → helper(buf) →
//! strcpy() in helper()`. A v2 summary captures, per function:
//!
//!   * Which Sink APIs the function invokes, and which of the
//!     function's own arg slots feed each sink.
//!   * Which Source APIs the function invokes, and which of its
//!     arg slots receive the tainted output.
//!
//! With a summary in hand, the SMT explorer at the CALLER site can
//! treat `caller(tainted_arg) → helper(...) → strcpy(...)` the same
//! as a direct strcpy call by mapping caller's tainted arg into
//! helper's parameter slot. This V4 commit ships only the
//! INTRA-FUNCTION summary build; V5 chains summaries across calls.

use std::collections::HashMap;

use crate::callgraph::{CallGraph, FuncId, Sccs};
use crate::ir::{CallTarget, SsaCfg, SsaTerminator, Stmt, VarId};
use crate::smt_explore::{AbiSlot, SinkSpec, SourceSpec, DEFAULT_SINKS, DEFAULT_SOURCES};

/// One Sink invocation observed inside a function. The summary
/// records which of the function's own arg slots flow into the
/// sink's watched argument; downstream SAT can then ask "if I taint
/// caller arg slot N, will it land in this sink's watched arg?"
#[derive(Debug, Clone)]
pub struct SinkInvocation {
    pub sink: SinkSpec,
    /// Address of the sink call (PC of the BL/CALL).
    pub call_site: u64,
    /// Slots of the enclosing function whose VarIds reach the
    /// sink's watched arg via lineage. Empty when the watched arg
    /// is a function-local constant or an unrelated VarId.
    pub tainted_caller_slots: Vec<AbiSlot>,
}

/// One Source invocation observed inside a function. The summary
/// records which of the function's arg slots receive the source's
/// tainted output (e.g. `recv(sock, ARG, len)` taints whichever
/// caller-slot the function passed for ARG).
#[derive(Debug, Clone)]
pub struct SourceEmission {
    pub source: SourceSpec,
    pub call_site: u64,
    pub tainted_caller_slots: Vec<AbiSlot>,
}

/// Summary for one function. v2 records intra-function
/// source/sink invocations; v3 may add taint-propagation edges
/// (arg-in → arg-out / Ret).
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    pub func: FuncId,
    pub sinks: Vec<SinkInvocation>,
    pub sources: Vec<SourceEmission>,
}

impl FunctionSummary {
    pub fn is_leaf(&self) -> bool {
        self.sinks.is_empty() && self.sources.is_empty()
    }
}

/// Compute the summary for one function. Walks the SSA, identifies
/// every Source / Sink invocation by matching the call target
/// against the imports map, and computes lineage from each call
/// arg back to one of the function's own arg slots.
///
/// `function_arg_vars`: map from `AbiSlot::Arg(N)` to the VarId
/// that represents the function's Nth incoming arg. Caller has
/// to supply this — it's calling-conv-dependent and the SMT
/// explorer already knows it. We accept it as an input rather
/// than re-deriving.
pub fn build_function_summary(
    func: FuncId,
    ssa: &SsaCfg,
    imports: &HashMap<u64, String>,
    function_arg_vars: &HashMap<u8, VarId>,
) -> FunctionSummary {
    let mut summary = FunctionSummary {
        func,
        sinks: Vec::new(),
        sources: Vec::new(),
    };

    for block in &ssa.blocks {
        for stmt in &block.stmts {
            if let Stmt::Call { target, args, .. } = stmt {
                process_call(
                    target,
                    args,
                    block.addr,
                    ssa,
                    imports,
                    function_arg_vars,
                    &mut summary,
                );
            }
        }
        if let SsaTerminator::Call { target, args, .. } = &block.terminator {
            process_call(
                target,
                args,
                block.addr,
                ssa,
                imports,
                function_arg_vars,
                &mut summary,
            );
        }
    }

    summary
}

fn process_call(
    target: &crate::ir::CallTarget,
    args: &[VarId],
    call_site: u64,
    ssa: &SsaCfg,
    imports: &HashMap<u64, String>,
    function_arg_vars: &HashMap<u8, VarId>,
    summary: &mut FunctionSummary,
) {
    let addr = match target {
        crate::ir::CallTarget::Direct(a) => *a,
        crate::ir::CallTarget::Indirect(_) => return,
    };
    let Some(raw_name) = imports.get(&addr) else {
        return;
    };
    let name = normalise_libc_name(raw_name);

    if let Some(spec) = DEFAULT_SOURCES.iter().find(|s| s.name == name) {
        let slot_idx = match spec.tainted {
            AbiSlot::Arg(n) => Some(n as usize),
            AbiSlot::Ret => None,
            AbiSlot::Global(_) => None,
        };
        let tainted_caller_slots = if let Some(idx) = slot_idx {
            args.get(idx)
                .map(|v| arg_slots_for_var(*v, ssa, function_arg_vars))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        summary.sources.push(SourceEmission {
            source: *spec,
            call_site,
            tainted_caller_slots,
        });
        return;
    }
    if let Some(spec) = DEFAULT_SINKS.iter().find(|s| s.name == name) {
        let slot_idx = match spec.watched {
            AbiSlot::Arg(n) => Some(n as usize),
            AbiSlot::Ret => None,
            AbiSlot::Global(_) => None,
        };
        let tainted_caller_slots = if let Some(idx) = slot_idx {
            args.get(idx)
                .map(|v| arg_slots_for_var(*v, ssa, function_arg_vars))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        summary.sinks.push(SinkInvocation {
            sink: *spec,
            call_site,
            tainted_caller_slots,
        });
    }
}

/// Determine which of the function's own arg slots `var` traces
/// back to via the SSA Var-chain plus one layer of Store→Load
/// redirection. Without the Store→Load layer most -O0 prologues
/// (which spill arg registers to stack and reload them at every
/// call site) defeat the chain — `arg_slots_for_var` would always
/// return empty for any compiled C function.
fn arg_slots_for_var(
    var: VarId,
    ssa: &SsaCfg,
    function_arg_vars: &HashMap<u8, VarId>,
) -> Vec<AbiSlot> {
    let mem = build_store_map(ssa);
    let mut out = Vec::new();
    let mut visited: std::collections::HashSet<u32> =
        std::collections::HashSet::new();
    let mut stack = vec![var];
    while let Some(cur) = stack.pop() {
        if !visited.insert(cur.0) || visited.len() > 64 {
            continue;
        }
        for (slot, arg_var) in function_arg_vars {
            if *arg_var == cur && !out.contains(&AbiSlot::Arg(*slot)) {
                out.push(AbiSlot::Arg(*slot));
            }
        }
        if let Some(def) = ssa.vars.get(cur.0 as usize) {
            match &def.expr {
                crate::ir::Expr::Var(inner) => stack.push(*inner),
                // v5.W2.D2a: global-pointer buffer flow. Real ARM32
                // router code rarely passes the source's tainted
                // arg through the caller's stack-frame (which is
                // what the Store→Load match below assumes); instead
                // it passes a global RAM address directly. Capture
                // this so the inter-procedural propagation can
                // bridge a leaf's `recv(_, GLOBAL, _, _)` to a
                // peer's `strcpy(_, GLOBAL)`.
                crate::ir::Expr::Const(va, _) if is_global_va(*va) && out.len() < 4 => {
                    let slot = AbiSlot::Global(*va);
                    if !out.contains(&slot) {
                        out.push(slot);
                    }
                }
                crate::ir::Expr::Load(addr) => {
                    // Recurse into the address subtree to find any
                    // Const leaves (covers Load(Const(va)), Load(
                    // Var(Const(va))), and Load(BinOp(Add, ptr,
                    // idx)) where ptr eventually bottoms to Const).
                    stack.push(*addr);
                    if let Some(key) = addr_canon(*addr, &ssa.vars) {
                        if let Some(stored) = mem.get(&key).copied() {
                            stack.push(stored);
                        }
                    }
                }
                crate::ir::Expr::FieldAccess(base, offset) => {
                    let key = field_access_canon(*base, *offset, &ssa.vars);
                    if let Some(stored) = mem.get(&key).copied() {
                        stack.push(stored);
                    }
                    // v5.W2.D2a: also descend into base so an
                    // arg-passed-through-struct-field surfaces the
                    // base's slot identity. The struct-field's
                    // offset is implicit in the global VA already.
                    stack.push(*base);
                }
                crate::ir::Expr::BinOp(_op, a, b) => {
                    // v5.W2.D2a: pointer arithmetic. Originally only
                    // Add/Sub descended (base + index pattern). v8:
                    // descend any BinOp — Heartbleed-shape length
                    // computation is `(Load(buf+0) << 8) | Load(buf+1)`
                    // which uses Lsl + Or. Without descending into
                    // arithmetic operators the chain stops at the
                    // BinOp and the source's tainted_caller_slot
                    // never reaches the buffer's Param/Global slot.
                    // Over-descent is OK at this layer — false slots
                    // get filtered downstream by lineage_eq.
                    stack.push(*a);
                    stack.push(*b);
                }
                crate::ir::Expr::Phi(inputs) => {
                    // v5.W2.D2a: descend into all Phi inputs; CBranch
                    // merges in real code commonly mask the param
                    // chain otherwise.
                    for v in inputs {
                        stack.push(*v);
                    }
                }
                crate::ir::Expr::UnaryOp(_op, a) => {
                    // v8: Zext / Sext / Neg / etc all preserve the
                    // taint identity. Heartbleed-shape on AArch64
                    // synthesises Zext when widening a byte load
                    // (`(uint16_t)buf[0]`); without descending the
                    // chain breaks at the first cast.
                    stack.push(*a);
                }
                _ => {}
            }
        }
    }
    out
}

/// Heuristic: a "global VA" is anything outside the typical
/// stack/heap range and large enough to be a real RAM address.
/// ARM32 + AArch64 + x86 all share the convention that anything
/// below 0x1000 (page 0) and anything in the typical scratch-
/// constant range (small ints, sub-page arithmetic) is unlikely
/// to be a pointer. This is a soft filter to keep AbiSlot::Global
/// out of the way of integer length args / index multipliers.
fn is_global_va(va: u64) -> bool {
    va >= 0x1000 && va < 0xffff_0000_0000_0000
}

/// Per-SSA Store-address → stored-value map. Keyed by a canonical
/// string form of the address expression so two SSA addresses that
/// COMPUTE the same address (typical -O0 reload patterns: each call
/// site freshly recomputes `add(fp, const)` with different Unique
/// VarIds) collide on the same key.
fn build_store_map(ssa: &SsaCfg) -> HashMap<String, VarId> {
    let mut m: HashMap<String, VarId> = HashMap::new();
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            if let Stmt::Store { addr, val } = stmt {
                if let Some(key) = addr_canon(*addr, &ssa.vars) {
                    m.insert(key, *val);
                }
            }
        }
    }
    m
}

/// Recursive canonical-form key for an address expression. Folds
/// `Var(Var(...))` chains to the underlying varnode and stringifies
/// `BinOp` / `Const` / `Load` so two structurally-equal address
/// computations on different SSA Unique varnodes share a key.
/// Build the same canonical key as `addr_canon` would produce for
/// `BinOp(Add, base, Const(offset, 8))` — so a `FieldAccess(base,
/// offset)` Load form aliases the corresponding pointer-arithmetic
/// Store on the same stack slot.
fn field_access_canon(
    base: VarId,
    offset: u64,
    vars: &[crate::ir::VarDef],
) -> String {
    let kb = addr_canon(base, vars).unwrap_or_else(|| "?".to_string());
    let kc = format!("C{}.8", offset);
    format!("BAdd({},{})", kb, kc)
}

fn addr_canon(var: VarId, vars: &[crate::ir::VarDef]) -> Option<String> {
    fn rec(var: VarId, vars: &[crate::ir::VarDef], depth: u32) -> Option<String> {
        if depth > 16 {
            return None;
        }
        let def = vars.get(var.0 as usize)?;
        Some(match &def.expr {
            crate::ir::Expr::Var(inner) => rec(*inner, vars, depth + 1)?,
            crate::ir::Expr::Const(c, sz) => format!("C{}.{}", c, sz),
            crate::ir::Expr::BinOp(op, a, b) => {
                let ka = rec(*a, vars, depth + 1).unwrap_or_else(|| "?".to_string());
                let kb = rec(*b, vars, depth + 1).unwrap_or_else(|| "?".to_string());
                format!("B{:?}({},{})", op, ka, kb)
            }
            crate::ir::Expr::UnaryOp(op, a) => {
                let ka = rec(*a, vars, depth + 1).unwrap_or_else(|| "?".to_string());
                format!("U{:?}({})", op, ka)
            }
            _ => format!(
                "V{:?}/{}/{}",
                def.varnode.space, def.varnode.offset, def.varnode.size
            ),
        })
    }
    rec(var, vars, 0)
}

/// Per-function context the V6 bottom-up builder needs. The SSA is
/// already required by V4; arg_vars maps `AbiSlot::Arg(N) → VarId`
/// for the function's incoming Nth arg.
pub struct FunctionContext<'a> {
    pub ssa: &'a SsaCfg,
    pub arg_vars: &'a HashMap<u8, VarId>,
}

/// v2.V6: walk the call graph in reverse-topological order
/// (leaves first), build each function's intra-summary via
/// `build_function_summary`, then enrich it by lifting every
/// already-computed callee summary into the caller's slot space.
///
/// Recursive SCCs (size > 1, or a self-looping single node) are
/// treated as opaque: their members get only the intra summary;
/// no inter-procedural propagation crosses the cycle. This matches
/// the v2 spec — a region-based memory model is needed before we
/// can soundly summarise across recursion.
pub fn build_summaries_bottom_up(
    graph: &CallGraph,
    sccs: &Sccs,
    contexts: &HashMap<FuncId, FunctionContext<'_>>,
    imports: &HashMap<u64, String>,
) -> HashMap<FuncId, FunctionSummary> {
    let mut summaries: HashMap<FuncId, FunctionSummary> = HashMap::new();
    for scc in &sccs.components {
        let scc_is_recursive = scc.len() > 1
            || scc
                .first()
                .map(|fid| sccs.is_recursive(*fid, graph))
                .unwrap_or(false);
        for &fid in scc {
            let Some(ctx) = contexts.get(&fid) else {
                continue;
            };
            let mut s = build_function_summary(fid, ctx.ssa, imports, ctx.arg_vars);
            if !scc_is_recursive {
                propagate_callee_summaries(ctx, imports, &summaries, &mut s);
            }
            summaries.insert(fid, s);
        }
    }
    summaries
}

fn propagate_callee_summaries(
    ctx: &FunctionContext<'_>,
    imports: &HashMap<u64, String>,
    summaries: &HashMap<FuncId, FunctionSummary>,
    out: &mut FunctionSummary,
) {
    for block in &ctx.ssa.blocks {
        for stmt in &block.stmts {
            if let Stmt::Call { target, args, .. } = stmt {
                propagate_one(target, args, block.addr, ctx, imports, summaries, out);
            }
        }
        if let SsaTerminator::Call { target, args, .. } = &block.terminator {
            propagate_one(target, args, block.addr, ctx, imports, summaries, out);
        }
    }
}

fn propagate_one(
    target: &CallTarget,
    args: &[VarId],
    call_site: u64,
    ctx: &FunctionContext<'_>,
    imports: &HashMap<u64, String>,
    summaries: &HashMap<FuncId, FunctionSummary>,
    out: &mut FunctionSummary,
) {
    let addr = match target {
        CallTarget::Direct(a) => *a,
        CallTarget::Indirect(_) => return,
    };
    if imports.contains_key(&addr) {
        return; // already covered by intra build_function_summary
    }
    let Some(callee_sum) = summaries.get(&FuncId(addr)) else {
        return;
    };
    for sink in &callee_sum.sinks {
        let caller_slots = remap_slots(&sink.tainted_caller_slots, args, ctx);
        out.sinks.push(SinkInvocation {
            sink: sink.sink,
            call_site,
            tainted_caller_slots: caller_slots,
        });
    }
    for src in &callee_sum.sources {
        let caller_slots = remap_slots(&src.tainted_caller_slots, args, ctx);
        out.sources.push(SourceEmission {
            source: src.source,
            call_site,
            tainted_caller_slots: caller_slots,
        });
    }
}

fn remap_slots(
    callee_slots: &[AbiSlot],
    caller_args: &[VarId],
    ctx: &FunctionContext<'_>,
) -> Vec<AbiSlot> {
    let mut out = Vec::new();
    for slot in callee_slots {
        match slot {
            AbiSlot::Arg(n) => {
                let Some(arg_var) = caller_args.get(*n as usize) else {
                    continue;
                };
                for cs in arg_slots_for_var(*arg_var, ctx.ssa, ctx.arg_vars) {
                    if !out.contains(&cs) {
                        out.push(cs);
                    }
                }
            }
            AbiSlot::Global(va) => {
                // Global slots pass through the call boundary
                // unchanged — the global is a process-wide
                // identifier, independent of caller frame.
                let cs = AbiSlot::Global(*va);
                if !out.contains(&cs) {
                    out.push(cs);
                }
            }
            AbiSlot::Ret => {
                // Ret-tainted callee output: untracked at this layer.
            }
        }
    }
    out
}

/// Recover the function's incoming-arg VarIds from the SSA's
/// `param_name` annotations (set by the calling-convention pass).
/// Returns a slot → VarId map for slots advertised as `param_N`.
pub fn arg_vars_from_ssa(ssa: &SsaCfg) -> HashMap<u8, VarId> {
    let mut out = HashMap::new();
    for v in &ssa.vars {
        if let Some(name) = &v.param_name {
            if let Some(rest) = name.strip_prefix("param_") {
                if let Ok(n) = rest.parse::<u8>() {
                    out.entry(n).or_insert(v.id);
                }
            }
        }
    }
    out
}

fn normalise_libc_name(raw: &str) -> &str {
    let stripped = raw.split('@').next().unwrap_or(raw);
    let unprefixed = stripped.trim_start_matches('_');
    // v2.V10: strip fortify-source _chk suffix so __strcpy_chk
    // matches the strcpy DEFAULT_SINKS entry.
    unprefixed.strip_suffix("_chk").unwrap_or(unprefixed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        BlockId, CallTarget, Diagnostic, Expr, InferredType, SsaBlock, SsaTerminator,
        VarDef,
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

    #[test]
    fn empty_function_yields_empty_summary() {
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
        let imports: HashMap<u64, String> = HashMap::new();
        let arg_vars: HashMap<u8, VarId> = HashMap::new();
        let s = build_function_summary(FuncId(0x1000), &ssa, &imports, &arg_vars);
        assert!(s.is_leaf());
    }

    #[test]
    fn function_invoking_strcpy_records_sink_with_caller_slot() {
        // helper(arg0, arg1) calls strcpy(arg0, arg1) directly.
        // arg0 = VarId(0), arg1 = VarId(1).
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0, 8)),
        ];
        let ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x125d8),
                    args: vec![VarId(0), VarId(1)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "strcpy".to_string());
        let mut arg_vars = HashMap::new();
        arg_vars.insert(0u8, VarId(0));
        arg_vars.insert(1u8, VarId(1));

        let s = build_function_summary(FuncId(0x1000), &ssa, &imports, &arg_vars);
        assert_eq!(s.sinks.len(), 1);
        assert_eq!(s.sinks[0].sink.name, "strcpy");
        // strcpy's watched slot is Arg(1) → caller's VarId(1) → caller arg slot 1
        assert_eq!(s.sinks[0].tainted_caller_slots, vec![AbiSlot::Arg(1)]);
        assert!(s.sources.is_empty());
    }

    #[test]
    fn function_invoking_recv_records_source_with_caller_slot() {
        // wrapper(buf) calls recv(0, buf, 256, 0).
        // The function has only 1 incoming arg → arg0 = VarId(0).
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),  // function arg 0 = buf
            mk_var(1, Expr::Const(0, 8)),  // sock = const 0
            mk_var(2, Expr::Const(256, 8)), // len = const 256
            mk_var(3, Expr::Const(0, 8)),  // flags = const 0
        ];
        let ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x125d8),
                    args: vec![VarId(1), VarId(0), VarId(2), VarId(3)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "recv".to_string());
        let mut arg_vars = HashMap::new();
        arg_vars.insert(0u8, VarId(0));

        let s = build_function_summary(FuncId(0x1000), &ssa, &imports, &arg_vars);
        assert_eq!(s.sources.len(), 1);
        assert_eq!(s.sources[0].source.name, "recv");
        // recv's tainted slot is Arg(1) which is VarId(0) = function arg 0
        assert_eq!(s.sources[0].tainted_caller_slots, vec![AbiSlot::Arg(0)]);
    }

    #[test]
    fn unrelated_args_yield_no_caller_slots() {
        // Function calls strcpy with sub-page constants, no
        // caller-supplied args. Uses 0x10/0x20 (below the 0x1000
        // global-VA cutoff in is_global_va) so the v5.W2.D2a
        // Global-slot probe correctly rejects them.
        let vars = vec![
            mk_var(0, Expr::Const(0x10, 8)),
            mk_var(1, Expr::Const(0x20, 8)),
        ];
        let ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x125d8),
                    args: vec![VarId(0), VarId(1)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "strcpy".to_string());
        let arg_vars: HashMap<u8, VarId> = HashMap::new();

        let s = build_function_summary(FuncId(0x1000), &ssa, &imports, &arg_vars);
        assert_eq!(s.sinks.len(), 1);
        assert!(s.sinks[0].tainted_caller_slots.is_empty());
    }

    #[test]
    fn bottom_up_lifts_callee_sink_into_caller_slot() {
        // helper(x, y): strcpy(x, y) at 0x2000.
        // outer(a, b): calls helper(a, b) at 0x1004.
        // Expect outer's summary to include a sink invocation with
        // tainted_caller_slots = [Arg(1)] (strcpy's watched=Arg(1) →
        // helper's arg1 → outer's arg1).
        use crate::callgraph::{build_call_graph, tarjan_sccs};

        // helper SSA: arg0=VarId(0), arg1=VarId(1), strcpy at 0x125d8.
        let helper_vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0, 8)),
        ];
        let helper_ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x2000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x125d8),
                    args: vec![VarId(0), VarId(1)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars: helper_vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let mut helper_args = HashMap::new();
        helper_args.insert(0u8, VarId(0));
        helper_args.insert(1u8, VarId(1));

        // outer SSA: arg0=VarId(0), arg1=VarId(1), calls helper at 0x2000.
        let outer_vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0, 8)),
        ];
        let outer_ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x2000),
                    args: vec![VarId(0), VarId(1)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars: outer_vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let mut outer_args = HashMap::new();
        outer_args.insert(0u8, VarId(0));
        outer_args.insert(1u8, VarId(1));

        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "strcpy".to_string());

        let funcs: Vec<(FuncId, &SsaCfg)> = vec![
            (FuncId(0x2000), &helper_ssa),
            (FuncId(0x1000), &outer_ssa),
        ];
        let graph = build_call_graph(&funcs, &imports);
        let sccs = tarjan_sccs(&graph);

        let mut contexts: HashMap<FuncId, FunctionContext<'_>> = HashMap::new();
        contexts.insert(
            FuncId(0x2000),
            FunctionContext {
                ssa: &helper_ssa,
                arg_vars: &helper_args,
            },
        );
        contexts.insert(
            FuncId(0x1000),
            FunctionContext {
                ssa: &outer_ssa,
                arg_vars: &outer_args,
            },
        );

        let summaries =
            build_summaries_bottom_up(&graph, &sccs, &contexts, &imports);

        // Helper has the direct strcpy sink.
        let helper_sum = summaries.get(&FuncId(0x2000)).unwrap();
        assert_eq!(helper_sum.sinks.len(), 1);
        assert_eq!(
            helper_sum.sinks[0].tainted_caller_slots,
            vec![AbiSlot::Arg(1)]
        );

        // Outer must have the LIFTED sink (no direct strcpy import call).
        let outer_sum = summaries.get(&FuncId(0x1000)).unwrap();
        assert_eq!(outer_sum.sinks.len(), 1);
        assert_eq!(outer_sum.sinks[0].sink.name, "strcpy");
        assert_eq!(
            outer_sum.sinks[0].tainted_caller_slots,
            vec![AbiSlot::Arg(1)]
        );
        // Call site should be the outer's call into helper, not the
        // helper's strcpy site.
        assert_eq!(outer_sum.sinks[0].call_site, 0x1000);
    }

    #[test]
    fn bottom_up_three_hop_wrapping_chain() {
        // v2.V7: outer(a, b) → mid(a, b) → inner(a, b) → strcpy(a, b).
        // The lift must propagate the strcpy sink up through TWO
        // wrapper layers, with the watched slot remaining Arg(1) at
        // every hop.
        use crate::callgraph::{build_call_graph, tarjan_sccs};

        let mk_pass_through = |callee_addr: u64, addr: u64| -> SsaCfg {
            SsaCfg {
                blocks: vec![SsaBlock {
                    id: BlockId(0),
                    addr,
                    stmts: vec![Stmt::Call {
                        target: CallTarget::Direct(callee_addr),
                        args: vec![VarId(0), VarId(1)],
                        out: None,
                    }],
                    terminator: SsaTerminator::Return(None),
                }],
                vars: vec![mk_var(0, Expr::Const(0, 8)), mk_var(1, Expr::Const(0, 8))],
                entry: BlockId(0),
                diagnostics: Vec::<Diagnostic>::new(),
            }
        };

        // inner: directly calls strcpy at 0x125d8.
        let inner_ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x3000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x125d8),
                    args: vec![VarId(0), VarId(1)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars: vec![mk_var(0, Expr::Const(0, 8)), mk_var(1, Expr::Const(0, 8))],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let mid_ssa = mk_pass_through(0x3000, 0x2000);
        let outer_ssa = mk_pass_through(0x2000, 0x1000);

        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "strcpy".to_string());

        let funcs: Vec<(FuncId, &SsaCfg)> = vec![
            (FuncId(0x3000), &inner_ssa),
            (FuncId(0x2000), &mid_ssa),
            (FuncId(0x1000), &outer_ssa),
        ];
        let graph = build_call_graph(&funcs, &imports);
        let sccs = tarjan_sccs(&graph);

        let mut arg_vars = HashMap::new();
        arg_vars.insert(0u8, VarId(0));
        arg_vars.insert(1u8, VarId(1));

        let mut contexts: HashMap<FuncId, FunctionContext<'_>> = HashMap::new();
        for (fid, ssa) in [
            (FuncId(0x3000), &inner_ssa),
            (FuncId(0x2000), &mid_ssa),
            (FuncId(0x1000), &outer_ssa),
        ] {
            contexts.insert(
                fid,
                FunctionContext {
                    ssa,
                    arg_vars: &arg_vars,
                },
            );
        }

        let summaries =
            build_summaries_bottom_up(&graph, &sccs, &contexts, &imports);
        for (fid, addr) in [
            (FuncId(0x3000), 0x3000u64),
            (FuncId(0x2000), 0x2000u64),
            (FuncId(0x1000), 0x1000u64),
        ] {
            let s = summaries.get(&fid).unwrap();
            assert_eq!(s.sinks.len(), 1, "fid {:#x}", fid.0);
            assert_eq!(s.sinks[0].sink.name, "strcpy");
            assert_eq!(
                s.sinks[0].tainted_caller_slots,
                vec![AbiSlot::Arg(1)],
                "fid {:#x}",
                fid.0
            );
            assert_eq!(s.sinks[0].call_site, addr, "fid {:#x}", fid.0);
        }
    }

    #[test]
    fn bottom_up_pass_through_with_slot_swap() {
        // v2.V7: helper(x, y) calls strcpy(y, x) — args SWAPPED.
        // outer(a, b) calls helper(a, b).
        // After lift, outer's strcpy entry must claim caller slot
        // Arg(0), not Arg(1), because helper's watched slot Arg(1)
        // is helper's `x` (which outer passed as Arg(0)).
        use crate::callgraph::{build_call_graph, tarjan_sccs};

        let helper_ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x2000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x125d8),
                    args: vec![VarId(1), VarId(0)], // strcpy(y, x) — swapped
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars: vec![mk_var(0, Expr::Const(0, 8)), mk_var(1, Expr::Const(0, 8))],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let outer_ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x2000),
                    args: vec![VarId(0), VarId(1)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars: vec![mk_var(0, Expr::Const(0, 8)), mk_var(1, Expr::Const(0, 8))],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };

        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "strcpy".to_string());

        let funcs: Vec<(FuncId, &SsaCfg)> = vec![
            (FuncId(0x2000), &helper_ssa),
            (FuncId(0x1000), &outer_ssa),
        ];
        let graph = build_call_graph(&funcs, &imports);
        let sccs = tarjan_sccs(&graph);

        let mut arg_vars = HashMap::new();
        arg_vars.insert(0u8, VarId(0));
        arg_vars.insert(1u8, VarId(1));

        let mut contexts: HashMap<FuncId, FunctionContext<'_>> = HashMap::new();
        contexts.insert(
            FuncId(0x2000),
            FunctionContext {
                ssa: &helper_ssa,
                arg_vars: &arg_vars,
            },
        );
        contexts.insert(
            FuncId(0x1000),
            FunctionContext {
                ssa: &outer_ssa,
                arg_vars: &arg_vars,
            },
        );

        let summaries =
            build_summaries_bottom_up(&graph, &sccs, &contexts, &imports);

        // helper's intra summary: strcpy watched=Arg(1) → helper's
        // VarId(0) → helper arg 0.
        let helper_sum = summaries.get(&FuncId(0x2000)).unwrap();
        assert_eq!(
            helper_sum.sinks[0].tainted_caller_slots,
            vec![AbiSlot::Arg(0)]
        );
        // outer's lifted summary: helper's tainted slot Arg(0) →
        // outer's call args[0]=VarId(0) → outer arg 0.
        let outer_sum = summaries.get(&FuncId(0x1000)).unwrap();
        assert_eq!(outer_sum.sinks.len(), 1);
        assert_eq!(
            outer_sum.sinks[0].tainted_caller_slots,
            vec![AbiSlot::Arg(0)]
        );
    }

    #[test]
    fn bottom_up_recursive_scc_is_opaque() {
        // a → b → a (mutual recursion). Both must be classified as
        // recursive and receive only intra summaries (which here are
        // empty since neither calls a sink directly).
        use crate::callgraph::{build_call_graph, tarjan_sccs};

        let make_caller_ssa = |callee_addr: u64| SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(callee_addr),
                    args: vec![],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars: vec![mk_var(0, Expr::Const(0, 8))],
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let a_ssa = make_caller_ssa(0xB000);
        let b_ssa = make_caller_ssa(0xA000);
        let imports: HashMap<u64, String> = HashMap::new();
        let arg_vars: HashMap<u8, VarId> = HashMap::new();

        let funcs: Vec<(FuncId, &SsaCfg)> =
            vec![(FuncId(0xA000), &a_ssa), (FuncId(0xB000), &b_ssa)];
        let graph = build_call_graph(&funcs, &imports);
        let sccs = tarjan_sccs(&graph);
        // Both nodes share one recursive SCC.
        assert!(sccs.is_recursive(FuncId(0xA000), &graph));

        let mut contexts: HashMap<FuncId, FunctionContext<'_>> = HashMap::new();
        contexts.insert(
            FuncId(0xA000),
            FunctionContext {
                ssa: &a_ssa,
                arg_vars: &arg_vars,
            },
        );
        contexts.insert(
            FuncId(0xB000),
            FunctionContext {
                ssa: &b_ssa,
                arg_vars: &arg_vars,
            },
        );
        let summaries =
            build_summaries_bottom_up(&graph, &sccs, &contexts, &imports);
        // Empty intra summaries; no propagation across the cycle.
        assert!(summaries.get(&FuncId(0xA000)).unwrap().is_leaf());
        assert!(summaries.get(&FuncId(0xB000)).unwrap().is_leaf());
    }

    #[test]
    fn libc_name_normalisation_matches_macho_underscore() {
        let vars = vec![mk_var(0, Expr::Const(0, 8))];
        let ssa = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0x125d8),
                    args: vec![VarId(0), VarId(0)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let mut imports = HashMap::new();
        imports.insert(0x125d8u64, "_strcpy".to_string());
        let arg_vars: HashMap<u8, VarId> = HashMap::new();

        let s = build_function_summary(FuncId(0x1000), &ssa, &imports, &arg_vars);
        assert_eq!(s.sinks.len(), 1);
        assert_eq!(s.sinks[0].sink.name, "strcpy");
    }
}
