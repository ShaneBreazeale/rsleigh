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

use crate::callgraph::FuncId;
use crate::ir::{SsaCfg, SsaTerminator, Stmt, VarId};
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
/// back to via the SSA Var-chain. Returns an empty Vec when the
/// var doesn't trace to any caller-supplied arg (e.g. it's a
/// function-local Const or comes from a Source's output).
fn arg_slots_for_var(
    var: VarId,
    ssa: &SsaCfg,
    function_arg_vars: &HashMap<u8, VarId>,
) -> Vec<AbiSlot> {
    let mut out = Vec::new();
    let mut visited: std::collections::HashSet<u32> =
        std::collections::HashSet::new();
    let mut stack = vec![var];
    while let Some(cur) = stack.pop() {
        if !visited.insert(cur.0) || visited.len() > 32 {
            continue;
        }
        for (slot, arg_var) in function_arg_vars {
            if *arg_var == cur && !out.contains(&AbiSlot::Arg(*slot)) {
                out.push(AbiSlot::Arg(*slot));
            }
        }
        if let Some(def) = ssa.vars.get(cur.0 as usize) {
            if let crate::ir::Expr::Var(inner) = &def.expr {
                stack.push(*inner);
            }
        }
    }
    out
}

fn normalise_libc_name(raw: &str) -> &str {
    let stripped = raw.split('@').next().unwrap_or(raw);
    stripped
        .trim_start_matches('_')
        .trim_start_matches('_')
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
        // Function calls strcpy with constants, no caller-supplied args.
        let vars = vec![
            mk_var(0, Expr::Const(0xAAAA, 8)),
            mk_var(1, Expr::Const(0xBBBB, 8)),
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
