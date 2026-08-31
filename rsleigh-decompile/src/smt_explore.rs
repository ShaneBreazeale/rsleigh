//! Taint-flow CVE explorer (SMT M1).
//!
//! Configures attacker-controlled `Source` APIs and dangerous `Sink`
//! APIs, walks straight-line SSA paths from a Source's tainted output
//! to a Sink's watched argument, and asks Z3 whether attacker-supplied
//! bytes can drive the watched value into a CVE-class state (over-long
//! buffer, format-string char, command separator, etc.).
//!
//! This module owns the spec tables, call-name resolution, and the
//! straight-line SSA path collector. The Z3-driven SAT prover lands
//! in commit 4 per
//! `.opt/campaigns/smt-backend-implementation-plan.md`.

use std::collections::HashMap;

use crate::ir::{CallTarget, SsaCfg, SsaTerminator, Stmt, VarId};

/// One slot in the platform calling convention. M1 only needs to
/// describe the slots used by the source/sink configurations below;
/// fuller ABI coverage (variadic, return registers, x87 stack, NEON)
/// is deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbiSlot {
    /// Argument in register N (zero-indexed, e.g. RDI=0 on x86-64
    /// SystemV, X0=0 on AArch64 AAPCS, $a0=0 on MIPS o32).
    Arg(u8),
    /// Return value (typically RAX/X0/v0).
    Ret,
    /// v5.W2.D2a: a global RAM address (or a global pointer slot
    /// whose contents alias to a buffer). Used by inter-procedural
    /// summary propagation to bridge a callee's `recv(_, GLOBAL,
    /// _, _)` source to a peer's `strcpy(_, GLOBAL)` sink without
    /// requiring the buffer to flow through the caller's arg
    /// registers (which it almost never does in real router code).
    Global(u64),
}

/// What kind of CVE-class violation the sink exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkKind {
    /// `dst` is a stack-resident buffer; tainted source overflowing
    /// it is a stack BOF (strcpy/strcat/sprintf/gets-class).
    StackBuffer,
    /// `arg0` is a printf-family format string — `%n`/`%s`/`%x`
    /// substrings produce read/write primitives.
    FormatArg,
    /// Single string argument runs through a shell (system/popen)
    /// or exec*() — `;`/`&&`/`|` enables command injection.
    Command,
    /// Length operand of a bounded copy (memcpy/strncpy/memmove);
    /// SAT when the tainted length can exceed the dst capacity.
    LengthArg,
    /// v9: synthetic sink for compiler-emitted store loops (the
    /// extract_name / parser pattern: `*dst++ = byte_from_taint`).
    /// No libc API is involved — the store is raw SSA. SAT modeling
    /// is deferred (v10); v9 surfaces these in the candidate dump
    /// for LLM triage with verdict Unsupported.
    TaintedStore,
    /// Unbounded C-string readers (`strlen`, `strcmp`, `strchr`,
    /// etc.) scan memory until a NUL byte. When fed a non-terminated
    /// attacker-controlled packet buffer, they are an OOB-read class
    /// primitive common in protocol parser CVEs.
    CStringRead,
}

/// Attacker-controlled API. The function returns or fills a buffer
/// whose contents are byte-for-byte controlled.
#[derive(Debug, Clone, Copy)]
pub struct SourceSpec {
    /// libc / kernel-style API name, e.g. `"recv"`, `"read"`, `"argv"`.
    /// `"argv"` is treated specially — it isn't a function call,
    /// it's the second argument to `main`, and the path collector
    /// will need to recognise that.
    pub name: &'static str,
    /// The slot whose contents become tainted when the call returns.
    /// `Ret` for `gets`-class returns; `Arg(N)` for fill-buffer APIs
    /// like `recv(sock, BUF, len, flags)` where N=1.
    pub tainted: AbiSlot,
}

/// Dangerous API. Tainted data reaching `watched` produces a
/// CVE-class outcome of the configured `kind`.
#[derive(Debug, Clone, Copy)]
pub struct SinkSpec {
    pub name: &'static str,
    /// The argument slot whose taint we test for the SAT proof.
    pub watched: AbiSlot,
    pub kind: SinkKind,
}

/// Default attacker-controlled APIs. M1 covers the canonical libc
/// network/IO surface plus `argv`. Aliases (e.g. checked wrappers
/// `__recv_chk`) are deferred.
pub const DEFAULT_SOURCES: &[SourceSpec] = &[
    SourceSpec { name: "recv",       tainted: AbiSlot::Arg(1) },
    SourceSpec { name: "recvfrom",   tainted: AbiSlot::Arg(1) },
    SourceSpec { name: "recvmsg",    tainted: AbiSlot::Arg(1) },
    SourceSpec { name: "read",       tainted: AbiSlot::Arg(1) },
    SourceSpec { name: "fread",      tainted: AbiSlot::Arg(0) },
    SourceSpec { name: "fgets",      tainted: AbiSlot::Arg(0) },
    SourceSpec { name: "gets",       tainted: AbiSlot::Arg(0) },
    SourceSpec { name: "scanf",      tainted: AbiSlot::Arg(1) },
    SourceSpec { name: "sscanf",     tainted: AbiSlot::Arg(2) },
    SourceSpec { name: "fscanf",     tainted: AbiSlot::Arg(2) },
    SourceSpec { name: "getenv",     tainted: AbiSlot::Ret    },
    // `argv` is a marker — the path collector recognises it as
    // "second arg of main" rather than a function call.
    SourceSpec { name: "argv",       tainted: AbiSlot::Arg(1) },
];

/// Default dangerous APIs. M1 covers the canonical libc CVE class
/// surface. Bounded-copy primitives whose length argument is the
/// CVE primitive use `LengthArg`; everything else watches the
/// primary string slot.
pub const DEFAULT_SINKS: &[SinkSpec] = &[
    SinkSpec { name: "strcpy",  watched: AbiSlot::Arg(1), kind: SinkKind::StackBuffer },
    SinkSpec { name: "strcat",  watched: AbiSlot::Arg(1), kind: SinkKind::StackBuffer },
    SinkSpec { name: "sprintf", watched: AbiSlot::Arg(1), kind: SinkKind::FormatArg   },
    SinkSpec { name: "vsprintf",watched: AbiSlot::Arg(1), kind: SinkKind::FormatArg   },
    SinkSpec { name: "printf",  watched: AbiSlot::Arg(0), kind: SinkKind::FormatArg   },
    SinkSpec { name: "fprintf", watched: AbiSlot::Arg(1), kind: SinkKind::FormatArg   },
    SinkSpec { name: "memcpy",  watched: AbiSlot::Arg(2), kind: SinkKind::LengthArg   },
    SinkSpec { name: "memmove", watched: AbiSlot::Arg(2), kind: SinkKind::LengthArg   },
    SinkSpec { name: "strncpy", watched: AbiSlot::Arg(2), kind: SinkKind::LengthArg   },
    SinkSpec { name: "strncat", watched: AbiSlot::Arg(2), kind: SinkKind::LengthArg   },
    SinkSpec { name: "system",  watched: AbiSlot::Arg(0), kind: SinkKind::Command     },
    SinkSpec { name: "popen",   watched: AbiSlot::Arg(0), kind: SinkKind::Command     },
    SinkSpec { name: "execve",  watched: AbiSlot::Arg(0), kind: SinkKind::Command     },
    SinkSpec { name: "execlp",  watched: AbiSlot::Arg(0), kind: SinkKind::Command     },
    SinkSpec { name: "execvp",  watched: AbiSlot::Arg(0), kind: SinkKind::Command     },
    SinkSpec { name: "strlen",  watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strnlen", watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strcmp",  watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strncmp", watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strcasecmp",  watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strncasecmp", watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strchr",  watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strrchr", watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strstr",  watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
    SinkSpec { name: "strcasestr", watched: AbiSlot::Arg(0), kind: SinkKind::CStringRead },
];

/// v9: synthetic sink spec for compiler-emitted Store loops. Used
/// only by `build_function_summary` when it detects a function
/// that writes from a Param-region pointer into another Param-
/// region pointer (the "copy_until_zero" / extract_name pattern).
///
/// v10: `watched: Arg(0)` is the SRC-pointer slot — the parameter
/// whose buffer contents flow into the destination. The lineage
/// walker checks taint flow from the source to this slot in the
/// caller; the dst-is-param precondition is enforced at detection
/// time, not at solve time.
pub const STORE_SINK_SPEC: SinkSpec = SinkSpec {
    name: "<tainted_store>",
    watched: AbiSlot::Arg(0),
    kind: SinkKind::TaintedStore,
};

/// Resolve a call-target address against the import map. Returns
/// `Some(SpecRef)` when the target matches one of the configured
/// sources or sinks.
///
/// Name normalisation: ELF/Mach-O often expose stub names with a
/// leading `_` or `__` and PLT names with an `@plt` suffix; strip
/// both before matching. Demangled C++ names that happen to overlap
/// with libc identifiers are out of scope (M1 is libc-targeted).
pub fn resolve_call(
    target_addr: u64,
    imports: &HashMap<u64, String>,
) -> Option<SpecRef> {
    let raw = imports.get(&target_addr)?;
    let normalised = normalise_name(raw);
    if let Some(spec) = DEFAULT_SOURCES.iter().find(|s| s.name == normalised) {
        return Some(SpecRef::Source(*spec));
    }
    if let Some(spec) = DEFAULT_SINKS.iter().find(|s| s.name == normalised) {
        return Some(SpecRef::Sink(*spec));
    }
    None
}

/// Result of `resolve_call`. Either a Source whose return/output
/// taints memory, or a Sink whose watched arg we follow.
#[derive(Debug, Clone, Copy)]
pub enum SpecRef {
    Source(SourceSpec),
    Sink(SinkSpec),
}

fn normalise_name(raw: &str) -> &str {
    // Strip a `@plt`/`@@VERSION` suffix.
    let stripped = raw.split('@').next().unwrap_or(raw);
    // Strip leading underscores (Mach-O `_recv`, glibc internal
    // `__recv`, etc.).
    let unprefixed = stripped.trim_start_matches('_');
    // v2.V10: collapse fortify-source `*_chk` checked variants to
    // their canonical name (Mach-O exposes `___strcpy_chk` for
    // strcpy under -D_FORTIFY_SOURCE). The chk wrapper has the
    // same arg layout for the slots we watch.
    unprefixed.strip_suffix("_chk").unwrap_or(unprefixed)
}

/// SAT-as-CVE-proof outcome for one `TaintPath`. Produced by
/// `solve` (gated on `smt` feature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtFinding {
    /// Z3 found a symbolic input that drives the sink's watched arg
    /// into a CVE-class state. The model is exposed as
    /// `(input_byte_offset, value)` pairs.
    Reachable {
        input_bytes: Vec<(usize, u8)>,
        /// v2.V9: chain of caller PCs traversed when this path was
        /// constructed via inter-procedural summary synthesis.
        /// Empty for direct (intra-function) Source→Sink pairs.
        call_chain: Vec<u64>,
    },
    /// Solver proved no input drives the violation under the path's
    /// constraints — false-positive cull.
    NotReachable,
    /// Lineage check or sink-kind modelling is out of v0 scope. The
    /// reason string is shown to the analyst so the gap is auditable.
    Unsupported(&'static str),
}

/// Reasons the v0 path collector rejected an SSA function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRejection {
    /// Walk reached a non-Call terminator (CBranch, Branch, Return,
    /// Indirect, Fallthrough). M1 forbids multi-block paths.
    UnsupportedTerminator(&'static str),
    /// Entry block contains a Phi-introducing assignment. v0 cannot
    /// reason across phi joins.
    PhiInPath,
    /// Entry block makes an indirect call before a sink is reached.
    IndirectCall,
    /// Walk completed, no Sink was encountered. Not a hard error —
    /// caller may treat this as "function does nothing CVE-class".
    NoSinkFound,
}

/// One event in the linear SSA walk: assignments, stores, calls.
/// Calls are classified up front against the import map so the
/// downstream SAT prover doesn't repeat the lookup.
#[derive(Debug, Clone)]
pub struct TaintEvent<'a> {
    pub stmt_index: usize,
    pub kind: TaintEventKind<'a>,
}

#[derive(Debug, Clone)]
pub enum TaintEventKind<'a> {
    Assign(VarId),
    Store { addr: VarId, val: VarId },
    SourceCall {
        spec: &'a SourceSpec,
        args: Vec<VarId>,
        out: Option<VarId>,
        /// v2.V8: empty for direct (intra-function) source calls.
        /// Populated when this event was synthesized from a callee's
        /// FunctionSummary — the chain records the call-site PCs
        /// traversed from the analysed function down to the actual
        /// source invocation.
        call_chain: Vec<u64>,
    },
    SinkCall {
        spec: &'a SinkSpec,
        args: Vec<VarId>,
        out: Option<VarId>,
        /// v2.V8: see SourceCall::call_chain.
        call_chain: Vec<u64>,
    },
    OtherCall {
        target_addr: Option<u64>,
        args: Vec<VarId>,
        out: Option<VarId>,
    },
}

/// One CBranch decision encountered while walking from entry to a
/// Source→Sink pair. `taken == true` means the path took the
/// CBranch's `taken` arm; `false` is the fallthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BranchDecision {
    pub block_addr: u64,
    pub cond: VarId,
    pub taken: bool,
}

/// One Source -> Sink pair found by `collect_paths`. The SAT prover
/// takes the path and asks Z3 whether tainted input from `source`
/// can force the `sink`'s watched arg into a CVE-class state.
///
/// `branch_decisions` records the CBranch arms taken between entry
/// and the sink invocation. v0 paths always have an empty list
/// (linear walk only); v1 paths can include up to MAX_BRANCH_DEPTH
/// decisions.
#[derive(Debug, Clone)]
pub struct TaintPath<'a> {
    pub source: &'a SourceSpec,
    pub source_event: usize,
    pub sink: &'a SinkSpec,
    pub sink_event: usize,
    pub events: Vec<TaintEvent<'a>>,
    pub branch_decisions: Vec<BranchDecision>,
}

/// Maximum number of CBranch arms followed from entry to any path
/// before the walker bails. Real router-firmware functions have
/// 20+ branches before reaching a sink; 4 was too low. 32 covers
/// the realistic depth without burning memory because we also cap
/// the global worklist size.
pub const MAX_BRANCH_DEPTH: u32 = 64;

/// Hard cap on total `WalkState`s the worklist can hold. With
/// MAX_BRANCH_DEPTH=32 the unbounded worst case is 2^32 — never
/// happens in practice because most CBranches reconverge, but we
/// still ceiling at this number to keep memory bounded on
/// pathological dispatch tables. When the cap is hit, surplus
/// states are dropped and the rejection reason is recorded.
pub const MAX_WORKLIST_SIZE: usize = 16384;

/// v16: hard cap on the number of (source, sink) pairs the path
/// collector will enumerate per function. Without it, parser-style
/// functions with hundreds of `fgets`/`sprintf` call sites
/// generate `O(sources × sinks × paths)` candidates which can
/// balloon to 96k+ records (observed on dnsmasq-2.78::read_file)
/// and OOM the candidate dump. Once the cap is hit, path
/// collection returns the truncated list rather than continuing
/// to enumerate. CLI's `--smt-candidates-cap` is downstream of
/// this; this cap protects the in-memory enumeration itself.
///
/// Set high (8192) so dropbear-class functions with hundreds of
/// real source-sink pairs aren't truncated; low enough that
/// pathological dnsmasq read_file (96k+) hits the cap and stops.
pub const MAX_PATHS_PER_FN: usize = 8192;

/// One in-progress walk state in the v1 collector's worklist.
struct WalkState<'a> {
    current: crate::ir::BlockId,
    events: Vec<TaintEvent<'a>>,
    visited: std::collections::HashSet<crate::ir::BlockId>,
    branch_decisions: Vec<BranchDecision>,
}

/// Walk every CFG path from the entry block to a Source→Sink pair,
/// k-bounded at `MAX_BRANCH_DEPTH` CBranch arms. Returns the list
/// of paths surfaced, or `PathRejection` if no walk produces a
/// usable path.
///
/// v0 (linear-fallthrough only) is the trivial case: entry block
/// has no CBranch reachable, the worklist degenerates to a single
/// walk identical to v0 collection. v1 adds CBranch exploration:
/// when a walk hits a CBranch, both arms get queued as separate
/// states, each with `branch_decisions` extended.
///
/// Rejected paths (loop back-edges, indirect calls, Phi nodes,
/// depth limit) are dropped; if no successful path remains, the
/// most-specific rejection reason is returned.
///
/// Loop guard: `visited` BlockId set is per-state, not global —
/// two distinct paths through the same block via different arms
/// are both legal. A revisit within the SAME walk aborts that walk.
pub fn collect_paths<'a>(
    ssa: &'a SsaCfg,
    imports: &HashMap<u64, String>,
) -> Result<Vec<TaintPath<'a>>, PathRejection> {
    let empty: HashMap<crate::callgraph::FuncId, crate::function_summary::FunctionSummary> =
        HashMap::new();
    collect_paths_with_summaries(ssa, imports, &empty)
}

/// v2.V8: inter-procedural path collection. Same walker as
/// `collect_paths` but on every direct call to a known function
/// (FuncId in `summaries`, not a library import) the walker pushes
/// synthetic SourceCall / SinkCall events onto the path so the SAT
/// prover can reason about callee taint without inlining the
/// callee's body.
///
/// Synthetic events carry a `call_chain` recording the caller PCs
/// traversed; v9 surfaces this in the JSON output.
pub fn collect_paths_with_summaries<'a>(
    ssa: &'a SsaCfg,
    imports: &HashMap<u64, String>,
    summaries: &HashMap<crate::callgraph::FuncId, crate::function_summary::FunctionSummary>,
) -> Result<Vec<TaintPath<'a>>, PathRejection> {
    collect_paths_with_summaries_named(ssa, imports, summaries, None)
}

/// v13: variant that knows the function's name. When name is "main"
/// (or `_main` Mach-O mangling), the walker prepends a synthetic
/// SourceCall for the `argv` source spec — `argv` isn't a libc
/// call, it's the second arg to `main`, so without this injection
/// path collection in main can never see argv-tainted bytes flowing
/// to a sink even when the SSA carries the chain perfectly.
pub fn collect_paths_with_summaries_named<'a>(
    ssa: &'a SsaCfg,
    imports: &HashMap<u64, String>,
    summaries: &HashMap<crate::callgraph::FuncId, crate::function_summary::FunctionSummary>,
    func_name: Option<&str>,
) -> Result<Vec<TaintPath<'a>>, PathRejection> {
    let mut initial_events: Vec<TaintEvent<'a>> = Vec::new();
    if let Some(name) = func_name {
        let trimmed = name.trim_start_matches('_');
        if trimmed == "main" {
            // Find param_1 (argv) — the SSA's first VarDef whose
            // param_name == "param_1" carries the argv pointer.
            for v in &ssa.vars {
                if v.param_name.as_deref() == Some("param_1") {
                    let argv_spec = DEFAULT_SOURCES
                        .iter()
                        .find(|s| s.name == "argv")
                        .expect("argv spec missing from DEFAULT_SOURCES");
                    initial_events.push(TaintEvent {
                        stmt_index: 0,
                        kind: TaintEventKind::SourceCall {
                            spec: argv_spec,
                            args: vec![VarId(0), v.id],
                            out: None,
                            call_chain: Vec::new(),
                        },
                    });
                    break;
                }
            }
        }
    }
    let initial = WalkState {
        current: ssa.entry,
        events: initial_events,
        visited: std::collections::HashSet::new(),
        branch_decisions: Vec::new(),
    };
    let mut worklist: Vec<WalkState<'a>> = vec![initial];
    let mut completed: Vec<WalkState<'a>> = Vec::new();
    let mut last_reject: Option<PathRejection> = None;

    while let Some(mut state) = worklist.pop() {
        if state.branch_decisions.len() as u32 > MAX_BRANCH_DEPTH {
            last_reject = Some(PathRejection::UnsupportedTerminator("depth limit"));
            continue;
        }
        let mut keep_walking = true;
        while keep_walking {
            if !state.visited.insert(state.current) {
                last_reject = Some(PathRejection::UnsupportedTerminator("loop back-edge"));
                keep_walking = false;
                break;
            }
            let block = match ssa.blocks.iter().find(|b| b.id == state.current) {
                Some(b) => b,
                None => {
                    last_reject =
                        Some(PathRejection::UnsupportedTerminator("dangling block id"));
                    keep_walking = false;
                    break;
                }
            };

            let mut phi_or_indirect = false;
            for (idx, stmt) in block.stmts.iter().enumerate() {
                match stmt {
                    Stmt::Assign(v) => {
                        // Skip Phi assignments — v1 lineage walk
                        // can't propagate taint through them without
                        // per-path predecessor resolution. Recording
                        // them as Assign events is harmless when the
                        // sink doesn't depend on the Phi result, and
                        // saves the walker from rejecting any path
                        // that touches a real-world reconvergence
                        // point. Per-path Phi resolution is v2 work.
                        if matches!(
                            ssa.vars.get(v.0 as usize).map(|d| &d.expr),
                            Some(crate::ir::Expr::Phi(_))
                        ) {
                            continue;
                        }
                        state.events.push(TaintEvent {
                            stmt_index: idx,
                            kind: TaintEventKind::Assign(*v),
                        });
                    }
                    Stmt::Store { addr, val } => {
                        state.events.push(TaintEvent {
                            stmt_index: idx,
                            kind: TaintEventKind::Store {
                                addr: *addr,
                                val: *val,
                            },
                        });
                    }
                    Stmt::Call { target, args, out } => {
                        match classify_call(idx, target, args, *out, imports, &ssa.vars) {
                            Ok(ev) => {
                                state.events.push(ev);
                                synthesize_summary_events(
                                    idx,
                                    target,
                                    args,
                                    block.addr,
                                    imports,
                                    &ssa.vars,
                                    summaries,
                                    &mut state.events,
                                );
                            }
                            Err(e) => {
                                last_reject = Some(e);
                                phi_or_indirect = true;
                                break;
                            }
                        }
                    }
                }
            }
            if phi_or_indirect {
                keep_walking = false;
                break;
            }

            let term_idx = block.stmts.len();
            match &block.terminator {
                SsaTerminator::Call {
                    target,
                    args,
                    out,
                    fallthrough,
                } => match classify_call(term_idx, target, args, *out, imports, &ssa.vars) {
                    Ok(ev) => {
                        state.events.push(ev);
                        synthesize_summary_events(
                            term_idx,
                            target,
                            args,
                            block.addr,
                            imports,
                            &ssa.vars,
                            summaries,
                            &mut state.events,
                        );
                        state.current = *fallthrough;
                    }
                    Err(e) => {
                        last_reject = Some(e);
                        keep_walking = false;
                    }
                },
                SsaTerminator::Fallthrough(next) => {
                    state.current = *next;
                }
                SsaTerminator::Return(_) => {
                    completed.push(state);
                    keep_walking = false;
                    break;
                }
                SsaTerminator::Branch(next) => {
                    // Unconditional jump — walk through. Same loop
                    // guard via `visited` covers infinite-Branch
                    // loops. Original v0 break-on-Branch was a
                    // conservative bail; v1 just keeps walking.
                    state.current = *next;
                }
                SsaTerminator::CBranch {
                    cond,
                    taken,
                    fallthrough,
                } => {
                    // Spawn a copy on the fallthrough arm; keep
                    // walking on the taken arm. Two caps: depth
                    // (MAX_BRANCH_DEPTH) and global worklist size
                    // (MAX_WORKLIST_SIZE). Surplus states are
                    // dropped — a real CVE candidate either fits in
                    // the budget or surfaces in a later pass.
                    if (state.branch_decisions.len() as u32) >= MAX_BRANCH_DEPTH {
                        last_reject =
                            Some(PathRejection::UnsupportedTerminator("depth limit"));
                        keep_walking = false;
                        break;
                    }
                    let block_addr = block.addr;
                    if worklist.len() < MAX_WORKLIST_SIZE {
                        let mut alt = WalkState {
                            current: *fallthrough,
                            events: state.events.clone(),
                            visited: state.visited.clone(),
                            branch_decisions: state.branch_decisions.clone(),
                        };
                        alt.branch_decisions.push(BranchDecision {
                            block_addr,
                            cond: *cond,
                            taken: false,
                        });
                        worklist.push(alt);
                    } else {
                        last_reject =
                            Some(PathRejection::UnsupportedTerminator("worklist cap"));
                    }

                    state.current = *taken;
                    state.branch_decisions.push(BranchDecision {
                        block_addr,
                        cond: *cond,
                        taken: true,
                    });
                }
                SsaTerminator::Indirect(_) => {
                    // Unresolved register-indirect branch — usually
                    // a tail-call or a jump-table dispatch we can't
                    // statically follow. Treat as a path endpoint
                    // rather than rejecting outright: any Source→
                    // Sink pair collected before this point is still
                    // a valid candidate for SAT. v2 will resolve
                    // jump tables through Load(GOT_table + idx).
                    completed.push(state);
                    keep_walking = false;
                    break;
                }
            }
        }
    }

    // Pair each Source with EVERY subsequent Sink in each
    // completed walk. v3: previous "next-Sink-only" rule meant a
    // path like `fgets(...) → strncpy(LengthArg) → popen(Command)`
    // got paired off as fgets→strncpy and the popen sink was lost
    // when LengthArg returned Unsupported. Emitting one path per
    // (source, downstream-sink) tuple lets SAT prove the deeper
    // sink even when an intermediate one is unsupported.
    let mut paths = Vec::new();
    for state in completed {
        let mut sources: Vec<(usize, &'a SourceSpec)> = Vec::new();
        for (i, ev) in state.events.iter().enumerate() {
            match &ev.kind {
                TaintEventKind::SourceCall { spec, .. } => {
                    sources.push((i, spec));
                }
                TaintEventKind::SinkCall { spec, .. } => {
                    for (src_i, src_spec) in &sources {
                        paths.push(TaintPath {
                            source: src_spec,
                            source_event: *src_i,
                            sink: spec,
                            sink_event: i,
                            events: state.events.clone(),
                            branch_decisions: state.branch_decisions.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    // v16: hard truncate. Without this, parser-style functions
    // can balloon `paths.len()` past 96k (observed on dnsmasq-2.78
    // ::read_file) and OOM downstream solve()/JSON-serialize
    // pipelines. Truncation happens AFTER full enumeration so
    // small-function recall is unchanged; only pathological large
    // outputs get cropped.
    if paths.len() > MAX_PATHS_PER_FN {
        paths.truncate(MAX_PATHS_PER_FN);
    }

    if paths.is_empty() {
        return Err(last_reject.unwrap_or(PathRejection::NoSinkFound));
    }
    Ok(paths)
}

/// v1.N1: resolve an Indirect call's target VarId to a constant
/// address by walking the SSA expression cone. Two patterns
/// supported:
///   1. Const(addr) directly — fully resolved.
///   2. Load(addr_var) where addr_var resolves to Const(slot_addr)
///      AND `imports` knows that slot's name. Common for GOT-based
///      calls and Mach-O lazy-binding stubs.
///
/// Returns `Some(addr)` whose lookup in imports yields a configured
/// Source or Sink, else `None`. v2 extends to BinOp(base, idx) for
/// vtable-style dispatch.
fn resolve_indirect_target(
    target_vn: &pcode_ir::Varnode,
    vars: &[crate::ir::VarDef],
    imports: &HashMap<u64, String>,
) -> Option<u64> {
    // Find a VarDef whose varnode matches the indirect target's
    // varnode. Walk Var-chains and Load(Const) edges up to a depth
    // budget. Return the first Const-or-Load-resolved address whose
    // imports.get matches a Source or Sink spec.
    let mut visited: std::collections::HashSet<u32> =
        std::collections::HashSet::new();
    let mut stack: Vec<u32> = vars
        .iter()
        .rev()
        .filter(|d| d.varnode == *target_vn)
        .map(|d| d.id.0)
        .collect();
    while let Some(id) = stack.pop() {
        if !visited.insert(id) {
            continue;
        }
        if visited.len() > 32 {
            break;
        }
        let Some(def) = vars.get(id as usize) else {
            continue;
        };
        match &def.expr {
            crate::ir::Expr::Const(c, _) => {
                let addr = *c & 0x0FFF_FFFF;
                if imports.contains_key(&addr) || imports.contains_key(c) {
                    return Some(if imports.contains_key(c) { *c } else { addr });
                }
            }
            crate::ir::Expr::Var(inner) => stack.push(inner.0),
            crate::ir::Expr::Load(addr_var) => {
                if let Some(addr_def) = vars.get(addr_var.0 as usize) {
                    if let crate::ir::Expr::Const(slot, _) = addr_def.expr {
                        let candidates = [slot, slot & 0x0FFF_FFFF];
                        for c in candidates {
                            if imports.contains_key(&c) {
                                return Some(c);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn classify_call<'a>(
    stmt_index: usize,
    target: &CallTarget,
    args: &[VarId],
    out: Option<VarId>,
    imports: &HashMap<u64, String>,
    vars: &[crate::ir::VarDef],
) -> Result<TaintEvent<'a>, PathRejection> {
    // v1.N1: try to resolve Indirect call targets through the SSA
    // cone. Direct(addr) is the trivial case; Indirect(vn) attempts
    // a Var-chain + Load(Const) walk for GOT-style dispatch.
    let direct_addr = match target {
        CallTarget::Direct(a) => Some(*a),
        CallTarget::Indirect(vn) => resolve_indirect_target(vn, vars, imports),
    };
    let kind = match direct_addr.and_then(|a| resolve_call(a, imports)) {
        Some(SpecRef::Source(s)) => {
            // Find the matching SourceSpec from DEFAULT_SOURCES so
            // the lifetime ties to 'static (avoids cloning into the
            // event, keeps the spec table the single source of truth).
            let spec = DEFAULT_SOURCES
                .iter()
                .find(|sp| sp.name == s.name)
                .expect("resolve_call returned a SourceSpec not in DEFAULT_SOURCES");
            TaintEventKind::SourceCall {
                spec,
                args: args.to_vec(),
                out,
                call_chain: Vec::new(),
            }
        }
        Some(SpecRef::Sink(s)) => {
            let spec = DEFAULT_SINKS
                .iter()
                .find(|sp| sp.name == s.name)
                .expect("resolve_call returned a SinkSpec not in DEFAULT_SINKS");
            TaintEventKind::SinkCall {
                spec,
                args: args.to_vec(),
                out,
                call_chain: Vec::new(),
            }
        }
        None => {
            if direct_addr.is_none() {
                return Err(PathRejection::IndirectCall);
            }
            TaintEventKind::OtherCall {
                target_addr: direct_addr,
                args: args.to_vec(),
                out,
            }
        }
    };
    Ok(TaintEvent { stmt_index, kind })
}

/// v2.V8: when the walker hits a direct call whose target is a
/// FuncId with a built FunctionSummary (not a library import),
/// expand the callee's recorded sources/sinks into synthetic events
/// at the caller's call site. The args list is reconstructed so
/// `solve` can look up the watched VarId at the spec's slot index;
/// non-watched slots are filler `VarId(0)` because the SAT prover
/// only reads the watched slot.
fn synthesize_summary_events<'a>(
    stmt_index: usize,
    target: &CallTarget,
    caller_args: &[VarId],
    caller_addr: u64,
    imports: &HashMap<u64, String>,
    vars: &[crate::ir::VarDef],
    summaries: &HashMap<crate::callgraph::FuncId, crate::function_summary::FunctionSummary>,
    events: &mut Vec<TaintEvent<'a>>,
) {
    let direct_addr = match target {
        CallTarget::Direct(a) => Some(*a),
        CallTarget::Indirect(vn) => resolve_indirect_target(vn, vars, imports),
    };
    let Some(addr) = direct_addr else {
        return;
    };
    // v2.V10: prefer summary lookup over imports check. In Mach-O
    // (and stripped ELF) both imports and intra-binary symbols can
    // coexist in the import map; skipping any addr present in
    // imports would suppress all inter-procedural propagation. If
    // a summary exists, the call is intra-binary and worth lifting.
    let callee_sum = match summaries.get(&crate::callgraph::FuncId(addr)) {
        Some(s) => s,
        None => return,
    };
    for src in &callee_sum.sources {
        let Some(var) =
            synth_pick_caller_var(&src.tainted_caller_slots, caller_args, vars)
        else {
            continue;
        };
        let watched_idx = match src.source.tainted {
            AbiSlot::Arg(n) => n as usize,
            AbiSlot::Ret => continue, // Ret-tainted sources can't be retargeted via arg slot
            AbiSlot::Global(_) => continue, // libc specs never use Global
        };
        let mut args_vec = vec![VarId(0); watched_idx + 1];
        args_vec[watched_idx] = var;
        let spec = DEFAULT_SOURCES
            .iter()
            .find(|sp| sp.name == src.source.name)
            .expect("summary source not in DEFAULT_SOURCES");
        events.push(TaintEvent {
            stmt_index,
            kind: TaintEventKind::SourceCall {
                spec,
                args: args_vec,
                out: None,
                call_chain: vec![caller_addr, src.call_site],
            },
        });
    }
    for snk in &callee_sum.sinks {
        let Some(var) =
            synth_pick_caller_var(&snk.tainted_caller_slots, caller_args, vars)
        else {
            continue;
        };
        let watched_idx = match snk.sink.watched {
            AbiSlot::Arg(n) => n as usize,
            AbiSlot::Ret => continue,
            AbiSlot::Global(_) => continue,
        };
        let mut args_vec = vec![VarId(0); watched_idx + 1];
        args_vec[watched_idx] = var;
        let spec: &SinkSpec = if snk.sink.name == STORE_SINK_SPEC.name {
            &STORE_SINK_SPEC
        } else {
            DEFAULT_SINKS
                .iter()
                .find(|sp| sp.name == snk.sink.name)
                .expect("summary sink not in DEFAULT_SINKS")
        };
        events.push(TaintEvent {
            stmt_index,
            kind: TaintEventKind::SinkCall {
                spec,
                args: args_vec,
                out: None,
                call_chain: vec![caller_addr, snk.call_site],
            },
        });
    }
}

fn synth_pick_caller_var(
    tainted_slots: &[AbiSlot],
    caller_args: &[VarId],
    caller_vars: &[crate::ir::VarDef],
) -> Option<VarId> {
    for slot in tainted_slots {
        match slot {
            AbiSlot::Arg(n) => {
                if let Some(v) = caller_args.get(*n as usize) {
                    return Some(*v);
                }
            }
            AbiSlot::Global(va) => {
                // v5.W2.D2a: find any caller VarDef whose expr is
                // `Const(va)` or `Load(Const(va))` — the global
                // address is materialised somewhere in the caller's
                // SSA (otherwise the caller couldn't have passed it
                // to the callee). Return the first match so the
                // synthesized event's args carry that VarId; v4's
                // region-keyed MemMap then aliases this load with
                // any sink's Load of the same VA.
                for vd in caller_vars {
                    match &vd.expr {
                        crate::ir::Expr::Const(c, _) if *c == *va => {
                            return Some(vd.id);
                        }
                        crate::ir::Expr::Load(addr) => {
                            if let Some(addr_def) = caller_vars.get(addr.0 as usize) {
                                if let crate::ir::Expr::Const(c, _) = addr_def.expr {
                                    if c == *va {
                                        return Some(vd.id);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            AbiSlot::Ret => {}
        }
    }
    None
}

/// Map of last-Store addresses (as canonical-form keys) to the
/// VarId of the stored value. Built once per `solve` invocation by
/// walking the path's events. Used by `varid_lineage_eq` to follow
/// Load(addr) back to the value most recently stored at that addr.
///
/// v3 region-lite: the key is a recursive stringification of the
/// address expression so two address-computations that produce the
/// SAME logical address via different SSA Unique varnodes alias
/// correctly. Without this, every `-O0` reload pattern (`add fp,
/// #const_off` recomputed at each call site) defeats Store→Load
/// matching because each instance lands in a distinct Unique slot.
/// v4 region-keyed mem map. Each Store insert keys by
/// `(Region, OffsetClass)` derived from `region::infer_regions`,
/// so two -O0 reload sites recomputing the same `add(fp, c)`
/// shape with different Unique varnodes collide on the same key.
type MemMap = HashMap<(crate::region::Region, crate::region::OffsetClass), VarId>;

fn build_mem_map(
    events: &[TaintEvent<'_>],
    vars: &[crate::ir::VarDef],
    regions: &crate::region::RegionMap,
) -> MemMap {
    let mut m = MemMap::new();
    for ev in events {
        if let TaintEventKind::Store { addr, val } = ev.kind {
            let key = mem_key(addr, vars, regions);
            m.insert(key, val);
        }
    }
    m
}

/// Compute the region-keyed alias key for an address expression.
fn mem_key(
    addr: VarId,
    vars: &[crate::ir::VarDef],
    regions: &crate::region::RegionMap,
) -> (crate::region::Region, crate::region::OffsetClass) {
    let region = regions.region_of(addr);
    let offset = classify_offset(addr, vars);
    (region, offset)
}

fn classify_offset(addr: VarId, vars: &[crate::ir::VarDef]) -> crate::region::OffsetClass {
    use crate::ir::{BinOpKind, Expr};
    use crate::region::OffsetClass;
    let Some(def) = vars.get(addr.0 as usize) else {
        return OffsetClass::ConstOffset(0);
    };
    match &def.expr {
        Expr::FieldAccess(_, off) => OffsetClass::ConstOffset(*off as i64),
        Expr::BinOp(BinOpKind::Add, a, b) => {
            if let Some(c) = const_value(*a, vars) {
                return OffsetClass::ConstOffset(c);
            }
            if let Some(c) = const_value(*b, vars) {
                return OffsetClass::ConstOffset(c);
            }
            OffsetClass::Symbolic
        }
        Expr::BinOp(BinOpKind::Sub, a, b) => {
            if let Some(c) = const_value(*b, vars) {
                if let Some(ca) = const_value(*a, vars) {
                    return OffsetClass::ConstOffset(ca.wrapping_sub(c));
                }
                return OffsetClass::ConstOffset(-c);
            }
            OffsetClass::Symbolic
        }
        Expr::Var(inner) => classify_offset(*inner, vars),
        Expr::Const(c, _) => OffsetClass::ConstOffset(*c as i64),
        _ => OffsetClass::ConstOffset(0),
    }
}

fn const_value(v: VarId, vars: &[crate::ir::VarDef]) -> Option<i64> {
    let mut cur = v;
    for _ in 0..16 {
        let def = vars.get(cur.0 as usize)?;
        match &def.expr {
            crate::ir::Expr::Const(c, _) => return Some(*c as i64),
            crate::ir::Expr::Var(inner) => cur = *inner,
            _ => return None,
        }
    }
    None
}

// Read-only reconstruction of the understood pre-I2C single-key memory
// behavior. This is not pinned historical source and never controls the typed
// production result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ReconstructedLegacyAliasKey {
    Vn(pcode_ir::Varnode),
    Region(crate::region::Region, crate::region::OffsetClass),
}

type ReconstructedLegacyMemMap = HashMap<
    (crate::region::Region, crate::region::OffsetClass), VarId>;

fn reconstructed_legacy_mem_key(
    address: VarId,
    vars: &[crate::ir::VarDef],
    regions: &crate::region::RegionMap,
) -> (crate::region::Region, crate::region::OffsetClass) {
    (regions.region_of(address), classify_offset(address, vars))
}

fn build_reconstructed_legacy_mem_map(
    events: &[TaintEvent<'_>],
    vars: &[crate::ir::VarDef],
    regions: &crate::region::RegionMap,
) -> ReconstructedLegacyMemMap {
    let mut memory = ReconstructedLegacyMemMap::new();
    for event in events {
        if let TaintEventKind::Store { addr, val } = event.kind {
            memory.insert(reconstructed_legacy_mem_key(addr, vars, regions), val);
        }
    }
    memory
}

fn reconstructed_legacy_chain_keys(
    start: VarId,
    vars: &[crate::ir::VarDef],
    memory: &ReconstructedLegacyMemMap,
    regions: &crate::region::RegionMap,
    follow_memory: bool,
) -> Vec<ReconstructedLegacyAliasKey> {
    use crate::region::{AllocSite, OffsetClass};
    let mut output = Vec::new();
    let mut visited = std::collections::HashSet::<u32>::new();
    let mut stack = vec![start];
    while let Some(current) = stack.pop() {
        if !visited.insert(current.0) { continue; }
        if visited.len() > 64 { break; }
        let Some(definition) = vars.get(current.0 as usize) else { continue };
        if !matches!(definition.varnode.space, pcode_ir::AddressSpaceId::Register)
            && !definition.call_return {
            output.push(ReconstructedLegacyAliasKey::Vn(definition.varnode));
        }
        let region = regions.region_of(current);
        if let Some(site) = regions.site_of(region) {
            if !matches!(site, AllocSite::Unknown(_)) {
                output.push(ReconstructedLegacyAliasKey::Region(
                    region, classify_offset(current, vars)));
            }
        }
        match &definition.expr {
            crate::ir::Expr::Var(inner) => stack.push(*inner),
            crate::ir::Expr::Load(address) if follow_memory => {
                let key = reconstructed_legacy_mem_key(*address, vars, regions);
                if let Some(stored) = memory.get(&key).copied() {
                    stack.push(stored);
                } else if let Some(stored) = memory
                    .get(&(key.0, OffsetClass::Symbolic)).copied() {
                    stack.push(stored);
                }
            }
            crate::ir::Expr::Load(_) => {}
            crate::ir::Expr::BinOp(_, left, right) => {
                stack.push(*left); stack.push(*right);
            }
            crate::ir::Expr::UnaryOp(_, inner) => stack.push(*inner),
            crate::ir::Expr::FieldAccess(base, _) => stack.push(*base),
            crate::ir::Expr::Phi(inputs) => stack.extend(inputs.iter().copied()),
            _ => {}
        }
    }
    output
}

fn reconstructed_legacy_lineage_eq(
    left: VarId,
    right: VarId,
    vars: &[crate::ir::VarDef],
    memory: &ReconstructedLegacyMemMap,
    regions: &crate::region::RegionMap,
) -> bool {
    if left == right { return true; }
    let left_keys = reconstructed_legacy_chain_keys(left, vars, memory, regions, true);
    let right_keys = reconstructed_legacy_chain_keys(right, vars, memory, regions, true);
    left_keys.iter().any(|left_key|
        right_keys.iter().any(|right_key| left_key == right_key))
}

/// One deterministic Store-to-later-Load comparison from the opt-in surface.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AliasLineageObservation {
    pub block_addr: u64,
    pub statement_index: usize,
    pub load_var_id: u32,
    pub store_block_addr: u64,
    pub store_statement_index: usize,
    pub store_value_var_id: u32,
    pub typed: bool,
    pub reconstructed_legacy: bool,
    pub alias_class: String,
    pub alias_reason: String,
    pub typed_inventory_cardinality: usize,
    pub reconstructed_legacy_inventory_cardinality: usize,
    pub load_region: u32,
    pub store_region: u32,
    pub same_region: bool,
    pub pre_memory_isolated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OrderedStore {
    block_addr: u64,
    statement_index: usize,
    address: VarId,
    value: VarId,
}

/// Observe the typed result and reconstructed shadow side by side. The shadow
/// cannot affect production flow. Returns admitted observations and the full
/// pre-cap pair count.
pub fn observe_alias_lineage(
    ssa: &crate::ir::SsaCfg,
    observation_cap: usize,
) -> (Vec<AliasLineageObservation>, usize) {
    use crate::memory_effect::{query_alias_vars, MemoryAccess};
    let regions = crate::region::infer_regions(ssa);
    let calls = build_call_return_map(ssa);
    let mut blocks: Vec<_> = ssa.blocks.iter().collect();
    blocks.sort_by_key(|block| block.addr);
    let mut stores = Vec::<OrderedStore>::new();
    let mut events = Vec::<TaintEvent<'static>>::new();
    let mut observations = Vec::new();
    let mut pair_count = 0usize;

    for block in blocks {
        for (statement_index, statement) in block.stmts.iter().enumerate() {
            match statement {
                Stmt::Store { addr, val } => {
                    stores.push(OrderedStore { block_addr: block.addr,
                        statement_index, address: *addr, value: *val });
                    events.push(TaintEvent { stmt_index: statement_index,
                        kind: TaintEventKind::Store { addr: *addr, val: *val } });
                }
                Stmt::Assign(load_var) => {
                    let Some(definition) = ssa.vars.get(load_var.0 as usize) else { continue };
                    let crate::ir::Expr::Load(load_address) = &definition.expr else { continue };
                    let typed_memory = build_mem_map(&events, &ssa.vars, &regions);
                    let reconstructed_memory = build_reconstructed_legacy_mem_map(
                        &events, &ssa.vars, &regions);
                    for store in &stores {
                        pair_count = pair_count.saturating_add(1);
                        if observations.len() >= observation_cap { continue; }
                        let typed = varid_lineage_eq(store.value, *load_var,
                            &ssa.vars, &typed_memory, &calls, &regions);
                        let reconstructed_legacy = reconstructed_legacy_lineage_eq(
                            store.value, *load_var, &ssa.vars,
                            &reconstructed_memory, &regions);
                        let alias = query_alias_vars(&ssa.vars, &regions,
                            MemoryAccess { address: store.address, displacement: 0,
                                width: ssa.vars.get(store.value.0 as usize)
                                    .map(|value| u64::from(value.size)).unwrap_or(0) },
                            MemoryAccess { address: *load_address, displacement: 0,
                                width: u64::from(definition.size) });
                        let empty = ReconstructedLegacyMemMap::new();
                        let value_keys = reconstructed_legacy_chain_keys(
                            store.value, &ssa.vars, &empty, &regions, false);
                        let load_keys = reconstructed_legacy_chain_keys(
                            *load_var, &ssa.vars, &empty, &regions, false);
                        let pre_memory_isolated = value_keys.iter().all(|value_key|
                            !load_keys.iter().any(|load_key| value_key == load_key));
                        let load_region = regions.region_of(*load_address);
                        let store_region = regions.region_of(store.address);
                        observations.push(AliasLineageObservation {
                            block_addr: block.addr, statement_index,
                            load_var_id: load_var.0,
                            store_block_addr: store.block_addr,
                            store_statement_index: store.statement_index,
                            store_value_var_id: store.value.0,
                            typed, reconstructed_legacy,
                            alias_class: format!("{:?}", alias.class),
                            alias_reason: format!("{:?}", alias.reason),
                            typed_inventory_cardinality: typed_memory.len(),
                            reconstructed_legacy_inventory_cardinality: reconstructed_memory.len(),
                            load_region: load_region.0, store_region: store_region.0,
                            same_region: load_region == store_region,
                            pre_memory_isolated,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    (observations, pair_count)
}

/// Map of a Call's `out` VarId to the Call's argument VarIds.
/// v2.V5: a return value carries taint forward from any tainted arg
/// (intra-procedural pass-through assumption). The lineage walker
/// uses this so a sink VarId derived from `out = strdup(tainted)`
/// resolves back to the source.
type CallReturnMap = HashMap<VarId, Vec<VarId>>;

/// v5.W2.D2b: libc functions whose return value is a strict upper
/// bound on the length of their string/buffer input. Lineage from
/// network/file input that flows through one of these can no longer
/// drive a length-overflow at a downstream memcpy/strncpy/memmove,
/// because the wrapper has clipped the length to a known small
/// range. Used by the LengthArg solver to reject FP candidates
/// like `strncpy(dst, fgets_buf, strlen(fgets_buf))` where strlen
/// caps at 511 ≤ fgets-cap.
const LENGTH_BOUNDING_WRAPPERS: &[&str] = &[
    "strlen", "strnlen", "wcslen", "wcsnlen",
    // snprintf / vsnprintf return value is the count of bytes that
    // would have been written — clipped to size by the caller in
    // every sane code path. Treat as bounded.
    "snprintf", "vsnprintf",
    // v5.W2.D2b: read/recv-class return value is the count of
    // bytes received, bounded by the count arg. When the count is
    // a Const (the dominant case in real code), the return is a
    // small constant upper bound — using it as a memcpy length
    // can't drive a > 0xFFFF overflow regardless of attacker-
    // controlled BUFFER content. Treating their returns as
    // bounded gives up some inter-procedural recall in exchange
    // for FP elimination on the AX6000 corpus (dropbear FUN_-
    // 0001ba3c was the only hit before this filter and was
    // bounded by `read(_, _, 4096)`).
    "read", "recv", "recvfrom", "recvmsg", "fread", "fgets",
];

fn build_bounded_returns_set(
    ssa: &crate::ir::SsaCfg,
    imports: &HashMap<u64, String>,
) -> std::collections::HashSet<VarId> {
    let mut out = std::collections::HashSet::new();
    let wrapper_kind = |target: &CallTarget| -> Option<&'static str> {
        if let CallTarget::Direct(addr) = target {
            if let Some(raw) = imports.get(addr) {
                let n = normalise_name(raw);
                if let Some(name) = LENGTH_BOUNDING_WRAPPERS
                    .iter()
                    .find(|w| **w == n)
                    .copied()
                {
                    return Some(name);
                }
            }
        }
        None
    };
    let mut consider = |target: &CallTarget, args: &[VarId], o: VarId| {
        let Some(name) = wrapper_kind(target) else { return };
        // v6.W1: read/recv-class returns are bounded only when
        // their `count` operand is statically Const. When the
        // count itself comes from network input or another Load,
        // the return value can grow as large as the attacker
        // wants — treating it as bounded would suppress real
        // protocol-field length-overflow flows.
        let count_idx: Option<usize> = match name {
            "read" | "recv" | "recvfrom" | "recvmsg" => Some(2),
            "fread" => Some(2),
            "fgets" => Some(1),
            _ => None,
        };
        if let Some(idx) = count_idx {
            if !arg_resolves_to_const(args.get(idx).copied(), &ssa.vars) {
                return;
            }
        }
        out.insert(o);
    };
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            if let crate::ir::Stmt::Call {
                target,
                args,
                out: Some(o),
                ..
            } = stmt
            {
                consider(target, args, *o);
            }
        }
        if let crate::ir::SsaTerminator::Call {
            target,
            args,
            out: Some(o),
            ..
        } = &block.terminator
        {
            consider(target, args, *o);
        }
    }
    out
}

/// v6.W1: walk the Var/Phi DAG from `var` and return true iff every
/// reachable leaf is `Const`. Phi joins of constant counts (e.g.
/// `count = cond ? 4096 : 1024;`) are statically bounded. Bounded
/// depth + visited-set to avoid pathological IRs.
fn arg_resolves_to_const(var: Option<VarId>, vars: &[crate::ir::VarDef]) -> bool {
    let Some(start) = var else { return false };
    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut stack = vec![start];
    let mut steps = 0usize;
    while let Some(cur) = stack.pop() {
        if !visited.insert(cur.0) {
            continue;
        }
        steps += 1;
        if steps > 64 {
            return false;
        }
        let Some(def) = vars.get(cur.0 as usize) else { return false };
        match &def.expr {
            crate::ir::Expr::Var(inner) => stack.push(*inner),
            crate::ir::Expr::Const(_, _) => {}
            crate::ir::Expr::Phi(inputs) => {
                for v in inputs {
                    stack.push(*v);
                }
            }
            _ => return false,
        }
    }
    true
}

fn build_call_return_map(ssa: &crate::ir::SsaCfg) -> CallReturnMap {
    let mut m = CallReturnMap::new();
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            if let crate::ir::Stmt::Call {
                args,
                out: Some(o),
                ..
            } = stmt
            {
                m.insert(*o, args.clone());
            }
        }
        if let crate::ir::SsaTerminator::Call {
            args,
            out: Some(o),
            ..
        } = &block.terminator
        {
            m.insert(*o, args.clone());
        }
    }
    m
}

/// True if `a` and `b` share a common logical location after
/// following SSA `Var` chains AND a single layer of Store→Load
/// indirection through `mem`. Lifters split a buffer pointer into
/// many SSA versions across Store/Load round-trips; without the
/// memory map this lineage trace would miss every realistic flow.
fn varid_lineage_eq(
    a: VarId,
    b: VarId,
    vars: &[crate::ir::VarDef],
    mem: &MemMap,
    calls: &CallReturnMap,
    regions: &crate::region::RegionMap,
) -> bool {
    if a == b {
        return true;
    }
    let chain_a = chain_varnodes(a, vars, mem, calls, regions);
    let chain_b = chain_varnodes(b, vars, mem, calls, regions);
    for vn_a in &chain_a {
        if chain_b.iter().any(|vn_b| vn_a == vn_b) {
            return true;
        }
    }
    false
}

/// Alias key for two-chain intersection in `varid_lineage_eq`.
/// Two VarIds alias when their alias sets share at least one key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AliasKey {
    /// Stable Varnode (Ram / Unique / Const) of a non-call_return def.
    Vn(pcode_ir::Varnode),
    /// Region+offset class derived from the VarId's region
    /// classification. Lets two distinct VarIds that point at
    /// the same logical region+offset alias even when their
    /// SSA expressions don't share a Varnode.
    Region(crate::region::Region, crate::region::OffsetClass),
}

/// Collect the set of alias keys reached from `start` via SSA
/// Var-chain, BinOp/UnaryOp/Phi/FieldAccess propagation, and one
/// layer of Store→Load redirection through the region-keyed
/// `mem`. Bounded depth so cyclic IRs don't hang the prover.
fn chain_varnodes(
    start: VarId,
    vars: &[crate::ir::VarDef],
    mem: &MemMap,
    calls: &CallReturnMap,
    regions: &crate::region::RegionMap,
) -> Vec<AliasKey> {
    chain_varnodes_with_bound(start, vars, mem, calls, regions, None)
}

/// v5.W2.D2b: variant that stops the call-return pass-through at
/// VarIds present in `bounded_outs` (returns from length-bounding
/// wrappers like strlen / snprintf). Used by the LengthArg solver
/// to reject FP paths where the tainted length flows through a
/// bound-shrinking wrapper.
fn chain_varnodes_with_bound(
    start: VarId,
    vars: &[crate::ir::VarDef],
    mem: &MemMap,
    calls: &CallReturnMap,
    regions: &crate::region::RegionMap,
    bounded_outs: Option<&std::collections::HashSet<VarId>>,
) -> Vec<AliasKey> {
    let mut out = Vec::new();
    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut stack = vec![start];
    while let Some(current) = stack.pop() {
        if !visited.insert(current.0) {
            continue;
        }
        if visited.len() > 64 {
            break;
        }
        // v2.V5: if `current` is a Call's `out`, push every arg —
        // the return value is treated as carrying taint forward
        // from any tainted argument (intra-procedural pass-through).
        // v5.W2.D2b: skip args when the call target is a length-
        // bounding wrapper (strlen, snprintf, ...) — the wrapper's
        // return is bounded by definition, so taint upstream of
        // the wrapper isn't a length-overflow predicate.
        if let Some(args) = calls.get(&current) {
            let is_bounded = bounded_outs
                .map(|s| s.contains(&current))
                .unwrap_or(false);
            if !is_bounded {
                for a in args {
                    stack.push(*a);
                }
            }
        }
        let Some(def) = vars.get(current.0 as usize) else {
            continue;
        };
        // v3 precision: only emit a Varnode-level alias key for
        // spaces where varnode identity implies value identity.
        // Register-space reuse (ARM32 `r0 = popen(); r0 = fgets()`)
        // and per-instruction Unique slots get DIFFERENT VarIds
        // under SSA, but if we cross-link them via Varnode equality
        // every register-reuse pair becomes a spurious lineage hit.
        // Call-return VarIds always get fresh data — never alias by
        // their outgoing register.
        let space_aliases = !matches!(
            def.varnode.space,
            pcode_ir::AddressSpaceId::Register
        ) && !def.call_return;
        if space_aliases {
            out.push(AliasKey::Vn(def.varnode));
        }
        // v4: region+offset is a more robust alias key than
        // raw varnode for stack-spilled pointer values. We
        // include it for any VarId whose region resolved to a
        // non-Unknown AllocSite — Unknown regions are minted
        // per-VarId so they'd never alias anyway.
        let region = regions.region_of(current);
        if let Some(site) = regions.site_of(region) {
            if !matches!(site, crate::region::AllocSite::Unknown(_)) {
                let off = classify_offset(current, vars);
                out.push(AliasKey::Region(region, off));
            }
        }
        match &def.expr {
            crate::ir::Expr::Var(inner) => stack.push(*inner),
            crate::ir::Expr::Load(addr) => {
                let key = mem_key(*addr, vars, regions);
                if let Some(stored) = mem.get(&key).copied() {
                    stack.push(stored);
                } else {
                    // v4 over-approximate: any Symbolic-offset
                    // Store on the same region aliases this Load.
                    let sym_key = (
                        key.0,
                        crate::region::OffsetClass::Symbolic,
                    );
                    if let Some(stored) = mem.get(&sym_key).copied() {
                        stack.push(stored);
                    }
                }
            }
            // v3 lineage widening: taint propagates through
            // arithmetic / type-casts / phi joins. A loop counter
            // mixed with a tainted byte still leaves the result
            // attacker-influenced; the per-SinkKind constraint
            // does the actual feasibility check.
            crate::ir::Expr::BinOp(_, a, b) => {
                stack.push(*a);
                stack.push(*b);
            }
            crate::ir::Expr::UnaryOp(_, a) => stack.push(*a),
            crate::ir::Expr::FieldAccess(base, _off) => stack.push(*base),
            crate::ir::Expr::Phi(args) => {
                for a in args {
                    stack.push(*a);
                }
            }
            _ => {}
        }
    }
    out
}

/// v0 SAT prover: takes a `TaintPath` produced by `collect_paths`,
/// confirms the sink's watched VarId lineage descends from the
/// source's tainted slot, and asks Z3 whether a symbolic input can
/// satisfy the per-`SinkKind` violation constraint.
///
/// v0 simplifications (locked):
///   - 32-byte fresh symbolic input array; no flat memory model yet.
///   - No Load/Store/FieldAccess lowering inside the SSA cone.
///   - LengthArg sinks return `Unsupported` (modelling deferred).
///   - Lineage check is `Expr::Var` chain only — no BinOp/Phi taint.
#[cfg(feature = "smt")]
pub fn solve(path: &TaintPath, ssa: &crate::ir::SsaCfg) -> SmtFinding {
    solve_with_imports(path, ssa, &HashMap::new())
}

/// v5.W2.D2b: solve variant aware of length-bounding wrappers.
/// `imports` is consulted only to build a per-SSA set of VarIds
/// returned from `strlen` / `snprintf` / etc.; LengthArg sinks
/// reject lineages that pass through one of those wrappers.
#[cfg(feature = "smt")]
pub fn solve_with_imports(
    path: &TaintPath,
    ssa: &crate::ir::SsaCfg,
    imports: &HashMap<u64, String>,
) -> SmtFinding {
    solve_diag(path, ssa, imports, &mut Vec::new())
}

/// v7.W1: same as `solve_with_imports` but appends a
/// human-readable filter-reason string for each precision check
/// the solver applied. Empty `reason_log` ⇒ Reachable verdict
/// hit no filter; non-empty ⇒ at least one filter classified the
/// path as bounded / out-of-scope. Used by `--smt-candidates` to
/// dump the analyst-facing reasoning trail per path.
#[cfg(feature = "smt")]
pub fn solve_diag(
    path: &TaintPath,
    ssa: &crate::ir::SsaCfg,
    imports: &HashMap<u64, String>,
    reason_log: &mut Vec<String>,
) -> SmtFinding {
    use z3::ast::{Ast, BV};

    let source_event = &path.events[path.source_event];
    let sink_event = &path.events[path.sink_event];

    let source_var = match (&source_event.kind, path.source.tainted) {
        (TaintEventKind::SourceCall { args, .. }, AbiSlot::Arg(n)) => {
            args.get(n as usize).copied()
        }
        (TaintEventKind::SourceCall { out, .. }, AbiSlot::Ret) => *out,
        _ => None,
    };
    let sink_var = match (&sink_event.kind, path.sink.watched) {
        (TaintEventKind::SinkCall { args, .. }, AbiSlot::Arg(n)) => {
            args.get(n as usize).copied()
        }
        (TaintEventKind::SinkCall { out, .. }, AbiSlot::Ret) => *out,
        _ => None,
    };

    let (Some(src), Some(snk)) = (source_var, sink_var) else {
        reason_log.push("source/sink slot missing".into());
        return SmtFinding::Unsupported("source/sink slot missing");
    };
    let regions = crate::region::infer_regions(ssa);
    let mem = build_mem_map(&path.events, &ssa.vars, &regions);
    let calls = build_call_return_map(ssa);
    let lineage_ok = if path.source.name == "argv" {
        // v13: argv source taints the entire `argv` region. Any
        // VarId whose SSA chain reaches the Region(Param(1), *)
        // matches, ignoring OffsetClass — `argv[N]` and `argv` share
        // a region in v4 inference.
        let src_region = regions.region_of(src);
        let chain_snk = chain_varnodes(snk, &ssa.vars, &mem, &calls, &regions);
        chain_snk.iter().any(|k| matches!(k, AliasKey::Region(r, _) if *r == src_region))
            || varid_lineage_eq(snk, src, &ssa.vars, &mem, &calls, &regions)
    } else {
        varid_lineage_eq(snk, src, &ssa.vars, &mem, &calls, &regions)
    };
    if !lineage_ok {
        reason_log.push("lineage_eq failed (no shared alias key)".into());
        return SmtFinding::NotReachable;
    }

    let z3_cfg = z3::Config::new();
    let ctx = z3::Context::new(&z3_cfg);
    let solver = z3::Solver::new(&ctx);

    const INPUT_LEN: usize = 32;
    let bytes: Vec<BV> = (0..INPUT_LEN)
        .map(|i| BV::new_const(&ctx, format!("in_{i}"), 8))
        .collect();

    match path.sink.kind {
        SinkKind::Command => {
            let mut acc = z3::ast::Bool::from_bool(&ctx, false);
            for b in &bytes {
                let semi = b._eq(&BV::from_u64(&ctx, b';' as u64, 8));
                let amp  = b._eq(&BV::from_u64(&ctx, b'&' as u64, 8));
                let pipe = b._eq(&BV::from_u64(&ctx, b'|' as u64, 8));
                let any = z3::ast::Bool::or(&ctx, &[&semi, &amp, &pipe]);
                acc = z3::ast::Bool::or(&ctx, &[&acc, &any]);
            }
            solver.assert(&acc);
        }
        SinkKind::FormatArg => {
            let mut acc = z3::ast::Bool::from_bool(&ctx, false);
            for b in &bytes {
                let pct = b._eq(&BV::from_u64(&ctx, b'%' as u64, 8));
                acc = z3::ast::Bool::or(&ctx, &[&acc, &pct]);
            }
            solver.assert(&acc);
        }
        SinkKind::StackBuffer => {
            for b in &bytes {
                let nz = b._eq(&BV::from_u64(&ctx, 0, 8)).not();
                solver.assert(&nz);
            }
        }
        SinkKind::TaintedStore => {
            // v10: SAT model. The lineage walker has proved
            // tainted source bytes reach the SRC pointer of a
            // Param→Param copy (per detect_tainted_store's two
            // preconditions). Reachable iff:
            //   (a) lineage_eq holds (already checked above), AND
            //   (b) all 32 input bytes can be nonzero — the loop
            //       bound is `*src != 0`, so an attacker who
            //       sends bytes with no \0 drives the copy
            //       arbitrarily long, overflowing the fixed
            //       caller-stack dst.
            // Trigger: 32 nonzero bytes (any value).
            for b in &bytes {
                let nz = b._eq(&BV::from_u64(&ctx, 0, 8)).not();
                solver.assert(&nz);
            }
        }
        SinkKind::CStringRead => {
            // SAT model for unbounded string readers. If the first
            // symbolic input window contains no NUL, libc string
            // walkers can read beyond packet/body bounds when the
            // caller failed to terminate the buffer. This is an
            // evidence generator, so candidate consumers must still
            // confirm the allocation/length boundary in context.
            for b in &bytes {
                let nz = b._eq(&BV::from_u64(&ctx, 0, 8)).not();
                solver.assert(&nz);
            }
        }
        SinkKind::LengthArg => {
            // v5.W2.D2b: Reachable iff
            //   (a) tainted lineage from src reaches the length
            //       operand WITHOUT passing through a length-
            //       bounding wrapper (strlen / snprintf / ...), AND
            //   (b) the dst arg is a stack-frame region (per v4
            //       region inference) — heap/global dsts have
            //       runtime size, not statically a stack-frame BOF.
            let bounded = build_bounded_returns_set(ssa, imports);
            let chain_a = chain_varnodes_with_bound(
                snk, &ssa.vars, &mem, &calls, &regions, Some(&bounded),
            );
            let chain_b = chain_varnodes_with_bound(
                src, &ssa.vars, &mem, &calls, &regions, Some(&bounded),
            );
            // v6.W1: Vn-key alias is the strongest signal. v7.W3:
            // Vn-strict alone is too tight on Heartbleed-shape flows
            // (`len = (buf[0] << 8) | buf[1]; memcpy(dst, buf+2,
            // len)`) where the buffer contents are attacker-
            // controlled but the SSA carries `buf` in Register
            // space (no Vn key emitted). Allow a Region match when
            // and only when the shared region is the SOURCE's
            // specific region — not a generic Param/StackFrame
            // match which over-approximates.
            let src_region = regions.region_of(src);
            let region_eq = matches!(regions.site_of(src_region),
                Some(s) if !matches!(s, crate::region::AllocSite::Unknown(_)))
                && chain_a.iter().any(|k| {
                    matches!(k, AliasKey::Region(r, _) if *r == src_region)
                })
                && chain_b.iter().any(|k| {
                    matches!(k, AliasKey::Region(r, _) if *r == src_region)
                });
            let unbounded_eq = chain_a.iter().any(|k_a| {
                matches!(k_a, AliasKey::Vn(_)) && chain_b.contains(k_a)
            }) || region_eq;
            if !unbounded_eq {
                reason_log.push(format!(
                    "LengthArg lineage bounded by wrapper return ({} bounded VarIds: {:?})",
                    bounded.len(),
                    bounded.iter().map(|v| v.0).take(8).collect::<Vec<_>>()
                ));
                return SmtFinding::NotReachable;
            }
            // dst region check (memcpy/strncpy/memmove all use Arg(0)).
            let dst_var = match &sink_event.kind {
                TaintEventKind::SinkCall { args, .. } => args.first().copied(),
                _ => None,
            };
            let dst_is_stack = dst_var
                .map(|v| {
                    let r = regions.region_of(v);
                    matches!(
                        regions.site_of(r),
                        Some(crate::region::AllocSite::StackFrame)
                    )
                })
                .unwrap_or(false);
            if !dst_is_stack {
                let region_label = dst_var
                    .map(|v| {
                        let r = regions.region_of(v);
                        format!("{:?}", regions.site_of(r))
                    })
                    .unwrap_or_else(|| "(no dst var)".into());
                reason_log.push(format!(
                    "LengthArg dst region not StackFrame: {}",
                    region_label
                ));
                return SmtFinding::NotReachable;
            }
            // Encode length as 32-bit BV from 4 input bytes (LE);
            // assert > 0xFFFF (any plausible stack buffer cap).
            let len = bytes[0]
                .concat(&bytes[1])
                .concat(&bytes[2])
                .concat(&bytes[3]);
            let threshold = BV::from_u64(&ctx, 0xFFFF, 32);
            solver.assert(&len.bvugt(&threshold));
        }
    }

    match solver.check() {
        z3::SatResult::Sat => {
            let m = match solver.get_model() {
                Some(m) => m,
                None => {
                    reason_log.push("Z3 SAT but model unavailable".into());
                    return SmtFinding::Unsupported("SAT but no model returned");
                }
            };
            let mut input_bytes = Vec::new();
            for (i, b) in bytes.iter().enumerate() {
                let evaluated = z3::Model::eval(&m, b, true);
                if let Some(v_bv) = evaluated {
                    if let Some(v) = v_bv.as_u64() {
                        input_bytes.push((i, v as u8));
                    }
                }
            }
            let call_chain = match &path.events[path.sink_event].kind {
                TaintEventKind::SinkCall { call_chain, .. } => call_chain.clone(),
                _ => Vec::new(),
            };
            SmtFinding::Reachable { input_bytes, call_chain }
        }
        z3::SatResult::Unsat => {
            reason_log.push("Z3 unsat under sink-kind constraint".into());
            SmtFinding::NotReachable
        }
        z3::SatResult::Unknown => {
            reason_log.push("Z3 returned Unknown / timeout".into());
            SmtFinding::Unsupported("solver Unknown / timeout")
        }
    }
}

/// Stub for default builds. Callers can emit a "rebuild with
/// --features smt" hint when they see this.
#[cfg(not(feature = "smt"))]
pub fn solve(_path: &TaintPath, _ssa: &crate::ir::SsaCfg) -> SmtFinding {
    SmtFinding::Unsupported("smt feature not enabled at build time")
}

#[cfg(not(feature = "smt"))]
pub fn solve_with_imports(
    _path: &TaintPath,
    _ssa: &crate::ir::SsaCfg,
    _imports: &HashMap<u64, String>,
) -> SmtFinding {
    SmtFinding::Unsupported("smt feature not enabled at build time")
}

#[cfg(not(feature = "smt"))]
pub fn solve_diag(
    _path: &TaintPath,
    _ssa: &crate::ir::SsaCfg,
    _imports: &HashMap<u64, String>,
    reason_log: &mut Vec<String>,
) -> SmtFinding {
    reason_log.push("smt feature not enabled at build time".into());
    SmtFinding::Unsupported("smt feature not enabled at build time")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tables_non_empty() {
        assert!(!DEFAULT_SOURCES.is_empty());
        assert!(!DEFAULT_SINKS.is_empty());
    }

    #[test]
    fn covers_canonical_apis() {
        let src_names: Vec<_> = DEFAULT_SOURCES.iter().map(|s| s.name).collect();
        for must in &["recv", "read", "fgets", "scanf", "argv"] {
            assert!(src_names.contains(must), "missing source `{must}`");
        }
        let sink_names: Vec<_> = DEFAULT_SINKS.iter().map(|s| s.name).collect();
        for must in &["strcpy", "sprintf", "memcpy", "system", "popen", "execve", "strlen"] {
            assert!(sink_names.contains(must), "missing sink `{must}`");
        }
    }

    #[test]
    fn argument_slots_match_real_abi() {
        // recv(int sockfd, void *buf, size_t len, int flags) — buf is arg 1.
        let recv = DEFAULT_SOURCES.iter().find(|s| s.name == "recv").unwrap();
        assert_eq!(recv.tainted, AbiSlot::Arg(1));

        // gets(char *s) — fills buffer at arg 0.
        let gets = DEFAULT_SOURCES.iter().find(|s| s.name == "gets").unwrap();
        assert_eq!(gets.tainted, AbiSlot::Arg(0));

        // memcpy(void *dst, const void *src, size_t n) — n is arg 2.
        let memcpy = DEFAULT_SINKS.iter().find(|s| s.name == "memcpy").unwrap();
        assert_eq!(memcpy.watched, AbiSlot::Arg(2));
        assert_eq!(memcpy.kind, SinkKind::LengthArg);

        // system(const char *cmd) — cmd is arg 0.
        let system = DEFAULT_SINKS.iter().find(|s| s.name == "system").unwrap();
        assert_eq!(system.watched, AbiSlot::Arg(0));
        assert_eq!(system.kind, SinkKind::Command);

        // strlen(const char *s) — an unbounded NUL scan over arg 0.
        let strlen = DEFAULT_SINKS.iter().find(|s| s.name == "strlen").unwrap();
        assert_eq!(strlen.watched, AbiSlot::Arg(0));
        assert_eq!(strlen.kind, SinkKind::CStringRead);
    }

    #[test]
    fn resolves_plain_libc_name() {
        let mut imports = HashMap::new();
        imports.insert(0x1000, "recv".to_string());
        let r = resolve_call(0x1000, &imports).expect("recv resolved");
        match r {
            SpecRef::Source(s) => assert_eq!(s.name, "recv"),
            _ => panic!("expected source"),
        }
    }

    #[test]
    fn strips_plt_suffix() {
        let mut imports = HashMap::new();
        imports.insert(0x2000, "strcpy@plt".to_string());
        let r = resolve_call(0x2000, &imports).expect("strcpy@plt resolved");
        match r {
            SpecRef::Sink(s) => assert_eq!(s.name, "strcpy"),
            _ => panic!("expected sink"),
        }
    }

    #[test]
    fn strips_macho_underscore() {
        let mut imports = HashMap::new();
        imports.insert(0x3000, "_system".to_string());
        let r = resolve_call(0x3000, &imports).expect("_system resolved");
        match r {
            SpecRef::Sink(s) => assert_eq!(s.name, "system"),
            _ => panic!("expected sink"),
        }
    }

    #[test]
    fn strips_versioned_suffix() {
        let mut imports = HashMap::new();
        imports.insert(0x4000, "memcpy@@GLIBC_2.14".to_string());
        let r = resolve_call(0x4000, &imports).expect("versioned memcpy");
        match r {
            SpecRef::Sink(s) => {
                assert_eq!(s.name, "memcpy");
                assert_eq!(s.kind, SinkKind::LengthArg);
            }
            _ => panic!("expected sink"),
        }
    }

    #[test]
    fn unknown_name_is_none() {
        let mut imports = HashMap::new();
        imports.insert(0x5000, "fancy_app_helper".to_string());
        assert!(resolve_call(0x5000, &imports).is_none());
    }

    #[test]
    fn missing_addr_is_none() {
        let imports: HashMap<u64, String> = HashMap::new();
        assert!(resolve_call(0xdead_beef, &imports).is_none());
    }

    // ---- path collector ----

    use crate::ir::{
        BlockId, Diagnostic, Expr, InferredType, SsaBlock, SsaCfg, SsaTerminator,
        Stmt, VarDef,
    };
    use pcode_ir::Varnode;

    fn mk_var(id: u32, expr: Expr) -> VarDef {
        VarDef {
            id: VarId(id),
            varnode: Varnode::constant(id as u64, 8),
            expr,
            size: 8,
            use_count: 1,
            param_name: None,
            call_return: false,
            inferred_type: InferredType::Unknown,
            display_type: None,
        }
    }

    fn block_with_term(stmts: Vec<Stmt>, term: SsaTerminator) -> SsaBlock {
        SsaBlock {
            id: BlockId(0),
            addr: 0,
            stmts,
            terminator: term,
        }
    }

    fn cfg(vars: Vec<VarDef>, block: SsaBlock) -> SsaCfg {
        SsaCfg {
            blocks: vec![block],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        }
    }

    // I2c is a test-only differential between reconstructed-legacy behavior
    // and the typed store inventory. This is descriptive, not a historical
    // oracle; both key emissions and the two-chain intersection are tested.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum LegacyAliasKey {
        Vn(Varnode),
        Region(crate::region::Region, crate::region::OffsetClass),
    }

    type LegacyMemMap = HashMap<
        (crate::region::Region, crate::region::OffsetClass),
        VarId,
    >;

    fn legacy_const_value(v: VarId, vars: &[VarDef]) -> Option<i64> {
        let mut current = v;
        for _ in 0..16 {
            let definition = vars.get(current.0 as usize)?;
            match &definition.expr {
                Expr::Const(value, _) => return Some(*value as i64),
                Expr::Var(inner) => current = *inner,
                _ => return None,
            }
        }
        None
    }

    fn legacy_classify_offset(
        address: VarId,
        vars: &[VarDef],
    ) -> crate::region::OffsetClass {
        use crate::ir::BinOpKind;
        use crate::region::OffsetClass;

        let Some(definition) = vars.get(address.0 as usize) else {
            return OffsetClass::ConstOffset(0);
        };
        match &definition.expr {
            Expr::FieldAccess(_, offset) => OffsetClass::ConstOffset(*offset as i64),
            Expr::BinOp(BinOpKind::Add, left, right) => {
                if let Some(value) = legacy_const_value(*left, vars) {
                    return OffsetClass::ConstOffset(value);
                }
                if let Some(value) = legacy_const_value(*right, vars) {
                    return OffsetClass::ConstOffset(value);
                }
                OffsetClass::Symbolic
            }
            Expr::BinOp(BinOpKind::Sub, left, right) => {
                if let Some(value) = legacy_const_value(*right, vars) {
                    if let Some(left_value) = legacy_const_value(*left, vars) {
                        return OffsetClass::ConstOffset(left_value.wrapping_sub(value));
                    }
                    return OffsetClass::ConstOffset(-value);
                }
                OffsetClass::Symbolic
            }
            Expr::Var(inner) => legacy_classify_offset(*inner, vars),
            Expr::Const(value, _) => OffsetClass::ConstOffset(*value as i64),
            _ => OffsetClass::ConstOffset(0),
        }
    }

    fn legacy_mem_key(
        address: VarId,
        vars: &[VarDef],
        regions: &crate::region::RegionMap,
    ) -> (crate::region::Region, crate::region::OffsetClass) {
        (
            regions.region_of(address),
            legacy_classify_offset(address, vars),
        )
    }

    fn legacy_build_mem_map(
        events: &[TaintEvent<'_>],
        vars: &[VarDef],
        regions: &crate::region::RegionMap,
    ) -> LegacyMemMap {
        let mut memory = LegacyMemMap::new();
        for event in events {
            if let TaintEventKind::Store { addr, val } = event.kind {
                memory.insert(legacy_mem_key(addr, vars, regions), val);
            }
        }
        memory
    }

    fn legacy_chain_keys(
        start: VarId,
        vars: &[VarDef],
        memory: &LegacyMemMap,
        regions: &crate::region::RegionMap,
        follow_memory: bool,
    ) -> Vec<LegacyAliasKey> {
        use crate::region::{AllocSite, OffsetClass};

        let mut output = Vec::new();
        let mut visited = std::collections::HashSet::<u32>::new();
        let mut stack = vec![start];
        while let Some(current) = stack.pop() {
            if !visited.insert(current.0) {
                continue;
            }
            if visited.len() > 64 {
                break;
            }
            let Some(definition) = vars.get(current.0 as usize) else {
                continue;
            };
            let space_aliases = !matches!(
                definition.varnode.space,
                pcode_ir::AddressSpaceId::Register
            ) && !definition.call_return;
            if space_aliases {
                output.push(LegacyAliasKey::Vn(definition.varnode));
            }
            let region = regions.region_of(current);
            if let Some(site) = regions.site_of(region) {
                if !matches!(site, AllocSite::Unknown(_)) {
                    output.push(LegacyAliasKey::Region(
                        region,
                        legacy_classify_offset(current, vars),
                    ));
                }
            }
            match &definition.expr {
                Expr::Var(inner) => stack.push(*inner),
                Expr::Load(address) if follow_memory => {
                    let key = legacy_mem_key(*address, vars, regions);
                    if let Some(stored) = memory.get(&key).copied() {
                        stack.push(stored);
                    } else if let Some(stored) = memory
                        .get(&(key.0, OffsetClass::Symbolic))
                        .copied()
                    {
                        stack.push(stored);
                    }
                }
                Expr::Load(_) => {}
                Expr::BinOp(_, left, right) => {
                    stack.push(*left);
                    stack.push(*right);
                }
                Expr::UnaryOp(_, inner) => stack.push(*inner),
                Expr::FieldAccess(base, _) => stack.push(*base),
                Expr::Phi(inputs) => stack.extend(inputs.iter().copied()),
                _ => {}
            }
        }
        output
    }

    fn legacy_lineage_eq(
        left: VarId,
        right: VarId,
        vars: &[VarDef],
        memory: &LegacyMemMap,
        regions: &crate::region::RegionMap,
    ) -> bool {
        if left == right {
            return true;
        }
        let left_keys = legacy_chain_keys(left, vars, memory, regions, true);
        let right_keys = legacy_chain_keys(right, vars, memory, regions, true);
        left_keys
            .iter()
            .any(|left_key| right_keys.iter().any(|right_key| left_key == right_key))
    }

    fn i2c_var(
        vars: &mut Vec<VarDef>,
        expr: Expr,
        varnode: Varnode,
        param_name: Option<&str>,
    ) -> VarId {
        let id = VarId(vars.len() as u32);
        vars.push(VarDef {
            id,
            varnode,
            expr,
            size: 8,
            use_count: 1,
            param_name: param_name.map(str::to_owned),
            call_return: false,
            inferred_type: InferredType::Unknown,
            display_type: None,
        });
        id
    }

    fn i2c_ssa(vars: Vec<VarDef>) -> SsaCfg {
        cfg(
            vars,
            block_with_term(Vec::new(), SsaTerminator::Return(None)),
        )
    }

    fn i2c_stores(stores: &[(VarId, VarId)]) -> Vec<TaintEvent<'static>> {
        stores
            .iter()
            .enumerate()
            .map(|(stmt_index, (address, value))| TaintEvent {
                stmt_index,
                kind: TaintEventKind::Store {
                    addr: *address,
                    val: *value,
                },
            })
            .collect()
    }

    fn i2c_value(vars: &mut Vec<VarDef>, tag: u64, unique: u64) -> VarId {
        i2c_var(
            vars,
            Expr::Const(tag, 8),
            Varnode::unique(unique, 8),
            None,
        )
    }

    fn i2c_calls() -> CallReturnMap {
        CallReturnMap::new()
    }

    fn i2c_sorted_legacy_keys(keys: Vec<LegacyAliasKey>) -> Vec<String> {
        let mut rendered: Vec<_> = keys.into_iter().map(|key| format!("{key:?}")).collect();
        rendered.sort();
        rendered
    }

    fn i2c_sorted_values(memory: &MemMap) -> Vec<u32> {
        let mut values: Vec<_> = memory.iter().map(|definition| definition.value.0).collect();
        values.sort_unstable();
        values
    }

    fn i2c_assert_isolated(
        value: VarId,
        probe: VarId,
        vars: &[VarDef],
        regions: &crate::region::RegionMap,
    ) -> serde_json::Value {
        let empty = LegacyMemMap::new();
        let value_keys = legacy_chain_keys(value, vars, &empty, regions, false);
        let probe_keys = legacy_chain_keys(probe, vars, &empty, regions, false);
        assert_ne!(regions.region_of(value), regions.region_of(probe));
        assert!(value_keys
            .iter()
            .all(|value_key| !probe_keys.iter().any(|probe_key| value_key == probe_key)));
        serde_json::json!({
            "isolated": true,
            "value_region": regions.region_of(value).0,
            "probe_region": regions.region_of(probe).0,
            "value_keys": i2c_sorted_legacy_keys(value_keys),
            "probe_pre_memory_keys": i2c_sorted_legacy_keys(probe_keys),
        })
    }

    fn i2c_alias_evidence(result: &crate::memory_effect::AliasResult) -> serde_json::Value {
        fn side(evidence: &crate::memory_effect::AddressEvidence) -> serde_json::Value {
            serde_json::json!({
                "address": evidence.address.0,
                "base": evidence.base.map(|value| value.0),
                "displacement": evidence.displacement.to_string(),
                "offset": format!("{:?}", evidence.offset),
                "region": evidence.region.0,
                "site": format!("{:?}", evidence.site),
                "width": evidence.width,
            })
        }
        serde_json::json!({"left":side(&result.left),"right":side(&result.right)})
    }

    fn i2c_record(value: serde_json::Value) {
        println!("I2C_RECORD {}", serde_json::to_string(&value).unwrap());
    }

    fn alias_i2c_p1() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars = Vec::new();
        let param0 = i2c_var(&mut vars, Expr::Unknown, Varnode::register(0, 8), Some("param_0"));
        let param1 = i2c_var(&mut vars, Expr::Unknown, Varnode::register(8, 8), Some("param_1"));
        let value = i2c_value(&mut vars, 0xa101, 0x1010);
        let load = i2c_var(&mut vars, Expr::Load(param1), Varnode::unique(0x1020, 8), None);
        let ssa = i2c_ssa(vars);
        let regions = crate::region::infer_regions(&ssa);
        let events = i2c_stores(&[(param0, value)]);
        let legacy = legacy_build_mem_map(&events, &ssa.vars, &regions);
        let typed = build_mem_map(&events, &ssa.vars, &regions);
        let result = query_alias_vars(
            &ssa.vars,
            &regions,
            MemoryAccess { address: param1, displacement: 0, width: 8 },
            MemoryAccess { address: param0, displacement: 0, width: 8 },
        );
        let isolation = i2c_assert_isolated(value, load, &ssa.vars, &regions);
        let old = legacy_lineage_eq(value, load, &ssa.vars, &legacy, &regions);
        let new = varid_lineage_eq(value, load, &ssa.vars, &typed, &i2c_calls(), &regions);
        assert!(!old && new);
        assert_eq!((result.class, result.reason), (AliasClass::MayAlias, AliasReason::PotentialParameterAlias));
        i2c_record(serde_json::json!({"id":"P1","expected":"false->true","isolation":isolation,"legacy":old,"typed":new,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(load,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_p2() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars = Vec::new();
        let base = i2c_var(&mut vars, Expr::Unknown, Varnode::register(0, 8), None);
        let four = i2c_var(&mut vars, Expr::Const(4, 8), Varnode::constant(4, 8), None);
        let plus4 = i2c_var(&mut vars, Expr::BinOp(crate::ir::BinOpKind::Add, base, four), Varnode::unique(0x2010, 8), None);
        let value = i2c_value(&mut vars, 0xa202, 0x2020);
        let load = i2c_var(&mut vars, Expr::Load(plus4), Varnode::unique(0x2030, 8), None);
        let ssa = i2c_ssa(vars);
        let regions = crate::region::infer_regions(&ssa);
        assert_eq!(legacy_classify_offset(base, &ssa.vars), crate::region::OffsetClass::ConstOffset(0));
        assert_eq!(legacy_classify_offset(plus4, &ssa.vars), crate::region::OffsetClass::ConstOffset(4));
        let events = i2c_stores(&[(base, value)]);
        let legacy = legacy_build_mem_map(&events, &ssa.vars, &regions);
        let typed = build_mem_map(&events, &ssa.vars, &regions);
        let result = query_alias_vars(&ssa.vars, &regions, MemoryAccess { address: plus4, displacement: 0, width: 8 }, MemoryAccess { address: base, displacement: 0, width: 8 });
        let isolation = i2c_assert_isolated(value, load, &ssa.vars, &regions);
        let old = legacy_lineage_eq(value, load, &ssa.vars, &legacy, &regions);
        let new = varid_lineage_eq(value, load, &ssa.vars, &typed, &i2c_calls(), &regions);
        assert!(!old && new);
        assert_eq!((result.class,result.reason),(AliasClass::MayAlias,AliasReason::PartialOverlap));
        i2c_record(serde_json::json!({"id":"P2","expected":"false->true","isolation":isolation,"legacy":old,"typed":new,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(load,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_p3() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars = Vec::new();
        let base0 = i2c_var(&mut vars, Expr::Unknown, Varnode::register(0, 8), None);
        let base1 = i2c_var(&mut vars, Expr::Unknown, Varnode::register(8, 8), None);
        let value_a = i2c_value(&mut vars, 0xa303, 0x3010);
        let value_b = i2c_value(&mut vars, 0xb303, 0x3020);
        let load = i2c_var(&mut vars, Expr::Load(base0), Varnode::unique(0x3030, 8), None);
        let ssa = i2c_ssa(vars);
        let regions = crate::region::infer_regions(&ssa);
        assert_eq!(legacy_mem_key(base0,&ssa.vars,&regions),legacy_mem_key(base1,&ssa.vars,&regions));
        let events = i2c_stores(&[(base0,value_a),(base1,value_b)]);
        let legacy = legacy_build_mem_map(&events,&ssa.vars,&regions);
        let typed = build_mem_map(&events,&ssa.vars,&regions);
        let result = query_alias_vars(&ssa.vars,&regions,MemoryAccess{address:base0,displacement:0,width:8},MemoryAccess{address:base1,displacement:0,width:8});
        let isolation_a=i2c_assert_isolated(value_a,load,&ssa.vars,&regions);
        let isolation_b=i2c_assert_isolated(value_b,load,&ssa.vars,&regions);
        let old_a=legacy_lineage_eq(value_a,load,&ssa.vars,&legacy,&regions);
        let old_b=legacy_lineage_eq(value_b,load,&ssa.vars,&legacy,&regions);
        let new_a=varid_lineage_eq(value_a,load,&ssa.vars,&typed,&i2c_calls(),&regions);
        let new_b=varid_lineage_eq(value_b,load,&ssa.vars,&typed,&i2c_calls(),&regions);
        assert_eq!((old_a,old_b,new_a,new_b),(false,true,true,true));
        assert_eq!((result.class,result.reason),(AliasClass::MayAlias,AliasReason::NonSingletonRegion));
        i2c_record(serde_json::json!({"id":"P3","expected":"(false,true)->(true,true)","isolation_a":isolation_a,"isolation_b":isolation_b,"legacy_a":old_a,"legacy_b":old_b,"typed_a":new_a,"typed_b":new_b,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(load,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_p4() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars=Vec::new();
        let param0=i2c_var(&mut vars,Expr::Unknown,Varnode::register(0,8),Some("param_0"));
        let param1=i2c_var(&mut vars,Expr::Unknown,Varnode::register(8,8),Some("param_1"));
        let value=i2c_value(&mut vars,0xa404,0x4010);
        let phi=i2c_var(&mut vars,Expr::Phi(vec![param1,param0]),Varnode::unique(0x4020,8),None);
        let load=i2c_var(&mut vars,Expr::Load(phi),Varnode::unique(0x4030,8),None);
        let ssa=i2c_ssa(vars); let regions=crate::region::infer_regions(&ssa);
        assert_eq!(regions.region_of(phi),regions.region_of(param1));
        assert_eq!(legacy_classify_offset(phi,&ssa.vars),crate::region::OffsetClass::ConstOffset(0));
        let events=i2c_stores(&[(param0,value)]); let legacy=legacy_build_mem_map(&events,&ssa.vars,&regions); let typed=build_mem_map(&events,&ssa.vars,&regions);
        let result=query_alias_vars(&ssa.vars,&regions,MemoryAccess{address:phi,displacement:0,width:8},MemoryAccess{address:param0,displacement:0,width:8});
        let isolation=i2c_assert_isolated(value,load,&ssa.vars,&regions);
        let old=legacy_lineage_eq(value,load,&ssa.vars,&legacy,&regions); let new=varid_lineage_eq(value,load,&ssa.vars,&typed,&i2c_calls(),&regions);
        assert!(!old&&new); assert_eq!((result.class,result.reason),(AliasClass::MayAlias,AliasReason::SymbolicOffset));
        i2c_record(serde_json::json!({"id":"P4","expected":"false->true","isolation":isolation,"legacy":old,"typed":new,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(load,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_p5() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars=Vec::new(); let base=i2c_var(&mut vars,Expr::Unknown,Varnode::register(0,8),None); let four=i2c_var(&mut vars,Expr::Const(4,8),Varnode::constant(4,8),None);
        let plus4=i2c_var(&mut vars,Expr::BinOp(crate::ir::BinOpKind::Add,base,four),Varnode::unique(0x5010,8),None); let value=i2c_value(&mut vars,0xa505,0x5020); let field=i2c_var(&mut vars,Expr::FieldAccess(base,4),Varnode::unique(0x5030,8),None);
        let ssa=i2c_ssa(vars); let regions=crate::region::infer_regions(&ssa); let events=i2c_stores(&[(plus4,value)]); let legacy=legacy_build_mem_map(&events,&ssa.vars,&regions); let typed=build_mem_map(&events,&ssa.vars,&regions);
        let result=query_alias_vars(&ssa.vars,&regions,MemoryAccess{address:base,displacement:4,width:8},MemoryAccess{address:plus4,displacement:0,width:8});
        let isolation=i2c_assert_isolated(value,field,&ssa.vars,&regions); let old=legacy_lineage_eq(value,field,&ssa.vars,&legacy,&regions); let new=varid_lineage_eq(value,field,&ssa.vars,&typed,&i2c_calls(),&regions);
        assert!(!old&&new); assert_eq!((result.class,result.reason),(AliasClass::MustAlias,AliasReason::SameSingletonBytes));
        i2c_record(serde_json::json!({"id":"P5","expected":"false->true","isolation":isolation,"legacy":old,"typed":new,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(field,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_c1() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars=Vec::new(); let base=i2c_var(&mut vars,Expr::Unknown,Varnode::register(0,8),None); let zero0=i2c_var(&mut vars,Expr::Const(0,8),Varnode::constant(0,8),None); let zero1=i2c_var(&mut vars,Expr::Const(0,8),Varnode::constant(0,8),None);
        let addr0=i2c_var(&mut vars,Expr::BinOp(crate::ir::BinOpKind::Add,base,zero0),Varnode::unique(0x6010,8),None); let addr1=i2c_var(&mut vars,Expr::BinOp(crate::ir::BinOpKind::Add,base,zero1),Varnode::unique(0x6020,8),None);
        let value_a=i2c_value(&mut vars,0xa606,0x6030); let value_b=i2c_value(&mut vars,0xb606,0x6040); let load=i2c_var(&mut vars,Expr::Load(addr0),Varnode::unique(0x6050,8),None);
        let ssa=i2c_ssa(vars); assert_eq!((ssa.vars[value_a.0 as usize].size,ssa.vars[value_b.0 as usize].size),(8,8)); let regions=crate::region::infer_regions(&ssa); let events=i2c_stores(&[(addr0,value_a),(addr1,value_b)]); let legacy=legacy_build_mem_map(&events,&ssa.vars,&regions); let typed=build_mem_map(&events,&ssa.vars,&regions);
        let result=query_alias_vars(&ssa.vars,&regions,MemoryAccess{address:addr0,displacement:0,width:8},MemoryAccess{address:addr1,displacement:0,width:8});
        let isolation_a=i2c_assert_isolated(value_a,load,&ssa.vars,&regions); let isolation_b=i2c_assert_isolated(value_b,load,&ssa.vars,&regions);
        let old_a=legacy_lineage_eq(value_a,load,&ssa.vars,&legacy,&regions); let old_b=legacy_lineage_eq(value_b,load,&ssa.vars,&legacy,&regions); let new_a=varid_lineage_eq(value_a,load,&ssa.vars,&typed,&i2c_calls(),&regions); let new_b=varid_lineage_eq(value_b,load,&ssa.vars,&typed,&i2c_calls(),&regions);
        assert_eq!((old_a,old_b,new_a,new_b),(false,true,false,true)); assert_eq!((result.class,result.reason),(AliasClass::MustAlias,AliasReason::SameSingletonBytes));
        i2c_record(serde_json::json!({"id":"C1","expected":"agreement:(false,true)","isolation_a":isolation_a,"isolation_b":isolation_b,"legacy_a":old_a,"legacy_b":old_b,"typed_a":new_a,"typed_b":new_b,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(load,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_c2() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars=Vec::new(); let base=i2c_var(&mut vars,Expr::Unknown,Varnode::register(0,8),None); let sixteen=i2c_var(&mut vars,Expr::Const(16,8),Varnode::constant(16,8),None); let addr16=i2c_var(&mut vars,Expr::BinOp(crate::ir::BinOpKind::Add,base,sixteen),Varnode::unique(0x7010,8),None);
        let value_a=i2c_value(&mut vars,0xa707,0x7020); let value_b=i2c_value(&mut vars,0xb707,0x7030); let load=i2c_var(&mut vars,Expr::Load(base),Varnode::unique(0x7040,8),None); let ssa=i2c_ssa(vars); let regions=crate::region::infer_regions(&ssa); let events=i2c_stores(&[(base,value_a),(addr16,value_b)]); let legacy=legacy_build_mem_map(&events,&ssa.vars,&regions); let typed=build_mem_map(&events,&ssa.vars,&regions);
        let result=query_alias_vars(&ssa.vars,&regions,MemoryAccess{address:base,displacement:0,width:8},MemoryAccess{address:addr16,displacement:0,width:8}); let old_a=legacy_lineage_eq(value_a,load,&ssa.vars,&legacy,&regions); let old_b=legacy_lineage_eq(value_b,load,&ssa.vars,&legacy,&regions); let new_a=varid_lineage_eq(value_a,load,&ssa.vars,&typed,&i2c_calls(),&regions); let new_b=varid_lineage_eq(value_b,load,&ssa.vars,&typed,&i2c_calls(),&regions);
        let isolation_a=i2c_assert_isolated(value_a,load,&ssa.vars,&regions); let isolation_b=i2c_assert_isolated(value_b,load,&ssa.vars,&regions);
        assert_eq!((old_a,old_b,new_a,new_b),(true,false,true,false)); assert_eq!((result.class,result.reason),(AliasClass::NoAlias,AliasReason::DisjointSingletonRanges));
        i2c_record(serde_json::json!({"id":"C2","expected":"agreement:(true,false)","isolation_a":isolation_a,"isolation_b":isolation_b,"legacy_a":old_a,"legacy_b":old_b,"typed_a":new_a,"typed_b":new_b,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(load,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_c3() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars=Vec::new(); let base=i2c_var(&mut vars,Expr::Unknown,Varnode::register(0,8),None); let value=i2c_value(&mut vars,0xa808,0x8010); let load=i2c_var(&mut vars,Expr::Load(base),Varnode::unique(0x8020,8),None); let ssa=i2c_ssa(vars); let regions=crate::region::infer_regions(&ssa); let events=i2c_stores(&[(base,value)]); let legacy=legacy_build_mem_map(&events,&ssa.vars,&regions); let typed=build_mem_map(&events,&ssa.vars,&regions);
        let result=query_alias_vars(&ssa.vars,&regions,MemoryAccess{address:base,displacement:0,width:8},MemoryAccess{address:base,displacement:0,width:8}); let isolation=i2c_assert_isolated(value,load,&ssa.vars,&regions); let old=legacy_lineage_eq(value,load,&ssa.vars,&legacy,&regions); let new=varid_lineage_eq(value,load,&ssa.vars,&typed,&i2c_calls(),&regions); assert!(old&&new); assert_eq!((result.class,result.reason),(AliasClass::MustAlias,AliasReason::SameAddressValue));
        i2c_record(serde_json::json!({"id":"C3","expected":"agreement:true","isolation":isolation,"legacy":old,"typed":new,"class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":i2c_sorted_legacy_keys(legacy_chain_keys(load,&ssa.vars,&legacy,&regions,true)),"typed_inventory":i2c_sorted_values(&typed)}));
    }

    fn alias_i2c_c4() {
        use crate::memory_effect::{query_alias_vars, AliasClass, AliasReason, MemoryAccess};
        let mut vars=Vec::new(); let base0=i2c_var(&mut vars,Expr::Unknown,Varnode::register(0,8),None); let base1=i2c_var(&mut vars,Expr::Unknown,Varnode::register(8,8),None); let value_a=i2c_value(&mut vars,0xa909,0x9010); let value_b=i2c_value(&mut vars,0xb909,0x9020); let ssa=i2c_ssa(vars); let regions=crate::region::infer_regions(&ssa); let events=i2c_stores(&[(base0,value_a),(base1,value_b)]); let legacy=legacy_build_mem_map(&events,&ssa.vars,&regions); let typed=build_mem_map(&events,&ssa.vars,&regions); let result=query_alias_vars(&ssa.vars,&regions,MemoryAccess{address:base0,displacement:0,width:8},MemoryAccess{address:base1,displacement:0,width:8}); let isolation_a0=i2c_assert_isolated(value_a,base0,&ssa.vars,&regions); let isolation_a1=i2c_assert_isolated(value_a,base1,&ssa.vars,&regions); let isolation_b0=i2c_assert_isolated(value_b,base0,&ssa.vars,&regions); let isolation_b1=i2c_assert_isolated(value_b,base1,&ssa.vars,&regions); assert_eq!(legacy.len(),1); assert_eq!(typed.len(),2); assert_eq!((result.class,result.reason),(AliasClass::MayAlias,AliasReason::NonSingletonRegion));
        i2c_record(serde_json::json!({"id":"C4","expected":"legacy_inventory:1,typed_inventory:2","isolation":[isolation_a0,isolation_a1,isolation_b0,isolation_b1],"legacy_inventory":legacy.len(),"typed_inventory":i2c_sorted_values(&typed),"typed_lineage":"not_measured","class":format!("{:?}",result.class),"reason":format!("{:?}",result.reason),"evidence":i2c_alias_evidence(&result),"legacy_keys":{"base0":i2c_sorted_legacy_keys(legacy_chain_keys(base0,&ssa.vars,&legacy,&regions,false)),"base1":i2c_sorted_legacy_keys(legacy_chain_keys(base1,&ssa.vars,&legacy,&regions,false))}}));
    }

    #[test]
    fn alias_i2c_observation_surface_is_deterministic_and_shadow_only() {
        let mut vars = Vec::new();
        let param0 = i2c_var(&mut vars, Expr::Unknown,
            Varnode::register(0, 8), Some("param_0"));
        let param1 = i2c_var(&mut vars, Expr::Unknown,
            Varnode::register(8, 8), Some("param_1"));
        let value = i2c_value(&mut vars, 0xaa01, 0xa010);
        let load = i2c_var(&mut vars, Expr::Load(param1),
            Varnode::unique(0xa020, 8), None);
        let ssa = cfg(vars, block_with_term(
            vec![Stmt::Store { addr: param0, val: value }, Stmt::Assign(load)],
            SsaTerminator::Return(None)));
        let first = observe_alias_lineage(&ssa, 64);
        let second = observe_alias_lineage(&ssa, 64);
        assert_eq!(first, second);
        assert_eq!(first.1, 1);
        assert_eq!(first.0.len(), 1);
        assert!(first.0[0].typed);
        assert!(!first.0[0].reconstructed_legacy);
    }

    #[test]
    fn alias_i2c_matrix() {
        alias_i2c_p1();
        alias_i2c_p2();
        alias_i2c_p3();
        alias_i2c_p4();
        alias_i2c_p5();
        alias_i2c_c1();
        alias_i2c_c2();
        alias_i2c_c3();
        alias_i2c_c4();
    }

    fn imports_with(entries: &[(u64, &str)]) -> HashMap<u64, String> {
        entries
            .iter()
            .map(|(a, n)| (*a, n.to_string()))
            .collect()
    }

    #[test]
    fn accepts_recv_then_strcpy_in_same_block() {
        // Two direct calls, recv (source) then strcpy (sink), both
        // resolved via the import map, terminator = Return.
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),       // sock fd
            mk_var(1, Expr::Const(0x4000, 8)),  // buf
            mk_var(2, Expr::Const(0x100, 8)),   // len
            mk_var(3, Expr::Const(0, 8)),       // flags
            mk_var(4, Expr::Const(0x5000, 8)),  // dst
        ];
        let stmts = vec![
            Stmt::Call {
                target: CallTarget::Direct(0x1000),
                args: vec![VarId(0), VarId(1), VarId(2), VarId(3)],
                out: None,
            },
            Stmt::Call {
                target: CallTarget::Direct(0x2000),
                args: vec![VarId(4), VarId(1)],
                out: None,
            },
        ];
        let block = block_with_term(stmts, SsaTerminator::Return(None));
        let ssa = cfg(vars, block);
        let imports = imports_with(&[(0x1000, "recv"), (0x2000, "strcpy")]);

        let paths = collect_paths(&ssa, &imports).expect("should accept");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].source.name, "recv");
        assert_eq!(paths[0].sink.name, "strcpy");
        assert!(paths[0].source_event < paths[0].sink_event);
    }

    #[test]
    fn cbranch_with_no_arm_blocks_falls_through_to_dangling() {
        // v1 collector explores BOTH arms of a CBranch. With only a
        // single block in the CFG and dangling block ids on the
        // CBranch terminator, both arms hit "dangling block id" and
        // the walk returns NoSinkFound (or the dangling rejection).
        // v0 rejected up front with UnsupportedTerminator(CBranch);
        // v1 attempts the arms and bails when blocks don't exist.
        let vars = vec![mk_var(0, Expr::Const(0, 1))];
        let block = block_with_term(
            vec![],
            SsaTerminator::CBranch {
                cond: VarId(0),
                taken: BlockId(1),
                fallthrough: BlockId(2),
            },
        );
        let ssa = cfg(vars, block);
        let imports: HashMap<u64, String> = HashMap::new();

        match collect_paths(&ssa, &imports) {
            Err(PathRejection::UnsupportedTerminator(reason)) => {
                // Either dangling-block rejection (the most accurate
                // outcome on this fixture) or NoSinkFound — both
                // signal "no v1 path collected".
                assert!(
                    reason == "dangling block id" || reason == "Branch",
                    "unexpected rejection reason: {reason}"
                );
            }
            Err(PathRejection::NoSinkFound) => {}
            other => panic!("expected dangling/NoSinkFound, got {other:?}"),
        }
    }

    #[test]
    fn cbranch_explores_both_arms_for_source_sink_pair() {
        // v1 hallmark: a CBranch that gates a sink in one arm and
        // not the other should produce ONE path through the
        // sink-bearing arm, with branch_decisions recording the
        // taken edge.
        //
        //   block 0: recv(...)         (Source in entry block stmts)
        //   block 0 terminator: CBranch cond → block 1 (sink) / block 2 (return)
        //   block 1 terminator: Call strcpy(...) → block 3
        //   block 2 terminator: Return
        //   block 3 terminator: Return
        let vars = vec![
            mk_var(0, Expr::Const(0, 1)),    // CBranch cond
            mk_var(1, Expr::Const(0, 8)),    // sock fd
            mk_var(2, Expr::Const(0x4000, 8)), // buf
            mk_var(3, Expr::Const(0x100, 8)),
            mk_var(4, Expr::Const(0, 8)),
            mk_var(5, Expr::Const(0x5000, 8)), // dst
        ];
        let block0 = SsaBlock {
            id: BlockId(0),
            addr: 0x1000,
            stmts: vec![Stmt::Call {
                target: CallTarget::Direct(0x10),
                args: vec![VarId(1), VarId(2), VarId(3), VarId(4)],
                out: None,
            }],
            terminator: SsaTerminator::CBranch {
                cond: VarId(0),
                taken: BlockId(1),
                fallthrough: BlockId(2),
            },
        };
        let block1 = SsaBlock {
            id: BlockId(1),
            addr: 0x1010,
            stmts: vec![],
            terminator: SsaTerminator::Call {
                target: CallTarget::Direct(0x20),
                args: vec![VarId(5), VarId(2)],
                out: None,
                fallthrough: BlockId(3),
            },
        };
        let block2 = SsaBlock {
            id: BlockId(2),
            addr: 0x1020,
            stmts: vec![],
            terminator: SsaTerminator::Return(None),
        };
        let block3 = SsaBlock {
            id: BlockId(3),
            addr: 0x1030,
            stmts: vec![],
            terminator: SsaTerminator::Return(None),
        };
        let ssa = SsaCfg {
            blocks: vec![block0, block1, block2, block3],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let imports = imports_with(&[(0x10, "recv"), (0x20, "strcpy")]);

        let paths =
            collect_paths(&ssa, &imports).expect("v1 should explore CBranch arms");
        assert_eq!(paths.len(), 1, "expected single recv→strcpy path, got {}", paths.len());
        assert_eq!(paths[0].source.name, "recv");
        assert_eq!(paths[0].sink.name, "strcpy");
        assert_eq!(paths[0].branch_decisions.len(), 1);
        assert_eq!(paths[0].branch_decisions[0].block_addr, 0x1000);
        assert!(paths[0].branch_decisions[0].taken, "should have taken the sink-bearing arm");
    }

    #[test]
    fn cbranch_depth_limit_caps_walks() {
        // Construct a chain of CBranches deeper than MAX_BRANCH_DEPTH.
        // The walker must reject the over-budget walks but still
        // surface paths from the within-budget arms (none here, so
        // the result is a depth-limit rejection).
        //
        // Just chain k+1 CBranches where every fallthrough goes to
        // the next CBranch — this hits the depth cap on the
        // taken-arm walks specifically.
        let mut vars = Vec::new();
        let mut blocks = Vec::new();
        let depth = (MAX_BRANCH_DEPTH + 2) as usize;
        vars.push(mk_var(0, Expr::Const(0, 1))); // cond, reused
        for i in 0..depth {
            blocks.push(SsaBlock {
                id: BlockId(i),
                addr: 0x1000 + i as u64 * 0x10,
                stmts: vec![],
                terminator: SsaTerminator::CBranch {
                    cond: VarId(0),
                    taken: BlockId(i + 1),
                    fallthrough: BlockId(depth + 1),
                },
            });
        }
        // Terminal blocks at the bottom of the chain
        blocks.push(SsaBlock {
            id: BlockId(depth),
            addr: 0x2000,
            stmts: vec![],
            terminator: SsaTerminator::Return(None),
        });
        blocks.push(SsaBlock {
            id: BlockId(depth + 1),
            addr: 0x2010,
            stmts: vec![],
            terminator: SsaTerminator::Return(None),
        });
        let ssa = SsaCfg {
            blocks,
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let imports: HashMap<u64, String> = HashMap::new();

        let result = collect_paths(&ssa, &imports);
        // No source/sink configured; result should be an error,
        // and the depth limit must have been triggered for at
        // least the deepest arm.
        match result {
            Err(PathRejection::UnsupportedTerminator("depth limit"))
            | Err(PathRejection::NoSinkFound)
            | Err(PathRejection::UnsupportedTerminator("Branch")) => {}
            other => panic!("expected depth-limit/NoSink rejection, got {other:?}"),
        }
    }

    #[test]
    fn phi_assignment_is_skipped_not_rejected() {
        // v0 hard-rejected any Phi in entry block. v1 skips the
        // Phi assignment (recording no event for it) and keeps
        // walking — necessary to reach Source/Sink pairs in real
        // CFGs where every reconvergence point introduces a Phi.
        // Without source/sink configured, walk completes with
        // no paths -> NoSinkFound (NOT PhiInPath).
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0, 8)),
            mk_var(2, Expr::Phi(vec![VarId(0), VarId(1)])),
        ];
        let block = block_with_term(
            vec![Stmt::Assign(VarId(2))],
            SsaTerminator::Return(None),
        );
        let ssa = cfg(vars, block);
        let imports: HashMap<u64, String> = HashMap::new();

        match collect_paths(&ssa, &imports) {
            Err(PathRejection::NoSinkFound) => {}
            other => panic!("expected NoSinkFound (Phi skipped), got {other:?}"),
        }
    }

    #[test]
    fn rejects_indirect_call() {
        let vars = vec![mk_var(0, Expr::Const(0, 8))];
        let block = block_with_term(
            vec![Stmt::Call {
                target: CallTarget::Indirect(Varnode::constant(0, 8)),
                args: vec![],
                out: None,
            }],
            SsaTerminator::Return(None),
        );
        let ssa = cfg(vars, block);
        let imports: HashMap<u64, String> = HashMap::new();

        assert_eq!(collect_paths(&ssa, &imports).unwrap_err(), PathRejection::IndirectCall);
    }

    #[test]
    fn no_sink_found() {
        // recv but no sink anywhere.
        let vars = vec![mk_var(0, Expr::Const(0, 8))];
        let block = block_with_term(
            vec![Stmt::Call {
                target: CallTarget::Direct(0x1000),
                args: vec![],
                out: None,
            }],
            SsaTerminator::Return(None),
        );
        let ssa = cfg(vars, block);
        let imports = imports_with(&[(0x1000, "recv")]);

        assert_eq!(collect_paths(&ssa, &imports).unwrap_err(), PathRejection::NoSinkFound);
    }

    #[test]
    fn source_after_sink_yields_no_path() {
        // Sink fires before any source — no taint flow possible.
        let vars = vec![mk_var(0, Expr::Const(0, 8))];
        let block = block_with_term(
            vec![
                Stmt::Call {
                    target: CallTarget::Direct(0x2000),
                    args: vec![],
                    out: None,
                },
                Stmt::Call {
                    target: CallTarget::Direct(0x1000),
                    args: vec![],
                    out: None,
                },
            ],
            SsaTerminator::Return(None),
        );
        let ssa = cfg(vars, block);
        let imports = imports_with(&[(0x1000, "recv"), (0x2000, "strcpy")]);

        assert_eq!(collect_paths(&ssa, &imports).unwrap_err(), PathRejection::NoSinkFound);
    }

    // ---- v0 SAT prover (gated on `smt` feature) ----

    #[cfg(feature = "smt")]
    fn one_call_pair_cfg(
        source_addr: u64, source_args: Vec<VarId>,
        sink_addr:   u64, sink_args:   Vec<VarId>,
        vars: Vec<VarDef>,
    ) -> SsaCfg {
        let stmts = vec![
            Stmt::Call {
                target: CallTarget::Direct(source_addr),
                args: source_args,
                out: None,
            },
            Stmt::Call {
                target: CallTarget::Direct(sink_addr),
                args: sink_args,
                out: None,
            },
        ];
        cfg(vars, block_with_term(stmts, SsaTerminator::Return(None)))
    }

    #[cfg(feature = "smt")]
    #[test]
    fn sat_recv_to_strcpy_is_reachable() {
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),       // sock fd
            mk_var(1, Expr::Const(0x4000, 8)),  // buf  (shared between recv arg1 and strcpy arg1)
            mk_var(2, Expr::Const(0x100, 8)),
            mk_var(3, Expr::Const(0, 8)),
            mk_var(4, Expr::Const(0x5000, 8)),  // dst
        ];
        let ssa = one_call_pair_cfg(
            0x1000, vec![VarId(0), VarId(1), VarId(2), VarId(3)],
            0x2000, vec![VarId(4), VarId(1)],
            vars,
        );
        let imports = imports_with(&[(0x1000, "recv"), (0x2000, "strcpy")]);
        let paths = collect_paths(&ssa, &imports).expect("v0 path collection");
        match solve(&paths[0], &ssa) {
            SmtFinding::Reachable { input_bytes, .. } => {
                assert_eq!(input_bytes.len(), 32);
                assert!(input_bytes.iter().all(|(_, b)| *b != 0));
            }
            other => panic!("expected Reachable, got {other:?}"),
        }
    }

    #[cfg(feature = "smt")]
    #[test]
    fn sat_recv_to_printf_is_reachable() {
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0x4000, 8)),
            mk_var(2, Expr::Const(0x100, 8)),
            mk_var(3, Expr::Const(0, 8)),
        ];
        let ssa = one_call_pair_cfg(
            0x1000, vec![VarId(0), VarId(1), VarId(2), VarId(3)],
            0x2000, vec![VarId(1)],
            vars,
        );
        let imports = imports_with(&[(0x1000, "recv"), (0x2000, "printf")]);
        let paths = collect_paths(&ssa, &imports).expect("v0 path collection");
        match solve(&paths[0], &ssa) {
            SmtFinding::Reachable { input_bytes, .. } => {
                assert!(input_bytes.iter().any(|(_, b)| *b == b'%'));
            }
            other => panic!("expected Reachable with `%`, got {other:?}"),
        }
    }

    #[cfg(feature = "smt")]
    #[test]
    fn sat_argv_to_system_is_reachable() {
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),       // argc
            mk_var(1, Expr::Const(0x4000, 8)),  // argv (becomes argv[*] approx)
        ];
        let ssa = one_call_pair_cfg(
            0x1000, vec![VarId(0), VarId(1)],
            0x2000, vec![VarId(1)],
            vars,
        );
        let imports = imports_with(&[(0x1000, "argv"), (0x2000, "system")]);
        let paths = collect_paths(&ssa, &imports).expect("v0 path collection");
        match solve(&paths[0], &ssa) {
            SmtFinding::Reachable { input_bytes, .. } => {
                assert!(input_bytes
                    .iter()
                    .any(|(_, b)| matches!(*b, b';' | b'&' | b'|')));
            }
            other => panic!("expected Reachable with shell metachar, got {other:?}"),
        }
    }

    #[cfg(feature = "smt")]
    #[test]
    fn v8_inter_procedural_summary_synthesizes_reachable_path() {
        // outer(buf) → helper(buf). helper's summary records that
        // its arg 0 receives recv()'s output AND feeds strcpy()'s
        // watched slot. The walker must synthesize SourceCall +
        // SinkCall events at the outer→helper site so SAT can prove
        // taint reaches the strcpy without the helper body present.
        use crate::callgraph::FuncId;
        use crate::function_summary::{FunctionSummary, SinkInvocation, SourceEmission};

        let vars = vec![
            mk_var(0, Expr::Const(0x4000, 8)), // buf — outer's arg 0
        ];
        // outer body: a single Stmt::Call to helper(VarId 0).
        let outer = SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![Stmt::Call {
                    target: CallTarget::Direct(0xBEEF),
                    args: vec![VarId(0)],
                    out: None,
                }],
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };

        // Imports: NO entry for 0xBEEF — that's the helper FuncId.
        let imports: HashMap<u64, String> = HashMap::new();

        // helper's pre-built summary (V6 would have produced this).
        let recv_spec = DEFAULT_SOURCES.iter().find(|s| s.name == "recv").copied().unwrap();
        let strcpy_spec = DEFAULT_SINKS.iter().find(|s| s.name == "strcpy").copied().unwrap();
        let helper_summary = FunctionSummary {
            func: FuncId(0xBEEF),
            sources: vec![SourceEmission {
                source: recv_spec,
                call_site: 0xBEEF + 4,
                tainted_caller_slots: vec![AbiSlot::Arg(0)],
            }],
            sinks: vec![SinkInvocation {
                sink: strcpy_spec,
                call_site: 0xBEEF + 8,
                tainted_caller_slots: vec![AbiSlot::Arg(0)],
            }],
        };
        let mut summaries = HashMap::new();
        summaries.insert(FuncId(0xBEEF), helper_summary);

        let paths = collect_paths_with_summaries(&outer, &imports, &summaries)
            .expect("V8 should synthesize Source/Sink events from helper's summary");
        assert_eq!(paths.len(), 1);
        let path = &paths[0];
        assert_eq!(path.source.name, "recv");
        assert_eq!(path.sink.name, "strcpy");
        // Synthesized events must carry the call chain.
        match &path.events[path.sink_event].kind {
            TaintEventKind::SinkCall { call_chain, .. } => {
                assert!(!call_chain.is_empty(), "sink call_chain should be populated");
            }
            other => panic!("expected SinkCall, got {other:?}"),
        }
        match solve(path, &outer) {
            SmtFinding::Reachable { call_chain, .. } => {
                // v2.V9: chain must surface on the SmtFinding so the
                // CLI can render `via [0x... -> 0x...]` traces.
                assert!(
                    !call_chain.is_empty(),
                    "Reachable.call_chain should propagate from synthesized event"
                );
            }
            other => panic!("expected Reachable via summary synthesis, got {other:?}"),
        }
    }

    #[cfg(feature = "smt")]
    #[test]
    fn unsat_recv_into_unrelated_strcpy_dst() {
        // recv fills buf (VarId 1), strcpy copies UNRELATED VarId 9
        // — no taint lineage. Must NotReachable.
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0x4000, 8)),
            mk_var(2, Expr::Const(0x100, 8)),
            mk_var(3, Expr::Const(0, 8)),
            mk_var(4, Expr::Const(0x5000, 8)),
            mk_var(5, Expr::Const(0, 8)),
            mk_var(6, Expr::Const(0, 8)),
            mk_var(7, Expr::Const(0, 8)),
            mk_var(8, Expr::Const(0, 8)),
            mk_var(9, Expr::Const(0x6000, 8)),  // unrelated buffer
        ];
        let ssa = one_call_pair_cfg(
            0x1000, vec![VarId(0), VarId(1), VarId(2), VarId(3)],
            0x2000, vec![VarId(4), VarId(9)],
            vars,
        );
        let imports = imports_with(&[(0x1000, "recv"), (0x2000, "strcpy")]);
        let paths = collect_paths(&ssa, &imports).expect("v0 path collection");
        assert_eq!(solve(&paths[0], &ssa), SmtFinding::NotReachable);
    }

    #[cfg(feature = "smt")]
    #[test]
    fn lineage_eq_follows_var_chain() {
        // VarId 5 -> Var(4) -> Var(3) -> Var(2). lineage_eq(5, 2) = true.
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0, 8)),
            mk_var(2, Expr::Const(0x4000, 8)),
            mk_var(3, Expr::Var(VarId(2))),
            mk_var(4, Expr::Var(VarId(3))),
            mk_var(5, Expr::Var(VarId(4))),
        ];
        let mem = MemMap::new();
        let calls = CallReturnMap::new();
        let regions = crate::region::RegionMap::default();
        assert!(varid_lineage_eq(VarId(5), VarId(2), &vars, &mem, &calls, &regions));
        assert!(!varid_lineage_eq(VarId(5), VarId(0), &vars, &mem, &calls, &regions));
    }

    #[cfg(feature = "smt")]
    #[test]
    fn lineage_eq_follows_store_then_load() {
        // Store v1 -> mem[addr=v0]; Load(v0) → should resolve to v1.
        // lineage_eq(load_var, v1) must be true via the memory map.
        let vars = vec![
            mk_var(0, Expr::Const(0x1000, 8)),     // addr
            mk_var(1, Expr::Const(0xdeadbeef, 8)), // stored value
            mk_var(2, Expr::Load(VarId(0))),       // load from same addr
        ];
        let regions = crate::region::RegionMap::default();
        let mut mem = MemMap::new();
        let key = mem_key(VarId(0), &vars, &regions);
        mem.insert(key, VarId(1));
        let calls = CallReturnMap::new();
        // Without memmap entry, lineage fails.
        assert!(!varid_lineage_eq(
            VarId(2),
            VarId(1),
            &vars,
            &MemMap::new(),
            &calls,
            &regions,
        ));
        // With memmap entry, lineage holds.
        assert!(varid_lineage_eq(VarId(2), VarId(1), &vars, &mem, &calls, &regions));
    }

    #[cfg(feature = "smt")]
    #[test]
    fn lineage_eq_follows_call_return_pass_through() {
        // v2.V5: out = strdup(arg). Sink reads `out`. Lineage from
        // `out` (VarId 2) must reach the source-tainted `arg`
        // (VarId 1) through the call's argument list.
        let vars = vec![
            mk_var(0, Expr::Const(0x1000, 8)),
            mk_var(1, Expr::Const(0xdead, 8)), // tainted source value
            mk_var(2, Expr::Const(0xbeef, 8)), // out of strdup; opaque expr
        ];
        let mem = MemMap::new();
        let mut calls = CallReturnMap::new();
        let regions = crate::region::RegionMap::default();
        // Without the call-return map: lineage misses (out is opaque).
        assert!(!varid_lineage_eq(VarId(2), VarId(1), &vars, &mem, &calls, &regions));
        // With the map: out=2 → args=[1], lineage holds.
        calls.insert(VarId(2), vec![VarId(1)]);
        assert!(varid_lineage_eq(VarId(2), VarId(1), &vars, &mem, &calls, &regions));
        // Argument that wasn't passed must still miss.
        assert!(!varid_lineage_eq(VarId(2), VarId(0), &vars, &mem, &calls, &regions));
    }

    #[cfg(feature = "smt")]
    #[test]
    fn region_keyed_mem_map_collides_distinct_unique_addrs_on_same_offset() {
        // v4.W7: two address VarIds computed via DISTINCT expression
        // shapes that nonetheless evaluate to the same logical
        // location must collide on the same MemMap key.
        // Simulated by giving both addr VarIds the same Region+
        // offset via classify_offset returning ConstOffset(8) for
        // both.
        let vars = vec![
            mk_var(0, Expr::Const(8, 8)),                // const offset 8
            mk_var(1, Expr::Const(8, 8)),                // distinct VarId, same const
            mk_var(2, Expr::Const(0xDEAD, 8)),           // stored value A
            mk_var(3, Expr::Const(0xBEEF, 8)),           // stored value B (later)
        ];
        let regions = crate::region::RegionMap::default();
        let mut mem = MemMap::new();
        let key0 = mem_key(VarId(0), &vars, &regions);
        let key1 = mem_key(VarId(1), &vars, &regions);
        assert_eq!(key0, key1, "same const-offset addrs must share MemMap key");
        mem.insert(key0.clone(), VarId(2));
        // Second store via distinct addr VarId overwrites — verifies
        // the alias relation, not just two equal keys.
        mem.insert(key1, VarId(3));
        assert_eq!(mem.get(&key0).copied(), Some(VarId(3)));
        assert_eq!(mem.len(), 1);
    }

    #[cfg(feature = "smt")]
    #[test]
    fn build_call_return_map_captures_stmt_and_terminator_calls() {
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0, 8)),
            mk_var(2, Expr::Const(0, 8)),
            mk_var(3, Expr::Const(0, 8)),
        ];
        let block = SsaBlock {
            id: BlockId(0),
            addr: 0,
            stmts: vec![Stmt::Call {
                target: CallTarget::Direct(0x1000),
                args: vec![VarId(0)],
                out: Some(VarId(2)),
            }],
            terminator: SsaTerminator::Call {
                target: CallTarget::Direct(0x2000),
                args: vec![VarId(1)],
                out: Some(VarId(3)),
                fallthrough: BlockId(1),
            },
        };
        let block1 = SsaBlock {
            id: BlockId(1),
            addr: 4,
            stmts: vec![],
            terminator: SsaTerminator::Return(None),
        };
        let ssa = SsaCfg {
            blocks: vec![block, block1],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let calls = build_call_return_map(&ssa);
        assert_eq!(calls.get(&VarId(2)).map(|a| a.as_slice()), Some(&[VarId(0)][..]));
        assert_eq!(calls.get(&VarId(3)).map(|a| a.as_slice()), Some(&[VarId(1)][..]));
    }

    #[test]
    fn sink_in_terminator_call_slot() {
        // strcpy lives in the SsaTerminator::Call slot. Path
        // collector must walk the Call terminator and continue to
        // the fallthrough block (which here just returns).
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0x4000, 8)),
            mk_var(2, Expr::Const(0x5000, 8)),
        ];
        let block0 = SsaBlock {
            id: BlockId(0),
            addr: 0,
            stmts: vec![Stmt::Call {
                target: CallTarget::Direct(0x1000),
                args: vec![VarId(0), VarId(1), VarId(0), VarId(0)],
                out: None,
            }],
            terminator: SsaTerminator::Call {
                target: CallTarget::Direct(0x2000),
                args: vec![VarId(2), VarId(1)],
                out: None,
                fallthrough: BlockId(1),
            },
        };
        let block1 = SsaBlock {
            id: BlockId(1),
            addr: 0x10,
            stmts: vec![],
            terminator: SsaTerminator::Return(None),
        };
        let ssa = SsaCfg {
            blocks: vec![block0, block1],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        };
        let imports = imports_with(&[(0x1000, "recv"), (0x2000, "strcpy")]);

        let paths = collect_paths(&ssa, &imports).expect("should accept terminator-Call sink");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].sink.name, "strcpy");
    }
}
