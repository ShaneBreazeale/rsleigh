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
];

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
    // Strip up to two leading underscores (Mach-O stubs commonly
    // expose `_recv`, glibc-internal names sometimes appear with
    // `__recv` for the *_chk family — we don't include checked
    // variants in M1, so this just unwraps the canonical name).
    stripped
        .trim_start_matches('_')
        .trim_start_matches('_')
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
    },
    SinkCall {
        spec: &'a SinkSpec,
        args: Vec<VarId>,
        out: Option<VarId>,
    },
    OtherCall {
        target_addr: Option<u64>,
        args: Vec<VarId>,
        out: Option<VarId>,
    },
}

/// One Source -> Sink pair found in a single basic block. The SAT
/// prover (commit 4) takes a path and asks Z3 whether tainted input
/// from `source` can force the `sink`'s watched arg into a CVE-class
/// state.
#[derive(Debug, Clone)]
pub struct TaintPath<'a> {
    pub source: &'a SourceSpec,
    pub source_event: usize,
    pub sink: &'a SinkSpec,
    pub sink_event: usize,
    pub events: Vec<TaintEvent<'a>>,
}

/// Walk the entry block of `ssa`, classify every statement against
/// the import map, and pair each Source with the next Sink. Returns
/// the collected paths, or `PathRejection` if the walk hits an
/// out-of-scope construct (Phi, indirect call, non-Call terminator).
///
/// v0 invariant: only the entry block is walked. The terminator must
/// be one of:
///   - `Call { target: Direct(addr), .. }` whose target IS a Sink
///     (the sink invocation lives in the terminator slot, e.g. a
///     tail call), OR
///   - any other terminator → reject as `UnsupportedTerminator`,
///     UNLESS at least one Sink already fired inside `stmts`.
///
/// In other words: every accepted path's Sink event lies either in
/// `stmts` or in the terminator's call slot. No second-block walk.
pub fn collect_paths<'a>(
    ssa: &'a SsaCfg,
    imports: &HashMap<u64, String>,
) -> Result<Vec<TaintPath<'a>>, PathRejection> {
    let entry = ssa
        .blocks
        .iter()
        .find(|b| b.id == ssa.entry)
        .ok_or(PathRejection::UnsupportedTerminator("missing entry block"))?;

    let mut events: Vec<TaintEvent<'a>> = Vec::with_capacity(entry.stmts.len() + 1);

    for (idx, stmt) in entry.stmts.iter().enumerate() {
        match stmt {
            Stmt::Assign(v) => {
                if matches!(ssa.vars.get(v.0 as usize).map(|d| &d.expr), Some(crate::ir::Expr::Phi(_))) {
                    return Err(PathRejection::PhiInPath);
                }
                events.push(TaintEvent { stmt_index: idx, kind: TaintEventKind::Assign(*v) });
            }
            Stmt::Store { addr, val } => {
                events.push(TaintEvent {
                    stmt_index: idx,
                    kind: TaintEventKind::Store { addr: *addr, val: *val },
                });
            }
            Stmt::Call { target, args, out } => {
                events.push(classify_call(idx, target, args, *out, imports)?);
            }
        }
    }

    // Terminator handling: a terminator-Call may itself be a Sink.
    let term_idx = entry.stmts.len();
    match &entry.terminator {
        SsaTerminator::Call { target, args, out, .. } => {
            events.push(classify_call(term_idx, target, args, *out, imports)?);
        }
        SsaTerminator::Return(_) => {
            // Tail of straight-line block — fine, nothing more to record.
        }
        SsaTerminator::Fallthrough(_) | SsaTerminator::Branch(_) => {
            // No paths fired inside this block, and the terminator
            // exits to another block. v0 rejects.
            if !events.iter().any(|e| matches!(e.kind, TaintEventKind::SinkCall { .. })) {
                return Err(PathRejection::UnsupportedTerminator("Fallthrough/Branch"));
            }
            // A sink already fired earlier — surface accepted paths,
            // ignore the unreachable continuation in v0.
        }
        SsaTerminator::CBranch { .. } => {
            return Err(PathRejection::UnsupportedTerminator("CBranch"));
        }
        SsaTerminator::Indirect(_) => {
            return Err(PathRejection::UnsupportedTerminator("Indirect"));
        }
    }

    // Pair each Source with the next Sink occurring after it. v0
    // greedy-pairs: closest sink wins, no backtracking.
    let mut paths = Vec::new();
    let mut last_source: Option<(usize, &'a SourceSpec)> = None;
    for (i, ev) in events.iter().enumerate() {
        match &ev.kind {
            TaintEventKind::SourceCall { spec, .. } => {
                last_source = Some((i, spec));
            }
            TaintEventKind::SinkCall { spec, .. } => {
                if let Some((src_i, src_spec)) = last_source.take() {
                    paths.push(TaintPath {
                        source: src_spec,
                        source_event: src_i,
                        sink: spec,
                        sink_event: i,
                        events: events.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    if paths.is_empty() {
        return Err(PathRejection::NoSinkFound);
    }
    Ok(paths)
}

fn classify_call<'a>(
    stmt_index: usize,
    target: &CallTarget,
    args: &[VarId],
    out: Option<VarId>,
    imports: &HashMap<u64, String>,
) -> Result<TaintEvent<'a>, PathRejection> {
    let direct_addr = match target {
        CallTarget::Direct(a) => Some(*a),
        CallTarget::Indirect(_) => None,
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
            TaintEventKind::SourceCall { spec, args: args.to_vec(), out }
        }
        Some(SpecRef::Sink(s)) => {
            let spec = DEFAULT_SINKS
                .iter()
                .find(|sp| sp.name == s.name)
                .expect("resolve_call returned a SinkSpec not in DEFAULT_SINKS");
            TaintEventKind::SinkCall { spec, args: args.to_vec(), out }
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
        for must in &["strcpy", "sprintf", "memcpy", "system", "popen", "execve"] {
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
    fn rejects_cbranch_terminator() {
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
                assert_eq!(reason, "CBranch");
            }
            other => panic!("expected UnsupportedTerminator(CBranch), got {other:?}"),
        }
    }

    #[test]
    fn rejects_phi_in_entry_block() {
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

        assert_eq!(collect_paths(&ssa, &imports).unwrap_err(), PathRejection::PhiInPath);
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

    #[test]
    fn sink_in_terminator_call_slot() {
        // strcpy lives in the SsaTerminator::Call slot (tail-call
        // shape). Path collector must surface it.
        let vars = vec![
            mk_var(0, Expr::Const(0, 8)),
            mk_var(1, Expr::Const(0x4000, 8)),
            mk_var(2, Expr::Const(0x5000, 8)),
        ];
        let stmts = vec![Stmt::Call {
            target: CallTarget::Direct(0x1000),
            args: vec![VarId(0), VarId(1), VarId(0), VarId(0)],
            out: None,
        }];
        let block = block_with_term(
            stmts,
            SsaTerminator::Call {
                target: CallTarget::Direct(0x2000),
                args: vec![VarId(2), VarId(1)],
                out: None,
                fallthrough: BlockId(0),
            },
        );
        let ssa = cfg(vars, block);
        let imports = imports_with(&[(0x1000, "recv"), (0x2000, "strcpy")]);

        let paths = collect_paths(&ssa, &imports).expect("should accept terminator-Call sink");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].sink.name, "strcpy");
    }
}
