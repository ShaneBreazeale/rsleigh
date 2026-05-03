//! Taint-flow CVE explorer (SMT M1).
//!
//! Configures attacker-controlled `Source` APIs and dangerous `Sink`
//! APIs, walks straight-line SSA paths from a Source's tainted output
//! to a Sink's watched argument, and asks Z3 whether attacker-supplied
//! bytes can drive the watched value into a CVE-class state (over-long
//! buffer, format-string char, command separator, etc.).
//!
//! This module owns the spec tables and the call-name resolution
//! plumbing. The SSA path collector and the Z3-driven SAT proof live
//! in subsequent commits per
//! `.opt/campaigns/smt-backend-implementation-plan.md`.

use std::collections::HashMap;

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
}
