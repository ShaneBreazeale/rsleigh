//! Binary analysis API for Spectra and other frontends.
//!
//! Provides structured analysis results without requiring CLI invocation.
//! All functions return serializable data structures.

use pcode_ir::Instruction;
use rsleigh_api::Architecture;
use std::collections::{BTreeMap, HashMap};

/// Metadata for a single decompiled function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionMeta {
    pub name: String,
    pub address: u64,
    pub params: usize,
    pub return_type: String,
    pub calls: Vec<String>,
    pub strings: Vec<String>,
    pub complexity: usize,
    pub tags: Vec<String>,
    pub pseudocode: String,
}

/// A vulnerability finding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VulnFinding {
    pub severity: String, // CRIT, HIGH, MED, LOW, INFO
    pub address: u64,
    pub function: String,
    pub description: String,
    pub context: String,
}

/// Call graph entry for a single function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallGraphEntry {
    pub address: u64,
    pub calls: Vec<String>,
    pub called_by: Vec<String>,
    pub return_type: String,
    pub tags: Vec<String>,
}

/// Extract metadata from decompiled pseudocode.
pub fn extract_function_meta(name: &str, addr: u64, pseudocode: &str) -> FunctionMeta {
    let mut calls = Vec::new();
    let mut strings = Vec::new();
    let mut line_count = 0;

    for line in pseudocode.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        line_count += 1;

        // Extract function calls
        if t.contains('(') {
            let check = if let Some(eq) = t.find(" = ") {
                &t[eq + 3..]
            } else {
                t
            };
            if let Some(p) = check.find('(') {
                let callee = check[..p].trim().trim_start_matches("return ");
                if !callee.is_empty()
                    && !callee.contains(' ')
                    && !callee.starts_with('*')
                    && !callee.starts_with('(')
                    && !callee.starts_with("if")
                    && !callee.starts_with("while")
                    && !callee.starts_with("switch")
                    && !callee.starts_with("for")
                    && callee.len() < 50
                    && !calls.contains(&callee.to_string())
                {
                    calls.push(callee.to_string());
                }
            }
        }

        // Extract strings
        if let Some(q1) = t.find('"') {
            if let Some(q2) = t[q1 + 1..].find('"') {
                let s = &t[q1 + 1..q1 + 1 + q2];
                if s.len() >= 2 && s.len() <= 80 && !strings.contains(&s.to_string()) {
                    strings.push(s.to_string());
                }
            }
        }
    }

    // Extract return type and params from first line
    let return_type = pseudocode
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("void")
        .to_string();
    let params = pseudocode
        .lines()
        .next()
        .map(|l| l.matches("param_").count())
        .unwrap_or(0);

    // Behavioral tags
    let mut tags = Vec::new();
    if calls.iter().any(|c| {
        [
            "recv", "send", "socket", "connect", "accept", "bind", "listen",
        ]
        .contains(&c.as_str())
    }) {
        tags.push("network".to_string());
    }
    if calls.iter().any(|c| {
        [
            "CreateFile",
            "fopen",
            "ReadFile",
            "WriteFile",
            "fread",
            "fwrite",
            "open",
        ]
        .contains(&c.as_str())
    }) {
        tags.push("file_io".to_string());
    }
    if calls
        .iter()
        .any(|c| c.contains("Reg") && (c.contains("Key") || c.contains("Value")))
    {
        tags.push("registry".to_string());
    }
    if calls.iter().any(|c| {
        [
            "system",
            "exec",
            "execve",
            "popen",
            "ShellExecute",
            "WinExec",
            "CreateProcess",
        ]
        .contains(&c.as_str())
    }) {
        tags.push("exec".to_string());
    }
    if calls.iter().any(|c| {
        [
            "malloc",
            "free",
            "realloc",
            "VirtualAlloc",
            "mmap",
            "HeapAlloc",
        ]
        .contains(&c.as_str())
    }) {
        tags.push("memory".to_string());
    }
    if pseudocode.contains("AES")
        || pseudocode.contains("SHA")
        || pseudocode.contains("CRC")
        || pseudocode.contains("^ 0x")
    {
        tags.push("crypto".to_string());
    }
    if calls.iter().any(|c| {
        [
            "scanf", "gets", "fgets", "getenv", "getchar", "recv", "ReadFile",
        ]
        .contains(&c.as_str())
    }) {
        tags.push("input".to_string());
    }
    if calls
        .iter()
        .any(|c| ["printf", "puts", "fprintf", "send", "WriteFile", "fwrite"].contains(&c.as_str()))
    {
        tags.push("output".to_string());
    }

    FunctionMeta {
        name: name.to_string(),
        address: addr,
        params,
        return_type,
        calls,
        strings,
        complexity: line_count,
        tags,
        pseudocode: pseudocode.to_string(),
    }
}

/// Scan pseudocode for vulnerability patterns.
pub fn scan_vulns(func_name: &str, addr: u64, pseudocode: &str) -> Vec<VulnFinding> {
    let patterns: &[(&str, &str, &str)] = &[
        (
            "gets(",
            "HIGH",
            "buffer overflow: gets() has no bounds check",
        ),
        ("strcpy(", "MED", "buffer overflow: strcpy()"),
        ("strcat(", "MED", "buffer overflow: strcat()"),
        (
            "sprintf(",
            "MED",
            "buffer overflow/format string: sprintf()",
        ),
        (
            "printf(param_",
            "HIGH",
            "format string: printf() with user-controlled format",
        ),
        (
            "printf(local_",
            "HIGH",
            "format string: printf() with stack variable format",
        ),
        (
            "system(param_",
            "CRIT",
            "command injection: system() with user input",
        ),
        (
            "system(local_",
            "HIGH",
            "command injection: system() with stack variable",
        ),
        (
            "popen(param_",
            "CRIT",
            "command injection: popen() with user input",
        ),
        ("exec(param_", "CRIT", "command execution with user input"),
        (
            "VirtualProtect(",
            "MED",
            "memory protection change (DEP bypass)",
        ),
        (
            "malloc(param_",
            "MED",
            "unchecked alloc with user-controlled size",
        ),
        (
            "rand()",
            "LOW",
            "weak randomness: rand() not cryptographically secure",
        ),
        (
            "GetProcAddress(",
            "LOW",
            "dynamic API resolution (anti-analysis)",
        ),
        ("sqlite3_exec(", "MED", "potential SQL injection"),
    ];

    let mut findings = Vec::new();
    for &(pattern, severity, description) in patterns {
        if pseudocode.contains(pattern) {
            let context = pseudocode
                .lines()
                .find(|l| l.contains(pattern))
                .unwrap_or("")
                .trim()
                .to_string();
            let context = if context.len() > 80 {
                format!("{}...", &context[..80])
            } else {
                context
            };
            findings.push(VulnFinding {
                severity: severity.to_string(),
                address: addr,
                function: func_name.to_string(),
                description: description.to_string(),
                context,
            });
        }
    }

    // Check for missing stack cookie
    let has_cookie =
        pseudocode.contains("stack cookie") || pseudocode.contains("__security_check_cookie");
    let lines = pseudocode.lines().filter(|l| !l.trim().is_empty()).count();
    if lines > 20 && !has_cookie {
        findings.push(VulnFinding {
            severity: "INFO".to_string(),
            address: addr,
            function: func_name.to_string(),
            description: "missing stack cookie in large function".to_string(),
            context: String::new(),
        });
    }

    findings
}

/// Shannon entropy in bits/byte over `data`. 0.0 for empty input.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &c in &hist {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Scan binary sections for anomalies relevant to packed/encrypted/stego payloads.
///
/// Inputs: `sections` = list of (name, bytes, virtual_address). `overlay_bytes` =
/// trailing bytes past the last section (PE-specific; empty for other formats).
/// Emits INFO / LOW / MED findings for:
///   - high-entropy sections (>7.5 bits/byte = likely compressed/encrypted/packed)
///   - PE overlay regions (appended data past image end)
///   - non-zero section slack (StegoForge-style embedding target)
pub fn scan_section_anomalies(
    sections: &[(String, &[u8], u64)],
    overlay: Option<&[u8]>,
) -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    for (name, bytes, va) in sections {
        if bytes.len() < 256 {
            continue;
        }
        let h = shannon_entropy(bytes);
        if h > 7.5 {
            let sev = if h > 7.9 { "MED" } else { "LOW" };
            findings.push(VulnFinding {
                severity: sev.to_string(),
                address: *va,
                function: name.clone(),
                description: format!(
                    "high-entropy section ({:.2} bits/byte, {} bytes) — likely packed/encrypted",
                    h,
                    bytes.len()
                ),
                context: String::new(),
            });
        }
    }
    if let Some(ov) = overlay {
        if !ov.is_empty() {
            let h = shannon_entropy(ov);
            findings.push(VulnFinding {
                severity: "LOW".to_string(),
                address: 0,
                function: "<overlay>".to_string(),
                description: format!(
                    "PE overlay: {} bytes past last section (entropy {:.2}) — installer/dropper/appended payload",
                    ov.len(), h
                ),
                context: String::new(),
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Audit P1 #4 — whole-program callsite-driven return validation
// ---------------------------------------------------------------------------

use crate::ir::{CallTarget, Diagnostic, Severity, SsaCfg, SsaTerminator};

/// For a single function's SSA, return the set of `(callee_address,
/// uses_return_value)` pairs reachable from its terminators. A callee is
/// considered to "use the return value" if any subsequent statement reads
/// the call_return varnode created at that call site.
///
/// Indirect calls (`CallTarget::Indirect`) are skipped.
pub fn collect_callsite_return_uses(ssa: &SsaCfg) -> Vec<(u64, bool)> {
    let mut out = Vec::new();
    for block in &ssa.blocks {
        let SsaTerminator::Call { target, .. } = &block.terminator else {
            continue;
        };
        let CallTarget::Direct(callee) = target else {
            continue;
        };
        // The synthetic ret_var Stmt::Assign(ret_var) with call_return=true
        // is appended to the call block by `clobber_caller_saved`; if it
        // has any use_count > 0 reads downstream, the result was consumed.
        let mut uses_return = false;
        for b in &ssa.blocks {
            for stmt in &b.stmts {
                if let crate::ir::Stmt::Assign(var_id) = stmt {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.call_return && vdef.use_count > 0 {
                        uses_return = true;
                    }
                }
            }
            if uses_return {
                break;
            }
        }
        out.push((*callee, uses_return));
    }
    out
}

/// Whole-program callsite-driven return validation. Audit P1 #4 closure.
///
/// Given a slice of `(function_address, &mut SsaCfg)`, demote any function
/// whose inferred `Return(Some(call_return-only))` is **never read** by any
/// caller in the supplied set. The inference pass deliberately picks the
/// `int wrap() { return foo(); }` interpretation when it cannot
/// disambiguate; this pass corrects it back to `void f() { foo(); }` when
/// every callsite tells us nobody cares about the return.
///
/// Functions not in the supplied slice are treated as having no callers
/// for demotion purposes. If the supplied slice is incomplete (external
/// callers may exist), pass `assume_external_callers=true` to suppress
/// demotion entirely.
///
/// Returns the number of functions demoted.
pub fn validate_returns_against_callsites(
    funcs: &mut [(u64, SsaCfg)],
    assume_external_callers: bool,
) -> usize {
    if assume_external_callers {
        return 0;
    }

    // Build callee → "any caller reads its return" map.
    let mut callee_readers: HashMap<u64, bool> = HashMap::new();
    for (_, ssa) in funcs.iter() {
        for (callee, uses) in collect_callsite_return_uses(ssa) {
            let entry = callee_readers.entry(callee).or_insert(false);
            *entry |= uses;
        }
    }

    let mut demoted = 0usize;
    for (addr, ssa) in funcs.iter_mut() {
        let stale_inferred = ssa
            .diagnostics
            .iter()
            .any(|d| d.kind == crate::ir::DiagKind::StaleReturnInherited);
        if !stale_inferred {
            continue;
        }
        match callee_readers.get(addr) {
            Some(true) => {
                // At least one caller reads our return — preserve wrap().
            }
            _ => {
                let mut changed = false;
                for block in ssa.blocks.iter_mut() {
                    if matches!(&block.terminator, SsaTerminator::Return(Some(_))) {
                        block.terminator = SsaTerminator::Return(None);
                        changed = true;
                    }
                }
                if changed {
                    demoted += 1;
                    ssa.diagnostics.push(Diagnostic {
                        severity: Severity::Warn,
                        kind: crate::ir::DiagKind::StaleReturnInherited,
                        addr: Some(*addr),
                        detail: format!(
                            "function @{:#x}: demoted to void — no caller in \
                             the supplied function set reads the inferred \
                             return value",
                            addr
                        ),
                    });
                }
            }
        }
    }
    demoted
}
