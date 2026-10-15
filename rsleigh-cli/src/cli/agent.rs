//! Bounded, verifiable evidence for coding agents.
use super::*;
use serde_json::{json, Value};

const AGENT_BRIEF_DEFAULT_FUNCTIONS: usize = 25;
const AGENT_BRIEF_MAX_FUNCTIONS: usize = 100;
const AGENT_BRIEF_MAX_FINDINGS: usize = 50;
const AGENT_INDEX_MAX_FUNCTIONS: usize = 10_000;
const AGENT_INDEX_MAX_FINDINGS: usize = 5_000;
const AGENT_CARD_MAX_INSTRUCTIONS: usize = 40;
const AGENT_CARD_MAX_PCODE_OPS: usize = 120;
const AGENT_CARD_MAX_PSEUDOCODE_BYTES: usize = 4_096;

#[derive(Debug, Clone)]
struct AgentFunction {
    address: u64,
    name: String,
    size: u64,
    complexity: usize,
    xrefs: usize,
    direct_targets: Vec<u64>,
    calls: Vec<String>,
    imports: Vec<String>,
    strings: Vec<String>,
    tags: Vec<String>,
    status: &'static str,
    diagnostics: Vec<Value>,
}

struct AgentAnalysis {
    format: &'static str,
    arch: rsleigh_api::Architecture,
    imagebase: u64,
    functions: Vec<AgentFunction>,
    total_functions: usize,
    findings: Vec<rsleigh_decompile::finding::FindingRecord>,
    total_findings: usize,
    imports: Vec<(u64, String)>,
}

fn requested_agent_limit(args: &[String], default: usize, maximum: usize) -> usize {
    args.iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(1, maximum)
}

/// Container format and load base. The base is what the loader maps the
/// image at before relocation (PE `ImageBase`, the lowest ELF `PT_LOAD`
/// page, the Mach-O `__TEXT` segment), matching what Ghidra reports, not the
/// first executable section.
fn agent_format_and_base(obj: &goblin::Object, segs: &[(u64, u64, u64)]) -> (&'static str, u64) {
    let lowest_section = || segs.iter().map(|(va, _, _)| *va).min().unwrap_or(0);
    match obj {
        goblin::Object::PE(pe) => ("pe", pe.image_base as u64),
        goblin::Object::Elf(elf) => (
            "elf",
            elf.program_headers
                .iter()
                .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
                .map(|ph| ph.p_vaddr & !ph.p_align.max(1).wrapping_sub(1))
                .min()
                .unwrap_or_else(lowest_section),
        ),
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => (
            "mach-o",
            macho
                .segments
                .iter()
                .find(|seg| seg.name().is_ok_and(|n| n == "__TEXT"))
                .map(|seg| seg.vmaddr)
                .unwrap_or_else(lowest_section),
        ),
        _ => ("unknown", 0),
    }
}

fn agent_arch_warnings(arch: rsleigh_api::Architecture) -> Vec<&'static str> {
    use rsleigh_api::Architecture;
    match arch {
        Architecture::X86_64 => Vec::new(),
        Architecture::X86_32 => {
            vec!["x86-32 calling-convention and legacy-mode decompilation are partial"]
        }
        Architecture::AArch64 => {
            vec!["NEON/SVE decoding is broader than vector/type recovery in pseudocode"]
        }
        Architecture::ARM32 => {
            vec!["ARM32 Thumb-2 and VFP/NEON lifting and decompilation are partial"]
        }
        Architecture::MIPS32 => {
            vec!["MIPS32 FPU/DSP/MIPS16/microMIPS lifting and decompilation are partial"]
        }
        Architecture::RiscV64 => {
            vec!["RISC-V discovery and F/D/B/K/P/Q/V/C lifting and decompilation are partial"]
        }
    }
}

fn agent_calling_convention(arch: rsleigh_api::Architecture, obj: &goblin::Object) -> &'static str {
    use rsleigh_api::Architecture;
    match arch {
        Architecture::X86_64 if matches!(obj, goblin::Object::PE(_)) => "Win64",
        Architecture::X86_64 => "SysV",
        Architecture::X86_32 | Architecture::MIPS32 => "cdecl32",
        Architecture::AArch64 => "AAPCS64",
        Architecture::ARM32 => "AAPCS32",
        Architecture::RiscV64 => "LP64",
    }
}

fn agent_symbols(
    obj: &goblin::Object,
    data: &[u8],
) -> Option<(
    rsleigh_api::Architecture,
    Vec<(u64, u64, u64)>,
    Vec<(u64, String)>,
)> {
    let (arch, segs, mut symbols) = parse_binary(obj, data)?;

    if let goblin::Object::PE(pe) = obj {
        if let Some(optional) = pe.header.optional_header {
            let entry =
                pe.image_base as u64 + optional.standard_fields.address_of_entry_point as u64;
            let existing: std::collections::HashSet<u64> =
                symbols.iter().map(|(addr, _)| *addr).collect();
            for (addr, name) in discover_pe_functions(entry, &segs, data, arch) {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    if let goblin::Object::Elf(elf) = obj {
        let needs_discovery = elf.syms.len() == 0
            || symbols.is_empty()
            || symbols.iter().all(|(_, name)| name.starts_with("FUN_"));
        if needs_discovery {
            let existing: std::collections::HashSet<u64> =
                symbols.iter().map(|(addr, _)| *addr).collect();
            for (addr, name) in discover_elf_functions(elf, &segs, data, arch) {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    let go_symbols = rsleigh_decompile::go_pclntab::parse(data);
    for (addr, name) in go_symbols {
        if let Some((_, current)) = symbols.iter_mut().find(|(candidate, _)| *candidate == addr) {
            if current.is_empty() || current.starts_with("FUN_") || current.starts_with("func_") {
                *current = name;
            }
        } else {
            symbols.push((addr, name));
        }
    }

    symbols.retain(|(addr, name)| {
        !name.is_empty()
            && !HIDDEN.contains(&name.as_str())
            && segs
                .iter()
                .any(|(va, size, _)| *addr >= *va && *addr < va + size)
    });
    symbols.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    symbols.dedup_by(|a, b| {
        if a.0 != b.0 {
            return false;
        }
        let a_generic = a.1.starts_with("FUN_") || a.1.starts_with("func_");
        let b_generic = b.1.starts_with("FUN_") || b.1.starts_with("func_");
        if a_generic && !b_generic {
            a.1 = b.1.clone();
        }
        true
    });
    Some((arch, segs, symbols))
}

fn collect_agent_byte_findings(
    binary_path: &str,
    data: &[u8],
) -> Vec<rsleigh_decompile::finding::FindingRecord> {
    use rsleigh_decompile::finding::{FindingConfidence, FindingRecord, FindingStage};

    let mut records = Vec::new();
    let texts = rsleigh_decompile::iot_capabilities::extract_printable_runs(data, 6);
    let mut urls = std::collections::BTreeSet::new();
    let mut ips = std::collections::BTreeSet::new();
    for text in &texts {
        for token in text.split_whitespace() {
            let value = token.trim_matches(|c: char| {
                matches!(
                    c,
                    '\"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
                )
            });
            if value.starts_with("http://")
                || value.starts_with("https://")
                || value.starts_with("ftp://")
            {
                urls.insert(value.trim_end_matches(['.', ':', '/']).to_string());
            }
            let host = value.split(':').next().unwrap_or(value);
            let octets: Option<Vec<u16>> = host
                .split('.')
                .map(|part| part.parse::<u16>().ok().filter(|octet| *octet <= 255))
                .collect();
            if let Some(octets) = octets {
                if octets.len() == 4 && octets.iter().filter(|&&octet| octet == 0).count() < 2 {
                    ips.insert(host.to_string());
                }
            }
        }
    }
    for (kind, values) in [("url", urls), ("ipv4", ips)] {
        for value in values {
            records.push(
                FindingRecord::new(
                    format!("ioc.{kind}"),
                    "ioc",
                    FindingConfidence::Pattern,
                    FindingStage::File,
                    format!("{kind}: {value}"),
                )
                .with_evidence(serde_json::json!({
                    "binary": binary_path,
                    "value": value,
                })),
            );
        }
    }

    if let Some(family) = rsleigh_decompile::iot_family::classify_bytes(data) {
        records.push(
            FindingRecord::new(
                "malware.family",
                "ioc",
                FindingConfidence::Heuristic,
                FindingStage::File,
                format!("family: {}", family.label),
            )
            .with_evidence(serde_json::json!({
                "binary": binary_path,
                "family_id": family.id,
                "variant": family.variant,
                "evidence": family.evidence,
            })),
        );
    }
    for capability in rsleigh_decompile::iot_capabilities::classify_bytes(data) {
        records.push(
            FindingRecord::new(
                "malware.capability",
                "ioc",
                FindingConfidence::Heuristic,
                FindingStage::File,
                format!("capability: {}", capability.label),
            )
            .with_evidence(serde_json::json!({
                "binary": binary_path,
                "capability_id": capability.id,
                "evidence": capability.evidence,
            })),
        );
    }
    records
}

fn finding_sort_key(record: &rsleigh_decompile::finding::FindingRecord) -> (u8, u8) {
    use rsleigh_decompile::finding::FindingConfidence;
    let severity = match record.severity.as_deref() {
        Some("CRIT") => 0,
        Some("HIGH") => 1,
        Some("MED") => 2,
        Some("LOW") => 3,
        Some("INFO") => 4,
        _ => 5,
    };
    let confidence = match record.confidence {
        FindingConfidence::Proved => 0,
        FindingConfidence::Heuristic => 1,
        FindingConfidence::Pattern => 2,
    };
    (severity, confidence)
}

type NativeImage<'a> = (
    goblin::Object<'a>,
    rsleigh_api::Architecture,
    Vec<(u64, u64, u64)>,
    Vec<(u64, String)>,
);

/// Parse a PE/ELF/Mach-O container and its discovered function map.
fn parse_native(data: &[u8]) -> Result<NativeImage<'_>, AgentError> {
    let obj = parse_object_lenient(data)
        .map_err(|e| AgentError::new("unsupported_format", e.to_string()))?;
    let (arch, segs, symbols) = agent_symbols(&obj, data).ok_or_else(|| {
        AgentError::new(
            "unsupported_format",
            "unsupported binary format or architecture",
        )
    })?;
    Ok((obj, arch, segs, symbols))
}

fn build_agent_analysis(
    binary_path: &str,
    data: &[u8],
    function_limit: usize,
    finding_limit: usize,
) -> Result<AgentAnalysis, AgentError> {
    use pcode_ir::{AddressSpaceId, PcodeOp};
    use rsleigh_decompile::finding::{FindingConfidence, FindingRecord, FindingStage};

    let (obj, arch, segs, symbols) = parse_native(data)?;
    let (format, imagebase) = agent_format_and_base(&obj, &segs);
    let import_map = build_import_map(&obj, data);
    let import_names: std::collections::HashSet<String> = import_map.values().cloned().collect();
    let name_by_addr: std::collections::HashMap<u64, String> = symbols.iter().cloned().collect();
    let mut decoder = rsleigh_api::Decoder::new(arch);
    let mut functions = Vec::new();
    let mut incoming: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

    for (address, name) in &symbols {
        let mut diagnostics = Vec::new();
        let instructions = decode_func_with_diagnostics(
            *address,
            &symbols,
            &segs,
            data,
            &mut decoder,
            &mut diagnostics,
        );
        if instructions.is_empty() {
            diagnostics.push(diagnostic(
                "decode",
                "no_instructions",
                "no decodable instructions",
            ));
        }
        let status = evidence_status(!instructions.is_empty(), &diagnostics);
        let size: u64 = instructions.iter().map(|(_, inst)| inst.len).sum();
        let mut complexity = 1usize;
        let mut direct_targets = Vec::new();
        for (_, instruction) in &instructions {
            for op in &instruction.ops {
                match op {
                    PcodeOp::CBranch { .. } => complexity += 1,
                    PcodeOp::Call { dest } if dest.space == AddressSpaceId::Ram => {
                        direct_targets.push(dest.offset);
                        *incoming.entry(dest.offset).or_insert(0) += 1;
                    }
                    _ => {}
                }
            }
        }
        direct_targets.sort_unstable();
        direct_targets.dedup();
        let mut calls = Vec::new();
        let mut imports = Vec::new();
        for target in &direct_targets {
            if let Some(import) = import_map.get(target) {
                imports.push(import.clone());
                calls.push(import.clone());
            } else if let Some(callee) = name_by_addr.get(target) {
                calls.push(callee.clone());
            } else {
                calls.push(format!("0x{target:x}"));
            }
        }
        calls.sort();
        calls.dedup();
        imports.sort();
        imports.dedup();
        functions.push(AgentFunction {
            address: *address,
            name: name.clone(),
            size,
            complexity,
            xrefs: 0,
            direct_targets,
            calls,
            imports,
            strings: Vec::new(),
            tags: Vec::new(),
            status,
            diagnostics,
        });
    }

    for function in &mut functions {
        function.xrefs = incoming.get(&function.address).copied().unwrap_or(0);
    }
    functions.sort_by(|a, b| {
        b.xrefs
            .cmp(&a.xrefs)
            .then_with(|| b.complexity.cmp(&a.complexity))
            .then_with(|| b.size.cmp(&a.size))
            .then_with(|| a.address.cmp(&b.address))
    });
    let total_functions = functions.len();
    functions.truncate(function_limit);

    let path = Path::new(binary_path);
    let mut findings = collect_agent_byte_findings(binary_path, data);
    for function in &mut functions {
        let instructions = decode_func(function.address, &symbols, &segs, data, &mut decoder);
        if instructions.is_empty() {
            continue;
        }
        let pseudocode =
            decompile_function(arch, &instructions, data, path, &mut function.diagnostics);
        function.status = evidence_status(true, &function.diagnostics);
        let meta = rsleigh_decompile::analysis::extract_function_meta(
            &function.name,
            function.address,
            &pseudocode,
        );
        function.strings = meta.strings.into_iter().take(5).collect();
        function.tags = meta.tags;
        for call in meta.calls {
            if !function.calls.contains(&call) {
                function.calls.push(call.clone());
            }
            if import_names.contains(&call) && !function.imports.contains(&call) {
                function.imports.push(call);
            }
        }
        function.calls.sort();
        function.calls.dedup();
        function.imports.sort();
        function.imports.dedup();

        for vuln in
            rsleigh_decompile::analysis::scan_vulns(&function.name, function.address, &pseudocode)
        {
            let mut record = FindingRecord::new(
                "vulnerability.pattern",
                "vulnscan",
                if vuln.severity == "INFO" {
                    FindingConfidence::Heuristic
                } else {
                    FindingConfidence::Pattern
                },
                FindingStage::Decompile,
                vuln.description,
            )
            .with_evidence(serde_json::json!({
                "binary": binary_path,
                "context": vuln.context,
            }));
            record.severity = Some(vuln.severity);
            record.function = Some(vuln.function);
            record.address = Some(format!("0x{:x}", vuln.address));
            findings.push(record);
        }
    }
    findings.sort_by_key(finding_sort_key);
    let total_findings = findings.len();
    findings.truncate(finding_limit);

    let mut imports: Vec<(u64, String)> = import_map.into_iter().collect();
    imports.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(AgentAnalysis {
        format,
        arch,
        imagebase,
        functions,
        total_functions,
        findings,
        total_findings,
        imports,
    })
}

fn agent_function_json(function: &AgentFunction) -> serde_json::Value {
    serde_json::json!({
        "name": function.name,
        "addr": format!("0x{:x}", function.address),
        "stage": "discover",
        "confidence": "pattern",
        "size": function.size,
        "complexity": function.complexity,
        "complexity_stage": "lift",
        "xrefs": function.xrefs,
        "imports": function.imports,
        "strings": function.strings,
        "calls": function.calls,
        "tags": function.tags,
        "status": function.status,
        "diagnostics": function.diagnostics,
    })
}

fn agent_trust_json() -> serde_json::Value {
    serde_json::json!({
        "primary": ["decoder", "pcode"],
        "hypothesis": ["pseudocode"],
        "leads": ["ioc", "vulnscan", "vm_helpers"],
        "proved_claim": "SMT record with verdict == Reachable (confidence == proved alone is not a positive verdict)",
        "disagreement_rule": "If pseudocode and P-code disagree, use P-code and report the conflict",
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

mod bundle;
mod cache;
mod capabilities;
mod card;
mod compare;
mod contracts;
mod evidence;
mod index;
mod investigation;
mod lookup;
mod mcp;
mod slice;

use contracts::AgentError;

/// Legacy `--diff`: rendered from the structured comparison model.
pub(super) fn legacy_diff(old_path: &str, new_path: &str, functions: &[String]) {
    compare::legacy(old_path, new_path, functions)
}

/// Usage text shared by bare invocation (stderr, exit 1) and `--help`.
pub(super) fn usage() -> String {
    capabilities::usage()
}

fn execution_scope(args: &[String]) -> Result<rsleigh_decompile::budget::Scope, AgentError> {
    let number = |flag| -> Result<Option<u64>, AgentError> {
        value_arg(args, flag)?
            .map(|v| {
                v.parse::<u64>().map_err(|_| {
                    AgentError::new(
                        "invalid_value",
                        format!("{flag} requires an unsigned integer"),
                    )
                })
            })
            .transpose()
    };
    Ok(rsleigh_decompile::budget::Scope::new(
        rsleigh_decompile::budget::Limits {
            decode_instructions: number("--max-decode-instructions")?,
            ssa_work: number("--max-ssa-work")?,
            deadline_ms: number("--deadline-ms")?,
        },
    ))
}

/// Keep SSA IDs tied to the same discovered boundaries in full dumps and slices.
pub(super) fn ssa_instructions(
    data: &[u8],
    address: u64,
) -> Result<(Vec<(u64, pcode_ir::Instruction)>, Vec<Value>), String> {
    let obj = parse_object_lenient(data).map_err(|e| e.to_string())?;
    let (arch, segs, symbols) =
        agent_symbols(&obj, data).ok_or("unsupported binary format or architecture")?;
    let mut diagnostics = Vec::new();
    let instructions = decode_func_raw_with_diagnostics(
        address,
        &symbols,
        &segs,
        data,
        &mut rsleigh_api::Decoder::new(arch),
        &mut diagnostics,
    );
    if instructions.is_empty() && rsleigh_decompile::budget::stopped().is_none() {
        return Err("no decodable instructions at requested address".into());
    }
    Ok((instructions, diagnostics))
}

fn diagnostic(stage: &str, code: &str, message: &str) -> Value {
    json!({"stage": stage, "code": code, "message": message})
}

fn evidence_status(has_evidence: bool, diagnostics: &[Value]) -> &'static str {
    if !has_evidence {
        "failed"
    } else if diagnostics.is_empty() {
        "ok"
    } else {
        "partial"
    }
}

fn recover_decompile(f: impl FnOnce() -> String, diagnostics: &mut Vec<Value>) -> String {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(text) if !text.trim().is_empty() => text,
        Ok(_) => {
            diagnostics.push(diagnostic(
                "decompile",
                "empty_output",
                "decompiler returned no pseudocode",
            ));
            String::new()
        }
        Err(_) => {
            diagnostics.push(diagnostic(
                "decompile",
                "decompile_panicked",
                "decompiler panicked; decoded instructions remain available",
            ));
            String::new()
        }
    }
}

/// Card diagnostics that describe the function itself rather than an
/// interrupted run; analyses carrying only these are complete and cacheable.
const DETERMINISTIC_DIAGNOSTICS: &[&str] =
    &["unresolved_control_flow", "body_truncated", "empty_body"];

/// Decompile one function body and record what its pseudocode cannot show:
/// control flow the pipeline could not resolve, and a body that prints empty
/// although the P-code calls or branches.
fn decompile_function(
    arch: rsleigh_api::Architecture,
    instructions: &[(u64, pcode_ir::Instruction)],
    data: &[u8],
    path: &Path,
    diagnostics: &mut Vec<Value>,
) -> String {
    let mut pipeline = Vec::new();
    let text = recover_decompile(
        || {
            let (text, found) = rsleigh_decompile::decompile_with_diagnostics(
                arch,
                instructions,
                Some(data),
                Some(path),
            );
            pipeline = found;
            text
        },
        diagnostics,
    );
    for d in rsleigh_decompile::unresolved_control_flow(&pipeline) {
        diagnostics.push(json!({"stage":"decompile","code":"unresolved_control_flow",
            "address":d.addr.map(|a| format!("0x{a:x}")),"message":d.detail}));
    }
    let does_work = instructions.iter().flat_map(|(_, i)| &i.ops).any(|op| {
        matches!(
            op,
            pcode_ir::PcodeOp::Call { .. }
                | pcode_ir::PcodeOp::CallInd { .. }
                | pcode_ir::PcodeOp::Branch { .. }
                | pcode_ir::PcodeOp::CBranch { .. }
                | pcode_ir::PcodeOp::BranchInd { .. }
        )
    });
    if !text.is_empty() && does_work && pseudocode_body_is_empty(&text) {
        diagnostics.push(diagnostic(
            "decompile",
            "empty_body",
            "pseudocode body is empty although the P-code calls or branches",
        ));
    }
    text
}

/// True when the function body holds nothing but declarations, comments,
/// braces, and a bare `return;`.
fn pseudocode_body_is_empty(text: &str) -> bool {
    !text
        .lines()
        .skip_while(|l| !l.trim_end().ends_with('{'))
        .skip(1)
        .map(str::trim)
        .any(|t| {
            let declaration = t.ends_with(';')
                && !t.contains('=')
                && !t.contains('(')
                && !t.starts_with("return")
                && t.contains(' ');
            !(t.is_empty()
                || t == "}"
                || t == "return;"
                || t.starts_with("//")
                || t.starts_with("/*")
                || t.starts_with('*')
                || declaration)
        })
}

fn value_arg<'a>(args: &'a [String], flag: &str) -> Result<Option<&'a str>, AgentError> {
    let mut matches = args.iter().enumerate().filter(|(_, a)| a.as_str() == flag);
    let Some((i, _)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(AgentError::new(
            "duplicate_option",
            format!("duplicate {flag}"),
        ));
    }
    args.get(i + 1)
        .filter(|a| !a.starts_with("--"))
        .map(|a| Some(a.as_str()))
        .ok_or_else(|| AgentError::new("missing_value", format!("{flag} requires a value")))
}

/// Every value of a repeatable flag, in argument order.
fn values_arg<'a>(args: &'a [String], flag: &str) -> Result<Vec<&'a str>, AgentError> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == flag)
        .map(|(i, _)| {
            args.get(i + 1)
                .filter(|a| !a.starts_with("--"))
                .map(String::as_str)
                .ok_or_else(|| AgentError::new("missing_value", format!("{flag} requires a value")))
        })
        .collect()
}

fn number_arg(args: &[String], flag: &str, default: usize) -> Result<usize, AgentError> {
    value_arg(args, flag)?
        .map(|s| {
            s.parse::<usize>().map_err(|_| {
                AgentError::new(
                    "invalid_value",
                    format!("{flag} requires an unsigned integer"),
                )
            })
        })
        .unwrap_or(Ok(default))
}

fn emit(value: &Value) {
    if evidence::capture(value) {
        return;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON value is serializable")
    );
}

fn analysis_status(analysis: &AgentAnalysis) -> &'static str {
    if analysis.functions.iter().all(|f| f.status == "ok") {
        "ok"
    } else if analysis.functions.iter().all(|f| f.status == "failed") {
        "failed"
    } else {
        "partial"
    }
}

fn status_exit(status: &str) -> u8 {
    match status {
        "ok" => 0,
        "partial" => 2,
        _ => 1,
    }
}

fn file_identity(binary_path: &str, data: &[u8], analysis: &AgentAnalysis) -> Value {
    json!({
        "path": binary_path, "stage":"file", "confidence":"proved",
        "size": data.len(), "format":analysis.format, "arch":format!("{:?}", analysis.arch),
        "imagebase":format!("0x{:x}", analysis.imagebase),
        "hashes":{"md5":compute_md5(data), "sha256":compute_sha256(data), "imphash":compute_imphash(data)}
    })
}

fn run_agent_brief(binary_path: &str, data: &[u8], args: &[String]) -> Result<u8, AgentError> {
    let limit = requested_agent_limit(
        args,
        AGENT_BRIEF_DEFAULT_FUNCTIONS,
        AGENT_BRIEF_MAX_FUNCTIONS,
    );
    let analysis = build_agent_analysis(binary_path, data, limit, AGENT_BRIEF_MAX_FINDINGS)?;
    let next = analysis
        .functions
        .first()
        .map(|f| {
            let address = format!("0x{:x}", f.address);
            [
                vec!["--xrefs", &address, "--json"],
                vec![&address, "--card", "--json", "--pcode"],
                vec!["--ssa-json", &address],
            ]
            .into_iter()
            .map(|tail| {
                let argv: Vec<String> = std::iter::once(binary_path)
                    .chain(tail)
                    .map(str::to_string)
                    .collect();
                investigation::render_command(&argv, investigation::Shell::Posix)
            })
            .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let status = analysis_status(&analysis);
    emit(&json!({
        "schema":"rsleigh.agent-brief/v1", "status":status,
        "tool_version":env!("CARGO_PKG_VERSION"), "file":file_identity(binary_path,data,&analysis),
        "functions":analysis.functions.iter().map(agent_function_json).collect::<Vec<_>>(),
        "findings":analysis.findings, "warnings":agent_arch_warnings(analysis.arch),
        "trust":agent_trust_json(), "next":next,
        "limits":{
            "functions_returned":analysis.functions.len(), "functions_total":analysis.total_functions,
            "functions_cap":AGENT_BRIEF_MAX_FUNCTIONS, "findings_returned":analysis.findings.len(),
            "findings_total":analysis.total_findings, "findings_cap":AGENT_BRIEF_MAX_FINDINGS,
            "strings_per_function":5, "pseudocode_bytes":0
        }
    }));
    Ok(status_exit(status))
}

/// Route a validated operation to its handler. `data` is the binary when the
/// invocation supplied one.
fn run_operation(
    op: &contracts::Operation,
    args: &[String],
    data: Option<&[u8]>,
) -> Result<u8, AgentError> {
    let binary =
        || data.ok_or_else(|| AgentError::new("invalid_target", "this operation requires FILE"));

    match op.id {
        "agent-brief" => run_agent_brief(&args[1], binary()?, args),
        "index" => index::build(
            &args[1],
            binary()?,
            args,
            value_arg(args, "--index")?.expect("validated mode value"),
        ),
        "verify-index" => index::verify(
            binary()?,
            value_arg(args, "--verify-index")?.expect("validated mode value"),
        ),
        "card" => card::run(&args[1], binary()?, args),
        "xrefs" => lookup::xrefs(&args[1], binary()?, args),
        "search" => lookup::search(&args[1], binary()?, args),
        "ssa-slice" => slice::run(binary()?, args),
        "export-bundle" => bundle::export(binary()?, args),
        "compare" => compare::run(&args[1], binary()?, args),
        "verify-bundle" => bundle::verify(data, args, investigation::validate_bundle),
        "import-bundle" => bundle::import(data, args, investigation::validate_bundle, |b| {
            investigation::import(b, args)
        }),
        "investigate" => investigation::create(&args[1], binary()?, args),
        "investigation" => investigation::run(data.map(|d| (args[1].as_str(), d)), args),
        other => Err(AgentError::new(
            "command_failed",
            format!("operation {other} has no handler"),
        )),
    }
}

/// Agent modes use one result/exit contract, including worker-thread panics.
/// 0 = completed, 2 = partial evidence, 1 = failed command.
pub(super) fn dispatch(args: &[String]) -> bool {
    let target_free =
        args.len() > 1 && (args[1].starts_with("--") || matches!(args[1].as_str(), "-h" | "-V"));
    let selected: Vec<&'static contracts::Operation> = if target_free {
        contracts::OPERATIONS
            .iter()
            .filter(|op| op.target != contracts::Target::Binary && op.mode.name == args[1])
            .collect()
    } else {
        let candidates: Vec<&'static contracts::Operation> = contracts::OPERATIONS
            .iter()
            .filter(|op| op.target != contracts::Target::None)
            .filter(|op| args.iter().skip(2).any(|a| a == op.mode.name))
            .collect();
        // A mode flag that another selected operation accepts as an ordinary
        // modifier (e.g. --investigation on --export-bundle) is not a mode.
        candidates
            .iter()
            .copied()
            .filter(|op| {
                !candidates.iter().any(|other| {
                    other.id != op.id && other.flags.iter().any(|f| f.name == op.mode.name)
                })
            })
            .collect()
    };
    if selected.is_empty() && !target_free {
        return false;
    }
    if args.iter().any(|a| a == "--raw")
        && !selected.is_empty()
        && selected
            .iter()
            .all(|op| lookup::RAW_LEGACY.contains(&op.id))
    {
        return false;
    }
    let (code, _) = invoke(selected, args.to_vec(), target_free, false);
    if code != 0 {
        std::process::exit(i32::from(code));
    }
    true
}

fn failure_envelope(schema: &str, error: &AgentError) -> Value {
    json!({"schema":schema, "status":"failed", "error":error.message, "error_code":error.code,
        "diagnostics":[diagnostic("command", "command_failed", &error.message)]})
}

/// Run selected operations on a worker thread under the agent contract. With
/// `collect`, every emitted document (failure envelope included) is returned
/// instead of printed; otherwise output goes to stdout as for the CLI.
fn invoke(
    selected: Vec<&'static contracts::Operation>,
    args: Vec<String>,
    target_free: bool,
    collect: bool,
) -> (u8, Vec<Value>) {
    let schema = selected
        .first()
        .map(|op| op.schema)
        .unwrap_or(capabilities::SCHEMA);
    let result = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || -> (Result<u8, AgentError>, Vec<Value>) {
            if collect {
                evidence::begin_capture();
            }
            let result = run_selected(&selected, &args, target_free);
            let output = if collect {
                evidence::end_capture()
            } else {
                Vec::new()
            };
            (result, output)
        });
    let (result, mut output) = match result
        .map_err(|e| {
            AgentError::new(
                "analysis_failed",
                format!("cannot start analysis worker: {e}"),
            )
        })
        .and_then(|t| {
            t.join()
                .map_err(|_| AgentError::new("analysis_failed", "analysis worker panicked"))
        }) {
        Ok((result, output)) => (result, output),
        Err(error) => (Err(error), Vec::new()),
    };
    match result {
        Ok(code) => (code, output),
        Err(error) => {
            let envelope = failure_envelope(schema, &error);
            if collect {
                output.push(envelope);
            } else {
                emit(&envelope);
                eprintln!("Error: {error}");
            }
            (1, output)
        }
    }
}

fn run_selected(
    selected: &[&'static contracts::Operation],
    args: &[String],
    target_free: bool,
) -> Result<u8, AgentError> {
    let Some(op) = selected.first().copied() else {
        return capabilities::run_target_free(args);
    };
    if selected.len() != 1 {
        return Err(AgentError::new(
            "multiple_modes",
            "select exactly one agent mode",
        ));
    }
    if args.iter().any(|a| a == "--raw") {
        return Err(AgentError::new(
            "unsupported_input",
            "agent modes require PE, ELF, or Mach-O input",
        ));
    }
    contracts::validate(op, args, if target_free { 1 } else { 2 })?;
    let data =
        if target_free {
            None
        } else {
            Some(std::fs::read(&args[1]).map_err(|e| {
                AgentError::new("input_unreadable", format!("cannot read binary: {e}"))
            })?)
        };
    let capture = op.flag("--evidence").is_some()
        && args
            .iter()
            .any(|a| a == "--evidence" || a == "--evidence-store");
    if !capture {
        return run_operation(op, args, data.as_deref());
    }
    let data = data.expect("evidence operations read a binary");
    evidence::preflight(args, &data)?;
    evidence::begin_capture();
    let result = run_operation(op, args, Some(&data));
    let captured = evidence::end_capture();
    let code = result?;
    evidence::finish(op, args, &data, captured, code)?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_body_ignores_declarations_comments_and_bare_return() {
        let empty = "// 0x42960\nvoid sqlite3_free(void * param_0) {\n    long lVar1;\n    /* note */\n\nreturn;\n}\n";
        assert!(pseudocode_body_is_empty(empty));
        let call = "void f(void) {\n    long lVar1;\n    free(lVar1);\n}\n";
        assert!(!pseudocode_body_is_empty(call));
        let value = "int g(void) {\nreturn 0;\n}\n";
        assert!(!pseudocode_body_is_empty(value));
    }

    #[test]
    fn decompiler_failures_are_partial_when_decode_evidence_survives() {
        for panic in [false, true] {
            let mut diagnostics = Vec::new();
            assert!(recover_decompile(
                || {
                    if panic {
                        panic!("fixture panic")
                    }
                    String::new()
                },
                &mut diagnostics
            )
            .is_empty());
            assert_eq!(evidence_status(true, &diagnostics), "partial");
            assert_eq!(diagnostics[0]["stage"], "decompile");
            assert_eq!(
                diagnostics[0]["code"],
                if panic {
                    "decompile_panicked"
                } else {
                    "empty_output"
                }
            );
        }
    }
}
