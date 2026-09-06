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

fn agent_format_and_base(obj: &goblin::Object, segs: &[(u64, u64, u64)]) -> (&'static str, u64) {
    match obj {
        goblin::Object::PE(pe) => ("pe", pe.image_base as u64),
        goblin::Object::Elf(_) => ("elf", segs.iter().map(|(va, _, _)| *va).min().unwrap_or(0)),
        goblin::Object::Mach(goblin::mach::Mach::Binary(_)) => (
            "mach-o",
            segs.iter().map(|(va, _, _)| *va).min().unwrap_or(0),
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

fn build_agent_analysis(
    binary_path: &str,
    data: &[u8],
    function_limit: usize,
    finding_limit: usize,
) -> Result<AgentAnalysis, String> {
    use pcode_ir::{AddressSpaceId, PcodeOp};
    use rsleigh_decompile::finding::{FindingConfidence, FindingRecord, FindingStage};

    let obj = parse_object_lenient(data).map_err(|error| error.to_string())?;
    let (arch, segs, symbols) = agent_symbols(&obj, data)
        .ok_or_else(|| "unsupported binary format or architecture".to_string())?;
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
        let size = instructions
            .last()
            .map(|(inst_addr, inst)| inst_addr + inst.len - address)
            .unwrap_or(0);
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
        let pseudocode = recover_decompile(
            || {
                rsleigh_decompile::decompile_with_binary(
                    arch,
                    &instructions,
                    Some(data),
                    Some(path),
                )
            },
            &mut function.diagnostics,
        );
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

mod cache;
mod card;
mod index;
mod slice;

fn execution_scope(args: &[String]) -> Result<rsleigh_decompile::budget::Scope, String> {
    let number = |flag| -> Result<Option<u64>, String> {
        value_arg(args, flag)?
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| format!("{flag} requires an unsigned integer"))
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

fn value_arg<'a>(args: &'a [String], flag: &str) -> Result<Option<&'a str>, String> {
    let mut matches = args.iter().enumerate().filter(|(_, a)| a.as_str() == flag);
    let Some((i, _)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(format!("duplicate {flag}"));
    }
    args.get(i + 1)
        .filter(|a| !a.starts_with("--"))
        .map(|a| Some(a.as_str()))
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn number_arg(args: &[String], flag: &str, default: usize) -> Result<usize, String> {
    value_arg(args, flag)?
        .map(|s| {
            s.parse::<usize>()
                .map_err(|_| format!("{flag} requires an unsigned integer"))
        })
        .unwrap_or(Ok(default))
}

fn emit(value: &Value) {
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

fn run_agent_brief(binary_path: &str, data: &[u8], args: &[String]) -> Result<u8, String> {
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
            let binary = shell_quote(binary_path);
            vec![
                format!("rsleigh {binary} --xrefs 0x{:x}", f.address),
                format!("rsleigh {binary} 0x{:x} --card --json --pcode", f.address),
                format!("rsleigh {binary} --ssa-json 0x{:x}", f.address),
            ]
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

/// Agent modes use one result/exit contract, including worker-thread panics.
/// 0 = completed, 2 = partial evidence, 1 = failed command.
pub(super) fn dispatch(args: &[String]) -> bool {
    let modes = [
        "--agent-brief",
        "--card",
        "--index",
        "--verify-index",
        "--ssa-slice",
    ];
    let selected: Vec<_> = modes
        .iter()
        .filter(|m| args.iter().any(|a| a == **m))
        .copied()
        .collect();
    if selected.is_empty() {
        return false;
    }
    let schema = match selected[0] {
        "--agent-brief" => "rsleigh.agent-brief/v1",
        "--card" => "rsleigh.card/v2",
        "--index" => "rsleigh.index/v2",
        "--verify-index" => "rsleigh.index-verification/v1",
        _ => "rsleigh.ssa-slice/v3",
    };
    let args = args.to_vec();
    let mode = selected[0];
    let result = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            if selected.len() != 1 {
                return Err("select exactly one agent mode".to_string());
            }
            if args.iter().any(|a| a == "--raw") {
                return Err("agent modes require PE, ELF, or Mach-O input".to_string());
            }
            let allowed: &[&str] = match mode {
                "--agent-brief" => &["--agent-brief", "--limit", "--json"],
                "--index" => &["--index", "--limit", "--json"],
                "--verify-index" => &["--verify-index", "--json"],
                "--card" => &[
                    "--card",
                    "--analysis-cache",
                    "--max-decode-instructions",
                    "--max-ssa-work",
                    "--deadline-ms",
                    "--json",
                    "--pcode",
                    "--decompile",
                    "--instruction-cursor",
                    "--operation-cursor",
                ],
                _ => &[
                    "--ssa-slice",
                    "--var",
                    "--call-site",
                    "--arg",
                    "--return",
                    "--at",
                    "--condition",
                    "--analysis-cache",
                    "--max-decode-instructions",
                    "--max-ssa-work",
                    "--deadline-ms",
                    "--max-nodes",
                    "--max-depth",
                    "--max-call-depth",
                    "--max-functions",
                    "--max-traversal-work",
                    "--json",
                ],
            };
            let takes_value = [
                "--index",
                "--verify-index",
                "--limit",
                "--instruction-cursor",
                "--operation-cursor",
                "--ssa-slice",
                "--var",
                "--call-site",
                "--arg",
                "--at",
                "--condition",
                "--analysis-cache",
                "--max-decode-instructions",
                "--max-ssa-work",
                "--deadline-ms",
                "--max-nodes",
                "--max-depth",
                "--max-call-depth",
                "--max-functions",
                "--max-traversal-work",
            ];
            let mut i = 2;
            while i < args.len() {
                let arg = args[i].as_str();
                if arg.starts_with("--") {
                    if !allowed.contains(&arg) {
                        return Err(format!("unsupported {mode} option: {arg}"));
                    }
                    if takes_value.contains(&arg) {
                        value_arg(&args, arg)?;
                        i += 1;
                    }
                } else if mode != "--card" {
                    return Err(format!("unexpected argument: {arg}"));
                }
                i += 1;
            }
            for flag in [
                "--limit",
                "--instruction-cursor",
                "--operation-cursor",
                "--max-nodes",
                "--max-depth",
                "--max-call-depth",
                "--max-functions",
                "--max-traversal-work",
            ] {
                if value_arg(&args, flag)?.is_some() {
                    number_arg(&args, flag, 0)?;
                }
            }
            if value_arg(&args, "--limit")?.is_some() && number_arg(&args, "--limit", 1)? == 0 {
                return Err("--limit must be positive".to_string());
            }
            let path = &args[1];
            let data = std::fs::read(path).map_err(|e| format!("cannot read binary: {e}"))?;
            match mode {
                "--agent-brief" => run_agent_brief(path, &data, &args),
                "--index" => {
                    index::build(path, &data, &args, value_arg(&args, "--index")?.unwrap())
                }
                "--verify-index" => {
                    index::verify(&data, value_arg(&args, "--verify-index")?.unwrap())
                }
                "--card" => card::run(path, &data, &args),
                _ => slice::run(&data, &args),
            }
        });
    let result = result
        .map_err(|e| format!("cannot start analysis worker: {e}"))
        .and_then(|t| t.join().map_err(|_| "analysis worker panicked".to_string()))
        .and_then(|r| r);
    let code = match result {
        Ok(code) => code,
        Err(error) => {
            emit(&json!({"schema":schema, "status":"failed", "error":error,
                "diagnostics":[diagnostic("command", "command_failed", &error)]}));
            eprintln!("Error: {error}");
            1
        }
    };
    if code != 0 {
        std::process::exit(i32::from(code));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
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
