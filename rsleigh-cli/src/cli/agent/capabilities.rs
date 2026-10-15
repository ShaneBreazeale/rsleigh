//! Target-free discovery: what operations exist, which inputs implement them,
//! and how analysis quality differs from operation availability.
use super::*;
use rsleigh_api::Architecture;

pub(super) const SCHEMA: &str = "rsleigh.capabilities/v1";

const ARCHITECTURES: [Architecture; 6] = [
    Architecture::X86_64,
    Architecture::X86_32,
    Architecture::AArch64,
    Architecture::ARM32,
    Architecture::MIPS32,
    Architecture::RiscV64,
];

/// Integer ABI argument selection and helper-call argument binding.
/// Slices consult this; discovery reports it. Exhaustive by design.
pub(super) fn supports_call_arguments(arch: Architecture) -> bool {
    match arch {
        Architecture::X86_64
        | Architecture::X86_32
        | Architecture::AArch64
        | Architecture::ARM32 => true,
        Architecture::MIPS32 | Architecture::RiscV64 => false,
    }
}

/// Exact stack/global store-to-load forwarding (docs/architectures.md).
fn supports_memory_forwarding(arch: Architecture) -> bool {
    match arch {
        Architecture::X86_64
        | Architecture::X86_32
        | Architecture::AArch64
        | Architecture::ARM32 => true,
        Architecture::MIPS32 | Architecture::RiscV64 => false,
    }
}

/// Per-stage quality from docs/architectures.md. Availability of an operation
/// never upgrades these labels.
fn stages(arch: Architecture) -> Value {
    let (decode, lift, discovery, decompile) = match arch {
        Architecture::X86_64 => ("tested", "tested", "tested", "tested"),
        Architecture::X86_32 => ("tested", "tested", "tested", "partial"),
        Architecture::AArch64 => ("tested", "tested", "tested", "tested"),
        // ARM mode lift is tested; Thumb/Thumb-2 lift is partial.
        Architecture::ARM32 => ("tested", "partial", "tested", "partial"),
        Architecture::MIPS32 => ("tested", "partial", "tested", "partial"),
        Architecture::RiscV64 => ("tested", "partial", "partial", "partial"),
    };
    json!({"decode":decode,"lift":lift,"discovery":discovery,"decompile":decompile})
}

fn architecture_json(arch: Architecture) -> Value {
    let arguments = supports_call_arguments(arch);
    let support = |yes: bool| if yes { "supported" } else { "unsupported" };
    json!({
        "id":format!("{arch:?}"),
        "stages":stages(arch),
        "warnings":agent_arch_warnings(arch),
        "dependency_queries":{
            "variable":"supported", "return":"supported", "condition":"supported",
            "call_argument":support(arguments),
            "helper_argument_binding":support(arguments),
            "exact_memory_forwarding":support(supports_memory_forwarding(arch)),
        },
    })
}

fn frontends() -> Value {
    let native: Vec<&str> = contracts::OPERATIONS
        .iter()
        .filter(|op| op.target != contracts::Target::None)
        .map(|op| op.id)
        .collect();
    json!([
        {"id":"pe","agent_operations":native},
        {"id":"elf","agent_operations":native},
        {"id":"mach-o","agent_operations":native},
        {"id":"raw","agent_operations":[],
         "reason":"raw images need analyst-supplied --raw ARCH and base; agent contracts require a parsed container"},
        {"id":"wasm","agent_operations":[],
         "reason":"WASM uses a separate reconstructor without decoder/P-code evidence"},
    ])
}

pub(super) fn tool_json() -> Value {
    let build = std::env::current_exe()
        .map_err(|e| e.to_string())
        .and_then(|exe| cache::tool_build_id(&exe))
        .unwrap_or_else(|error| json!({"kind":"unavailable","error":error}));
    json!({"name":"rsleigh","version":env!("CARGO_PKG_VERSION"),"build":build})
}

pub(super) fn catalog() -> Value {
    json!({
        "schema":SCHEMA, "status":"ok", "tool":tool_json(),
        "exit_codes":{"0":"complete","2":"partial evidence","1":"failed"},
        "operations":contracts::OPERATIONS.iter().map(contracts::operation_json).collect::<Vec<_>>(),
        "frontends":frontends(),
        "architectures":ARCHITECTURES.iter().map(|a| architecture_json(*a)).collect::<Vec<_>>(),
        "errors":contracts::ERROR_CODES.iter().map(|(code, meaning)| json!({"code":code,"meaning":meaning})).collect::<Vec<_>>(),
        "trust":agent_trust_json(),
        "interpretation":{
            "execution_status":["ok","partial","failed"],
            "finding_confidence":["pattern","heuristic","proved"],
            "assessment":["confirmed","provisional","unsupported"],
            "rule":"execution status, coverage, and claim strength are independent fields",
        },
        "placeholders":{"FILE":"input binary path","FUNCTION":"discovered function name or 0x address",
            "DIR":"output directory","STORE":"evidence store or investigation directory","BUNDLE":"evidence bundle directory",
            "QUERY":"search text, API name, constant, or comma-separated behavior tags"},
    })
}

const LEGACY_USAGE: &[(&str, &str)] = &[
    ("rsleigh <binary>", "List functions"),
    ("rsleigh <binary> <func> [func2..]", "Decompile functions"),
    ("rsleigh <binary> --all", "Decompile all functions"),
    ("rsleigh <binary> --json", "List functions as JSON"),
    ("rsleigh <binary> <func> --json", "Decompile as JSON"),
    (
        "rsleigh <binary> --disasm <func>",
        "Disassemble with P-code",
    ),
    (
        "rsleigh <binary> --sigs <file.json>",
        "Load extra signatures",
    ),
    ("rsleigh <binary> --yara", "Generate YARA detection rule"),
    (
        "rsleigh <binary> --imphash",
        "Compute imphash (Mandiant) for PE",
    ),
    (
        "rsleigh <binary> --hashes",
        "Print sha256, md5, imphash, size",
    ),
    (
        "rsleigh old.bin --diff new.bin",
        "Diff decompilation (show changes)",
    ),
    (
        "rsleigh <binary> --taint",
        "Taint analysis (trace user input to sinks)",
    ),
    (
        "rsleigh <binary> --summary",
        "AI summary (one-line per function)",
    ),
    (
        "rsleigh <binary> --xrefs <func>",
        "Cross-references (callers + callees)",
    ),
    (
        "rsleigh <binary> --search <query>",
        "Find functions by string/pattern",
    ),
    (
        "rsleigh <binary> --search --api <name>",
        "Find functions calling API",
    ),
    (
        "rsleigh <binary> --search --const <hex>",
        "Find functions with constant",
    ),
    (
        "rsleigh <binary> --seh-fixpoint",
        "Apply SEH-driven SMC patches until fixpoint",
    ),
    (
        "rsleigh <binary> --vulnscan",
        "Scan for vulnerability patterns",
    ),
    (
        "rsleigh <binary> --smt-explore <func> [--smt-summaries] [--json]",
        "SMT taint-flow proof (requires --features smt)",
    ),
    (
        "rsleigh <binary> --ioc [--json]",
        "Extract IOCs (URLs, IPs, paths, registry keys)",
    ),
    (
        "rsleigh <binary> <finding mode> --findings-ndjson",
        "Emit shared finding records",
    ),
    (
        "rsleigh <binary> --xor-strings [--json]",
        "Brute single-byte XOR string recovery",
    ),
    (
        "rsleigh <binary> --sigcheck [--json]",
        "Parse Authenticode signature metadata",
    ),
    (
        "rsleigh <binary> --resources [--dump DIR] [--json]",
        "Walk PE resources; --dump extracts blobs",
    ),
    (
        "rsleigh <binary> --all --compact",
        "Token-efficient output (no decls/blanks)",
    ),
    (
        "rsleigh <binary> --all --brief",
        "Calls + strings only (minimal tokens)",
    ),
    (
        "rsleigh <binary> --all --min-complexity 10",
        "Skip trivial functions",
    ),
    (
        "rsleigh <binary> --all --jobs 8 --fn-timeout 10",
        "Threads, and seconds per function before it is skipped (0 = none)",
    ),
    ("rsleigh <binary> --callgraph", "Export call graph as JSON"),
    (
        "rsleigh <binary> --classes",
        "Recover C++ classes from RTTI",
    ),
    (
        "rsleigh <binary> --raw <arch>",
        "Load raw binary (mips32/arm32/x86-64/...)",
    ),
];

/// Usage text: legacy modes plus agent operations generated from contracts.
pub(super) fn usage() -> String {
    let mut text = String::from("rsleigh — pure Rust decompiler\n\nUsage:\n");
    for (command, help) in LEGACY_USAGE {
        text.push_str(&format!("  {command:<44} {help}\n"));
    }
    text.push_str("\nAgent operations (typed contracts; see --capabilities --json):\n");
    for op in contracts::OPERATIONS {
        text.push_str(&format!(
            "  {}\n      {} [{}]\n",
            op.usage(),
            op.summary,
            op.schema
        ));
    }
    text.push_str(
        "\nTarget-free:\n  rsleigh --help | --version [--json] | --capabilities [--json]\n\
         \x20 rsleigh --mcp                 Model Context Protocol server on stdio\n\
         Agent exits: 0 complete, 2 partial evidence, 1 failed.\n\
         Paths beginning with '-' must be written as ./NAME.\n",
    );
    text
}

fn render_text(catalog: &Value) {
    println!(
        "rsleigh {} capabilities ({})",
        catalog["tool"]["version"].as_str().unwrap_or(""),
        SCHEMA
    );
    for op in catalog["operations"].as_array().into_iter().flatten() {
        println!(
            "\n{}  [{}]\n  {}\n  {}",
            op["id"].as_str().unwrap_or(""),
            op["schema"].as_str().unwrap_or(""),
            op["summary"].as_str().unwrap_or(""),
            op["usage"].as_str().unwrap_or("")
        );
    }
    println!("\nInputs implementing agent operations: PE, ELF, Mach-O (not raw or WASM).");
    for arch in catalog["architectures"].as_array().into_iter().flatten() {
        println!(
            "  {:<8} stages={} queries={}",
            arch["id"].as_str().unwrap_or(""),
            arch["stages"],
            arch["dependency_queries"]
        );
    }
}

/// Handle invocations whose first argument is an option. Never reads a target.
pub(super) fn run_target_free(args: &[String]) -> Result<u8, AgentError> {
    let json_output = args.iter().any(|a| a == "--json");
    let only = |allowed: &[&str]| -> Result<(), AgentError> {
        match args[2..].iter().find(|a| !allowed.contains(&a.as_str())) {
            Some(extra) => Err(AgentError::new(
                if extra.starts_with("--") {
                    "unsupported_option"
                } else {
                    "unexpected_argument"
                },
                format!("unsupported {} argument: {extra}", args[1]),
            )),
            None => Ok(()),
        }
    };
    match args[1].as_str() {
        "--help" | "-h" => {
            only(&[])?;
            print!("{}", usage());
        }
        "--version" | "-V" => {
            only(&["--json"])?;
            if json_output {
                emit(&json!({"schema":"rsleigh.version/v1","status":"ok","tool":tool_json()}));
            } else {
                println!("rsleigh {}", env!("CARGO_PKG_VERSION"));
            }
        }
        "--mcp" => {
            only(&[])?;
            return super::mcp::serve();
        }
        "--capabilities" => {
            only(&["--json"])?;
            let catalog = catalog();
            if json_output {
                emit(&catalog);
            } else {
                render_text(&catalog);
            }
        }
        other => {
            return Err(AgentError::new(
                "unknown_option",
                format!("unknown option {other}; write binary paths beginning with '-' as ./NAME"),
            ))
        }
    }
    Ok(0)
}
