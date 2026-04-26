//! rsleigh CLI — decompile any binary to C-like pseudocode.
//!
//! Usage:
//!   rsleigh <binary>                    # list functions
//!   rsleigh <binary> <func>             # decompile one function
//!   rsleigh <binary> --all              # decompile all functions
//!   rsleigh <binary> --json             # list functions as JSON
//!   rsleigh <binary> <func> --json      # decompile as JSON
//!   rsleigh <binary> --disasm <func>    # disassemble (P-code)

mod wasm;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static ANNOTATE_CRYPTO: AtomicBool = AtomicBool::new(false);

fn maybe_annotate_crypto(s: String) -> String {
    if ANNOTATE_CRYPTO.load(Ordering::Relaxed) {
        rsleigh_decompile::crypto_constants::rewrite_text(&s)
    } else {
        s
    }
}

/// Demangle a Swift symbol name to a human-readable form.
/// Returns None if not a Swift symbol.
fn demangle_swift_symbol(name: &str) -> Option<String> {
    let s = name
        .strip_prefix("$s")
        .or_else(|| name.strip_prefix("$S"))?;

    // Parse module name: <length><name>
    let (module, rest) = parse_swift_id(s)?;

    // Try class + method/property
    if let Some((class_name, after_class)) = parse_swift_id(rest) {
        if after_class.starts_with('C') {
            let after_c = &after_class[1..];
            if after_c.starts_with("ACycfC") || after_c.starts_with("ACycfc") {
                return Some(format!("{}.init", class_name));
            }
            if after_c == "fd" || after_c == "fD" {
                return Some(format!("{}.deinit", class_name));
            }
            if after_c == "Ma" {
                return Some(format!("{}.__metadata", class_name));
            }
            if after_c == "MF" {
                return Some(format!("{}.__fields", class_name));
            }
            if after_c == "Mm" || after_c == "Mf" || after_c == "N" {
                return Some(format!("{}.__metadata", class_name));
            }

            if let Some((prop_name, after_prop)) = parse_swift_id(after_c) {
                if after_prop.contains("vg") {
                    return Some(format!("{}.{}.getter", class_name, prop_name));
                }
                if after_prop.contains("vs") {
                    return Some(format!("{}.{}.setter", class_name, prop_name));
                }
                if after_prop.contains("vM") {
                    return Some(format!("{}.{}.modify", class_name, prop_name));
                }
                if after_prop.contains("Wvd") {
                    return Some(format!("{}.{}", class_name, prop_name));
                }
                return Some(format!("{}.{}", class_name, prop_name));
            }
            return Some(class_name.to_string());
        }
        // Free function
        if after_class.ends_with('F') || after_class.contains("yS") {
            return Some(class_name.to_string());
        }
    }

    // stdlib ($ss prefix)
    if module == "s" {
        if let Some((entity, _)) = parse_swift_id(rest) {
            return Some(format!("Swift.{}", entity));
        }
    }

    None
}

fn parse_swift_id(s: &str) -> Option<(&str, &str)> {
    let mut len_end = 0;
    while len_end < s.len() && s.as_bytes()[len_end].is_ascii_digit() {
        len_end += 1;
    }
    if len_end == 0 {
        return None;
    }
    let len: usize = s[..len_end].parse().ok()?;
    if len_end + len > s.len() {
        return None;
    }
    Some((&s[len_end..len_end + len], &s[len_end + len..]))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("rsleigh — pure Rust decompiler");
        eprintln!("Usage:");
        eprintln!("  rsleigh <binary>                  List functions");
        eprintln!("  rsleigh <binary> <func> [func2..] Decompile functions");
        eprintln!("  rsleigh <binary> --all             Decompile all functions");
        eprintln!("  rsleigh <binary> --json             List functions as JSON");
        eprintln!("  rsleigh <binary> <func> --json     Decompile as JSON");
        eprintln!("  rsleigh <binary> --disasm <func>   Disassemble with P-code");
        eprintln!("  rsleigh <binary> --sigs <file.json> Load extra signatures");
        eprintln!("  rsleigh <binary> --yara             Generate YARA detection rule");
        eprintln!("  rsleigh <binary> --imphash          Compute imphash (Mandiant) for PE");
        eprintln!("  rsleigh <binary> --hashes           Print sha256, md5, imphash, size");
        eprintln!("  rsleigh old.bin --diff new.bin      Diff decompilation (show changes)");
        eprintln!(
            "  rsleigh <binary> --taint            Taint analysis (trace user input to sinks)"
        );
        eprintln!("  rsleigh <binary> --summary          AI summary (one-line per function)");
        eprintln!("  rsleigh <binary> --xrefs <func>     Cross-references (callers + callees)");
        eprintln!("  rsleigh <binary> --search <query>   Find functions by string/pattern");
        eprintln!("  rsleigh <binary> --search --api <name>  Find functions calling API");
        eprintln!("  rsleigh <binary> --search --const <hex> Find functions with constant");
        eprintln!("  rsleigh <binary> --seh-fixpoint      Apply SEH-driven SMC patches until fixpoint, report new functions");
        eprintln!("  rsleigh <binary> --vulnscan          Scan for vulnerability patterns");
        eprintln!(
            "  rsleigh <binary> --all --compact     Token-efficient output (no decls/blanks)"
        );
        eprintln!("  rsleigh <binary> --all --brief       Calls + strings only (minimal tokens)");
        eprintln!("  rsleigh <binary> --all --min-complexity 10  Skip trivial functions");
        eprintln!("  rsleigh <binary> --callgraph         Export call graph as JSON");
        eprintln!("  rsleigh <binary> --classes           Recover C++ classes from RTTI");
        eprintln!(
            "  rsleigh <binary> --raw <arch>       Load raw binary (mips32/arm32/x86-64/...)"
        );
        std::process::exit(1);
    }

    let binary_path = &args[1];
    let json_mode = args.iter().any(|a| a == "--json");
    let all_mode = args.iter().any(|a| a == "--all");
    let disasm_mode = args.iter().any(|a| a == "--disasm");
    let pcode_json_mode = args.iter().any(|a| a == "--pcode-json");
    let ssa_json_mode = args.iter().any(|a| a == "--ssa-json");
    let yara_mode = args.iter().any(|a| a == "--yara");
    let imphash_mode = args.iter().any(|a| a == "--imphash");
    let hashes_mode = args.iter().any(|a| a == "--hashes");
    let summary_mode = args.iter().any(|a| a == "--summary");
    let xrefs_mode = args.iter().any(|a| a == "--xrefs");
    let search_mode = args.iter().any(|a| a == "--search");
    let vulnscan_mode = args.iter().any(|a| a == "--vulnscan");
    let classes_mode = args.iter().any(|a| a == "--classes");
    let compact_mode = args.iter().any(|a| a == "--compact");
    let brief_mode = args.iter().any(|a| a == "--brief");
    let annotate_crypto_mode = args.iter().any(|a| a == "--annotate-crypto");
    ANNOTATE_CRYPTO.store(annotate_crypto_mode, Ordering::Relaxed);
    let min_complexity: usize = args
        .iter()
        .position(|a| a == "--min-complexity")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let callgraph_mode = args.iter().any(|a| a == "--callgraph");
    let seh_fixpoint_mode = args.iter().any(|a| a == "--seh-fixpoint");
    let sections_mode = args.iter().any(|a| a == "--sections");

    // VM-helper flags. All take a comma-separated list of hex addresses
    // (or a single address) and emit one line per handler.
    let vm_classify_arg = args
        .iter()
        .position(|a| a == "--vm-classify-handlers")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let tag_dispatch_arg = args
        .iter()
        .position(|a| a == "--tag-dispatch")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let summarise_arg = args
        .iter()
        .position(|a| a == "--summarise-handlers")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let vm_dispatch_arg = args
        .iter()
        .position(|a| a == "--vm-dispatch")
        .and_then(|i| args.get(i + 1))
        .cloned();

    if sections_mode {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        run_section_scan(binary_path, &data);
        return;
    }

    // --vm-classify-handlers / --tag-dispatch / --summarise-handlers:
    // VM-RE helper flags. Each takes a comma-separated list of hex
    // addresses (or single address). Emit one line per handler and
    // exit.
    if vm_classify_arg.is_some()
        || tag_dispatch_arg.is_some()
        || summarise_arg.is_some()
        || vm_dispatch_arg.is_some()
    {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        let obj = match goblin::Object::parse(&data) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Error: cannot parse binary: {}", e);
                std::process::exit(1);
            }
        };
        let parse_addrs = |s: &str| -> Vec<u64> {
            s.split(',')
                .filter_map(|t| {
                    let t = t.trim();
                    let t = t.trim_start_matches("0x").trim_start_matches("0X");
                    u64::from_str_radix(t, 16).ok()
                })
                .collect()
        };
        if let Some(arg) = vm_classify_arg.as_ref() {
            let addrs = parse_addrs(arg);
            let encs = rsleigh_decompile::vm_handler_classify::classify_all(&obj, &data, &addrs);
            for line in rsleigh_decompile::vm_handler_classify::render(&encs) {
                println!("{}", line);
            }
            return;
        }
        if let Some(arg) = tag_dispatch_arg.as_ref() {
            let addrs = parse_addrs(arg);
            for &a in &addrs {
                let cases = rsleigh_decompile::tag_dispatch::scan_function(&obj, &data, a);
                println!("=== {:#x} — {} cases ===", a, cases.len());
                for line in rsleigh_decompile::tag_dispatch::render(&cases) {
                    println!("  {}", line);
                }
            }
            return;
        }
        if let Some(arg) = summarise_arg.as_ref() {
            let addrs = parse_addrs(arg);
            let summaries = rsleigh_decompile::handler_summary::summarise_all(&obj, &data, &addrs);
            for line in rsleigh_decompile::handler_summary::render(&summaries) {
                println!("{}", line);
            }
            return;
        }
        if let Some(arg) = vm_dispatch_arg.as_ref() {
            let addrs = parse_addrs(arg);
            for &a in &addrs {
                if let Some(info) = rsleigh_decompile::vm_dispatch_extract::extract(&obj, &data, a)
                {
                    for line in rsleigh_decompile::vm_dispatch_extract::render(&info) {
                        println!("{}", line);
                    }
                } else {
                    println!("dispatcher @ {:#x}: extraction failed", a);
                }
            }
            return;
        }
    }

    if seh_fixpoint_mode {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        // Full-discovery fixpoint: at each step, re-run the CLI's complete
        // function-discovery pipeline against the mutated image.  This
        // picks up not just SEH handlers and scope-table filters but also
        // PyMethodDef registrations, RIP-relative function pointers in
        // .rdata, and the prologue / CALL-descent passes that run in
        // `discover_pe_functions`.
        let result = rsleigh_decompile::seh_static::smc_fixpoint(&data, 16, |img| {
            let Ok(obj) = goblin::Object::parse(img) else {
                return vec![];
            };
            let Some((arch, segs, mut symbols)) = parse_binary(&obj, img) else {
                return vec![];
            };
            if symbols.is_empty() {
                if let goblin::Object::PE(pe) = &obj {
                    let base = pe.image_base as u64;
                    if let Some(optional) = pe.header.optional_header {
                        let entry = base + optional.standard_fields.address_of_entry_point as u64;
                        symbols = discover_pe_functions(entry, &segs, img, arch);
                    }
                }
            }
            if let goblin::Object::PE(pe) = &obj {
                if pe.is_64 {
                    for (addr, _) in scan_pymethoddef(&segs, img) {
                        symbols.push((addr, String::new()));
                    }
                    let seh = rsleigh_decompile::seh_static::parse_pe64_seh(img);
                    for a in rsleigh_decompile::seh_static::handler_addresses(&seh) {
                        symbols.push((a, String::new()));
                    }
                    for a in rsleigh_decompile::seh_static::scope_table_addresses(img) {
                        symbols.push((a, String::new()));
                    }
                }
            }
            let mut addrs: Vec<u64> = symbols.into_iter().map(|(a, _)| a).collect();
            addrs.sort_unstable();
            addrs.dedup();
            addrs
        });
        println!(
            "iterations: {}  converged: {}",
            result.iterations, result.converged
        );
        println!("patches applied: {}", result.patches.len());
        for p in &result.patches {
            let preview: String = p
                .bytes
                .iter()
                .take(16)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let more = if p.bytes.len() > 16 { " .." } else { "" };
            println!(
                "  patch @ {:#x}  len={:4}  from handler {:#x}  [{}{}]",
                p.target_va,
                p.bytes.len(),
                p.handler_va,
                preview,
                more
            );
        }
        println!(
            "newly discovered functions: {}",
            result.newly_discovered_fns.len()
        );
        for va in &result.newly_discovered_fns {
            println!("  {:#x}", va);
        }
        return;
    }

    if yara_mode {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        generate_yara_rule(binary_path, &data);
        return;
    }

    if imphash_mode {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        match compute_imphash(&data) {
            Some(h) => println!("{}", h),
            None => {
                eprintln!("imphash: not a PE binary with imports");
                std::process::exit(1);
            }
        }
        return;
    }

    if hashes_mode {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        let sha256 = compute_sha256(&data);
        let md5 = compute_md5(&data);
        let imphash = compute_imphash(&data);
        println!("file:    {}", binary_path);
        println!("size:    {}", data.len());
        println!("md5:     {}", md5);
        println!("sha256:  {}", sha256);
        if let Some(h) = imphash {
            println!("imphash: {}", h);
        }
        return;
    }

    // C++ class recovery
    if classes_mode {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        // Try MSVC RTTI first, then GCC RTTI
        let mut classes = rsleigh_decompile::cpp_class::recover_msvc_classes(&data);
        if classes.is_empty() {
            classes = rsleigh_decompile::cpp_class::recover_gcc_classes(&data);
        }
        if classes.is_empty() {
            eprintln!("No C++ RTTI classes found (binary may not have RTTI, or is stripped)");
        } else {
            eprintln!("{} C++ classes recovered from RTTI", classes.len());
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&classes).unwrap());
            } else {
                print!("{}", rsleigh_decompile::cpp_class::format_classes(&classes));
            }
        }
        return;
    }

    // Summary/Xrefs/Search/Vulnscan/Callgraph modes
    if summary_mode || xrefs_mode || search_mode || vulnscan_mode || callgraph_mode {
        let data = match std::fs::read(binary_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        let bp = binary_path.clone();
        let args_clone = args.clone();
        let t = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                if summary_mode {
                    run_summary(&bp, &data);
                } else if xrefs_mode {
                    let target = args_clone
                        .iter()
                        .position(|a| a == "--xrefs")
                        .and_then(|i| args_clone.get(i + 1))
                        .cloned()
                        .unwrap_or_default();
                    run_xrefs(&bp, &data, &target);
                } else if vulnscan_mode {
                    run_vulnscan(&bp, &data);
                } else if callgraph_mode {
                    run_callgraph(&bp, &data);
                } else {
                    // Search mode
                    let search_idx = args_clone.iter().position(|a| a == "--search").unwrap();
                    let api_mode = args_clone.iter().any(|a| a == "--api");
                    let const_mode = args_clone.iter().any(|a| a == "--const");
                    let tag_mode = args_clone.iter().any(|a| a == "--tag");
                    let decompile_results = args_clone.iter().any(|a| a == "--decompile");
                    let json_output = args_clone.iter().any(|a| a == "--json");
                    let query = args_clone
                        .iter()
                        .skip(search_idx + 1)
                        .find(|a| !a.starts_with("--"))
                        .cloned()
                        .unwrap_or_default();
                    if query.is_empty() {
                        eprintln!("Usage: rsleigh <binary> --search <query>");
                        eprintln!("       rsleigh <binary> --search --api <func_name>");
                        eprintln!("       rsleigh <binary> --search --const <hex_value>");
                        eprintln!("       rsleigh <binary> --search --tag network,crypto");
                        eprintln!("       rsleigh <binary> --search <query> --json");
                        eprintln!("       rsleigh <binary> --search <query> --decompile");
                        return;
                    }
                    run_search(
                        &bp,
                        &data,
                        &query,
                        api_mode,
                        const_mode,
                        tag_mode,
                        decompile_results,
                        json_output,
                    );
                }
            })
            .unwrap();
        if let Err(e) = t.join() {
            eprintln!("Panic: {:?}", e);
        }
        return;
    }

    // Diff mode: compare two binaries
    if let Some(diff_idx) = args.iter().position(|a| a == "--diff") {
        let new_path = args.get(diff_idx + 1).cloned().unwrap_or_else(|| {
            eprintln!("Usage: rsleigh old.bin --diff new.bin [func_name]");
            std::process::exit(1);
        });
        // Optional: specific function to diff
        let func_filter: Vec<String> = args
            .iter()
            .enumerate()
            .filter(|(i, a)| {
                *i >= 2
                    && !a.starts_with("--")
                    && a.as_str() != new_path
                    && a.as_str() != binary_path
            })
            .map(|(_, a)| a.clone())
            .collect();
        let old_path = binary_path.clone();
        let t = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || diff_binaries(&old_path, &new_path, &func_filter))
            .unwrap();
        if let Err(e) = t.join() {
            eprintln!("Panic: {:?}", e);
        }
        return;
    }

    // Load external signature database if --sigs provided
    if let Some(pos) = args.iter().position(|a| a == "--sigs") {
        if let Some(sigs_path) = args.get(pos + 1) {
            match rsleigh_decompile::signatures::load_json_file(std::path::Path::new(sigs_path)) {
                Ok(n) => eprintln!("Loaded {} signatures from {}", n, sigs_path),
                Err(e) => eprintln!("Warning: {}", e),
            }
        }
    }

    let t = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn({
            let binary_path = binary_path.clone();
            let args = args.clone();
            move || run(&binary_path, &args, json_mode, all_mode, disasm_mode)
        })
        .unwrap();

    match t.join() {
        Ok(()) => {}
        Err(_) => {
            eprintln!("Error: stack overflow during decompilation");
            std::process::exit(1);
        }
    }
}

/// Hidden GCC runtime symbols to exclude from listing.
const HIDDEN: &[&str] = &[
    "deregister_tm_clones",
    "register_tm_clones",
    "frame_dummy",
    "__do_global_dtors_aux",
    "__libc_csu_init",
    "__libc_csu_fini",
    "_dl_relocate_static_pie",
    "__do_global_ctors_aux",
];

/// Compact pseudocode for token efficiency: strip declarations, blank lines, reduce indent.
fn compact_output(output: &str) -> String {
    output
        .lines()
        .filter(|l| {
            let t = l.trim();
            // Skip empty lines
            if t.is_empty() {
                return false;
            }
            // Skip variable declarations (type varN;)
            if t.ends_with(';')
                && !t.contains('=')
                && !t.contains('(')
                && (t.starts_with("int ")
                    || t.starts_with("long ")
                    || t.starts_with("uint")
                    || t.starts_with("char ")
                    || t.starts_with("float ")
                    || t.starts_with("double ")
                    || t.starts_with("bool "))
            {
                return false;
            }
            true
        })
        .map(|l| {
            // Reduce indent: 4 spaces → 2 spaces
            let indent = l.len() - l.trim_start().len();
            let new_indent = indent / 2;
            format!("{}{}", " ".repeat(new_indent), l.trim())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Brief mode: show only calls, comparisons, strings, returns — skip assignments.
fn brief_output(output: &str) -> String {
    let mut result = Vec::new();
    for line in output.lines() {
        let t = line.trim();
        // Keep function signature
        if t.contains("func_") && t.contains('(') && t.ends_with('{') {
            result.push(line.to_string());
            continue;
        }
        // Keep closing brace
        if t == "}" {
            result.push(line.to_string());
            continue;
        }
        // Keep calls (lines with function_name() pattern)
        if t.contains('(')
            && t.contains(')')
            && !t.starts_with("//")
            && (t.ends_with(';') || t.ends_with('{'))
        {
            // Skip pure assignments: var = expr; (no function call)
            if t.contains(" = ") {
                let rhs = &t[t.find(" = ").unwrap() + 3..];
                if !rhs.contains('(') {
                    continue;
                } // pure assignment
            }
            result.push(line.to_string());
            continue;
        }
        // Keep control flow
        if t.starts_with("if (")
            || t.starts_with("} else")
            || t.starts_with("while (")
            || t.starts_with("for (")
            || t.starts_with("switch (")
            || t.starts_with("return ")
            || t.starts_with("break")
            || t.starts_with("case ")
        {
            result.push(line.to_string());
            continue;
        }
        // Keep string references
        if t.contains('"') {
            result.push(line.to_string());
            continue;
        }
        // Keep comments (annotations, crypto, taint)
        if t.starts_with("//")
            && (t.contains("TAINT")
                || t.contains("XOR")
                || t.contains("stack string")
                || t.contains("AES")
                || t.contains("SHA"))
        {
            result.push(line.to_string());
        }
    }
    result.join("\n")
}

fn run(binary_path: &str, args: &[String], json_mode: bool, all_mode: bool, disasm_mode: bool) {
    let data = match std::fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: cannot read {}: {}", binary_path, e);
            std::process::exit(1);
        }
    };

    // WebAssembly detection: magic bytes \0asm
    if data.len() >= 4 && &data[0..4] == b"\0asm" {
        run_wasm(&data, args, all_mode);
        return;
    }

    // Raw binary mode: --raw <arch> [--base <addr>]
    let raw_arch_idx = args.iter().position(|a| a == "--raw");
    if let Some(idx) = raw_arch_idx {
        let arch_str = args.get(idx + 1).map(|s| s.as_str()).unwrap_or("mips32");
        let base_idx = args.iter().position(|a| a == "--base");
        let base = base_idx
            .and_then(|i| args.get(i + 1))
            .and_then(|s| {
                if let Some(hex) = s.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    s.parse::<u64>().ok()
                }
            })
            .unwrap_or(0);
        let arch = match arch_str {
            "x86-64" | "x86_64" | "x64" => rsleigh_api::Architecture::X86_64,
            "x86-32" | "x86" | "i386" => rsleigh_api::Architecture::X86_32,
            "arm32" | "arm" | "ARM32" => rsleigh_api::Architecture::ARM32,
            "aarch64" | "arm64" | "AArch64" => rsleigh_api::Architecture::AArch64,
            "mips32" | "mips" | "MIPS32" => rsleigh_api::Architecture::MIPS32,
            "riscv64" | "riscv" | "RISCV64" => rsleigh_api::Architecture::RiscV64,
            _ => {
                eprintln!(
                    "Unknown arch: {}. Use: x86-64, x86-32, arm32, aarch64, mips32, riscv64",
                    arch_str
                );
                std::process::exit(1);
            }
        };
        run_raw(&data, arch, base, args, all_mode);
        return;
    }

    let path = Path::new(binary_path);
    let obj = match goblin::Object::parse(&data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: cannot parse binary: {}", e);
            std::process::exit(1);
        }
    };

    // VM-packer family fingerprint. Currently detects PyVMProtect via PE
    // section-table layout. Emits a one-shot advisory banner so the
    // analyst knows what scheme they're up against before they sink hours
    // into manual reversing.
    if let Some(fp) = rsleigh_decompile::vm_fingerprint::detect(&obj) {
        eprint!("{}", rsleigh_decompile::vm_fingerprint::banner(&fp));
    }

    // JMP <reg> tail-call trampolines: 1- or 2-byte gadgets every IAT
    // call routes through. PyVMProtect uses one at `0x180040770` etc.
    let trampolines = rsleigh_decompile::jmp_rax_trampoline::scan(&obj, &data);
    if !trampolines.is_empty() {
        eprintln!(
            "// [trampoline] found {} `JMP <reg>` gadget(s):",
            trampolines.len()
        );
        for t in trampolines.iter().take(8) {
            eprintln!("//   - {:#x}: JMP {}", t.addr, t.reg);
        }
        if trampolines.len() > 8 {
            eprintln!("//   ... and {} more", trampolines.len() - 8);
        }
    }

    // XOR-encoded vtable dispatch — VM packers route every handler
    // through a single CALL [trampoline] preceded by a key+vtable XOR
    // chain. Detect those dispatchers given the trampoline gadgets we
    // already found.
    if !trampolines.is_empty() {
        let tramp_vas: Vec<u64> = trampolines.iter().map(|t| t.addr).collect();
        let iat_slots =
            rsleigh_decompile::xor_vtable::iat_slots_for_trampolines(&obj, &data, &tramp_vas);
        if !iat_slots.is_empty() {
            let dispatchers = rsleigh_decompile::xor_vtable::scan(&obj, &data, &iat_slots);
            if !dispatchers.is_empty() {
                eprintln!(
                    "// [xor-vtable] found {} XOR-encoded dispatcher site(s):",
                    dispatchers.len()
                );
                for d in dispatchers.iter().take(8) {
                    eprintln!(
                        "//   - call@{:#x} → trampoline_slot={:#x}, key/table slots={:?}",
                        d.call_site_va,
                        d.trampoline_slot,
                        d.data_slots
                            .iter()
                            .take(4)
                            .map(|s| format!("{:#x}", s))
                            .collect::<Vec<_>>(),
                    );
                }
                if dispatchers.len() > 8 {
                    eprintln!("//   ... and {} more", dispatchers.len() - 8);
                }
                eprintln!(
                    "// hint: emulate init chain to extract runtime values \
                     of the listed slots; XOR them to recover the cleartext \
                     vtable base + handler key."
                );
            }
        }
    }

    // Hash-resolved API resolver classifier — combines PEB walk with
    // hash-multiply detection (ROR13 / DJB2 / FNV-1) to label the
    // resolver function with its hash variant.
    let resolvers = rsleigh_decompile::api_resolver::scan(&obj, &data);
    if !resolvers.is_empty() {
        eprintln!(
            "// [api-resolver] found {} hash-resolved API resolver(s):",
            resolvers.len()
        );
        for line in rsleigh_decompile::api_resolver::render(&resolvers)
            .iter()
            .take(8)
        {
            eprintln!("//   - {}", line);
        }
        if resolvers.len() > 8 {
            eprintln!("//   ... and {} more", resolvers.len() - 8);
        }
    }

    // PEB-walk anti-debug + API-resolver pattern.
    let peb_hits = rsleigh_decompile::peb_walk_detect::scan(&obj, &data);
    if !peb_hits.is_empty() {
        eprintln!("// [peb-walk] found {} PEB-access site(s):", peb_hits.len());
        for line in rsleigh_decompile::peb_walk_detect::render(&peb_hits)
            .iter()
            .take(8)
        {
            eprintln!("//   - {}", line);
        }
        if peb_hits.len() > 8 {
            eprintln!("//   ... and {} more", peb_hits.len() - 8);
        }
    }

    // Anti-debug timing probes: RDTSC/RDPMC/RDTSCP pairs within ~256B.
    if let goblin::Object::PE(pe) = &obj {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        let mut all_probes = Vec::new();
        for sec in &pe.sections {
            if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            let raddr = sec.pointer_to_raw_data as usize;
            let rsize = sec.size_of_raw_data as usize;
            if raddr + rsize > data.len() {
                continue;
            }
            let base_va = pe.image_base as u64 + sec.virtual_address as u64;
            let (_reads, probes) = rsleigh_decompile::antidebug_timing::scan_region(
                &data[raddr..raddr + rsize],
                base_va,
            );
            all_probes.extend(probes);
        }
        if !all_probes.is_empty() {
            eprintln!(
                "// [anti-debug] found {} timing-counter probe(s):",
                all_probes.len()
            );
            for p in all_probes.iter().take(8) {
                eprintln!(
                    "//   - {}",
                    rsleigh_decompile::antidebug_timing::render_probe(p)
                );
            }
            if all_probes.len() > 8 {
                eprintln!("//   ... and {} more", all_probes.len() - 8);
            }
        }
    }

    // SHA-256 implementation detection via H0/K constant density.
    let sha_hits = rsleigh_decompile::sha256_func_detect::scan(&obj, &data);
    if !sha_hits.is_empty() {
        eprintln!("// [sha256] found {} SHA-256 region(s):", sha_hits.len());
        for line in rsleigh_decompile::sha256_func_detect::render(&sha_hits)
            .iter()
            .take(8)
        {
            eprintln!("//   - {}", line);
        }
        if sha_hits.len() > 8 {
            eprintln!("//   ... and {} more", sha_hits.len() - 8);
        }
    }

    let (arch, segs, mut symbols) = match parse_binary(&obj, &data) {
        Some(r) => r,
        None => {
            eprintln!("Error: unsupported binary format");
            std::process::exit(1);
        }
    };

    // Apply FID databases (if --fid passed) to rename anonymous funcs.
    apply_fid_to_symbols(&data, arch, &segs, &mut symbols, args);

    // Go `.gopclntab` name recovery. Stripped Go binaries carry full
    // runtime symbol info in this section; merge into symbols list so
    // anonymous func_* entries get their real names (main.main, etc.).
    {
        let go_syms = rsleigh_decompile::go_pclntab::parse(&data);
        if !go_syms.is_empty() {
            eprintln!("[go] .gopclntab: {} symbols", go_syms.len());
            let existing: std::collections::HashSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            let pclntab_set: std::collections::HashSet<u64> = go_syms.keys().copied().collect();
            for (pc, name) in &go_syms {
                if !existing.contains(pc) {
                    symbols.push((*pc, name.clone()));
                }
            }
            // Drop anonymous FUN_* / func_* entries that sit inside a
            // Go function's stack-check preamble. Go funcs begin with
            //   4 bytes: CMP RSP, [R14+0x10]
            //   6 bytes: JBE rel32 morestack
            // so real body starts at entry+10. The prior function-
            // discovery pass treats the body as a separate function via
            // CALL-target scan. Remove those spurious entries.
            symbols.retain(|(a, n)| {
                let is_anon =
                    n.starts_with("FUN_") || n.starts_with("func_") || n.starts_with("sub_");
                if !is_anon {
                    return true;
                }
                // Check any pclntab entry E where E + 1..=16 == a.
                let base = a.saturating_sub(16);
                !(base..*a).any(|candidate| pclntab_set.contains(&candidate))
            });
        }
    }

    // For stripped PE binaries: discover functions from entry point + CALL targets
    if symbols.is_empty() {
        if let goblin::Object::PE(pe) = &obj {
            let base = pe.image_base as u64;
            let entry = base
                + pe.header
                    .optional_header
                    .unwrap()
                    .standard_fields
                    .address_of_entry_point as u64;
            symbols = discover_pe_functions(entry, &segs, &data, arch);
        }
    }

    // Always run PyMethodDef scan for PE64 — even when the export table is
    // non-empty, Python C-extensions register most of their methods through
    // PyMethodDef arrays rather than direct exports.
    if let goblin::Object::PE(pe) = &obj {
        if pe.is_64 {
            let mut seen: std::collections::HashSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in scan_pymethoddef(&segs, &data) {
                if seen.insert(addr) {
                    symbols.push((addr, name));
                }
            }
            // PE64 SEH handlers live in .text but are never reached by CALL
            // descent, vtable scans, or prologue heuristics — they are only
            // visible to the OS exception dispatcher. Enumerate them from
            // UNWIND_INFO and register as functions.
            let seh = rsleigh_decompile::seh_static::parse_pe64_seh(&data);
            for addr in rsleigh_decompile::seh_static::handler_addresses(&seh) {
                if seen.insert(addr) {
                    symbols.push((addr, format!("seh_handler_{:x}", addr)));
                }
            }
            // Filter functions and __except resumption blocks from
            // SCOPE_TABLE — these are reached only by the exception
            // dispatcher, never by CALL descent.
            for addr in rsleigh_decompile::seh_static::scope_table_addresses(&data) {
                if seen.insert(addr) {
                    symbols.push((addr, format!("seh_scope_{:x}", addr)));
                }
            }
        }
    }

    // For stripped ELF binaries: discover functions via entry point, CALL scanning, prologues
    // Also trigger for ELF with only import symbols (dynsym but no symtab)
    let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
        elf.syms.len() == 0 || symbols.iter().all(|(_, n)| n.starts_with("FUN_"))
    } else {
        false
    };
    if is_elf_stripped || (symbols.is_empty() && matches!(&obj, goblin::Object::Elf(_))) {
        if let goblin::Object::Elf(elf) = &obj {
            let discovered = discover_elf_functions(elf, &segs, &data, arch);
            // Merge: keep existing named symbols, add discovered ones
            let existing: std::collections::BTreeSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in discovered {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    // Scratch-buffer leak detector — alloc + write + return-Py_None
    // pattern (PyVMProtect v5 anti-emu trick).
    if let goblin::Object::PE(pe) = &obj {
        if pe.is_64 {
            let iat = rsleigh_decompile::handler_summary::build_iat_map(&obj, &data);
            if !iat.is_empty() {
                // Sweep CALL rel32 targets in executable sections — symbol
                // discovery on PyVMProtect-style binaries is sparse, so the
                // raw call-graph is the better candidate set.
                let mut call_targets: std::collections::HashSet<u64> =
                    symbols.iter().map(|(a, _)| *a).collect();
                const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
                for sec in &pe.sections {
                    if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                        continue;
                    }
                    let raddr = sec.pointer_to_raw_data as usize;
                    let rsize = sec.size_of_raw_data as usize;
                    if raddr + rsize > data.len() {
                        continue;
                    }
                    let base_va = pe.image_base as u64 + sec.virtual_address as u64;
                    let body = &data[raddr..raddr + rsize];
                    let mut k = 0;
                    while k + 5 <= body.len() {
                        if body[k] == 0xe8 {
                            let d32 = i32::from_le_bytes([
                                body[k + 1],
                                body[k + 2],
                                body[k + 3],
                                body[k + 4],
                            ]);
                            let next_rip = base_va.wrapping_add((k + 5) as u64);
                            let target = next_rip.wrapping_add(d32 as i64 as u64);
                            call_targets.insert(target);
                        }
                        k += 1;
                    }
                    // Prologue sweep — PyVMProtect indirect-only callees
                    // (e.g. const-pool resolver) are missed by call-graph
                    // alone. Catch common 64-bit prologues at 16B align.
                    let mut k = 0;
                    while k + 8 <= body.len() {
                        let is_prologue = (body[k] == 0x48
                            && body[k + 1] == 0x89
                            && body[k + 2] == 0x5c
                            && body[k + 3] == 0x24)
                            || (body[k] == 0x48 && body[k + 1] == 0x83 && body[k + 2] == 0xec)
                            || (body[k] == 0x48 && body[k + 1] == 0x81 && body[k + 2] == 0xec)
                            || (body[k] == 0x40 && body[k + 1] == 0x53)
                            || (body[k] == 0x40 && body[k + 1] == 0x55)
                            || (body[k] == 0x40 && body[k + 1] == 0x57);
                        if is_prologue {
                            call_targets.insert(base_va + k as u64);
                        }
                        k += 16;
                    }
                }
                let func_vas: Vec<u64> = call_targets.into_iter().collect();
                let leaks = rsleigh_decompile::scratch_leak::scan_functions(
                    &obj, &data, &iat, &func_vas, 0x800,
                );
                if !leaks.is_empty() {
                    eprintln!(
                        "// [scratch-leak] found {} alloc+return-None pattern(s):",
                        leaks.len()
                    );
                    for line in rsleigh_decompile::scratch_leak::render(&leaks)
                        .iter()
                        .take(16)
                    {
                        eprintln!("//   - {}", line);
                    }
                    if leaks.len() > 16 {
                        eprintln!("//   ... and {} more", leaks.len() - 16);
                    }
                }
            }
        }
    }

    // Determine which functions to process
    // Skip --flag arguments and their values (e.g., --sigs path.json, --fid file.fidb)
    let value_flag_positions: std::collections::HashSet<usize> = args
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            if a == "--sigs" || a == "--fid" {
                Some(i + 1)
            } else {
                None
            }
        })
        .collect();
    let func_args: Vec<&str> = args[2..]
        .iter()
        .enumerate()
        .filter(|(i, a)| {
            if a.starts_with("--") {
                return false;
            }
            // Index in the full args array is i + 2.
            if value_flag_positions.contains(&(*i + 2)) {
                return false;
            }
            true
        })
        .map(|(_, a)| a.as_str())
        .collect();

    if func_args.is_empty() && !all_mode && !disasm_mode {
        // List functions. Hide CRT-internal / runtime glue whose names start
        // with a single `_` (`_init`, `_fini`, `_start`, `_dl_*`, etc.) but
        // KEEP demangled-candidate symbols starting with `_Z` / `__Z` (C++
        // Itanium mangling) / `_GLOBAL_` (GCC static init) since those are
        // the real program surface area.
        let funcs: Vec<(&str, u64)> = symbols
            .iter()
            .filter(|(_, n)| {
                if n.is_empty() {
                    return false;
                }
                if n.starts_with("dyld") {
                    return false;
                }
                if HIDDEN.contains(&n.as_str()) {
                    return false;
                }
                // Allow C++ / Itanium / Swift / static-init names.
                if n.starts_with("_Z")
                    || n.starts_with("__Z")
                    || n.starts_with("_GLOBAL_")
                    || n.starts_with("$s")
                    || n.starts_with("_$s")
                {
                    return true;
                }
                // Hide well-known CRT glue by prefix. Python-visible method
                // names (e.g. `_ttokwy5gsm`, `__name__`) start with `_` too,
                // so a blanket underscore filter is wrong.
                if n.starts_with("_dl_")
                    || n.starts_with("__do_global")
                    || n.starts_with("__libc_")
                    || n.starts_with("__pthread_")
                    || n.starts_with("_GLOBAL__sub_I_")
                    || matches!(
                        n.as_str(),
                        "_init" | "_fini" | "_start" | "_DYNAMIC" | "_GLOBAL_OFFSET_TABLE_"
                    )
                {
                    return false;
                }
                true
            })
            .map(|(a, n)| (n.as_str(), *a))
            .collect();

        if json_mode {
            // Rich JSON: decompile each function and extract metadata
            let path = std::path::Path::new(binary_path);
            let mut dec = rsleigh_api::Decoder::new(arch);
            let entries: Vec<serde_json::Value> = funcs
                .iter()
                .map(|(name, addr)| {
                    let insts = decode_func(*addr, &symbols, &segs, &data, &mut dec);
                    if insts.is_empty() {
                        return serde_json::json!({
                            "name": name, "address": format!("0x{:x}", addr),
                            "size": 0, "calls": [], "strings": [], "return_type": "void"
                        });
                    }
                    let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rsleigh_decompile::decompile_with_binary(
                            arch,
                            &insts,
                            Some(&data),
                            Some(path),
                        )
                    }))
                    .map(maybe_annotate_crypto)
                    .unwrap_or_default();

                    // Extract metadata from decompiled output
                    let mut calls = Vec::new();
                    let mut strings = Vec::new();
                    let mut line_count = 0;
                    for line in output.lines() {
                        let t = line.trim();
                        if t.is_empty() || t.starts_with("//") {
                            continue;
                        }
                        line_count += 1;
                        // Extract calls
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
                                if s.len() >= 2
                                    && s.len() <= 80
                                    && !strings.contains(&s.to_string())
                                {
                                    strings.push(s.to_string());
                                }
                            }
                        }
                    }
                    // Extract return type from first line
                    let return_type = output
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().next())
                        .unwrap_or("void");
                    // Extract param count from signature
                    let params = output
                        .lines()
                        .next()
                        .map(|l| l.matches("param_").count())
                        .unwrap_or(0);
                    let size = insts
                        .last()
                        .map(|(a, i)| (*a + i.len - addr) as u64)
                        .unwrap_or(0);

                    serde_json::json!({
                        "name": name,
                        "address": format!("0x{:x}", addr),
                        "size": size,
                        "params": params,
                        "return_type": return_type,
                        "calls": calls,
                        "strings": strings,
                        "complexity": line_count,
                        "pseudocode": output,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "binary": binary_path,
                    "arch": format!("{:?}", arch),
                    "function_count": entries.len(),
                    "functions": entries,
                }))
                .unwrap()
            );
        } else {
            eprintln!("Architecture: {:?}", arch);
            eprintln!("{} functions:", funcs.len());
            for (name, addr) in &funcs {
                println!("  0x{:08x}  {}", addr, name);
            }
        }
        return;
    }

    // Determine target functions
    let targets: Vec<String> = if all_mode {
        symbols
            .iter()
            .filter(|(_, n)| {
                !n.starts_with('_')
                    && !n.starts_with("dyld")
                    && !HIDDEN.contains(&n.as_str())
                    && !n.is_empty()
            })
            .map(|(_, n)| n.clone())
            .collect()
    } else {
        func_args.iter().map(|s| s.to_string()).collect()
    };

    let mut dec = rsleigh_api::Decoder::new(arch);

    if disasm_mode {
        // Disassembly mode
        for name in &targets {
            let func_addr =
                if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    symbols.iter().find(|(_, n)| n == name).map(|(a, _)| *a)
                };
            if let Some(func_addr) = func_addr {
                let insts = decode_func(func_addr, &symbols, &segs, &data, &mut dec);
                if json_mode {
                    let entries: Vec<serde_json::Value> = insts
                        .iter()
                        .map(|(a, inst)| {
                            serde_json::json!({
                                "address": format!("0x{:x}", a),
                                "disassembly": inst.disassembly,
                                "length": inst.len,
                                "pcode_ops": inst.ops.len(),
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "function": name, "instructions": entries
                        }))
                        .unwrap()
                    );
                } else {
                    println!("=== {} (0x{:x}) ===", name, func_addr);
                    for (a, inst) in &insts {
                        println!("  0x{:08x}  {}", a, inst.disassembly);
                    }
                }
            } else {
                eprintln!("Function '{}' not found", name);
            }
        }
        return;
    }

    // --pcode-json and --ssa-json: dump intermediate state for one or
    // more functions. Useful for bench debugging — see exactly what
    // P-code the lifter produced and what SSA fold did with it.
    let pcode_json = args.iter().any(|a| a == "--pcode-json");
    let ssa_json = args.iter().any(|a| a == "--ssa-json");
    if pcode_json || ssa_json {
        for name in &targets {
            let func_addr =
                if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    symbols.iter().find(|(_, n)| n == name).map(|(a, _)| *a)
                };
            let Some(func_addr) = func_addr else {
                eprintln!("Function '{}' not found", name);
                continue;
            };
            let insts = decode_func(func_addr, &symbols, &segs, &data, &mut dec);
            if insts.is_empty() {
                eprintln!("// {} — no instructions", name);
                continue;
            }
            let func_name = symbols
                .iter()
                .find(|(a, _)| *a == func_addr)
                .map(|(_, n)| n.clone())
                .unwrap_or_else(|| format!("func_{:x}", func_addr));
            if pcode_json {
                let entries: Vec<serde_json::Value> = insts
                    .iter()
                    .map(|(a, inst)| {
                        serde_json::json!({
                            "address":     format!("0x{:x}", a),
                            "disassembly": inst.disassembly,
                            "length":      inst.len,
                            "ops":         inst.ops.iter()
                                .map(|op| serde_json::json!({ "op": format!("{:?}", op) }))
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "function":     func_name,
                        "address":      format!("0x{:x}", func_addr),
                        "instructions": entries,
                    }))
                    .unwrap()
                );
            }
            if ssa_json {
                let cfg = rsleigh_decompile::cfg::build_cfg(&insts);
                let cc = match arch {
                    rsleigh_api::Architecture::X86_64
                        if rsleigh_decompile::go_pclntab::parse(&data)
                            .keys()
                            .next()
                            .is_some() =>
                    {
                        rsleigh_decompile::fold::CallingConv::GoAmd64
                    }
                    rsleigh_api::Architecture::X86_32 | rsleigh_api::Architecture::MIPS32 => {
                        rsleigh_decompile::fold::CallingConv::Cdecl32
                    }
                    rsleigh_api::Architecture::ARM32 => rsleigh_decompile::fold::CallingConv::Arm32,
                    rsleigh_api::Architecture::AArch64 => {
                        rsleigh_decompile::fold::CallingConv::AArch64
                    }
                    _ => rsleigh_decompile::fold::CallingConv::SysV,
                };
                let mut ssa = rsleigh_decompile::ssa::build_ssa_with_cc(&cfg, cc);
                rsleigh_decompile::fold::fold_with_cc(&mut ssa, cc);
                let blocks: Vec<serde_json::Value> = ssa
                    .blocks
                    .iter()
                    .enumerate()
                    .map(|(bi, blk)| {
                        let stmts: Vec<serde_json::Value> = blk
                            .stmts
                            .iter()
                            .map(|s| serde_json::json!({ "stmt": format!("{:?}", s) }))
                            .collect();
                        serde_json::json!({
                            "id":         bi,
                            "addr":       format!("0x{:x}", blk.addr),
                            "stmts":      stmts,
                            "terminator": format!("{:?}", blk.terminator),
                        })
                    })
                    .collect();
                let vars: Vec<serde_json::Value> = ssa
                    .vars
                    .iter()
                    .enumerate()
                    .map(|(vi, v)| {
                        serde_json::json!({
                            "id":           vi,
                            "varnode":      format!("{:?}", v.varnode),
                            "expr":         format!("{:?}", v.expr),
                            "size":         v.size,
                            "param_name":   v.param_name,
                            "inferred":     format!("{:?}", v.inferred_type),
                            "call_return":  v.call_return,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "function": func_name,
                        "address":  format!("0x{:x}", func_addr),
                        "blocks":   blocks,
                        "vars":     vars,
                    }))
                    .unwrap()
                );
            }
        }
        return;
    }

    // Decompile mode — two-pass for interprocedural type propagation
    // Pass 1: quick decompile all targets to learn parameter/return types + struct params
    if all_mode && targets.len() > 1 {
        let mut learned: Vec<rsleigh_decompile::LearnedFuncType> = Vec::new();
        let mut callsite_returns: Vec<(u64, &'static str)> = Vec::new();
        let mut learned_structs: Vec<rsleigh_decompile::LearnedStructParam> = Vec::new();

        for name in &targets {
            let func_addr =
                if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    symbols.iter().find(|(_, n)| n == name).map(|(a, _)| *a)
                };
            if let Some(func_addr) = func_addr {
                let insts = decode_func(func_addr, &symbols, &segs, &data, &mut dec);
                if !insts.is_empty() {
                    // Extract learned types from this function
                    if let Some(lt) =
                        rsleigh_decompile::extract_learned_types(arch, &insts, Some(&data))
                    {
                        learned.push(lt);
                    }
                    // Infer callee return types from how this function uses call results
                    let returns =
                        rsleigh_decompile::infer_returns_from_callsites(arch, &insts, Some(&data));
                    callsite_returns.extend(returns);

                    // Extract struct param identifications from decompiled output
                    let output = rsleigh_decompile::decompile_with_binary(
                        arch,
                        &insts,
                        Some(&data),
                        Some(path),
                    );
                    let structs = rsleigh_decompile::extract_learned_structs(func_addr, &output);
                    learned_structs.extend(structs);
                }
            }
        }

        // Merge call-site inferred returns into learned types
        callsite_returns.sort_by_key(|(a, _)| *a);
        callsite_returns.dedup_by_key(|(a, _)| *a);
        for (addr, ret_type) in &callsite_returns {
            // Only add if we don't already have a return type for this function
            if !learned
                .iter()
                .any(|lt| lt.addr == *addr && lt.return_type.is_some())
            {
                learned.push(rsleigh_decompile::LearnedFuncType {
                    addr: *addr,
                    param_types: Vec::new(),
                    return_type: Some(ret_type),
                });
            }
        }

        if !learned.is_empty() {
            rsleigh_decompile::signatures::register_learned_types(&learned);
        }
        if !learned_structs.is_empty() {
            rsleigh_decompile::signatures::register_learned_structs(&learned_structs);
        }
    }

    // Pass 2: full decompilation with learned types available
    let mut results: Vec<serde_json::Value> = Vec::new();

    for name in &targets {
        // Support hex addresses like 0x1400013f0
        let func_addr =
            if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                symbols.iter().find(|(_, n)| n == name).map(|(a, _)| *a)
            };
        if let Some(func_addr) = func_addr {
            let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decompile_func(func_addr, &symbols, &segs, &data, &mut dec, arch, path)
            })) {
                Ok(o) => o,
                Err(_) => "// decompilation failed (stack overflow)\n".to_string(),
            };

            if json_mode {
                // Extract rich metadata from pseudocode
                let mut calls = Vec::new();
                let mut strings = Vec::new();
                let mut line_count = 0;
                for line in output.lines() {
                    let t = line.trim();
                    if t.is_empty() || t.starts_with("//") {
                        continue;
                    }
                    line_count += 1;
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
                                && callee.len() < 50
                                && !calls.contains(&callee.to_string())
                            {
                                calls.push(callee.to_string());
                            }
                        }
                    }
                    if let Some(q1) = t.find('"') {
                        if let Some(q2) = t[q1 + 1..].find('"') {
                            let s = &t[q1 + 1..q1 + 1 + q2];
                            if s.len() >= 2 && s.len() <= 80 && !strings.contains(&s.to_string()) {
                                strings.push(s.to_string());
                            }
                        }
                    }
                }
                let return_type = output
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().next())
                    .unwrap_or("void");
                let params = output
                    .lines()
                    .next()
                    .map(|l| l.matches("param_").count())
                    .unwrap_or(0);
                results.push(serde_json::json!({
                    "name": name,
                    "address": format!("0x{:x}", func_addr),
                    "params": params,
                    "return_type": return_type,
                    "calls": calls,
                    "strings": strings,
                    "complexity": line_count,
                    "pseudocode": output.trim(),
                }));
            } else {
                // Apply token-efficiency modes
                let is_compact = args.iter().any(|a| a == "--compact");
                let is_brief = args.iter().any(|a| a == "--brief");
                let min_comp: usize = args
                    .iter()
                    .position(|a| a == "--min-complexity")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);

                // Skip trivial functions
                let line_count = output
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("//"))
                    .count();
                if min_comp > 0 && line_count < min_comp {
                    continue;
                }

                let display = if is_brief {
                    brief_output(&output)
                } else if is_compact {
                    compact_output(&output)
                } else {
                    output.clone()
                };

                if !display.trim().is_empty() {
                    println!("// {}", name);
                    for line in display.lines() {
                        if !line.trim().is_empty() {
                            println!("{}", line);
                        }
                    }
                    println!();
                }
            }
        } else {
            eprintln!("Function '{}' not found", name);
        }
    }

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "binary": binary_path,
                "arch": format!("{:?}", arch),
                "functions": results,
            }))
            .unwrap()
        );
    }
}

fn decode_func(
    fa: u64,
    symbols: &[(u64, String)],
    segs: &[(u64, u64, u64)],
    data: &[u8],
    dec: &mut rsleigh_api::Decoder,
) -> Vec<(u64, pcode_ir::Instruction)> {
    let off = segs.iter().find_map(|(va, sz, fo)| {
        if fa >= *va && fa < va + sz {
            Some(fo + (fa - va))
        } else {
            None
        }
    });
    let Some(off) = off else {
        return vec![];
    };
    let max = 4096.min(data.len() - off as usize);
    let raw_bytes = &data[off as usize..off as usize + max];
    // Function-start padding skip. When a CALL rel32 target lands on
    // inter-function zero padding (or .pdata reports a stale entry into
    // an unmapped slot), the bogus decode floods the disassembly. Only
    // skip when leading 4 bytes are all 0x00 — that pattern is benign
    // padding on x86/x86-64 and the AArch64 `udf #0` trap, neither of
    // which is a real function start.
    let pad_skip: usize = if raw_bytes.len() >= 4 && raw_bytes[..4] == [0u8; 4] {
        raw_bytes
            .iter()
            .take(32)
            .position(|&b| b != 0x00)
            .unwrap_or(raw_bytes.len().min(32))
    } else {
        0
    };
    let fa = fa + pad_skip as u64;
    let bytes = &raw_bytes[pad_skip..];
    let max = bytes.len();
    let next_func = symbols
        .iter()
        .filter(|(a, name)| *a > fa && !name.starts_with("seh_scope_"))
        .map(|(a, _)| *a)
        .min()
        .unwrap_or(fa + max as u64);
    let decode_max = ((next_func - fa) as usize).min(max);

    // Go stack-check preamble extension. Three known shapes on amd64:
    //   A. Small frame (0-128 bytes):
    //        49 3b 66 10        cmp rsp, [r14+0x10]
    //        0f 86 rr rr rr rr  jbe morestack
    //   B. Medium frame via LEA (uses RSP-N as comparison value):
    //        4c 8d 64 24 ii     lea r12, [rsp-ii]
    //        4d 3b 66 10        cmp r12, [r14+0x10]
    //        0f 86 rr rr rr rr  jbe morestack
    //   C. Large frame (>32K) uses 32-bit displacement in LEA:
    //        4c 8d a4 24 ii ii ii ii  lea r12, [rsp-iiiiiiii]
    //        4d 3b 66 10
    //        0f 86 rr rr rr rr
    //
    // Function-discovery (CALL-target scan) plants a spurious FUN_
    // symbol at the byte past the JBE because morestack never returns
    // to the JBE; it jumps back to the function entry. Extend decode_max
    // past that FUN_ boundary when a preamble is detected.
    let extended_max = {
        // Go preamble compares RSP against g.stackguard0 (at offset 0x10)
        // OR g.preempt (at 0x18, used for cooperative preemption). Both
        // bytes are valid for the ModR/M displacement after `[R14+disp8]`.
        let is_stackguard_off = |b: u8| b == 0x10 || b == 0x18;
        let is_small = bytes.len() >= 10
            && bytes[0] == 0x49
            && bytes[1] == 0x3b
            && bytes[2] == 0x66
            && is_stackguard_off(bytes[3])
            && bytes[4] == 0x0f
            && bytes[5] == 0x86;
        let is_lea8 = bytes.len() >= 15
            && bytes[0] == 0x4c
            && bytes[1] == 0x8d
            && bytes[2] == 0x64
            && bytes[3] == 0x24
            && bytes[5] == 0x4d
            && bytes[6] == 0x3b
            && bytes[7] == 0x66
            && is_stackguard_off(bytes[8])
            && bytes[9] == 0x0f
            && bytes[10] == 0x86;
        let is_lea32 = bytes.len() >= 18
            && bytes[0] == 0x4c
            && bytes[1] == 0x8d
            && bytes[2] == 0xa4
            && bytes[3] == 0x24
            && bytes[8] == 0x4d
            && bytes[9] == 0x3b
            && bytes[10] == 0x66
            && is_stackguard_off(bytes[11])
            && bytes[12] == 0x0f
            && bytes[13] == 0x86;
        let mut ext = decode_max;
        if is_small || is_lea8 || is_lea32 {
            let scan_start = if is_small {
                10
            } else if is_lea8 {
                15
            } else {
                18
            };
            let scan_max = max.min(8192);
            // Walk forward looking for the NEXT Go preamble (= next
            // function boundary). Don't stop on RET — Go funcs have
            // early returns, panic exits, and morestack tails BEFORE
            // the real function end. Use the next-preamble pattern as
            // the only firm boundary.
            let mut found_boundary = false;
            for i in scan_start..scan_max {
                let next_small = bytes[i] == 0x49
                    && i + 3 < scan_max
                    && bytes[i + 1] == 0x3b
                    && bytes[i + 2] == 0x66
                    && (bytes[i + 3] == 0x10 || bytes[i + 3] == 0x18);
                let next_lea8 = bytes[i] == 0x4c
                    && i + 8 < scan_max
                    && bytes[i + 1] == 0x8d
                    && bytes[i + 2] == 0x64
                    && bytes[i + 3] == 0x24
                    && bytes[i + 5] == 0x4d
                    && bytes[i + 6] == 0x3b
                    && bytes[i + 7] == 0x66
                    && (bytes[i + 8] == 0x10 || bytes[i + 8] == 0x18);
                let next_lea32 = bytes[i] == 0x4c
                    && i + 11 < scan_max
                    && bytes[i + 1] == 0x8d
                    && bytes[i + 2] == 0xa4
                    && bytes[i + 3] == 0x24
                    && bytes[i + 8] == 0x4d
                    && bytes[i + 9] == 0x3b
                    && bytes[i + 10] == 0x66
                    && (bytes[i + 11] == 0x10 || bytes[i + 11] == 0x18);
                if next_small || next_lea8 || next_lea32 {
                    ext = ext.max(i);
                    found_boundary = true;
                    break;
                }
            }
            if !found_boundary {
                ext = scan_max;
            }
        }
        ext
    };
    let decode_max = extended_max;
    let mut insts = Vec::new();
    let mut io = 0;
    while io < decode_max {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dec.decode(&bytes[io..], fa + io as u64)
        })) {
            Ok(Ok(inst)) => {
                let l = inst.len as usize;
                if l == 0 {
                    io += 1;
                    continue;
                }
                insts.push((fa + io as u64, inst));
                io += l;
            }
            Ok(Err(_)) => break,
            Err(_) => {
                io += 1;
            }
        }
    }
    insts
}

fn decompile_func(
    fa: u64,
    symbols: &[(u64, String)],
    segs: &[(u64, u64, u64)],
    data: &[u8],
    dec: &mut rsleigh_api::Decoder,
    arch: rsleigh_api::Architecture,
    path: &Path,
) -> String {
    let insts = decode_func(fa, symbols, segs, data, dec);
    if insts.is_empty() {
        return "// no instructions\n".to_string();
    }
    maybe_annotate_crypto(rsleigh_decompile::decompile_with_binary(
        arch,
        &insts,
        Some(data),
        Some(path),
    ))
}

/// Generate a YARA detection rule from binary analysis.
/// Extracts unique strings, imports, hex patterns, and crypto signatures.
/// Diff two binaries: decompile both, match functions, show unified diff of changes.
fn diff_binaries(old_path: &str, new_path: &str, func_filter: &[String]) {
    use std::collections::BTreeMap;

    eprintln!("Comparing: {} vs {}", old_path, new_path);

    // Helper: decompile all functions in a binary, return map of name → pseudocode
    let decompile_all = |path: &str| -> BTreeMap<String, String> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error reading {}: {}", path, e);
                return BTreeMap::new();
            }
        };
        let obj = match goblin::Object::parse(&data) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Error parsing {}: {}", path, e);
                return BTreeMap::new();
            }
        };
        let (arch, segs, mut symbols) = match parse_binary(&obj, &data) {
            Some(r) => r,
            None => {
                eprintln!("Unsupported format: {}", path);
                return BTreeMap::new();
            }
        };

        // Discover functions for stripped binaries
        if symbols.is_empty() {
            if let goblin::Object::PE(pe) = &obj {
                let base = pe.image_base as u64;
                let entry = base
                    + pe.header
                        .optional_header
                        .unwrap()
                        .standard_fields
                        .address_of_entry_point as u64;
                symbols = discover_pe_functions(entry, &segs, &data, arch);
            }
        }
        let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
            elf.syms.len() == 0
        } else {
            false
        };
        if is_elf_stripped {
            if let goblin::Object::Elf(elf) = &obj {
                let discovered = discover_elf_functions(elf, &segs, &data, arch);
                let existing: std::collections::BTreeSet<u64> =
                    symbols.iter().map(|(a, _)| *a).collect();
                for (addr, name) in discovered {
                    if !existing.contains(&addr) {
                        symbols.push((addr, name));
                    }
                }
            }
        }

        let p = std::path::Path::new(path);
        let import_map = build_import_map(&obj, &data);
        let mut dec = rsleigh_api::Decoder::new(arch);
        let mut result = BTreeMap::new();

        for (func_addr, func_name) in &symbols {
            let off = segs.iter().find_map(|(va, sz, fo)| {
                if *func_addr >= *va && *func_addr < va + sz {
                    Some(fo + (func_addr - va))
                } else {
                    None
                }
            });
            let Some(off) = off else { continue };
            let max = 8192.min(data.len().saturating_sub(off as usize));
            if max < 2 {
                continue;
            }
            let bytes = &data[off as usize..off as usize + max];

            let next_func = symbols
                .iter()
                .filter(|(a, _)| *a > *func_addr)
                .map(|(a, _)| *a)
                .min()
                .unwrap_or(func_addr + max as u64);
            let decode_max = ((next_func - func_addr) as usize).min(max);

            let mut insts = Vec::new();
            let mut pos = 0;
            while pos < decode_max {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    dec.decode(&bytes[pos..], func_addr + pos as u64)
                })) {
                    Ok(Ok(inst)) => {
                        let l = inst.len as usize;
                        if l == 0 {
                            pos += 1;
                            continue;
                        }
                        insts.push((func_addr + pos as u64, inst));
                        pos += l;
                    }
                    _ => {
                        pos += 1;
                    }
                }
            }

            if !insts.is_empty() {
                let output = maybe_annotate_crypto(rsleigh_decompile::decompile_with_binary(
                    arch,
                    &insts,
                    Some(&data),
                    Some(p),
                ));
                if !output.trim().is_empty() {
                    result.insert(func_name.clone(), output);
                }
            }
        }
        eprintln!("  {}: {} functions decompiled", path, result.len());
        result
    };

    let old_funcs = decompile_all(old_path);
    let new_funcs = decompile_all(new_path);

    // Match functions and compute diffs
    let mut all_names: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    for k in old_funcs.keys() {
        all_names.insert(k);
    }
    for k in new_funcs.keys() {
        all_names.insert(k);
    }

    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    let mut unchanged = 0usize;

    for name in &all_names {
        // Filter if specific functions requested
        if !func_filter.is_empty() && !func_filter.iter().any(|f| f.as_str() == name.as_str()) {
            continue;
        }

        let old_code = old_funcs.get(*name);
        let new_code = new_funcs.get(*name);

        match (old_code, new_code) {
            (None, Some(new)) => {
                added += 1;
                println!("=== ADDED: {} ===", name);
                for line in new.lines() {
                    println!("\x1b[32m+ {}\x1b[0m", line); // green
                }
                println!();
            }
            (Some(old), None) => {
                removed += 1;
                println!("=== REMOVED: {} ===", name);
                for line in old.lines() {
                    println!("\x1b[31m- {}\x1b[0m", line); // red
                }
                println!();
            }
            (Some(old), Some(new)) => {
                if old == new {
                    unchanged += 1;
                    continue;
                }
                changed += 1;
                println!("=== CHANGED: {} ===", name);
                // Simple line-by-line diff
                let old_lines: Vec<&str> = old.lines().collect();
                let new_lines: Vec<&str> = new.lines().collect();
                // Use longest common subsequence for basic diff
                let diff = simple_diff(&old_lines, &new_lines);
                for (tag, line) in &diff {
                    match tag {
                        '-' => println!("\x1b[31m- {}\x1b[0m", line),
                        '+' => println!("\x1b[32m+ {}\x1b[0m", line),
                        ' ' => println!("  {}", line),
                        _ => {}
                    }
                }
                println!();
            }
            (None, None) => {}
        }
    }

    println!("--- Summary ---");
    println!("Unchanged: {}", unchanged);
    println!("Changed:   {}", changed);
    println!("Added:     {}", added);
    println!("Removed:   {}", removed);
}

/// Simple line diff using LCS (longest common subsequence).
fn simple_diff<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<(char, &'a str)> {
    // Build LCS table
    let m = old.len();
    let n = new.len();
    let mut dp = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if old[i - 1] == new[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack to produce diff
    let mut result = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            result.push((' ', old[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            result.push(('+', new[j - 1]));
            j -= 1;
        } else {
            result.push(('-', old[i - 1]));
            i -= 1;
        }
    }
    result.reverse();
    result
}

/// Build import map from binary for decompilation.
fn build_import_map(obj: &goblin::Object, data: &[u8]) -> std::collections::HashMap<u64, String> {
    let mut map = std::collections::HashMap::new();
    match obj {
        goblin::Object::PE(pe) => {
            for imp in &pe.imports {
                if imp.rva != 0 {
                    map.insert(pe.image_base as u64 + imp.rva as u64, imp.name.to_string());
                }
            }
        }
        goblin::Object::Elf(elf) => {
            for sym in elf.dynsyms.iter() {
                if sym.st_value != 0 {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            map.insert(sym.st_value, name.to_string());
                        }
                    }
                }
            }
        }
        _ => {}
    }
    map
}

/// Generate a one-line summary per function for AI-assisted triage.
/// Shows: function name, calls made, strings referenced, patterns detected.
fn run_summary(binary_path: &str, data: &[u8]) {
    let obj = match goblin::Object::parse(data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let (arch, segs, mut symbols) = match parse_binary(&obj, data) {
        Some(r) => r,
        None => {
            eprintln!("Unsupported format");
            return;
        }
    };
    // Discover functions for stripped binaries
    if symbols.is_empty() {
        if let goblin::Object::PE(pe) = &obj {
            let base = pe.image_base as u64;
            let entry = base
                + pe.header
                    .optional_header
                    .unwrap()
                    .standard_fields
                    .address_of_entry_point as u64;
            symbols = discover_pe_functions(entry, &segs, data, arch);
        }
    }
    let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
        elf.syms.len() == 0
    } else {
        false
    };
    if is_elf_stripped {
        if let goblin::Object::Elf(elf) = &obj {
            let discovered = discover_elf_functions(elf, &segs, data, arch);
            let existing: std::collections::BTreeSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in discovered {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    let path = std::path::Path::new(binary_path);
    let import_map = build_import_map(&obj, data);
    let mut dec = rsleigh_api::Decoder::new(arch);

    eprintln!("{} functions in {}", symbols.len(), binary_path);
    println!(
        "{:<14} {:<25} {:<40} {}",
        "Address", "Name", "Calls", "Strings/Patterns"
    );
    println!("{}", "-".repeat(100));

    for (func_addr, func_name) in &symbols {
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if *func_addr >= *va && *func_addr < va + sz {
                Some(fo + (func_addr - va))
            } else {
                None
            }
        });
        let Some(off) = off else { continue };
        let max = 4096.min(data.len().saturating_sub(off as usize));
        if max < 2 {
            continue;
        }
        let bytes = &data[off as usize..off as usize + max];

        let next_func = symbols
            .iter()
            .filter(|(a, _)| *a > *func_addr)
            .map(|(a, _)| *a)
            .min()
            .unwrap_or(func_addr + max as u64);
        let decode_max = ((next_func - func_addr) as usize).min(max);

        let mut insts = Vec::new();
        let mut pos = 0;
        while pos < decode_max {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec.decode(&bytes[pos..], func_addr + pos as u64)
            })) {
                Ok(Ok(inst)) => {
                    let l = inst.len as usize;
                    if l == 0 {
                        pos += 1;
                        continue;
                    }
                    insts.push((func_addr + pos as u64, inst));
                    pos += l;
                }
                _ => {
                    pos += 1;
                }
            }
        }

        if insts.is_empty() {
            continue;
        }

        // Decompile and extract metadata
        let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
        }));
        let output = match output {
            Ok(o) => o,
            Err(_) => continue,
        };

        // Extract calls
        let mut calls = Vec::new();
        for line in output.lines() {
            let t = line.trim();
            if t.contains('(')
                && t.contains(')')
                && !t.starts_with("//")
                && !t.starts_with("if ")
                && !t.starts_with("while ")
                && !t.starts_with("for ")
                && !t.contains(" = ")
            {
                // Standalone call: func_name(args);
                if let Some(paren) = t.find('(') {
                    let callee = t[..paren].trim().trim_start_matches("return ");
                    if !callee.is_empty() && !callee.contains(' ') && callee.len() < 40 {
                        calls.push(callee.to_string());
                    }
                }
            }
            // Also extract from assignments: var = func(args);
            if let Some(eq) = t.find(" = ") {
                let rhs = &t[eq + 3..];
                if let Some(paren) = rhs.find('(') {
                    let callee = rhs[..paren].trim();
                    if !callee.is_empty()
                        && !callee.starts_with('*')
                        && !callee.starts_with('(')
                        && !callee.contains(' ')
                        && callee.len() < 40
                    {
                        if !calls.contains(&callee.to_string()) {
                            calls.push(callee.to_string());
                        }
                    }
                }
            }
        }

        // Extract strings
        let mut strings = Vec::new();
        for line in output.lines() {
            let t = line.trim();
            if let Some(q1) = t.find('"') {
                if let Some(q2) = t[q1 + 1..].find('"') {
                    let s = &t[q1 + 1..q1 + 1 + q2];
                    if s.len() >= 3 && s.len() <= 40 && !strings.contains(&s.to_string()) {
                        strings.push(s.to_string());
                    }
                }
            }
        }

        // Detect patterns
        let mut patterns = Vec::new();
        if output.contains("XOR") || output.contains("^ 0x") {
            patterns.push("xor");
        }
        if output.contains("AES") || output.contains("SHA") || output.contains("CRC32") {
            patterns.push("crypto");
        }
        if output.contains("TAINT") {
            patterns.push("taint");
        }
        if output.contains("stack cookie") {
            patterns.push("canary");
        }
        if output.contains("VirtualAlloc") || output.contains("mmap") {
            patterns.push("alloc");
        }
        if output.contains("recv") || output.contains("send") || output.contains("socket") {
            patterns.push("network");
        }
        if output.contains("RegSetValue") || output.contains("RegCreateKey") {
            patterns.push("registry");
        }
        if output.contains("CreateFile") || output.contains("fopen") {
            patterns.push("file");
        }
        if output.contains("system(") || output.contains("exec(") || output.contains("popen(") {
            patterns.push("exec");
        }

        // Format output
        let calls_str = if calls.len() > 3 {
            format!("{}, +{} more", calls[..3].join(", "), calls.len() - 3)
        } else {
            calls.join(", ")
        };

        let mut info_parts = Vec::new();
        if !strings.is_empty() {
            let s = if strings.len() > 2 {
                format!("\"{}\" +{}", strings[0], strings.len() - 1)
            } else {
                strings
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            info_parts.push(s);
        }
        if !patterns.is_empty() {
            info_parts.push(format!("[{}]", patterns.join(",")));
        }

        println!(
            "0x{:012x} {:<25} {:<40} {}",
            func_addr,
            func_name,
            calls_str,
            info_parts.join(" ")
        );
    }
}

/// Show cross-references for a function: callers, callees, strings, data refs.
fn run_xrefs(binary_path: &str, data: &[u8], target_name: &str) {
    if target_name.is_empty() {
        eprintln!("Usage: rsleigh <binary> --xrefs <func_name>");
        return;
    }

    let obj = match goblin::Object::parse(data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let (arch, segs, mut symbols) = match parse_binary(&obj, data) {
        Some(r) => r,
        None => {
            eprintln!("Unsupported format");
            return;
        }
    };
    if symbols.is_empty() {
        if let goblin::Object::PE(pe) = &obj {
            let base = pe.image_base as u64;
            let entry = base
                + pe.header
                    .optional_header
                    .unwrap()
                    .standard_fields
                    .address_of_entry_point as u64;
            symbols = discover_pe_functions(entry, &segs, data, arch);
        }
    }
    let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
        elf.syms.len() == 0
    } else {
        false
    };
    if is_elf_stripped {
        if let goblin::Object::Elf(elf) = &obj {
            let discovered = discover_elf_functions(elf, &segs, data, arch);
            let existing: std::collections::BTreeSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in discovered {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    // Find the target function
    let target_addr = if let Some(hex) = target_name.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        symbols
            .iter()
            .find(|(_, n)| n == target_name)
            .map(|(a, _)| *a)
    };
    let Some(target_addr) = target_addr else {
        eprintln!("Function '{}' not found", target_name);
        return;
    };
    let target_display = symbols
        .iter()
        .find(|(a, _)| *a == target_addr)
        .map(|(_, n)| n.as_str())
        .unwrap_or(target_name);

    let path = std::path::Path::new(binary_path);
    let mut dec = rsleigh_api::Decoder::new(arch);

    // Phase 1: Decompile target function to find its callees and strings
    let mut callees = Vec::new();
    let mut strings_in_target = Vec::new();
    let mut target_output = String::new();
    {
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if target_addr >= *va && target_addr < va + sz {
                Some(fo + (target_addr - va))
            } else {
                None
            }
        });
        if let Some(off) = off {
            let max = 8192.min(data.len().saturating_sub(off as usize));
            let bytes = &data[off as usize..off as usize + max];
            let next_func = symbols
                .iter()
                .filter(|(a, _)| *a > target_addr)
                .map(|(a, _)| *a)
                .min()
                .unwrap_or(target_addr + max as u64);
            let decode_max = ((next_func - target_addr) as usize).min(max);
            let mut insts = Vec::new();
            let mut pos = 0;
            while pos < decode_max {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    dec.decode(&bytes[pos..], target_addr + pos as u64)
                })) {
                    Ok(Ok(inst)) => {
                        let l = inst.len as usize;
                        if l == 0 {
                            pos += 1;
                            continue;
                        }
                        insts.push((target_addr + pos as u64, inst));
                        pos += l;
                    }
                    _ => {
                        pos += 1;
                    }
                }
            }
            if !insts.is_empty() {
                target_output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
                }))
                .unwrap_or_default();
            }
        }
        // Extract callees and strings from decompiled output
        for line in target_output.lines() {
            let t = line.trim();
            // Extract function calls
            if t.contains('(') && !t.starts_with("//") {
                if let Some(paren) = t.find('(') {
                    let before = if let Some(eq) = t.find(" = ") {
                        &t[eq + 3..paren]
                    } else {
                        &t[..paren]
                    };
                    let callee = before.trim().trim_start_matches("return ");
                    if !callee.is_empty()
                        && !callee.contains(' ')
                        && !callee.starts_with('*')
                        && !callee.starts_with('(')
                        && !callee.starts_with("if")
                        && !callee.starts_with("while")
                        && callee.len() < 50
                        && !callees.contains(&callee.to_string())
                    {
                        callees.push(callee.to_string());
                    }
                }
            }
            // Extract strings
            if let Some(q1) = t.find('"') {
                if let Some(q2) = t[q1 + 1..].find('"') {
                    let s = &t[q1 + 1..q1 + 1 + q2];
                    if s.len() >= 2 && s.len() <= 60 {
                        strings_in_target.push(s.to_string());
                    }
                }
            }
        }
    }

    // Phase 2: Scan ALL functions to find callers (functions that call target)
    let mut callers = Vec::new();
    for (func_addr, func_name) in &symbols {
        if *func_addr == target_addr {
            continue;
        }
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if *func_addr >= *va && *func_addr < va + sz {
                Some(fo + (func_addr - va))
            } else {
                None
            }
        });
        let Some(off) = off else { continue };
        let max = 4096.min(data.len().saturating_sub(off as usize));
        if max < 2 {
            continue;
        }
        let bytes = &data[off as usize..off as usize + max];
        let next_func = symbols
            .iter()
            .filter(|(a, _)| *a > *func_addr)
            .map(|(a, _)| *a)
            .min()
            .unwrap_or(func_addr + max as u64);
        let decode_max = ((next_func - func_addr) as usize).min(max);
        let mut insts = Vec::new();
        let mut pos = 0;
        while pos < decode_max {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec.decode(&bytes[pos..], func_addr + pos as u64)
            })) {
                Ok(Ok(inst)) => {
                    let l = inst.len as usize;
                    if l == 0 {
                        pos += 1;
                        continue;
                    }
                    // Check if this instruction calls the target
                    let dis = &inst.disassembly;
                    if dis.starts_with("CALL ") || dis.starts_with("BL ") {
                        if let Some(target_str) = dis.split_whitespace().nth(1) {
                            if let Some(hex) = target_str.strip_prefix("0x") {
                                if let Ok(addr) = u64::from_str_radix(hex, 16) {
                                    if addr == target_addr {
                                        callers.push((func_addr.clone(), func_name.clone()));
                                    }
                                }
                            }
                        }
                    }
                    insts.push((func_addr + pos as u64, inst));
                    pos += l;
                }
                _ => {
                    pos += 1;
                }
            }
        }
    }

    // Output
    println!(
        "=== Cross-references for {} (0x{:x}) ===",
        target_display, target_addr
    );
    println!();
    println!("Called by ({} callers):", callers.len());
    if callers.is_empty() {
        println!("  (none found — may be called indirectly or is entry point)");
    }
    for (addr, name) in &callers {
        println!("  0x{:012x}  {}", addr, name);
    }
    println!();
    println!("Calls ({} callees):", callees.len());
    for callee in &callees {
        println!("  {}", callee);
    }
    println!();
    if !strings_in_target.is_empty() {
        println!("Strings ({}):", strings_in_target.len());
        for s in &strings_in_target {
            println!("  \"{}\"", s);
        }
        println!();
    }
    println!("Decompiled output:");
    println!("{}", target_output);
}

/// Search for functions matching a query: string, API call, or hex constant.
fn run_search(
    binary_path: &str,
    data: &[u8],
    query: &str,
    api_mode: bool,
    const_mode: bool,
    tag_mode: bool,
    decompile_results: bool,
    json_output: bool,
) {
    let obj = match goblin::Object::parse(data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let (arch, segs, mut symbols) = match parse_binary(&obj, data) {
        Some(r) => r,
        None => {
            eprintln!("Unsupported format");
            return;
        }
    };
    if symbols.is_empty() {
        if let goblin::Object::PE(pe) = &obj {
            let base = pe.image_base as u64;
            let entry = base
                + pe.header
                    .optional_header
                    .unwrap()
                    .standard_fields
                    .address_of_entry_point as u64;
            symbols = discover_pe_functions(entry, &segs, data, arch);
        }
    }
    let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
        elf.syms.len() == 0
    } else {
        false
    };
    if is_elf_stripped {
        if let goblin::Object::Elf(elf) = &obj {
            let discovered = discover_elf_functions(elf, &segs, data, arch);
            let existing: std::collections::BTreeSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in discovered {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    let path = std::path::Path::new(binary_path);
    let mut dec = rsleigh_api::Decoder::new(arch);
    let query_lower = query.to_lowercase();

    let mode_str = if api_mode {
        " (API)"
    } else if const_mode {
        " (const)"
    } else if tag_mode {
        " (tag)"
    } else {
        ""
    };
    eprintln!(
        "Searching {} functions for '{}'{}...",
        symbols.len(),
        query,
        mode_str
    );

    // matches: (addr, name, reason, context, pseudocode)
    let mut matches: Vec<(u64, String, String, String, String)> = Vec::new();

    // Tag-based search: decompile all, extract tags, filter
    if tag_mode {
        let search_tags: Vec<&str> = query.split(',').map(|s| s.trim()).collect();
        for (func_addr, func_name) in &symbols {
            let insts = decode_func(*func_addr, &symbols, &segs, data, &mut dec);
            if insts.is_empty() {
                continue;
            }
            let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
            })) {
                Ok(o) => o,
                Err(_) => continue,
            };

            let meta =
                rsleigh_decompile::analysis::extract_function_meta(func_name, *func_addr, &output);
            let has_tag = search_tags
                .iter()
                .any(|t| meta.tags.iter().any(|mt| mt == t));
            if has_tag {
                let matched_tags: Vec<&str> = meta
                    .tags
                    .iter()
                    .filter(|t| search_tags.contains(&t.as_str()))
                    .map(|t| t.as_str())
                    .collect();
                let calls_str = if meta.calls.len() > 3 {
                    format!("{}, +{}", meta.calls[..3].join(", "), meta.calls.len() - 3)
                } else {
                    meta.calls.join(", ")
                };
                matches.push((
                    *func_addr,
                    func_name.clone(),
                    format!("tags: [{}]", matched_tags.join(",")),
                    calls_str,
                    output,
                ));
            }
        }
        // Skip the rest of the function and go to output
        return output_search_results(&matches, query, json_output, decompile_results);
    }

    for (func_addr, func_name) in &symbols {
        // Quick pre-filter: check function name first
        if !api_mode && !const_mode && func_name.to_lowercase().contains(&query_lower) {
            matches.push((
                func_addr.clone(),
                func_name.clone(),
                "name match".to_string(),
                String::new(),
                String::new(),
            ));
            continue;
        }

        let off = segs.iter().find_map(|(va, sz, fo)| {
            if *func_addr >= *va && *func_addr < va + sz {
                Some(fo + (func_addr - va))
            } else {
                None
            }
        });
        let Some(off) = off else { continue };
        let max = 4096.min(data.len().saturating_sub(off as usize));
        if max < 2 {
            continue;
        }
        let bytes = &data[off as usize..off as usize + max];

        let next_func = symbols
            .iter()
            .filter(|(a, _)| *a > *func_addr)
            .map(|(a, _)| *a)
            .min()
            .unwrap_or(func_addr + max as u64);
        let decode_max = ((next_func - func_addr) as usize).min(max);

        // For API mode: decompile and search for function call pattern "api_name("
        if api_mode {
            let mut insts = Vec::new();
            let mut pos = 0;
            while pos < decode_max {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    dec.decode(&bytes[pos..], func_addr + pos as u64)
                })) {
                    Ok(Ok(inst)) => {
                        let l = inst.len as usize;
                        if l == 0 {
                            pos += 1;
                            continue;
                        }
                        insts.push((func_addr + pos as u64, inst));
                        pos += l;
                    }
                    _ => {
                        pos += 1;
                    }
                }
            }
            if insts.is_empty() {
                continue;
            }
            let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
            })) {
                Ok(o) => o,
                Err(_) => continue,
            };
            // Search for "api_name(" pattern — must be a call, not just a substring
            let call_pattern = format!("{}(", query);
            if output.contains(&call_pattern) {
                let context_line = output
                    .lines()
                    .find(|l| l.contains(&call_pattern) && !l.trim().starts_with("//"))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let context = if context_line.len() > 80 {
                    format!("{}...", &context_line[..80])
                } else {
                    context_line
                };
                matches.push((
                    *func_addr,
                    func_name.clone(),
                    format!("calls {}", query),
                    context,
                    output,
                ));
            }
            continue;
        }

        // For const mode: search for the hex constant in instruction bytes
        if const_mode {
            let const_val = if let Some(hex) = query.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                query.parse::<u64>().ok()
            };
            if let Some(val) = const_val {
                // Search for the constant in instruction immediates
                let val_le4 = (val as u32).to_le_bytes();
                let val_le8 = val.to_le_bytes();
                let val_be4 = (val as u32).to_be_bytes();
                let found = if val <= 0xFFFFFFFF {
                    bytes[..decode_max]
                        .windows(4)
                        .any(|w| w == val_le4 || w == val_be4)
                } else {
                    bytes[..decode_max].windows(8).any(|w| w == val_le8)
                };
                if found {
                    matches.push((
                        *func_addr,
                        func_name.clone(),
                        format!("contains 0x{:x}", val),
                        String::new(),
                        String::new(),
                    ));
                }
            }
            continue;
        }

        // Default string search: first check raw bytes for the query string
        // (much faster than decompiling). If found, decompile for context.
        let query_bytes = query.as_bytes();
        let has_raw_match = bytes[..decode_max]
            .windows(query_bytes.len())
            .any(|w| w.eq_ignore_ascii_case(query_bytes));
        // Also check for wide string (UTF-16LE)
        let wide_query: Vec<u8> = query.bytes().flat_map(|b| [b, 0]).collect();
        let has_wide_match = if wide_query.len() <= decode_max {
            bytes[..decode_max]
                .windows(wide_query.len())
                .any(|w| w == wide_query.as_slice())
        } else {
            false
        };

        if has_raw_match || has_wide_match {
            // Quick match from raw bytes — decompile for context
            let mut insts = Vec::new();
            let mut pos = 0;
            while pos < decode_max {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    dec.decode(&bytes[pos..], func_addr + pos as u64)
                })) {
                    Ok(Ok(inst)) => {
                        let l = inst.len as usize;
                        if l == 0 {
                            pos += 1;
                            continue;
                        }
                        insts.push((func_addr + pos as u64, inst));
                        pos += l;
                    }
                    _ => {
                        pos += 1;
                    }
                }
            }
            let (context, full_output) = if !insts.is_empty() {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
                })) {
                    Ok(output) => {
                        let ctx = output
                            .lines()
                            .find(|l| l.to_lowercase().contains(&query_lower))
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        (ctx, output)
                    }
                    Err(_) => (String::new(), String::new()),
                }
            } else {
                (String::new(), String::new())
            };
            let context = if context.len() > 80 {
                format!("{}...", &context[..80])
            } else {
                context
            };
            let match_type = if has_wide_match && !has_raw_match {
                "wide string"
            } else {
                "string"
            };
            matches.push((
                *func_addr,
                func_name.clone(),
                match_type.to_string(),
                context,
                full_output,
            ));
            continue;
        }

        // Fallback: also search by decompiling if no raw match
        // (catches computed strings, API names from import resolution, etc.)
        // Only do this for short queries that might be API names
        if query.len() >= 4 && query.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            let mut insts = Vec::new();
            let mut pos = 0;
            while pos < decode_max {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    dec.decode(&bytes[pos..], func_addr + pos as u64)
                })) {
                    Ok(Ok(inst)) => {
                        let l = inst.len as usize;
                        if l == 0 {
                            pos += 1;
                            continue;
                        }
                        insts.push((func_addr + pos as u64, inst));
                        pos += l;
                    }
                    _ => {
                        pos += 1;
                    }
                }
            }
            if !insts.is_empty() {
                if let Ok(output) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
                })) {
                    if output.to_lowercase().contains(&query_lower) {
                        let context = output
                            .lines()
                            .find(|l| l.to_lowercase().contains(&query_lower))
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        let context = if context.len() > 80 {
                            format!("{}...", &context[..80])
                        } else {
                            context
                        };
                        matches.push((
                            *func_addr,
                            func_name.clone(),
                            "pseudocode match".to_string(),
                            context,
                            output.clone(),
                        ));
                    }
                }
            }
        }
    }

    output_search_results(&matches, query, json_output, decompile_results);
}

/// Format and display search results.
fn output_search_results(
    matches: &[(u64, String, String, String, String)],
    query: &str,
    json_output: bool,
    decompile_results: bool,
) {
    if json_output {
        let entries: Vec<serde_json::Value> = matches
            .iter()
            .map(|(addr, name, reason, context, pseudocode)| {
                let mut entry = serde_json::json!({
                    "address": format!("0x{:x}", addr),
                    "name": name,
                    "match_type": reason,
                });
                if !context.is_empty() {
                    entry
                        .as_object_mut()
                        .unwrap()
                        .insert("context".to_string(), serde_json::json!(context));
                }
                if decompile_results && !pseudocode.is_empty() {
                    entry
                        .as_object_mut()
                        .unwrap()
                        .insert("pseudocode".to_string(), serde_json::json!(pseudocode));
                }
                entry
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "query": query,
                "match_count": matches.len(),
                "results": entries,
            }))
            .unwrap()
        );
    } else {
        println!("{} matches for '{}':", matches.len(), query);
        println!();
        for (addr, name, reason, context, pseudocode) in matches {
            println!("  0x{:012x}  {:<25} {}", addr, name, reason);
            if !context.is_empty() {
                println!("                  {}", context);
            }
            if decompile_results && !pseudocode.is_empty() {
                println!();
                for line in pseudocode.lines() {
                    println!("    {}", line);
                }
                println!();
            }
        }
    }
}

/// Scan for common vulnerability patterns in decompiled output.
fn run_section_scan(binary_path: &str, data: &[u8]) {
    let obj = match goblin::Object::parse(data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let mut sec_list: Vec<(String, &[u8], u64)> = Vec::new();
    let mut overlay: Option<&[u8]> = None;
    match &obj {
        goblin::Object::PE(pe) => {
            let mut end_fo: usize = 0;
            for sec in &pe.sections {
                let name = String::from_utf8_lossy(&sec.name)
                    .trim_end_matches('\0')
                    .to_string();
                let fo = sec.pointer_to_raw_data as usize;
                let sz = sec.size_of_raw_data as usize;
                if fo == 0 || sz == 0 {
                    continue;
                }
                let end = fo.saturating_add(sz).min(data.len());
                if fo < end {
                    sec_list.push((
                        name,
                        &data[fo..end],
                        sec.virtual_address as u64 + pe.image_base as u64,
                    ));
                    if end > end_fo {
                        end_fo = end;
                    }
                }
            }
            if end_fo < data.len() {
                overlay = Some(&data[end_fo..]);
            }
        }
        goblin::Object::Elf(elf) => {
            for sh in &elf.section_headers {
                if sh.sh_type != goblin::elf::section_header::SHT_PROGBITS {
                    continue;
                }
                let fo = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                if sz == 0 {
                    continue;
                }
                let end = fo.saturating_add(sz).min(data.len());
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                if fo < end {
                    sec_list.push((name, &data[fo..end], sh.sh_addr));
                }
            }
        }
        goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
            for seg in &m.segments {
                for sec_result in seg {
                    if let Ok((sec, sec_data)) = sec_result {
                        let name = sec.name().unwrap_or("").to_string();
                        if !sec_data.is_empty() {
                            sec_list.push((name, sec_data, sec.addr));
                        }
                    }
                }
            }
        }
        _ => {}
    }

    println!("=== Section Anomaly Scan: {} ===", binary_path);
    println!();
    println!("{:<24} {:>10}  entropy", "section", "bytes");
    for (name, bytes, _va) in &sec_list {
        let h = rsleigh_decompile::analysis::shannon_entropy(bytes);
        let flag = if h > 7.9 {
            " ** HIGH"
        } else if h > 7.5 {
            " * elevated"
        } else {
            ""
        };
        println!("  {:<22} {:>10}  {:>5.2}{}", name, bytes.len(), h, flag);
    }
    if let Some(ov) = overlay {
        if !ov.is_empty() {
            let h = rsleigh_decompile::analysis::shannon_entropy(ov);
            println!(
                "  {:<22} {:>10}  {:>5.2}  (PE overlay)",
                "<overlay>",
                ov.len(),
                h
            );
        }
    }
    println!();
    let findings = rsleigh_decompile::analysis::scan_section_anomalies(&sec_list, overlay);
    if findings.is_empty() {
        println!("No anomalies.");
    } else {
        println!("Findings:");
        for f in &findings {
            println!("  [{}] {} — {}", f.severity, f.function, f.description);
        }
    }
}

fn run_vulnscan(binary_path: &str, data: &[u8]) {
    let obj = match goblin::Object::parse(data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let (arch, segs, mut symbols) = match parse_binary(&obj, data) {
        Some(r) => r,
        None => {
            eprintln!("Unsupported");
            return;
        }
    };
    if symbols.is_empty() {
        if let goblin::Object::PE(pe) = &obj {
            let base = pe.image_base as u64;
            let entry = base
                + pe.header
                    .optional_header
                    .unwrap()
                    .standard_fields
                    .address_of_entry_point as u64;
            symbols = discover_pe_functions(entry, &segs, data, arch);
        }
    }
    let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
        elf.syms.len() == 0
    } else {
        false
    };
    if is_elf_stripped {
        if let goblin::Object::Elf(elf) = &obj {
            let discovered = discover_elf_functions(elf, &segs, data, arch);
            let existing: std::collections::BTreeSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in discovered {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    let path = std::path::Path::new(binary_path);
    let mut dec = rsleigh_api::Decoder::new(arch);

    // Vulnerability patterns: (pattern_in_pseudocode, severity, description)
    let vuln_patterns: &[(&str, &str, &str)] = &[
        // Buffer overflows
        (
            "gets(",
            "HIGH",
            "buffer overflow: gets() has no bounds check",
        ),
        (
            "strcpy(",
            "MED",
            "buffer overflow: strcpy() has no bounds check",
        ),
        (
            "strcat(",
            "MED",
            "buffer overflow: strcat() has no bounds check",
        ),
        (
            "sprintf(",
            "MED",
            "buffer overflow/format string: sprintf() no bounds check",
        ),
        (
            "vsprintf(",
            "MED",
            "buffer overflow/format string: vsprintf()",
        ),
        // Format strings
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
            "fprintf(param_",
            "HIGH",
            "format string: fprintf() with user-controlled format",
        ),
        (
            "syslog(param_",
            "MED",
            "format string: syslog() with user-controlled format",
        ),
        // Command injection
        (
            "system(param_",
            "CRIT",
            "command injection: system() with user-controlled argument",
        ),
        (
            "system(local_",
            "HIGH",
            "command injection: system() with stack variable",
        ),
        (
            "popen(param_",
            "CRIT",
            "command injection: popen() with user-controlled argument",
        ),
        (
            "exec(param_",
            "CRIT",
            "command execution: exec() with user-controlled argument",
        ),
        ("ShellExecute", "MED", "command execution: ShellExecute()"),
        ("WinExec(", "MED", "command execution: WinExec()"),
        ("CreateProcess", "MED", "process creation: CreateProcess()"),
        // Memory issues
        (
            "free(",
            "LOW",
            "potential use-after-free: check if pointer used after free()",
        ),
        ("VirtualAlloc(", "LOW", "executable memory allocation"),
        (
            "VirtualProtect(",
            "MED",
            "memory protection change (DEP bypass)",
        ),
        ("mmap(", "LOW", "memory mapping"),
        // Integer issues
        (
            "malloc(param_",
            "MED",
            "unchecked allocation: malloc() with user-controlled size",
        ),
        (
            "realloc(param_",
            "MED",
            "unchecked reallocation with user-controlled size",
        ),
        // Crypto issues
        (
            "rand()",
            "LOW",
            "weak randomness: rand() is not cryptographically secure",
        ),
        ("srand(", "LOW", "weak randomness: srand() seed"),
        // Info disclosure
        (
            "GetProcAddress(",
            "LOW",
            "dynamic API resolution (anti-analysis)",
        ),
        ("LoadLibrary", "LOW", "dynamic library loading"),
        // SQL injection
        (
            "sqlite3_exec(",
            "MED",
            "potential SQL injection if query contains user input",
        ),
        ("mysql_query(", "MED", "potential SQL injection"),
    ];

    eprintln!(
        "Scanning {} functions for vulnerability patterns...",
        symbols.len()
    );
    let mut findings: Vec<(String, u64, String, String, String)> = Vec::new(); // (severity, addr, name, vuln, context)

    for (func_addr, func_name) in &symbols {
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if *func_addr >= *va && *func_addr < va + sz {
                Some(fo + (func_addr - va))
            } else {
                None
            }
        });
        let Some(off) = off else { continue };
        let max = 4096.min(data.len().saturating_sub(off as usize));
        if max < 2 {
            continue;
        }

        let insts = decode_func(*func_addr, &symbols, &segs, data, &mut dec);
        if insts.is_empty() {
            continue;
        }

        let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
        })) {
            Ok(o) => o,
            Err(_) => continue,
        };

        for &(pattern, severity, description) in vuln_patterns {
            if output.contains(pattern) {
                let context = output
                    .lines()
                    .find(|l| l.contains(pattern))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let context = if context.len() > 70 {
                    format!("{}...", &context[..70])
                } else {
                    context
                };
                findings.push((
                    severity.to_string(),
                    *func_addr,
                    func_name.clone(),
                    description.to_string(),
                    context,
                ));
            }
        }

        // Special: check for missing stack cookie in large functions
        let has_cookie = output.contains("stack cookie")
            || output.contains("__security_check_cookie")
            || output.contains("__stack_chk_fail");
        let line_count = output.lines().filter(|l| !l.trim().is_empty()).count();
        if line_count > 20 && !has_cookie {
            findings.push((
                "INFO".to_string(),
                *func_addr,
                func_name.clone(),
                "missing stack cookie in large function".to_string(),
                String::new(),
            ));
        }
    }

    // Section-level anomaly scan: entropy (packed/encrypted) + PE overlay
    let mut sec_list: Vec<(String, &[u8], u64)> = Vec::new();
    let mut overlay: Option<&[u8]> = None;
    match &obj {
        goblin::Object::PE(pe) => {
            let mut end_fo: usize = 0;
            for sec in &pe.sections {
                let name = String::from_utf8_lossy(&sec.name)
                    .trim_end_matches('\0')
                    .to_string();
                let fo = sec.pointer_to_raw_data as usize;
                let sz = sec.size_of_raw_data as usize;
                if fo == 0 || sz == 0 {
                    continue;
                }
                let end = fo.saturating_add(sz).min(data.len());
                if fo < end {
                    sec_list.push((
                        name,
                        &data[fo..end],
                        sec.virtual_address as u64 + pe.image_base as u64,
                    ));
                    if end > end_fo {
                        end_fo = end;
                    }
                }
            }
            if end_fo < data.len() {
                overlay = Some(&data[end_fo..]);
            }
        }
        goblin::Object::Elf(elf) => {
            for sh in &elf.section_headers {
                if sh.sh_type != goblin::elf::section_header::SHT_PROGBITS {
                    continue;
                }
                let fo = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                if sz == 0 {
                    continue;
                }
                let end = fo.saturating_add(sz).min(data.len());
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                if fo < end {
                    sec_list.push((name, &data[fo..end], sh.sh_addr));
                }
            }
        }
        goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
            for seg in &m.segments {
                for sec_result in seg {
                    if let Ok((sec, sec_data)) = sec_result {
                        let name = sec.name().unwrap_or("").to_string();
                        if !sec_data.is_empty() {
                            sec_list.push((name, sec_data, sec.addr));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let sec_findings = rsleigh_decompile::analysis::scan_section_anomalies(&sec_list, overlay);
    for f in sec_findings {
        findings.push((f.severity, f.address, f.function, f.description, f.context));
    }

    // Sort by severity
    let severity_order = |s: &str| match s {
        "CRIT" => 0,
        "HIGH" => 1,
        "MED" => 2,
        "LOW" => 3,
        _ => 4,
    };
    findings.sort_by(|a, b| severity_order(&a.0).cmp(&severity_order(&b.0)));

    // Output
    println!(
        "=== Vulnerability Scan: {} ({} functions) ===",
        binary_path,
        symbols.len()
    );
    println!();
    let crit = findings.iter().filter(|f| f.0 == "CRIT").count();
    let high = findings.iter().filter(|f| f.0 == "HIGH").count();
    let med = findings.iter().filter(|f| f.0 == "MED").count();
    let low = findings.iter().filter(|f| f.0 == "LOW").count();
    println!(
        "Summary: {} CRIT, {} HIGH, {} MED, {} LOW ({} total findings)",
        crit,
        high,
        med,
        low,
        findings.len()
    );
    println!();
    for (severity, addr, name, vuln, context) in &findings {
        let color = match severity.as_str() {
            "CRIT" => "\x1b[91m",
            "HIGH" => "\x1b[31m",
            "MED" => "\x1b[33m",
            "LOW" => "\x1b[36m",
            _ => "\x1b[37m",
        };
        println!(
            "  {}{:<4}\x1b[0m  0x{:012x}  {:<25} {}",
            color, severity, addr, name, vuln
        );
        if !context.is_empty() {
            println!("        {}", context);
        }
    }
}

/// Export full call graph as JSON.
fn run_callgraph(binary_path: &str, data: &[u8]) {
    let obj = match goblin::Object::parse(data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let (arch, segs, mut symbols) = match parse_binary(&obj, data) {
        Some(r) => r,
        None => {
            eprintln!("Unsupported");
            return;
        }
    };
    if symbols.is_empty() {
        if let goblin::Object::PE(pe) = &obj {
            let base = pe.image_base as u64;
            let entry = base
                + pe.header
                    .optional_header
                    .unwrap()
                    .standard_fields
                    .address_of_entry_point as u64;
            symbols = discover_pe_functions(entry, &segs, data, arch);
        }
    }
    let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
        elf.syms.len() == 0
    } else {
        false
    };
    if is_elf_stripped {
        if let goblin::Object::Elf(elf) = &obj {
            let discovered = discover_elf_functions(elf, &segs, data, arch);
            let existing: std::collections::BTreeSet<u64> =
                symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in discovered {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    let path = std::path::Path::new(binary_path);
    let mut dec = rsleigh_api::Decoder::new(arch);
    let mut graph: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();

    eprintln!("Building call graph for {} functions...", symbols.len());

    for (func_addr, func_name) in &symbols {
        let insts = decode_func(*func_addr, &symbols, &segs, data, &mut dec);
        if insts.is_empty() {
            continue;
        }

        let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
        })) {
            Ok(o) => o,
            Err(_) => continue,
        };

        // Extract callees from pseudocode
        let mut calls = Vec::new();
        for line in output.lines() {
            let t = line.trim();
            if t.contains('(') && !t.starts_with("//") {
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
        }

        // Classify function behavior
        let mut tags = Vec::new();
        if calls.iter().any(|c| {
            [
                "recv", "send", "socket", "connect", "accept", "bind", "listen",
            ]
            .contains(&c.as_str())
        }) {
            tags.push("network");
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
                "read",
                "write",
            ]
            .contains(&c.as_str())
        }) {
            tags.push("file_io");
        }
        if calls
            .iter()
            .any(|c| c.contains("Reg") || c.contains("Registry"))
        {
            tags.push("registry");
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
            tags.push("exec");
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
            tags.push("memory");
        }
        if output.contains("AES")
            || output.contains("SHA")
            || output.contains("CRC")
            || output.contains("^ 0x")
        {
            tags.push("crypto");
        }
        if calls
            .iter()
            .any(|c| ["printf", "puts", "fprintf", "sprintf", "snprintf"].contains(&c.as_str()))
        {
            tags.push("output");
        }
        if calls
            .iter()
            .any(|c| ["scanf", "gets", "fgets", "getenv", "getchar"].contains(&c.as_str()))
        {
            tags.push("input");
        }

        let return_type = output
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or("void");

        graph.insert(
            func_name.clone(),
            serde_json::json!({
                "address": format!("0x{:x}", func_addr),
                "calls": calls,
                "return_type": return_type,
                "tags": tags,
            }),
        );
    }

    // Build called_by reverse map
    let mut called_by: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (func_name, info) in &graph {
        if let Some(calls) = info.get("calls").and_then(|c| c.as_array()) {
            for callee in calls {
                if let Some(callee_name) = callee.as_str() {
                    called_by
                        .entry(callee_name.to_string())
                        .or_default()
                        .push(func_name.clone());
                }
            }
        }
    }

    // Merge called_by into graph
    let mut final_graph = serde_json::Map::new();
    for (name, info) in &graph {
        let mut entry = info.clone();
        if let Some(callers) = called_by.get(name) {
            entry
                .as_object_mut()
                .unwrap()
                .insert("called_by".to_string(), serde_json::json!(callers));
        }
        final_graph.insert(name.clone(), entry);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": binary_path,
            "arch": format!("{:?}", arch),
            "function_count": graph.len(),
            "callgraph": final_graph,
        }))
        .unwrap()
    );
}

/// Demangle a C++/Swift symbol name for display, falling back to the raw
/// name when demangling fails. Strips the parameter list tail to keep the
/// one-line listing compact: `QObject::connect(QObject const*, ...)` →
/// `QObject::connect`. `.cold.NN` / `.part.NN` / `.constprop.N` suffixes
/// (GCC IPA clones) are preserved so the analyst can distinguish variants.
fn demangle_symbol(name: &str) -> String {
    // Keep GCC/clang IPA suffixes intact on the original-name fallback.
    let (core, suffix) = match name.find('.') {
        Some(p)
            if name[p..].starts_with(".cold")
                || name[p..].starts_with(".part")
                || name[p..].starts_with(".constprop")
                || name[p..].starts_with(".isra")
                || name[p..].starts_with(".lto_priv") =>
        {
            (&name[..p], &name[p..])
        }
        _ => (name, ""),
    };
    if !(core.starts_with("_Z") || core.starts_with("__Z")) {
        return name.to_string();
    }
    let Ok(sym) = cpp_demangle::Symbol::new(core.as_bytes()) else {
        return name.to_string();
    };
    let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) else {
        return name.to_string();
    };
    // Trim parameter list — matching rsleigh-decompile::imports::demangle_name.
    let pretty = if let Some(paren) = demangled.find('(') {
        let before = &demangled[..paren];
        if !before.is_empty() && !before.ends_with('>') {
            before.to_string()
        } else {
            demangled
        }
    } else {
        demangled
    };
    if suffix.is_empty() {
        pretty
    } else {
        format!("{}{}", pretty, suffix)
    }
}

/// Load FID databases from `--fid <path>` args and apply fingerprint
/// matches to anonymous `func_*` / `sub_*` / `FUN_*` symbols.
fn apply_fid_to_symbols(
    data: &[u8],
    arch: rsleigh_api::Architecture,
    segs: &[(u64, u64, u64)],
    symbols: &mut [(u64, String)],
    args: &[String],
) {
    let mut dbs: Vec<rsleigh_fid::FidDb> = Vec::new();
    // Auto-load bundled glibc/musl/libstdc++ DBs unless --no-fid-auto.
    if !args.iter().any(|a| a == "--no-fid-auto") {
        for (lib, db) in rsleigh_fid::bundled_dbs(arch) {
            eprintln!("[fid] bundled {}: {} entries", lib, db.entries.len());
            dbs.push(db);
        }
    }
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--fid" {
            if let Some(p) = args.get(i + 1) {
                match std::fs::File::open(p)
                    .and_then(|f| rsleigh_fid::FidDb::read(f).map_err(Into::into))
                {
                    Ok(db) => {
                        eprintln!("[fid] loaded {} entries from {}", db.entries.len(), p);
                        dbs.push(db);
                    }
                    Err(e) => eprintln!("[fid] skip {}: {}", p, e),
                }
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    if dbs.is_empty() {
        return;
    }
    let quiet_banner = args.iter().any(|a| a == "--fid-quiet");
    let _ = quiet_banner;
    let va_slice = |va: u64| -> Option<&[u8]> {
        for (vstart, vend, foff) in segs {
            if va >= *vstart && va < *vend {
                let rel = (va - vstart) as usize;
                let fstart = *foff as usize + rel;
                let vsize = (vend - va) as usize;
                let end = fstart.saturating_add(vsize).min(data.len());
                if fstart < data.len() {
                    return Some(&data[fstart..end]);
                }
            }
        }
        None
    };
    let mut hits = 0usize;
    for (addr, name) in symbols.iter_mut() {
        let anon =
            name.starts_with("func_") || name.starts_with("sub_") || name.starts_with("FUN_");
        if !anon {
            continue;
        }
        let Some(body) = va_slice(*addr) else {
            continue;
        };
        // Cap body at 4KB — most real funcs are well under this.
        let body = &body[..body.len().min(4096)];
        for db in &dbs {
            if let Some(matched) = rsleigh_fid::identify(arch, body, *addr, db) {
                *name = matched.to_string();
                hits += 1;
                break;
            }
        }
    }
    if hits > 0 {
        eprintln!("[fid] matched {} anonymous symbols", hits);
    }
}

/// Compute MD5 hash of data, return lowercase hex string.
fn compute_md5(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compute SHA-256 hash of data, return lowercase hex string.
fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Mandiant imphash: MD5 of the comma-joined, lowercased `dll.function`
/// entries built from the PE import table. DLL extensions are stripped to
/// a known short set; ordinal-only imports are encoded as `ord<N>`.
///
/// Returns None for non-PE binaries or PE files with no imports.
///
/// Spec: github.com/mandiant/pefile (imphash()).
fn compute_imphash(data: &[u8]) -> Option<String> {
    use md5::{Digest, Md5};
    let obj = goblin::Object::parse(data).ok()?;
    let pe = match obj {
        goblin::Object::PE(pe) => pe,
        _ => return None,
    };
    if pe.imports.is_empty() {
        return None;
    }

    // Mandiant's normalization:
    //  - lowercase DLL name
    //  - strip extension if it's one of:
    //      .dll, .ocx, .sys, .drv, .cpl, .exe
    //  - function name: lowercase as-is; ordinal → "ord<num>"
    let strip_exts = [".dll", ".ocx", ".sys", ".drv", ".cpl", ".exe"];
    let mut entries: Vec<String> = Vec::new();
    for imp in &pe.imports {
        let mut dll = imp.dll.to_ascii_lowercase();
        for ext in &strip_exts {
            if dll.ends_with(ext) {
                dll.truncate(dll.len() - ext.len());
                break;
            }
        }
        // goblin's pe.imports gives named symbols directly; ordinals come
        // through as names like "Ordinal_123" or empty. Use the Import's
        // name field: if it looks like an ordinal placeholder, rewrite.
        let name = imp.name.to_ascii_lowercase();
        let fn_name = if name.starts_with("ordinal_") {
            // "ordinal_123" → "ord123"
            format!("ord{}", &name[8..])
        } else if name.is_empty() {
            // Truly unnamed ordinal — fall back to ordinal field
            format!("ord{}", imp.ordinal)
        } else {
            name
        };
        entries.push(format!("{}.{}", dll, fn_name));
    }

    // Mandiant preserves import-table order (NOT sorted). Deduplication: no.
    let joined = entries.join(",");
    let mut h = Md5::new();
    h.update(joined.as_bytes());
    Some(h.finalize().iter().map(|b| format!("{:02x}", b)).collect())
}

fn generate_yara_rule(binary_path: &str, data: &[u8]) {
    use std::collections::{BTreeMap, BTreeSet};

    let filename = std::path::Path::new(binary_path)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_");
    let rule_name = format!("rsleigh_{}", filename);

    let mut strings: BTreeSet<String> = BTreeSet::new();
    let mut wide_strings: BTreeSet<String> = BTreeSet::new();
    let mut hex_patterns: Vec<(String, String)> = Vec::new(); // (name, hex)
    let mut imports: BTreeSet<String> = BTreeSet::new();
    let mut meta: BTreeMap<String, String> = BTreeMap::new();

    // Meta information
    meta.insert("tool".into(), "rsleigh".into());
    meta.insert("date".into(), chrono_date());
    let file_size = data.len();
    meta.insert("filesize".into(), format!("{}", file_size));

    // Detect format
    let is_pe = data.len() > 2 && &data[0..2] == b"MZ";
    let is_elf = data.len() > 4 && &data[0..4] == b"\x7fELF";
    if is_pe {
        meta.insert("filetype".into(), "PE".into());
    }
    if is_elf {
        meta.insert("filetype".into(), "ELF".into());
    }

    // 1. Extract ASCII strings (6+ chars, printable, not too common)
    {
        let mut pos = 0;
        while pos < data.len() {
            if data[pos] >= 0x20 && data[pos] < 0x7f {
                let start = pos;
                while pos < data.len() && data[pos] >= 0x20 && data[pos] < 0x7f {
                    pos += 1;
                }
                let len = pos - start;
                if len >= 6 && len <= 200 {
                    if let Ok(s) = std::str::from_utf8(&data[start..pos]) {
                        let s = s.trim();
                        // Filter out common/generic strings
                        let is_charset = s.contains("ABCDEFGHIJ") && s.contains("abcdefghij");
                        let is_sequential = s
                            .bytes()
                            .zip(s.bytes().skip(1))
                            .filter(|(a, b)| *b == a + 1)
                            .count()
                            > s.len() / 2;
                        if s.len() >= 6
                            && !is_charset && !is_sequential
                            && !s.chars().all(|c| c == ' ' || c == '.' || c == '-' || c == '0')
                            && !s.starts_with("GCC:")
                            && !s.starts_with("GNU ")
                            && !s.starts_with("!This program")
                            && !s.contains("Copyright")
                            && !s.contains("GLIBC")
                            && !s.starts_with(".debug")
                            && !s.starts_with(".note")
                            && !s.starts_with(".symtab")
                            && !s.starts_with(".strtab")
                            && !s.starts_with('`') // MSVC demangled names (generic)
                            && !s.contains("Descriptor")
                            && !s.contains("constructor")
                            && !s.contains("destructor")
                            && !s.starts_with("AppPolicy") // CRT internal
                            && !s.contains("template-parameter")
                            && !s.contains("Hierarchy")
                        {
                            strings.insert(s.to_string());
                        }
                    }
                }
            } else {
                pos += 1;
            }
        }
    }

    // 2. Extract wide strings (UTF-16LE, for PE binaries)
    if is_pe {
        let mut pos = 0;
        while pos + 1 < data.len() {
            if data[pos] >= 0x20 && data[pos] < 0x7f && data[pos + 1] == 0 {
                let start = pos;
                while pos + 1 < data.len()
                    && data[pos] >= 0x20
                    && data[pos] < 0x7f
                    && data[pos + 1] == 0
                {
                    pos += 2;
                }
                let char_count = (pos - start) / 2;
                if char_count >= 6 && char_count <= 100 {
                    let chars: String = data[start..pos]
                        .chunks(2)
                        .filter_map(|c| {
                            if c.len() == 2 {
                                Some(c[0] as char)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !strings.contains(&chars) {
                        // don't duplicate ASCII
                        wide_strings.insert(chars);
                    }
                }
            } else {
                pos += 1;
            }
        }
    }

    // 3. Extract imports (PE + ELF)
    if let Ok(obj) = goblin::Object::parse(data) {
        match &obj {
            goblin::Object::PE(pe) => {
                for imp in &pe.imports {
                    imports.insert(imp.name.to_string());
                }
                if let Some(name) = pe.name {
                    meta.insert("original_name".into(), name.to_string());
                }
            }
            goblin::Object::Elf(elf) => {
                for sym in elf.dynsyms.iter() {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() && name.len() > 3 {
                            imports.insert(name.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // 4. Detect crypto constants
    let crypto_sigs: &[(&str, &[u8])] = &[
        (
            "aes_sbox",
            &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],
        ),
        (
            "sha256_k",
            &[0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71],
        ),
        (
            "sha256_k_be",
            &[0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91],
        ),
        ("md5_t", &[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8]),
        (
            "crc32_table",
            &[0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77],
        ),
        ("chacha20", b"expand 32-byte k"),
        (
            "blowfish_p",
            &[0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3],
        ),
    ];
    for (name, pattern) in crypto_sigs {
        if data.windows(pattern.len()).any(|w| w == *pattern) {
            let hex = pattern
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            hex_patterns.push((format!("crypto_{}", name), hex));
        }
    }

    // 5. Extract unique byte patterns from entry point / first function
    if let Ok(obj) = goblin::Object::parse(data) {
        let entry_bytes = match &obj {
            goblin::Object::PE(pe) => {
                let entry_rva = pe
                    .header
                    .optional_header
                    .map(|h| h.standard_fields.address_of_entry_point as usize)
                    .unwrap_or(0);
                pe.sections.iter().find_map(|s| {
                    let sr = s.virtual_address as usize;
                    if entry_rva >= sr && entry_rva < sr + s.virtual_size as usize {
                        let fo = s.pointer_to_raw_data as usize + (entry_rva - sr);
                        if fo + 32 <= data.len() {
                            Some(&data[fo..fo + 32])
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
            }
            goblin::Object::Elf(elf) => {
                let entry = elf.header.e_entry as usize;
                elf.section_headers.iter().find_map(|sh| {
                    if entry >= sh.sh_addr as usize && entry < (sh.sh_addr + sh.sh_size) as usize {
                        let fo = sh.sh_offset as usize + (entry - sh.sh_addr as usize);
                        if fo + 32 <= data.len() {
                            Some(&data[fo..fo + 32])
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
            }
            _ => None,
        };
        if let Some(bytes) = entry_bytes {
            let hex = bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            hex_patterns.push(("entry_point".into(), hex));
        }
    }

    // 6. Select best strings for the rule (most unique, not too long)
    // Score strings: prefer longer, with special chars, not common words
    let mut scored_strings: Vec<(i32, &String)> = strings
        .iter()
        .map(|s| {
            let mut score = s.len() as i32;
            if s.contains('/') || s.contains('\\') {
                score += 5;
            } // paths
            if s.contains("http") || s.contains("://") {
                score += 10;
            } // URLs
            if s.contains(".dll") || s.contains(".exe") || s.contains(".sys") {
                score += 10;
            }
            if s.contains("password") || s.contains("secret") || s.contains("key") {
                score += 15;
            }
            if s.contains("cmd") || s.contains("shell") || s.contains("exec") {
                score += 10;
            }
            if s.starts_with("Error") || s.starts_with("Warning") {
                score -= 5;
            }
            // Penalize very common strings
            if s.len() > 50 {
                score -= 10;
            }
            (score, s)
        })
        .collect();
    scored_strings.sort_by(|a, b| b.0.cmp(&a.0));

    // Select top 20 strings
    let selected_strings: Vec<&String> = scored_strings.iter().take(20).map(|(_, s)| *s).collect();

    // Select top 5 wide strings
    let selected_wide: Vec<&String> = wide_strings.iter().take(5).collect();

    // Select suspicious imports
    let suspicious_imports: Vec<&String> = imports
        .iter()
        .filter(|i| {
            let il = i.to_lowercase();
            il.contains("virtualalloc")
                || il.contains("writeprocessmemory")
                || il.contains("createremotethread")
                || il.contains("ntcreatethreadex")
                || il.contains("loadlibrary")
                || il.contains("getprocaddress")
                || il.contains("cryptencrypt")
                || il.contains("internetopen")
                || il.contains("urldownload")
                || il.contains("shellexecute")
                || il.contains("regsetvalue")
                || il.contains("createservice")
                || il.contains("socket")
                || il.contains("connect")
                || il.contains("recv")
                || il.contains("send")
                || il.contains("exec")
                || il.contains("system")
                || il.contains("popen")
                || il.contains("fork")
        })
        .take(10)
        .collect();

    // Output YARA rule
    println!("rule {} {{", rule_name);
    println!("    meta:");
    for (k, v) in &meta {
        println!("        {} = \"{}\"", k, v);
    }
    println!("        description = \"Auto-generated by rsleigh decompiler\"");
    println!();

    println!("    strings:");
    let mut str_idx = 0;
    for s in &selected_strings {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        println!("        $s{} = \"{}\"", str_idx, escaped);
        str_idx += 1;
    }
    for s in &selected_wide {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        println!("        $w{} = \"{}\" wide", str_idx, escaped);
        str_idx += 1;
    }
    for (name, hex) in &hex_patterns {
        println!("        $h_{} = {{ {} }}", name, hex);
    }
    for (i, imp) in suspicious_imports.iter().enumerate() {
        println!("        $imp{} = \"{}\"", i, imp);
    }
    println!();

    // Condition: require several strings + optional hex patterns
    let total_str_count = selected_strings.len() + selected_wide.len();
    let min_match = (total_str_count / 3).max(3).min(total_str_count);
    println!("    condition:");
    let mut conditions = Vec::new();
    if is_pe {
        conditions.push("uint16(0) == 0x5A4D".to_string()); // MZ header
    } else if is_elf {
        conditions.push("uint32(0) == 0x464C457F".to_string()); // \x7fELF
    }
    if total_str_count > 0 {
        conditions.push(format!("{} of ($s*, $w*)", min_match));
    }
    if !hex_patterns.is_empty() {
        conditions.push("any of ($h_*)".to_string());
    }
    if !suspicious_imports.is_empty() {
        conditions.push(format!("{} of ($imp*)", suspicious_imports.len().min(3)));
    }
    if conditions.is_empty() {
        conditions.push("true".to_string());
    }
    println!("        {}", conditions.join(" and\n        "));
    println!("}}");
}

fn chrono_date() -> String {
    // Simple date without chrono dependency
    "2026-04-13".to_string()
}

fn run_raw(
    data: &[u8],
    arch: rsleigh_api::Architecture,
    base: u64,
    args: &[String],
    all_mode: bool,
) {
    eprintln!(
        "Architecture: {:?} (raw binary, base=0x{:x}, size={})",
        arch,
        base,
        data.len()
    );

    // Treat entire file as one code segment
    let segs = vec![(base, data.len() as u64, 0u64)];

    // Discover functions via CALL scanning
    let mut found = std::collections::BTreeSet::new();
    found.insert(base); // entry at base

    let mut dec = rsleigh_api::Decoder::new(arch);
    let code_end = base + data.len() as u64;

    // Architecture-specific CALL scanning
    match arch {
        rsleigh_api::Architecture::MIPS32 => {
            // MIPS JAL: 000011 imm26 → opcode 0x0C000000
            for i in (0..data.len().saturating_sub(3)).step_by(4) {
                let word = u32::from_be_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
                if (word >> 26) == 3 {
                    // JAL
                    let target =
                        ((base + i as u64) & 0xF0000000) | ((word & 0x03FFFFFF) as u64) << 2;
                    if target >= base && target < code_end {
                        found.insert(target);
                    }
                }
            }
            // Also try little-endian MIPS
            let mut found_le = std::collections::BTreeSet::new();
            for i in (0..data.len().saturating_sub(3)).step_by(4) {
                let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
                if (word >> 26) == 3 {
                    let target =
                        ((base + i as u64) & 0xF0000000) | ((word & 0x03FFFFFF) as u64) << 2;
                    if target >= base && target < code_end {
                        found_le.insert(target);
                    }
                }
            }
            // Use whichever endianness found more targets
            if found_le.len() > found.len() * 2 {
                found = found_le;
                found.insert(base);
                eprintln!("Detected: MIPS little-endian ({} JAL targets)", found.len());
            } else {
                eprintln!("Detected: MIPS big-endian ({} JAL targets)", found.len());
            }
        }
        rsleigh_api::Architecture::ARM32 => {
            for i in (0..data.len().saturating_sub(3)).step_by(4) {
                let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
                if (word & 0x0F000000) == 0x0B000000 {
                    // BL
                    let imm24 = word & 0x00FFFFFF;
                    let offset = if imm24 & 0x800000 != 0 {
                        ((imm24 | 0xFF000000) as i32) << 2
                    } else {
                        (imm24 as i32) << 2
                    };
                    let target = (base as i64 + i as i64 + 8 + offset as i64) as u64;
                    if target >= base && target < code_end {
                        found.insert(target);
                    }
                }
            }
        }
        rsleigh_api::Architecture::X86_64 | rsleigh_api::Architecture::X86_32 => {
            for i in 0..data.len().saturating_sub(5) {
                if data[i] == 0xE8 {
                    let rel = i32::from_le_bytes(data[i + 1..i + 5].try_into().unwrap_or([0; 4]));
                    let target = (base as i64 + i as i64 + 5 + rel as i64) as u64;
                    if target >= base && target < code_end {
                        found.insert(target);
                    }
                }
            }
        }
        _ => {}
    }

    let symbols: Vec<(u64, String)> = found
        .into_iter()
        .map(|addr| (addr, format!("FUN_{:08x}", addr)))
        .collect();

    // Which functions to process? Skip --raw/--base and their values.
    let skip_values: std::collections::HashSet<usize> = {
        let mut s = std::collections::HashSet::new();
        for (i, a) in args.iter().enumerate() {
            if a == "--raw" || a == "--base" {
                s.insert(i);
                s.insert(i + 1);
            }
            if a == "--all" || a == "--json" || a == "--disasm" || a == "--sigs" {
                s.insert(i);
            }
        }
        s
    };
    let func_args: Vec<&str> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| *i >= 2 && !a.starts_with("--") && !skip_values.contains(i))
        .map(|(_, a)| a.as_str())
        .collect();

    if func_args.is_empty() && !all_mode {
        eprintln!("{} functions:", symbols.len());
        for (addr, name) in &symbols {
            println!("  0x{:08x}  {}", addr, name);
        }
    } else {
        let to_decompile: Vec<&(u64, String)> = if all_mode {
            symbols.iter().collect()
        } else {
            symbols
                .iter()
                .filter(|(_, n)| func_args.iter().any(|a| n == a))
                .collect()
        };
        let path = std::path::Path::new("raw.bin");
        for (addr, name) in to_decompile {
            let off = (*addr - base) as usize;
            let max = 4096.min(data.len().saturating_sub(off));
            if max < 4 {
                continue;
            }
            let bytes = &data[off..off + max];
            let mut pos = 0;
            let mut insts = Vec::new();
            let next_func = symbols
                .iter()
                .filter(|(a, _)| *a > *addr)
                .map(|(a, _)| *a)
                .min()
                .unwrap_or(*addr + max as u64);
            let decode_max = ((next_func - *addr) as usize).min(max);
            while pos < decode_max {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    dec.decode(&bytes[pos..], *addr + pos as u64)
                })) {
                    Ok(Ok(inst)) => {
                        let l = inst.len as usize;
                        if l == 0 {
                            pos += 4;
                            continue;
                        }
                        insts.push((*addr + pos as u64, inst));
                        pos += l;
                    }
                    Ok(Err(_)) | Err(_) => {
                        pos += 4;
                    }
                }
            }
            if !insts.is_empty() {
                let output = maybe_annotate_crypto(rsleigh_decompile::decompile_with_binary(
                    arch,
                    &insts,
                    Some(data),
                    Some(path),
                ));
                if !output.trim().is_empty() {
                    println!("// {}", name);
                    println!("{}", output);
                }
            }
        }
    }
}

fn run_wasm(data: &[u8], args: &[String], all_mode: bool) {
    eprintln!("Architecture: WebAssembly");
    let funcs = wasm::parse_wasm(data);

    // Which functions to decompile?
    let func_args: Vec<&str> = args[2..]
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(|a| a.as_str())
        .collect();

    if func_args.is_empty() && !all_mode {
        // List functions
        println!("{} functions:", funcs.len());
        for f in &funcs {
            let params: Vec<&str> = f
                .params
                .iter()
                .map(|t| match t {
                    wasmparser::ValType::I32 => "i32",
                    wasmparser::ValType::I64 => "i64",
                    wasmparser::ValType::F32 => "f32",
                    wasmparser::ValType::F64 => "f64",
                    _ => "?",
                })
                .collect();
            let ret = f
                .results
                .first()
                .map(|t| match t {
                    wasmparser::ValType::I32 => "i32",
                    wasmparser::ValType::I64 => "i64",
                    wasmparser::ValType::F32 => "f32",
                    wasmparser::ValType::F64 => "f64",
                    _ => "?",
                })
                .unwrap_or("void");
            println!(
                "  func[{}]  {:20} ({}) -> {}",
                f.index,
                f.name,
                params.join(", "),
                ret
            );
        }
    } else {
        // Decompile
        let to_decompile: Vec<&wasm::WasmFunc> = if all_mode {
            funcs.iter().collect()
        } else {
            funcs
                .iter()
                .filter(|f| {
                    func_args
                        .iter()
                        .any(|a| f.name == *a || format!("func_{}", f.index) == *a)
                })
                .collect()
        };

        for f in &to_decompile {
            let code = wasm::decompile_wasm_func(data, f, &funcs);
            println!("{}", code);
        }
    }
}

fn parse_binary(
    obj: &goblin::Object,
    _data: &[u8],
) -> Option<(
    rsleigh_api::Architecture,
    Vec<(u64, u64, u64)>,
    Vec<(u64, String)>,
)> {
    match obj {
        goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
            let arch = match m.header.cputype() {
                7 | 0x01000007 => rsleigh_api::Architecture::X86_64,
                12 | 0x0100000c => rsleigh_api::Architecture::AArch64,
                _ => return None,
            };
            let mut segs = Vec::new();
            for seg in &m.segments {
                if let Ok(secs) = seg.sections() {
                    for sec in secs {
                        segs.push((sec.0.addr, sec.0.size, sec.0.offset as u64));
                    }
                }
            }
            let mut syms = Vec::new();
            // Exported/defined symbols
            if let Some(ref st) = m.symbols {
                for s in st.iter() {
                    if let Ok((name, nlist)) = s {
                        if nlist.n_type & 0xe == 0xe && nlist.n_value != 0 {
                            let clean = name.strip_prefix('_').unwrap_or(name);
                            let display =
                                demangle_swift_symbol(clean).unwrap_or_else(|| clean.to_string());
                            syms.push((nlist.n_value, display));
                        }
                    }
                }
            }
            // Parse LC_FUNCTION_STARTS — gives ALL function entry points as ULEB128 deltas.
            // This is the Mach-O equivalent of PE .pdata — the most reliable function discovery.
            let text_vmaddr = m
                .segments
                .iter()
                .find(|s| s.name().ok() == Some("__TEXT"))
                .map(|s| s.vmaddr)
                .unwrap_or(0);
            if text_vmaddr > 0 {
                for lc in &m.load_commands {
                    if let goblin::mach::load_command::CommandVariant::FunctionStarts(ref fs) =
                        lc.command
                    {
                        let off = fs.dataoff as usize;
                        let size = fs.datasize as usize;
                        if off + size <= _data.len() {
                            let mut pos = off;
                            let end = off + size;
                            let mut addr = text_vmaddr;
                            while pos < end {
                                // ULEB128 decode
                                let mut delta: u64 = 0;
                                let mut shift = 0;
                                loop {
                                    if pos >= end {
                                        break;
                                    }
                                    let b = _data[pos] as u64;
                                    pos += 1;
                                    delta |= (b & 0x7f) << shift;
                                    shift += 7;
                                    if b & 0x80 == 0 {
                                        break;
                                    }
                                }
                                if delta == 0 {
                                    break;
                                }
                                addr += delta;
                                // Add if not already in symbol list
                                if !syms.iter().any(|(a, _)| *a == addr) {
                                    syms.push((addr, format!("FUN_{:x}", addr)));
                                }
                            }
                        }
                    }
                }
            }
            // Parse ObjC method lists for implementation addresses.
            // __objc_methlist contains relative method lists with IMP pointers.
            // __objc_const in __DATA contains class_ro_t with baseMethods pointers.
            for seg in &m.segments {
                if let Ok(secs) = seg.sections() {
                    for (sec, _sec_data) in secs {
                        let sname = std::str::from_utf8(&sec.sectname)
                            .unwrap_or("")
                            .trim_end_matches('\0');
                        // __objc_stubs: each entry is a small stub (ADRP+LDR+BR on ARM64,
                        // JMP on x86_64). Every stub_size-aligned address is a function.
                        if sname == "__objc_stubs" || sname == "__stubs" {
                            let _soff = sec.offset as usize;
                            let ssize = sec.size as usize;
                            let saddr = sec.addr;
                            // Determine stub size: ARM64=12 bytes, x86_64=8 bytes
                            let stub_size: usize =
                                if matches!(arch, rsleigh_api::Architecture::AArch64) {
                                    12
                                } else {
                                    8
                                };
                            let mut pos = 0usize;
                            while pos + stub_size <= ssize {
                                let addr = saddr + pos as u64;
                                if !syms.iter().any(|(a, _)| *a == addr) {
                                    syms.push((addr, format!("objc_stub_{:x}", addr)));
                                }
                                pos += stub_size;
                            }
                        }
                        if sname == "__objc_methlist" {
                            // Relative method lists (modern ObjC, ARM64)
                            // Each method_list_t: uint32_t entsize_and_flags, uint32_t count
                            // Then count × method_t entries (relative offsets)
                            let soff = sec.offset as usize;
                            let ssize = sec.size as usize;
                            let saddr = sec.addr;
                            let mut pos = 0usize;
                            while pos + 8 <= ssize && soff + pos + 8 <= _data.len() {
                                let entsize_flags = u32::from_le_bytes(
                                    _data[soff + pos..soff + pos + 4]
                                        .try_into()
                                        .unwrap_or([0; 4]),
                                );
                                let count = u32::from_le_bytes(
                                    _data[soff + pos + 4..soff + pos + 8]
                                        .try_into()
                                        .unwrap_or([0; 4]),
                                );
                                let entsize = (entsize_flags & 0x3FFFFFFF) as usize;
                                let is_relative = entsize_flags & 0x80000000 != 0;

                                if count > 1000 || entsize == 0 || entsize > 64 {
                                    pos += 8;
                                    continue;
                                }
                                let _list_start = pos;

                                for m_idx in 0..count as usize {
                                    let m_off = soff + pos + 8 + m_idx * entsize;
                                    if m_off + entsize > _data.len() {
                                        break;
                                    }

                                    if is_relative && entsize >= 12 {
                                        // Relative method_t: int32_t name, int32_t types, int32_t imp
                                        // imp is relative to its own address
                                        let imp_field_addr =
                                            saddr + (pos + 8 + m_idx * entsize + 8) as u64;
                                        let imp_rel = i32::from_le_bytes(
                                            _data[m_off + 8..m_off + 12]
                                                .try_into()
                                                .unwrap_or([0; 4]),
                                        );
                                        let imp =
                                            imp_field_addr.wrapping_add(imp_rel as i64 as u64);
                                        if !syms.iter().any(|(a, _)| *a == imp) {
                                            syms.push((imp, format!("objc_method_{:x}", imp)));
                                        }
                                    } else if !is_relative && entsize >= 24 {
                                        // Absolute method_t: ptr name, ptr types, ptr imp
                                        let imp = u64::from_le_bytes(
                                            _data[m_off + 16..m_off + 24]
                                                .try_into()
                                                .unwrap_or([0; 8]),
                                        );
                                        if imp > 0 && !syms.iter().any(|(a, _)| *a == imp) {
                                            syms.push((imp, format!("objc_method_{:x}", imp)));
                                        }
                                    }
                                }
                                pos += 8 + count as usize * entsize;
                                // Align to 4 bytes
                                if pos % 4 != 0 {
                                    pos += 4 - (pos % 4);
                                }
                            }
                        }
                    }
                }
            }

            Some((arch, segs, syms))
        }
        goblin::Object::Elf(elf) => {
            let arch = match elf.header.e_machine {
                0x3E => rsleigh_api::Architecture::X86_64,
                0xB7 => rsleigh_api::Architecture::AArch64,
                0x28 => rsleigh_api::Architecture::ARM32,
                0x08 => rsleigh_api::Architecture::MIPS32,
                0xF3 => rsleigh_api::Architecture::RiscV64,
                _ => return None,
            };
            let segs = elf
                .section_headers
                .iter()
                .filter(|sh| sh.sh_flags & 0x4 != 0)
                .map(|sh| (sh.sh_addr, sh.sh_size, sh.sh_offset))
                .collect();
            let mut syms = Vec::new();
            for sym in elf.syms.iter() {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            syms.push((sym.st_value, demangle_symbol(name)));
                        }
                    }
                }
            }
            for sym in elf.dynsyms.iter() {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            syms.push((sym.st_value, demangle_symbol(name)));
                        }
                    }
                }
            }
            Some((arch, segs, syms))
        }
        goblin::Object::PE(pe) => {
            // Detect architecture from PE machine type
            let arch = match pe.header.coff_header.machine {
                0xAA64 => rsleigh_api::Architecture::AArch64, // ARM64
                0x8664 => rsleigh_api::Architecture::X86_64,  // AMD64
                0x014C => rsleigh_api::Architecture::X86_32,  // i386
                0x01C4 => rsleigh_api::Architecture::ARM32,   // ARMv7
                _ => {
                    if pe.is_64 {
                        rsleigh_api::Architecture::X86_64
                    } else {
                        rsleigh_api::Architecture::X86_32
                    }
                }
            };
            let base = pe.image_base as u64;
            let segs = pe
                .sections
                .iter()
                .filter(|s| s.characteristics & 0x20000000 != 0)
                .map(|s| {
                    (
                        base + s.virtual_address as u64,
                        s.virtual_size as u64,
                        s.pointer_to_raw_data as u64,
                    )
                })
                .collect();
            let mut syms = Vec::new();
            for exp in pe.exports.iter() {
                if let Some(name) = exp.name {
                    if exp.rva != 0 {
                        syms.push((base + exp.rva as u64, name.to_string()));
                    }
                }
            }
            Some((arch, segs, syms))
        }
        _ => None,
    }
}

/// Discover functions in a stripped PE by recursive descent from entry point.
/// Follows direct CALL targets to find function boundaries.
fn discover_pe_functions(
    entry: u64,
    segs: &[(u64, u64, u64)],
    data: &[u8],
    arch: rsleigh_api::Architecture,
) -> Vec<(u64, String)> {
    use std::collections::{BTreeSet, VecDeque};

    let mut found = BTreeSet::new();
    let mut queue = VecDeque::new();
    found.insert(entry);
    queue.push_back(entry);

    let mut dec = rsleigh_api::Decoder::new(arch);

    while let Some(func_addr) = queue.pop_front() {
        // Translate VA to file offset
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if func_addr >= *va && func_addr < va + sz {
                Some(fo + (func_addr - va))
            } else {
                None
            }
        });
        let Some(off) = off else { continue };
        let max = 4096.min(data.len().saturating_sub(off as usize));
        if max == 0 {
            continue;
        }
        let bytes = &data[off as usize..off as usize + max];

        let mut io = 0usize;
        while io < max {
            let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec.decode(&bytes[io..], func_addr + io as u64)
            }));
            match ok {
                Ok(Ok(inst)) => {
                    let l = inst.len as usize;
                    if l == 0 {
                        io += 1;
                        continue;
                    }
                    // Look for CALL with direct target
                    for op in &inst.ops {
                        if let pcode_ir::PcodeOp::Call { dest, .. } = op {
                            if dest.space == pcode_ir::AddressSpaceId::Ram {
                                let call_target = dest.offset;
                                // Only follow targets in executable segments
                                let in_seg = segs
                                    .iter()
                                    .any(|(va, sz, _)| call_target >= *va && call_target < va + sz);
                                if in_seg && !found.contains(&call_target) {
                                    found.insert(call_target);
                                    queue.push_back(call_target);
                                }
                            }
                        }
                    }
                    // Stop at RET
                    if inst
                        .ops
                        .iter()
                        .any(|op| matches!(op, pcode_ir::PcodeOp::Return { .. }))
                    {
                        break;
                    }
                    io += l;
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    io += 1;
                }
            }
        }
    }

    // Phase 2a: Parse .pdata exception directory for PE64 (gives exact function boundaries)
    if let Ok(obj) = goblin::Object::parse(data) {
        if let goblin::Object::PE(pe) = &obj {
            if pe.is_64 {
                let base = pe.image_base as u64;
                for sec in &pe.sections {
                    let name = std::str::from_utf8(&sec.name)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    if name == ".pdata" {
                        let fo = sec.pointer_to_raw_data as usize;
                        let sz = sec.virtual_size.min(sec.size_of_raw_data) as usize;
                        if fo + sz <= data.len() {
                            // Entry size depends on architecture:
                            // x86-64: 12 bytes (BeginAddress:4, EndAddress:4, UnwindData:4)
                            // ARM64:  8 bytes (BeginAddress:4, UnwindData:4)
                            let pe_off_local =
                                u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0; 4]))
                                    as usize;
                            let machine = u16::from_le_bytes([
                                data[pe_off_local + 4],
                                data[pe_off_local + 5],
                            ]);
                            let entry_size: usize = if machine == 0xAA64 { 8 } else { 12 };

                            let mut off = 0;
                            while off + entry_size <= sz {
                                let begin_rva = u32::from_le_bytes([
                                    data[fo + off],
                                    data[fo + off + 1],
                                    data[fo + off + 2],
                                    data[fo + off + 3],
                                ]) as u64;
                                if begin_rva == 0 {
                                    break;
                                }
                                let func_va = base + begin_rva;
                                if !found.contains(&func_va) {
                                    let in_seg = segs
                                        .iter()
                                        .any(|(va, sz, _)| func_va >= *va && func_va < va + sz);
                                    if in_seg {
                                        found.insert(func_va);
                                    }
                                }
                                off += entry_size;
                            }
                        }
                    }
                }
            }
        }
    }

    let is_aarch64 = matches!(
        arch,
        rsleigh_api::Architecture::AArch64 | rsleigh_api::Architecture::ARM32
    );

    // Phase 2b: Prologue scanning — find functions not reached by direct CALL.
    // Scan executable sections for common function prologues:
    //   55 8B EC       push ebp; mov ebp, esp  (x86-32 standard)
    //   55 89 E5       push ebp; mov esp, ebp  (GCC variant)
    //   48 89 5C 24    mov [rsp+...], rbx      (x86-64 MS ABI)
    //   48 83 EC       sub rsp, imm8           (x86-64 leaf)
    for (seg_va, seg_sz, seg_fo) in segs {
        let fo = *seg_fo as usize;
        let sz = (*seg_sz as usize).min(data.len().saturating_sub(fo));
        if fo + sz > data.len() {
            continue;
        }
        let bytes = &data[fo..fo + sz];

        let mut off = 0usize;
        while off + 3 <= sz {
            let va = seg_va + off as u64;
            if !found.contains(&va) {
                let boundary = off == 0 || matches!(bytes[off - 1], 0xC3 | 0xCC | 0x90 | 0x00);
                let is_prologue =
                    // === x86-32 patterns ===
                    // push ebp; mov ebp, esp (55 8B EC / 55 89 E5)
                    (bytes[off] == 0x55 && off + 3 <= sz
                        && ((bytes[off+1] == 0x8B && bytes[off+2] == 0xEC)
                            || (bytes[off+1] == 0x89 && bytes[off+2] == 0xE5)))
                    // push esi/edi at boundary — only if followed by another push or sub esp
                    || (off + 2 <= sz && (bytes[off] == 0x56 || bytes[off] == 0x57)
                        && boundary && off > 0
                        && matches!(bytes[off+1], 0x53 | 0x55 | 0x56 | 0x57 | 0x83 | 0x8B))
                    // mov reg, [esp+4] at boundary
                    || (off + 4 <= sz && bytes[off] == 0x8B
                        && (bytes[off+1] == 0x44 || bytes[off+1] == 0x4C)
                        && bytes[off+2] == 0x24 && bytes[off+3] == 0x04
                        && boundary && off > 0)
                    // === x86-64 patterns ===
                    // sub rsp, imm8 (48 83 EC xx) — standard x86-64 prologue
                    || (off + 4 <= sz && bytes[off] == 0x48
                        && bytes[off+1] == 0x83 && bytes[off+2] == 0xEC
                        && boundary)
                    // sub rsp, imm32 (48 81 EC xx xx xx xx) — large frame
                    || (off + 7 <= sz && bytes[off] == 0x48
                        && bytes[off+1] == 0x81 && bytes[off+2] == 0xEC
                        && boundary)
                    // push rbp (55) at boundary in 64-bit context
                    || (bytes[off] == 0x55 && off + 2 <= sz
                        && bytes[off+1] == 0x48  // followed by REX prefix (mov rbp, rsp)
                        && boundary)
                    // mov [rsp+N], rbx (48 89 5C 24 xx) — Windows x64 ABI
                    || (off + 5 <= sz && bytes[off] == 0x48
                        && bytes[off+1] == 0x89 && bytes[off+2] == 0x5C
                        && bytes[off+3] == 0x24
                        && boundary)
                    // mov [rsp+N], rdi (48 89 7C 24 xx) — save first param
                    || (off + 5 <= sz && bytes[off] == 0x48
                        && bytes[off+1] == 0x89 && bytes[off+2] == 0x7C
                        && bytes[off+3] == 0x24
                        && boundary)
                    // push rbx (53) at boundary with REX following (common Win64 prologue)
                    || (off + 2 <= sz && bytes[off] == 0x53
                        && boundary && off > 0
                        && bytes[off+1] == 0x48)
                    // push r-prefixed (41 5x) at boundary — push r12..r15
                    || (off + 3 <= sz && bytes[off] == 0x41
                        && matches!(bytes[off+1], 0x54 | 0x55 | 0x56 | 0x57)
                        && boundary && off > 0);

                if is_prologue {
                    let valid_boundary =
                        off == 0 || matches!(bytes[off - 1], 0xC3 | 0xCC | 0x90 | 0x00);
                    if valid_boundary {
                        found.insert(va);
                    }
                }
            }
            off += 1;
        }
    }

    // AArch64 prologue scanning (4-byte aligned instructions)
    if is_aarch64 {
        for (seg_va, seg_sz, seg_fo) in segs {
            let fo = *seg_fo as usize;
            let sz = (*seg_sz as usize).min(data.len().saturating_sub(fo));
            if fo + sz > data.len() {
                continue;
            }
            let bytes = &data[fo..fo + sz];

            let mut off = 0usize;
            while off + 4 <= sz {
                let va = seg_va + off as u64;
                if !found.contains(&va) {
                    let insn = u32::from_le_bytes([
                        bytes[off],
                        bytes[off + 1],
                        bytes[off + 2],
                        bytes[off + 3],
                    ]);

                    // Check for AArch64 function prologues:
                    // STP X29, X30, [SP, #off] — save FP+LR (both pre-index and signed offset)
                    //   Pre-index: A98xxxxx (STP X29,X30,[SP,#-N]!)
                    //   Signed offset: A9BF7BFD etc. (STP X29,X30,[SP,#-16])
                    // Check: Rt=29(FP), Rt2=30(LR), Rn=31(SP), opc=10 (64-bit)
                    let rt = insn & 0x1F;
                    let rt2 = (insn >> 10) & 0x1F;
                    let rn = (insn >> 5) & 0x1F;
                    let is_stp_fp_lr =
                        // STP pre-index: A98xxxxx
                        ((insn & 0xFFE00000) == 0xA9800000 && rt == 29 && rt2 == 30)
                        // STP signed offset: A9xxxxxx where Rt=29, Rt2=30, Rn=31
                        || ((insn & 0xFFC00000) == 0xA9000000 && rt == 29 && rt2 == 30 && rn == 31);

                    // SUB SP, SP, #imm — stack frame allocation
                    let is_sub_sp = (insn & 0xFF0003E0) == 0xD10003E0 && ((insn >> 5) & 0x1F) == 31;

                    // STP with SP base (callee-saved register saves, any register pair)
                    let _is_stp_sp = (insn & 0xFFC00000) == 0xA9000000 && rn == 31;

                    // ADRP — common leaf function start (loads page address)
                    let is_adrp = (insn & 0x9F000000) == 0x90000000;

                    // MOV X29, SP (set frame pointer without STP — some leaf functions)
                    let is_mov_fp_sp = insn == 0x910003FD; // ADD X29, SP, #0

                    // LDR from literal pool or GOT — common in position-independent thunks
                    let is_ldr_lit = (insn & 0xFF000000) == 0x58000000; // LDR Xt, label

                    // Boundary check: previous instruction should be RET (D65F03C0) or 0/padding
                    let prev_ok = if off >= 4 {
                        let prev_insn = u32::from_le_bytes([
                            bytes[off - 4],
                            bytes[off - 3],
                            bytes[off - 2],
                            bytes[off - 1],
                        ]);
                        prev_insn == 0xD65F03C0  // RET
                            || prev_insn == 0x00000000  // padding
                            || prev_insn == 0xD503201F  // NOP
                            || (prev_insn >> 26) == 0b000101 // B (unconditional branch)
                    } else {
                        true // start of section
                    };

                    if is_stp_fp_lr || is_sub_sp {
                        // STP FP/LR and SUB SP are strong prologues — accept with loose boundary
                        found.insert(va);
                    } else if prev_ok && (is_adrp || is_mov_fp_sp || is_ldr_lit) {
                        // Weaker patterns — require boundary check
                        found.insert(va);
                    }
                }
                off += 4;
            }
        }
    }

    // Phase 2c: Exhaustive CALL target scanning.
    // Scan all executable sections for CALL instructions and collect targets.
    // x86: E8 rel32 (5 bytes)
    // AArch64: BL imm26 (4 bytes, opcode 10010100 + 26-bit signed offset)
    for (seg_va, seg_sz, seg_fo) in segs {
        let fo = *seg_fo as usize;
        let sz = (*seg_sz as usize).min(data.len().saturating_sub(fo));
        if fo + sz > data.len() {
            continue;
        }
        let bytes = &data[fo..fo + sz];

        if is_aarch64 {
            // AArch64: BL imm26 — instruction format: 1001_01xx_xxxx_xxxx_xxxx_xxxx_xxxx_xxxx
            // Top 6 bits = 100101, bottom 26 bits = signed offset (in instructions, × 4)
            let mut off = 0usize;
            while off + 4 <= sz {
                let insn = u32::from_le_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                ]);
                if (insn >> 26) == 0b100101 {
                    // BL
                    let imm26 = insn & 0x03FF_FFFF;
                    // Sign-extend 26-bit to 64-bit, multiply by 4
                    let offset = if imm26 & 0x0200_0000 != 0 {
                        ((imm26 | 0xFC00_0000) as i32 as i64) * 4
                    } else {
                        (imm26 as i64) * 4
                    };
                    let target = (seg_va + off as u64).wrapping_add(offset as u64);
                    let in_seg = segs
                        .iter()
                        .any(|(va, sz, _)| target >= *va && target < va + sz);
                    if in_seg && !found.contains(&target) {
                        found.insert(target);
                    }
                }
                off += 4; // AArch64 instructions are 4-byte aligned
            }
        } else {
            // x86: E8 rel32 (CALL)
            let mut off = 0usize;
            while off + 5 <= sz {
                if bytes[off] == 0xE8 {
                    let disp = i32::from_le_bytes([
                        bytes[off + 1],
                        bytes[off + 2],
                        bytes[off + 3],
                        bytes[off + 4],
                    ]);
                    let target = (seg_va + off as u64 + 5).wrapping_add(disp as i64 as u64);
                    let in_seg = segs
                        .iter()
                        .any(|(va, sz, _)| target >= *va && target < va + sz);
                    if in_seg && !found.contains(&target) {
                        found.insert(target);
                    }
                }
                off += 1;
            }
        }
    }

    // Phase 3: Thunk discovery — find JMP [rip+disp] import thunks at function boundaries.
    // Only for PE64 — PE32 thunks are already found by the prologue scanner or import resolution.
    let is_pe64 = goblin::Object::parse(data)
        .ok()
        .and_then(|o| {
            if let goblin::Object::PE(pe) = o {
                Some(pe.is_64)
            } else {
                None
            }
        })
        .unwrap_or(false);
    if is_pe64 {
        for (seg_va, seg_sz, seg_fo) in segs {
            let fo = *seg_fo as usize;
            let sz = (*seg_sz as usize).min(data.len().saturating_sub(fo));
            if fo + sz > data.len() {
                continue;
            }
            let bytes = &data[fo..fo + sz];

            let mut off = 0usize;
            while off + 2 <= sz {
                let va = seg_va + off as u64;
                if !found.contains(&va) {
                    let boundary = off == 0 || matches!(bytes[off - 1], 0xC3 | 0xCC | 0x90 | 0x00);
                    if boundary {
                        let is_thunk =
                        // JMP [rip+disp32]: FF 25 xx xx xx xx (import thunks)
                        (off + 6 <= sz && bytes[off] == 0xFF && bytes[off+1] == 0x25)
                        // JMP rel32: E9 xx xx xx xx (C++ virtual thunks, tail calls)
                        // At function boundaries — preceded by RET/INT3/NOP.
                        || (off + 5 <= sz && bytes[off] == 0xE9
                            && off > 0 && matches!(bytes[off - 1], 0xC3 | 0xCC | 0x90));

                        if is_thunk {
                            found.insert(va);
                        }
                    }
                }
                off += 1;
            }
        }
    } // end if is_pe64

    // Phase 4: Data reference scanning — find function pointers in .rdata/.data sections.
    // Vtable entries, C++ exception handler tables, and callback registrations point to
    // code addresses that aren't reached by CALL descent.
    // Only for PE64 — PE32 has too many false positives from 32-bit values that look like pointers.
    if let Ok(obj) = goblin::Object::parse(data) {
        if let goblin::Object::PE(pe) = &obj {
            if !pe.is_64 { /* skip PE32 */
            } else {
                let _base = pe.image_base as u64;
                // Identify executable address range
                let mut text_start = u64::MAX;
                let mut text_end = 0u64;
                for seg in segs.iter() {
                    text_start = text_start.min(seg.0);
                    text_end = text_end.max(seg.0 + seg.1);
                }

                for sec in &pe.sections {
                    let name = std::str::from_utf8(&sec.name)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    if name == ".rdata" || name == ".data" || name == "_RDATA" {
                        let fo = sec.pointer_to_raw_data as usize;
                        let sz = sec.virtual_size.min(sec.size_of_raw_data) as usize;
                        if fo + sz > data.len() {
                            continue;
                        }
                        let ptr_size: usize = 8; // PE64 only

                        // Phase 4a: Vtable detection — consecutive function pointer arrays.
                        // A vtable is 2+ consecutive 8-byte pointers into .text.
                        // All pointers in a vtable are accepted without prologue check
                        // (vtable entries include tiny thunks like "mov al, 1; ret" and
                        // C++ adjustment thunks like "sub rcx, N; jmp real_method").
                        {
                            let mut consecutive = 0usize;
                            let mut vtable_ptrs: Vec<u64> = Vec::new();
                            let mut off = 0usize;
                            while off + ptr_size <= sz {
                                let ptr = u64::from_le_bytes(
                                    data[fo + off..fo + off + 8].try_into().unwrap_or([0; 8]),
                                );
                                if ptr >= text_start && ptr < text_end {
                                    vtable_ptrs.push(ptr);
                                    consecutive += 1;
                                } else {
                                    if consecutive >= 2 {
                                        for &vptr in &vtable_ptrs[vtable_ptrs.len() - consecutive..]
                                        {
                                            found.insert(vptr);
                                        }
                                    }
                                    consecutive = 0;
                                }
                                off += ptr_size;
                            }
                            if consecutive >= 2 {
                                for &vptr in &vtable_ptrs[vtable_ptrs.len() - consecutive..] {
                                    found.insert(vptr);
                                }
                            }
                        }

                        // Phase 4b: Single function pointers with strict prologue verification.
                        let mut off = 0usize;
                        while off + ptr_size <= sz {
                            let ptr = u64::from_le_bytes(
                                data[fo + off..fo + off + 8].try_into().unwrap_or([0; 8]),
                            );

                            if ptr >= text_start && ptr < text_end && !found.contains(&ptr) {
                                let target_fo = segs.iter().find_map(|(va, sz, sfo)| {
                                    if ptr >= *va && ptr < va + sz {
                                        Some(sfo + (ptr - va))
                                    } else {
                                        None
                                    }
                                });
                                if let Some(target_fo) = target_fo {
                                    let tfo = target_fo as usize;
                                    if tfo + 3 <= data.len() {
                                        let (b0, b1, b2) =
                                            (data[tfo], data[tfo + 1], data[tfo + 2]);
                                        let looks_like_func = (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC)     // sub rsp, imm8
                                        || (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC)   // sub rsp, imm32
                                        || (b0 == 0x55 && b1 == 0x48)                 // push rbp; REX
                                        || (b0 == 0x48 && b1 == 0x89 && (b2 == 0x5C || b2 == 0x7C)) // mov [rsp+N]
                                        || (b0 == 0xFF && b1 == 0x25)                 // JMP [rip+disp]
                                        || b0 == 0xE9                                 // JMP rel32
                                        || (b0 == 0x55 && b1 == 0x8B && b2 == 0xEC)   // push ebp; mov
                                        // MSVC: push <reg>; sub rsp, imm8 (reg = rbx/rbp/rsi/rdi)
                                        || ((b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57)
                                            && b1 == 0x48 && b2 == 0x83)
                                        // MSVC: push <reg>; sub rsp, imm32
                                        || ((b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57)
                                            && b1 == 0x48 && b2 == 0x81)
                                        // MSVC: mov [rsp+0x10], rdx / [rsp+0x18], r8 (arg home)
                                        || (b0 == 0x48 && b1 == 0x89 && b2 == 0x54)
                                        || (b0 == 0x4C && b1 == 0x89 && b2 == 0x44);
                                        if looks_like_func {
                                            found.insert(ptr);
                                        }
                                    }
                                }
                            }
                            off += ptr_size;
                        }
                    }
                }
            }
        }
    }

    // Also run PyMethodDef scan during the stripped-PE path so `--all`
    // automatically picks up Python-registered methods.
    for (addr, name) in scan_pymethoddef(segs, data) {
        found.insert(addr);
        // Names attached here lose to existing FUN_xxx in the final map;
        // that's OK — the standalone caller above owns name attribution.
        let _ = name;
    }

    let sorted: Vec<u64> = found.into_iter().collect();
    sorted
        .iter()
        .map(|addr| (*addr, format!("FUN_{:08x}", addr)))
        .collect()
}

/// Scan PE64 data sections for PyMethodDef arrays.
///
/// A PyMethodDef entry is a 32-byte struct:
///   { const char *ml_name; PyCFunction ml_meth; int ml_flags; const char *ml_doc; }
/// Arrays are terminated by a zeroed sentinel. Python C-extensions use this to
/// expose methods that would otherwise never be called by any function inside
/// the module, so neither CALL-target descent nor vtable scanning finds them.
///
/// Validation rules per entry, all of which must hold:
///   * ml_meth  — within the executable address range
///   * ml_name  — points to a short (<=64 byte) ASCII identifier, non-empty
///   * ml_flags — fits in a u32 and its value is a plausible METH_* bitmask
///   * ml_doc   — NULL, or points to ASCII text
///
/// Returns a list of (function_va, method_name) for each discovered method.
fn scan_pymethoddef(segs: &[(u64, u64, u64)], data: &[u8]) -> Vec<(u64, String)> {
    let obj = match goblin::Object::parse(data) {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let pe = match obj {
        goblin::Object::PE(pe) => pe,
        _ => return vec![],
    };
    if !pe.is_64 {
        return vec![];
    }

    // segs contains only executable sections — used for the .text range
    // check. For string lookups we need all readable sections.
    let mut text_start = u64::MAX;
    let mut text_end = 0u64;
    for seg in segs.iter() {
        text_start = text_start.min(seg.0);
        text_end = text_end.max(seg.0 + seg.1);
    }
    let base = pe.image_base as u64;
    let all_segs: Vec<(u64, u64, u64)> = pe
        .sections
        .iter()
        .filter(|s| (s.characteristics & 0x40000000) != 0) // readable
        .map(|s| {
            (
                base + s.virtual_address as u64,
                s.virtual_size.min(s.size_of_raw_data) as u64,
                s.pointer_to_raw_data as u64,
            )
        })
        .collect();
    let va_to_fo = |va: u64| -> Option<usize> {
        all_segs.iter().find_map(|(v, s, fo)| {
            if va >= *v && va < v + s {
                Some(*fo as usize + (va - v) as usize)
            } else {
                None
            }
        })
    };
    // Strict C identifier (used for ml_name)
    let read_ident = |va: u64| -> Option<String> {
        let fo = va_to_fo(va)?;
        if fo >= data.len() {
            return None;
        }
        let slice = &data[fo..data.len().min(fo + 128)];
        let end = slice.iter().position(|&b| b == 0)?;
        if end == 0 || end > 64 {
            return None;
        }
        let s = &slice[..end];
        if !s.iter().all(|&b| b == b'_' || b.is_ascii_alphanumeric()) {
            return None;
        }
        Some(String::from_utf8_lossy(s).into_owned())
    };
    // Loose printable-ASCII check (used for ml_doc — doc strings contain
    // spaces, punctuation, newlines). An empty string (first byte is NUL)
    // is accepted as equivalent to a NULL doc.
    let read_text_ok = |va: u64| -> bool {
        let Some(fo) = va_to_fo(va) else {
            return false;
        };
        if fo >= data.len() {
            return false;
        }
        let slice = &data[fo..data.len().min(fo + 512)];
        let end = match slice.iter().position(|&b| b == 0) {
            Some(e) => e,
            None => return false,
        };
        slice[..end]
            .iter()
            .all(|&b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
    };

    let mut out: Vec<(u64, String)> = Vec::new();
    for sec in &pe.sections {
        let ch = sec.characteristics;
        let is_read = (ch & 0x40000000) != 0;
        let is_exec = (ch & 0x20000000) != 0;
        let is_init = (ch & 0x00000040) != 0;
        if !is_read || is_exec || !is_init {
            continue;
        }
        let fo = sec.pointer_to_raw_data as usize;
        let sz = sec.virtual_size.min(sec.size_of_raw_data) as usize;
        if fo + sz > data.len() || sz < 32 {
            continue;
        }

        let mut off = 0usize;
        while off + 32 <= sz {
            let rd_q = |o: usize| {
                u64::from_le_bytes(data[fo + o..fo + o + 8].try_into().unwrap_or([0; 8]))
            };
            let ml_name = rd_q(off);
            let ml_meth = rd_q(off + 8);
            let ml_flags_q = rd_q(off + 16);
            let ml_doc = rd_q(off + 24);

            let ml_flags_hi = (ml_flags_q >> 32) as u32;
            let ml_flags = ml_flags_q as u32;

            let meth_ok = ml_meth >= text_start && ml_meth < text_end;
            let flags_ok = ml_flags_hi == 0 && ml_flags < 0x1000;
            let name_str = if meth_ok && flags_ok {
                read_ident(ml_name)
            } else {
                None
            };
            let doc_ok = ml_doc == 0 || read_text_ok(ml_doc);

            if meth_ok && flags_ok && doc_ok && name_str.is_some() {
                out.push((ml_meth, name_str.unwrap()));
                off += 32;
                continue;
            }
            off += 8;
        }
    }
    out
}

/// Discover functions in a stripped ELF binary.
/// Uses entry point, CALL scanning, prologue patterns, PLT enumeration, and .init_array.
fn discover_elf_functions(
    elf: &goblin::elf::Elf,
    segs: &[(u64, u64, u64)],
    data: &[u8],
    arch: rsleigh_api::Architecture,
) -> Vec<(u64, String)> {
    use std::collections::BTreeSet;

    let mut found = BTreeSet::new();

    // Detect endianness and pointer size from ELF header
    let is_big_endian = elf
        .header
        .endianness()
        .unwrap_or(goblin::container::Endian::Little)
        == goblin::container::Endian::Big;
    let is_32bit = elf.header.e_machine == 0x08 // MIPS
        || elf.header.e_machine == 0x28          // ARM
        || (elf.header.e_machine == 0x03 && elf.header.e_ident[4] == 1); // x86 32-bit
    let ptr_size: usize = if is_32bit { 4 } else { 8 };

    // Endian-aware pointer reading helpers
    let read_u32_elf = |bytes: &[u8]| -> u32 {
        if is_big_endian {
            u32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4]))
        } else {
            u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]))
        }
    };
    let read_u64_elf = |bytes: &[u8]| -> u64 {
        if is_big_endian {
            u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        } else {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        }
    };
    let read_i32_elf = |bytes: &[u8]| -> i32 {
        if is_big_endian {
            i32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4]))
        } else {
            i32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]))
        }
    };
    let read_ptr_elf = |bytes: &[u8]| -> u64 {
        if is_32bit {
            read_u32_elf(bytes) as u64
        } else {
            read_u64_elf(bytes)
        }
    };
    let read_i64_elf = |bytes: &[u8]| -> i64 {
        if is_big_endian {
            i64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        } else {
            i64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        }
    };

    // 1. Entry point
    let entry = elf.header.e_entry;
    if entry != 0 {
        found.insert(entry);
    }

    // 2. .init and .fini section addresses
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if (name == ".init" || name == ".fini") && sh.sh_addr != 0 {
            found.insert(sh.sh_addr);
        }
        // .init_array / .fini_array contain function pointers
        if (name == ".init_array" || name == ".fini_array") && sh.sh_size > 0 {
            let fo = sh.sh_offset as usize;
            let count = (sh.sh_size as usize) / ptr_size;
            for i in 0..count {
                if fo + i * ptr_size + ptr_size <= data.len() {
                    let ptr = read_ptr_elf(&data[fo + i * ptr_size..]);
                    if ptr != 0 && ptr != u64::MAX && ptr != 0xFFFFFFFF {
                        found.insert(ptr);
                    }
                }
            }
        }
    }

    // 3. PLT entries — each is a small stub that jumps to a GOT entry
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name.starts_with(".plt") && sh.sh_addr != 0 && sh.sh_size > 0 {
            // PLT entries are typically 16 bytes each (first entry is special)
            let entry_size = if sh.sh_entsize > 0 { sh.sh_entsize } else { 16 };
            let mut addr = sh.sh_addr + entry_size; // skip PLT[0]
            while addr < sh.sh_addr + sh.sh_size {
                found.insert(addr);
                addr += entry_size;
            }
        }
    }

    // 4. Find .text section bounds for CALL scanning
    let text_section = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text");

    if let Some(text) = text_section {
        let text_addr = text.sh_addr;
        let text_size = text.sh_size;
        let text_fo = text.sh_offset as usize;
        let text_end = text_addr + text_size;

        // 4b. Architecture-specific raw CALL scanning for initial seeds.
        if text_fo + text_size as usize <= data.len() {
            let text_bytes = &data[text_fo..text_fo + text_size as usize];

            if matches!(arch, rsleigh_api::Architecture::ARM32) {
                // ARM32 BL (Branch with Link): condition[31:28] 1011 imm24
                // Encoding: cccc 1011 xxxx xxxx xxxx xxxx xxxx xxxx
                // Byte pattern: xx xx xx xB (little-endian, top nibble of byte[3] is cond, byte[3]&0x0F == 0x0B)
                // Most common: 0xEB (AL condition = always)
                for i in (0..text_bytes.len().saturating_sub(3)).step_by(4) {
                    let word =
                        u32::from_le_bytes(text_bytes[i..i + 4].try_into().unwrap_or([0; 4]));
                    let is_bl = (word & 0x0F000000) == 0x0B000000; // BL opcode
                    if is_bl {
                        let imm24 = word & 0x00FFFFFF;
                        // Sign-extend 24-bit immediate
                        let offset = if imm24 & 0x800000 != 0 {
                            ((imm24 | 0xFF000000) as i32) << 2
                        } else {
                            (imm24 as i32) << 2
                        };
                        // PC is at instruction + 8 in ARM mode
                        let target = (text_addr as i64 + i as i64 + 8 + offset as i64) as u64;
                        if target >= text_addr && target < text_end {
                            found.insert(target);
                        }
                    }
                }

                // ARM32 PUSH {regs, lr} prologue: E92D xxxx where xxxx has bit 14 set (LR)
                for i in (0..text_bytes.len().saturating_sub(3)).step_by(4) {
                    let word =
                        u32::from_le_bytes(text_bytes[i..i + 4].try_into().unwrap_or([0; 4]));
                    // STMDB SP!, {regs} = E92D xxxx (PUSH)
                    if (word & 0xFFFF0000) == 0xE92D0000 {
                        let reglist = word & 0xFFFF;
                        if reglist & (1 << 14) != 0 {
                            // LR in register list
                            // Verify: preceded by function boundary (previous word is a return)
                            if i == 0 || {
                                let prev = u32::from_le_bytes(
                                    text_bytes[i - 4..i].try_into().unwrap_or([0; 4]),
                                );
                                // BX LR = E12FFF1E, POP {pc} = E8BD8xxx, MOV PC, LR = E1A0F00E
                                (prev & 0x0FFFFFFF) == 0x012FFF1E // BX LR
                                || (prev & 0xFFFF0000) == 0xE8BD0000 && (prev & 0x8000) != 0 // POP {.., PC}
                                || prev == 0xE1A0F00E // MOV PC, LR
                                || prev == 0x00000000 // padding
                            } {
                                found.insert(text_addr + i as u64);
                            }
                        }
                    }

                    // Thumb PUSH {regs, lr}: B5xx (16-bit)
                    // Check both halfwords in this 4-byte window
                    for off in [0usize, 2] {
                        if i + off + 1 < text_bytes.len() {
                            let hw = u16::from_le_bytes(
                                text_bytes[i + off..i + off + 2]
                                    .try_into()
                                    .unwrap_or([0; 2]),
                            );
                            if (hw & 0xFF00) == 0xB500 {
                                // PUSH {.., LR}
                                let addr = text_addr + (i + off) as u64;
                                if !found.contains(&addr) {
                                    // Thumb PUSH at aligned boundary
                                    if off == 0 || {
                                        let prev_hw = u16::from_le_bytes(
                                            text_bytes[i + off - 2..i + off]
                                                .try_into()
                                                .unwrap_or([0; 2]),
                                        );
                                        // POP {.., PC} = BDxx, BX LR = 4770
                                        (prev_hw & 0xFF00) == 0xBD00
                                            || prev_hw == 0x4770
                                            || prev_hw == 0x0000
                                    } {
                                        found.insert(addr);
                                    }
                                }
                            }
                        }
                    }
                }

                // Thumb BL: F000 F800-FFFF (32-bit Thumb instruction)
                for i in 0..text_bytes.len().saturating_sub(3) {
                    let hw1 = u16::from_le_bytes(text_bytes[i..i + 2].try_into().unwrap_or([0; 2]));
                    let hw2 =
                        u16::from_le_bytes(text_bytes[i + 2..i + 4].try_into().unwrap_or([0; 2]));
                    // BL: hw1[15:11] = 11110, hw2[15:12] = 1101 (BL) or 1100 (BLX)
                    if (hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000 {
                        let s = ((hw1 >> 10) & 1) as i32;
                        let imm10 = (hw1 & 0x3FF) as i32;
                        let j1 = ((hw2 >> 13) & 1) as i32;
                        let j2 = ((hw2 >> 11) & 1) as i32;
                        let imm11 = (hw2 & 0x7FF) as i32;
                        let i1 = !(j1 ^ s) & 1;
                        let i2 = !(j2 ^ s) & 1;
                        let offset = if s != 0 {
                            (0xFF000000u32 as i32)
                                | (s << 24)
                                | (i1 << 23)
                                | (i2 << 22)
                                | (imm10 << 12)
                                | (imm11 << 1)
                        } else {
                            (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                        };
                        let target = (text_addr as i64 + i as i64 + 4 + offset as i64) as u64;
                        if target >= text_addr && target < text_end {
                            found.insert(target);
                        }
                    }
                }
            }

            if matches!(arch, rsleigh_api::Architecture::AArch64) {
                // AArch64 BL: 1001 01xx xxxx xxxx xxxx xxxx xxxx xxxx = 0x94000000 mask 0xFC000000
                for i in (0..text_bytes.len().saturating_sub(3)).step_by(4) {
                    let word =
                        u32::from_le_bytes(text_bytes[i..i + 4].try_into().unwrap_or([0; 4]));
                    if (word & 0xFC000000) == 0x94000000 {
                        let imm26 = word & 0x03FFFFFF;
                        let offset = if imm26 & 0x02000000 != 0 {
                            ((imm26 | 0xFC000000) as i32) << 2
                        } else {
                            (imm26 as i32) << 2
                        };
                        let target = (text_addr as i64 + i as i64 + offset as i64) as u64;
                        if target >= text_addr && target < text_end {
                            found.insert(target);
                        }
                    }
                }
            }

            if matches!(arch, rsleigh_api::Architecture::MIPS32) {
                // MIPS JAL (Jump And Link): opcode 000011 imm26
                // Big-endian: (word >> 26) == 3
                // Target: (PC & 0xF0000000) | (imm26 << 2)
                for i in (0..text_bytes.len().saturating_sub(3)).step_by(4) {
                    let word =
                        u32::from_be_bytes(text_bytes[i..i + 4].try_into().unwrap_or([0; 4]));
                    if (word >> 26) == 3 {
                        // JAL opcode
                        let imm26 = word & 0x03FFFFFF;
                        let target = ((text_addr + i as u64) & 0xF0000000) | ((imm26 as u64) << 2);
                        if target >= text_addr && target < text_end && target % 4 == 0 {
                            found.insert(target);
                        }
                    }
                }

                // Also scan for BAL (Branch And Link): opcode=000001 rs=00000 rt=10001 imm16
                // Big-endian: 0x0411xxxx
                // And BGEZAL: opcode=000001 rt=10001 — same encoding
                for i in (0..text_bytes.len().saturating_sub(3)).step_by(4) {
                    let word =
                        u32::from_be_bytes(text_bytes[i..i + 4].try_into().unwrap_or([0; 4]));
                    let opcode = word >> 26;
                    let rt = (word >> 16) & 0x1F;
                    if opcode == 1 && rt == 17 {
                        // BGEZAL/BAL
                        let imm16 = (word & 0xFFFF) as i16;
                        let offset = (imm16 as i64) << 2;
                        let pc = text_addr + i as u64 + 4; // delay slot: PC+4
                        let target = (pc as i64 + offset) as u64;
                        if target >= text_addr && target < text_end && target % 4 == 0 {
                            found.insert(target);
                        }
                    }
                }
            }
        }

        // 5. Decoder-based CALL target discovery with indirect call resolution.
        // Decode from known function starts, track register values via LEA/MOV,
        // and resolve both direct CALL 0xNNNN and indirect CALL RAX/CALL [RIP+N].
        {
            let mut dec = rsleigh_api::Decoder::new(arch);
            let mut new_targets = BTreeSet::new();
            let max_seeds = 2000;

            // Helper: read a pointer from a virtual address in the binary
            let read_ptr = |va: u64| -> Option<u64> {
                let off = segs.iter().find_map(|(sva, sz, fo)| {
                    if va >= *sva && va < sva + sz {
                        Some((fo + (va - sva)) as usize)
                    } else {
                        None
                    }
                })?;
                if off + ptr_size <= data.len() {
                    Some(read_ptr_elf(&data[off..]))
                } else {
                    None
                }
            };

            // Also scan .text raw bytes for CALL [RIP+disp32] (FF 15 XX XX XX XX)
            // These are indirect calls through GOT — the GOT entry may contain
            // a resolved function address (for statically linked or pre-resolved).
            if text_fo + text_size as usize <= data.len() {
                let text_bytes = &data[text_fo..text_fo + text_size as usize];
                for i in 0..text_bytes.len().saturating_sub(6) {
                    if text_bytes[i] == 0xFF && text_bytes[i + 1] == 0x15 {
                        // CALL [RIP+disp32]
                        let disp = i32::from_le_bytes(
                            text_bytes[i + 2..i + 6].try_into().unwrap_or([0; 4]),
                        );
                        let got_va = (text_addr as i64 + i as i64 + 6 + disp as i64) as u64;
                        if let Some(target) = read_ptr(got_va) {
                            if target >= text_addr && target < text_end {
                                new_targets.insert(target);
                            }
                        }
                    }
                    // JMP [RIP+disp32] (FF 25 XX XX XX XX) — PLT-style indirect jump
                    if text_bytes[i] == 0xFF && text_bytes[i + 1] == 0x25 {
                        let disp = i32::from_le_bytes(
                            text_bytes[i + 2..i + 6].try_into().unwrap_or([0; 4]),
                        );
                        let got_va = (text_addr as i64 + i as i64 + 6 + disp as i64) as u64;
                        if let Some(target) = read_ptr(got_va) {
                            if target >= text_addr && target < text_end {
                                new_targets.insert(target);
                            }
                        }
                    }
                }
            }
            for t in &new_targets {
                found.insert(*t);
            }
            new_targets.clear();

            // Decoder-based discovery with register tracking
            for _round in 0..2 {
                let start_count = found.len();
                let seeds: Vec<u64> = found
                    .iter()
                    .filter(|a| **a >= text_addr && **a < text_end)
                    .take(max_seeds)
                    .copied()
                    .collect();
                for func_addr in seeds {
                    let off = segs.iter().find_map(|(va, sz, fo)| {
                        if func_addr >= *va && func_addr < va + sz {
                            Some((fo + (func_addr - va)) as usize)
                        } else {
                            None
                        }
                    });
                    let Some(off) = off else { continue };
                    let max = 4096.min(data.len().saturating_sub(off));
                    if max < 2 {
                        continue;
                    }
                    let bytes = &data[off..off + max];

                    // Mini register tracker: maps register name → known address value
                    let mut reg_vals: std::collections::HashMap<String, u64> =
                        std::collections::HashMap::new();
                    let mut pos = 0;
                    for _ in 0..500 {
                        if pos + 1 >= bytes.len() {
                            break;
                        }
                        if let Ok(inst) = dec.decode(&bytes[pos..], func_addr + pos as u64) {
                            let sz = inst.len as usize;
                            if sz == 0 {
                                break;
                            }
                            let dis = &inst.disassembly;
                            let _inst_addr = func_addr + pos as u64;

                            // Track LEA reg, [RIP+disp] → reg = computed address
                            if dis.starts_with("LEA ") {
                                let parts: Vec<&str> =
                                    dis.splitn(3, |c: char| c == ',' || c == ' ').collect();
                                if parts.len() >= 3 {
                                    let dest = parts[1].trim().trim_end_matches(',');
                                    let src = parts[2].trim();
                                    // LEA with immediate address: "LEA RAX,0xNNNN" or "LEA RAX,[0xNNNN]"
                                    let addr_str =
                                        src.trim_start_matches('[').trim_end_matches(']');
                                    if let Some(hex) = addr_str.strip_prefix("0x") {
                                        if let Ok(addr) = u64::from_str_radix(hex, 16) {
                                            reg_vals.insert(dest.to_string(), addr);
                                        }
                                    }
                                }
                            }

                            // Track MOV reg, imm → reg = constant
                            if dis.starts_with("MOV ") && !dis.contains('[') {
                                let parts: Vec<&str> =
                                    dis.splitn(3, |c: char| c == ',' || c == ' ').collect();
                                if parts.len() >= 3 {
                                    let dest = parts[1].trim().trim_end_matches(',');
                                    let src = parts[2].trim();
                                    if let Some(hex) = src.strip_prefix("0x") {
                                        if let Ok(val) = u64::from_str_radix(hex, 16) {
                                            reg_vals.insert(dest.to_string(), val);
                                        }
                                    }
                                }
                            }

                            // Collect CALL targets — both direct and indirect
                            if dis.starts_with("CALL ") {
                                let target_part = &dis[5..];
                                if let Some(hex) = target_part.trim().strip_prefix("0x") {
                                    // Direct CALL 0xNNNN
                                    if let Ok(target) = u64::from_str_radix(hex, 16) {
                                        if target >= text_addr && target < text_end {
                                            new_targets.insert(target);
                                        }
                                    }
                                } else if target_part.contains('[') {
                                    // Indirect CALL [addr] — try to resolve via P-code ops
                                    // Parse: "CALL dword ptr [0xNNNN]" or "CALL qword ptr [RIP + 0xNN]"
                                    let bracket_content = target_part
                                        .split('[')
                                        .nth(1)
                                        .unwrap_or("")
                                        .split(']')
                                        .next()
                                        .unwrap_or("");
                                    if let Some(hex) = bracket_content.strip_prefix("0x") {
                                        if let Ok(mem_addr) = u64::from_str_radix(hex, 16) {
                                            if let Some(target) = read_ptr(mem_addr) {
                                                if target >= text_addr && target < text_end {
                                                    new_targets.insert(target);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    // Indirect CALL REG — resolve from tracked register value
                                    let reg = target_part.trim();
                                    if let Some(&val) = reg_vals.get(reg) {
                                        if val >= text_addr && val < text_end {
                                            new_targets.insert(val);
                                        }
                                    }
                                }
                            }

                            // MIPS: collect JAL targets from decoded instructions
                            // MIPS JAL disassembles as "jal 0xNNNNNNNN"
                            if dis.starts_with("jal ") {
                                let target_part = &dis[4..];
                                if let Some(hex) = target_part.trim().strip_prefix("0x") {
                                    if let Ok(target) = u64::from_str_radix(hex, 16) {
                                        if target >= text_addr && target < text_end {
                                            new_targets.insert(target);
                                        }
                                    }
                                }
                            }
                            // MIPS: "bal 0xNNNN" (branch and link)
                            if dis.starts_with("bal ")
                                || dis.starts_with("bgezal ")
                                || dis.starts_with("bltzal ")
                            {
                                let target_part = dis.split_whitespace().last().unwrap_or("");
                                if let Some(hex) = target_part.strip_prefix("0x") {
                                    if let Ok(target) = u64::from_str_radix(hex, 16) {
                                        if target >= text_addr && target < text_end {
                                            new_targets.insert(target);
                                        }
                                    }
                                }
                            }

                            // Invalidate destination register on any other write
                            // (simplistic: CALL clobbers RAX, other writes clobber dest)
                            if dis.starts_with("CALL ") {
                                reg_vals.remove("RAX");
                                reg_vals.remove("RCX");
                                reg_vals.remove("RDX");
                                reg_vals.remove("RSI");
                                reg_vals.remove("RDI");
                                reg_vals.remove("R8");
                                reg_vals.remove("R9");
                                reg_vals.remove("R10");
                                reg_vals.remove("R11");
                            }

                            // Terminators: x86 RET/HLT, MIPS JR RA (jr ra)
                            if dis.starts_with("RET") || dis.starts_with("HLT") || dis == "jr ra" {
                                break;
                            }
                            pos += sz;
                        } else {
                            break;
                        }
                    }
                }
                for t in &new_targets {
                    found.insert(*t);
                }
                new_targets.clear();
                if found.len() == start_count {
                    break;
                }
            }
        }

        // 5b. Parse .eh_frame_hdr for function addresses.
        // The .eh_frame_hdr contains a sorted table of (PC, FDE) pairs — every function
        // with exception handling or unwind info has an entry here. This is authoritative.
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name != ".eh_frame_hdr" {
                continue;
            }
            let fo = sh.sh_offset as usize;
            let hdr_addr = sh.sh_addr;
            if fo + 12 > data.len() {
                break;
            }
            let version = data[fo];
            if version != 1 {
                break;
            }
            let fde_count_enc = data[fo + 2];
            let table_enc = data[fo + 3];
            // Read FDE count (offset 8, encoding determines size)
            let fde_count = match fde_count_enc {
                0x03 => read_i32_elf(&data[fo + 8..]) as usize,
                _ => read_u32_elf(&data[fo + 8..]) as usize,
            };
            if fde_count == 0 || fde_count > 100_000 {
                break;
            }
            let table_start = fo + 12;
            // Table encoding 0x3b = DW_EH_PE_datarel | DW_EH_PE_sdata4 (most common)
            if table_enc == 0x3b {
                for i in 0..fde_count {
                    let entry_off = table_start + i * 8;
                    if entry_off + 4 > data.len() {
                        break;
                    }
                    let pc_rel = read_i32_elf(&data[entry_off..]);
                    let pc = (hdr_addr as i64 + pc_rel as i64) as u64;
                    if pc > 0 && pc < text_end + 0x10000 {
                        found.insert(pc);
                    }
                }
            }
        }

        // 5b2. Parse .eh_frame directly for FDE initial_location addresses.
        // Complements .eh_frame_hdr: catches FDEs not in the index and works when
        // .eh_frame_hdr is missing. Each FDE has a PC-relative initial_location.
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name != ".eh_frame" {
                continue;
            }
            let ef_addr = sh.sh_addr;
            let ef_off = sh.sh_offset as usize;
            let ef_size = sh.sh_size as usize;
            if ef_off + ef_size > data.len() {
                break;
            }

            let mut pos = 0;
            while pos + 8 < ef_size {
                let fo = ef_off + pos;
                let length = read_u32_elf(&data[fo..]) as usize;
                if length == 0 {
                    break;
                } // terminator
                if length > ef_size - pos {
                    break;
                } // corrupt
                let record_start = pos + 4;
                let cie_id = read_u32_elf(&data[fo + 4..]);

                if cie_id != 0 {
                    // FDE: initial_location is at offset 8 from record start,
                    // encoded as sdata4 PC-relative (most common for gcc/clang)
                    let iloc_off = fo + 8;
                    if iloc_off + 4 <= data.len() {
                        let iloc_rel = read_i32_elf(&data[iloc_off..]);
                        let iloc =
                            (ef_addr as i64 + (iloc_off - ef_off) as i64 + iloc_rel as i64) as u64;
                        if iloc > 0 && iloc < text_end + 0x10000 {
                            found.insert(iloc);
                        }
                    }
                }
                pos = record_start + length;
            }
        }

        // 5b3. C++ RTTI vtable chain walking.
        // Vtable layout: [offset_to_top(8)] [typeinfo_ptr(8)] [vfunc0(8)] [vfunc1(8)] ...
        // Identify vtables by: offset_to_top is 0 or small, typeinfo_ptr points to
        // .data.rel.ro/.rodata, and next entries point into .text.
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name != ".data.rel.ro" {
                continue;
            }
            let _sec_addr = sh.sh_addr;
            let sec_off = sh.sh_offset as usize;
            let sec_size = sh.sh_size as usize;
            if sec_off + sec_size > data.len() || sec_size < 24 {
                continue;
            }

            // Collect all data section address ranges for typeinfo pointer validation
            let data_sections: Vec<(u64, u64)> = elf
                .section_headers
                .iter()
                .filter(|s| {
                    let n = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("");
                    matches!(n, ".data.rel.ro" | ".rodata" | ".data")
                })
                .map(|s| (s.sh_addr, s.sh_addr + s.sh_size))
                .collect();
            let in_data = |addr: u64| -> bool {
                data_sections
                    .iter()
                    .any(|(start, end)| addr >= *start && addr < *end)
            };

            let mut i = 0;
            while i + 3 * ptr_size <= sec_size {
                let offset_to_top = if is_32bit {
                    read_i32_elf(&data[sec_off + i..]) as i64
                } else {
                    read_i64_elf(&data[sec_off + i..])
                };
                let typeinfo_ptr = read_ptr_elf(&data[sec_off + i + ptr_size..]);
                let first_entry = read_ptr_elf(&data[sec_off + i + 2 * ptr_size..]);

                // Vtable heuristic: offset_to_top is 0 or small, typeinfo points to data,
                // first entry points to executable code
                if offset_to_top.unsigned_abs() <= 1024
                    && in_data(typeinfo_ptr)
                    && first_entry >= text_addr
                    && first_entry < text_end
                {
                    // Walk virtual function entries
                    let mut j = 2 * ptr_size;
                    while i + j + ptr_size <= sec_size {
                        let vfunc = read_ptr_elf(&data[sec_off + i + j..]);
                        if vfunc >= text_addr && vfunc < text_end {
                            found.insert(vfunc);
                            j += ptr_size;
                        } else {
                            break;
                        }
                    }
                    i += j; // skip past vtable
                } else {
                    i += ptr_size;
                }
            }
        }

        // 5c. Full data section pointer scan — find ALL 8-byte values pointing into executable code
        // Covers vtables, function pointer arrays, switch jump tables, C++ RTTI
        {
            let _all_exec_start = elf
                .section_headers
                .iter()
                .filter(|sh| sh.sh_flags & 0x4 != 0 && sh.sh_addr > 0)
                .map(|sh| sh.sh_addr)
                .min()
                .unwrap_or(text_addr);
            let _all_exec_end = elf
                .section_headers
                .iter()
                .filter(|sh| sh.sh_flags & 0x4 != 0 && sh.sh_addr > 0)
                .map(|sh| sh.sh_addr + sh.sh_size)
                .max()
                .unwrap_or(text_end);

            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if !matches!(name, ".rodata" | ".data.rel.ro") {
                    continue;
                }
                let fo = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                if fo + sz > data.len() || sz < ptr_size {
                    continue;
                }
                let is_vtable_section = name == ".data.rel.ro";
                let ps = ptr_size; // local alias
                for i in (0..sz.saturating_sub(ps - 1)).step_by(ps) {
                    let ptr = read_ptr_elf(&data[fo + i..]);
                    if ptr >= text_addr && ptr < text_end {
                        if is_vtable_section {
                            // .data.rel.ro: vtable entries are always function pointers
                            found.insert(ptr);
                        } else if matches!(arch, rsleigh_api::Architecture::MIPS32) {
                            // MIPS: validate with prologue check
                            let target_idx = (ptr - text_addr) as usize;
                            if text_fo + target_idx + 4 < data.len() {
                                let word = u32::from_be_bytes(
                                    data[text_fo + target_idx..text_fo + target_idx + 4]
                                        .try_into()
                                        .unwrap_or([0; 4]),
                                );
                                let strong = (word & 0xFFFF0000) == 0x27BD0000  // addiu sp, sp, -N
                                    || (word & 0xFFFF0000) == 0x3C1C0000         // lui gp, N
                                    || (word & 0xFFFF0000) == 0xAFBF0000; // sw ra, N(sp)
                                if strong {
                                    found.insert(ptr);
                                } else {
                                    let mut run = 0;
                                    let psi = ps as i64;
                                    for k in [-psi, psi, 2 * psi].iter() {
                                        let neighbor = i as i64 + k;
                                        if neighbor >= 0 && (neighbor as usize) + ps <= sz {
                                            let np = read_ptr_elf(&data[fo + neighbor as usize..]);
                                            if np >= text_addr && np < text_end {
                                                run += 1;
                                            }
                                        }
                                    }
                                    if run >= 2 {
                                        found.insert(ptr);
                                    }
                                }
                            }
                        } else {
                            // x86/ARM: existing prologue checks
                            let target_idx = (ptr - text_addr) as usize;
                            if text_fo + target_idx + 4 < data.len() {
                                let b0 = data[text_fo + target_idx];
                                let b1 = data[text_fo + target_idx + 1];
                                let strong = matches!(
                                    (b0, b1),
                                    (0x55, 0x48)
                                        | (0x55, 0x53)
                                        | (0x53, 0x48)
                                        | (0x53, 0x55)
                                        | (0x41, 0x54)
                                        | (0x41, 0x55)
                                        | (0x41, 0x56)
                                        | (0x41, 0x57)
                                        | (0x48, 0x83)
                                        | (0x48, 0x81)
                                        | (0xF3, 0x0F)
                                        | (0x55, 0x41)
                                );
                                if strong {
                                    found.insert(ptr);
                                } else {
                                    let mut run = 0;
                                    let psi = ps as i64;
                                    for k in [-psi, psi, 2 * psi].iter() {
                                        let neighbor = i as i64 + k;
                                        if neighbor >= 0 && (neighbor as usize) + ps <= sz {
                                            let np = read_ptr_elf(&data[fo + neighbor as usize..]);
                                            if np >= text_addr && np < text_end {
                                                run += 1;
                                            }
                                        }
                                    }
                                    if run >= 2 {
                                        found.insert(ptr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5d. E9 JMP rel32 pass — add tail call thunks at function boundaries.
        // Only add when JMP is preceded by strict terminators (RET/INT3/NOP padding).
        // Do NOT include 0xFF — it's the last byte of many multi-byte instructions.
        if text_fo + text_size as usize <= data.len() {
            let text_bytes = &data[text_fo..text_fo + text_size as usize];
            for i in 0..text_bytes.len().saturating_sub(5) {
                if text_bytes[i] == 0xE9 {
                    let rel =
                        i32::from_le_bytes(text_bytes[i + 1..i + 5].try_into().unwrap_or([0; 4]));
                    let target = (text_addr as i64 + i as i64 + 5 + rel as i64) as u64;
                    if target < text_addr || target >= text_end {
                        continue;
                    }
                    let at_boundary =
                        i == 0 || matches!(text_bytes[i - 1], 0xC3 | 0x90 | 0xCC | 0x00);
                    if at_boundary {
                        found.insert(text_addr + i as u64);
                    }
                }
            }
        }

        // 6. Prologue pattern scanning in .text
        if text_fo + text_size as usize <= data.len() {
            let text_bytes = &data[text_fo..text_fo + text_size as usize];
            let is_boundary = |i: usize| -> bool {
                i == 0
                    || matches!(
                        text_bytes[i - 1],
                        0xC3 | 0x90 | 0xCC | 0x00 | 0xC2 | 0xCB | 0xCA
                    )
            };
            // Also accept NOP padding sequences (66 66 2e 0f 1f etc.)
            let is_boundary_or_nop = |i: usize| -> bool {
                if is_boundary(i) {
                    return true;
                }
                // Multi-byte NOP: 66 90, 0f 1f XX, 66 2e 0f 1f
                if i >= 2 && text_bytes[i - 1] == 0x90 && text_bytes[i - 2] == 0x66 {
                    return true;
                }
                if i >= 1 && text_bytes[i - 1] == 0x90 {
                    return true;
                }
                false
            };

            for i in 0..text_bytes.len().saturating_sub(4) {
                let addr = text_addr + i as u64;
                if found.contains(&addr) {
                    continue;
                }

                let b0 = text_bytes[i];
                let b1 = if i + 1 < text_bytes.len() {
                    text_bytes[i + 1]
                } else {
                    0
                };
                let b2 = if i + 2 < text_bytes.len() {
                    text_bytes[i + 2]
                } else {
                    0
                };
                let b3 = if i + 3 < text_bytes.len() {
                    text_bytes[i + 3]
                } else {
                    0
                };

                let matched = match (b0, b1, b2, b3) {
                    // push rbp; mov rbp, rsp (55 48 89 e5)
                    (0x55, 0x48, 0x89, 0xe5) => true,
                    // push rbp; mov rbp, rsp (55 48 8b ec)
                    (0x55, 0x48, 0x8b, 0xec) => true,
                    // push rbx; sub rsp (53 48 83 ec)
                    (0x53, 0x48, 0x83, 0xec) => true,
                    // push rbx; push rbp (53 55 ..) — C++ common
                    (0x53, 0x55, _, _) => true,
                    // push r12; push rbp (41 54 55 ..)
                    (0x41, 0x54, 0x55, _) => true,
                    // push r12; push rbx (41 54 53 ..)
                    (0x41, 0x54, 0x53, _) => true,
                    // push r13; push r12 (41 55 41 54)
                    (0x41, 0x55, 0x41, 0x54) => true,
                    // push r14; push r13 (41 56 41 55)
                    (0x41, 0x56, 0x41, 0x55) => true,
                    // push r15; push r14 (41 57 41 56)
                    (0x41, 0x57, 0x41, 0x56) => true,
                    // sub rsp, imm8 (48 83 ec NN) — leaf function
                    (0x48, 0x83, 0xEC, _) => true,
                    // sub rsp, imm32 (48 81 ec NN NN NN NN) — large stack frame
                    (0x48, 0x81, 0xEC, _) => true,
                    // push rbp; push rbx (55 53 ..)
                    (0x55, 0x53, _, _) => true,
                    // push rbp; push r12 (55 41 54 ..)
                    (0x55, 0x41, 0x54, _) => true,
                    // push rbp; sub rsp (55 48 83 ec) — already covered by push rbp patterns
                    // mov rdi, rsi or similar arg setup as first instruction (rare standalone)
                    _ => false,
                };

                if matched && is_boundary_or_nop(i) {
                    found.insert(addr);
                }

                // endbr64 (f3 0f 1e fa) — CET indirect branch target
                // Only count as function if preceded by a function terminator or NOP padding.
                // Switch case targets also have endbr64 but are NOT function entries.
                if b0 == 0xF3 && b1 == 0x0F && b2 == 0x1E && b3 == 0xFA {
                    if is_boundary_or_nop(i) {
                        found.insert(addr);
                    }
                }
            }
        }

        // 6a. MIPS prologue pattern scanning in .text
        if matches!(arch, rsleigh_api::Architecture::MIPS32) {
            if text_fo + text_size as usize <= data.len() {
                let text_bytes = &data[text_fo..text_fo + text_size as usize];

                // MIPS function boundary detection: JR RA (0x03E00008) or
                // JR RA in delay slot pair (JR RA + NOP = 03E00008 00000000)
                let is_mips_boundary = |i: usize| -> bool {
                    if i == 0 {
                        return true;
                    }
                    // Check if previous instruction is JR RA (return)
                    if i >= 8 {
                        // JR RA = 0x03E00008, typically followed by NOP (delay slot)
                        let prev2 = u32::from_be_bytes(
                            text_bytes[i - 8..i - 4].try_into().unwrap_or([0; 4]),
                        );
                        let prev1 =
                            u32::from_be_bytes(text_bytes[i - 4..i].try_into().unwrap_or([0; 4]));
                        if prev2 == 0x03E00008 {
                            return true;
                        } // JR RA (prev was delay slot)
                        if prev1 == 0x03E00008 {
                            return true;
                        } // JR RA right before
                    }
                    if i >= 4 {
                        let prev =
                            u32::from_be_bytes(text_bytes[i - 4..i].try_into().unwrap_or([0; 4]));
                        if prev == 0x00000000 {
                            return true;
                        } // NOP padding
                        if prev == 0x03E00008 {
                            return true;
                        } // JR RA
                    }
                    false
                };

                for i in (0..text_bytes.len().saturating_sub(7)).step_by(4) {
                    let addr = text_addr + i as u64;
                    if found.contains(&addr) {
                        continue;
                    }

                    let word =
                        u32::from_be_bytes(text_bytes[i..i + 4].try_into().unwrap_or([0; 4]));
                    let next_word =
                        u32::from_be_bytes(text_bytes[i + 4..i + 8].try_into().unwrap_or([0; 4]));

                    // Pattern 1: addiu sp, sp, -N (0x27BDxxxx where xxxx is negative = high bit set)
                    // This is the most common MIPS function prologue
                    let is_addiu_sp = (word & 0xFFFF0000) == 0x27BD0000 && (word & 0x8000) != 0;

                    if is_addiu_sp {
                        // Strong: addiu sp followed by sw ra (save return address)
                        let next_is_sw_ra = (next_word & 0xFFFF0000) == 0xAFBF0000;
                        // Also strong: addiu sp followed by sw s8/fp
                        let next_is_sw_fp = (next_word & 0xFFFF0000) == 0xAFBE0000;
                        // Also accept: addiu sp followed by lui gp (PIC prologue)
                        let next_is_lui_gp = (next_word & 0xFFFF0000) == 0x3C1C0000;

                        if next_is_sw_ra || next_is_sw_fp || next_is_lui_gp {
                            // Strong prologue — always add
                            found.insert(addr);
                        } else if is_mips_boundary(i) {
                            // Weaker prologue but at a function boundary
                            found.insert(addr);
                        }
                    }

                    // Pattern 2: lui gp, N followed by addiu gp (PIC code, GP setup)
                    // Some functions start with GP setup before stack allocation
                    let is_lui_gp = (word & 0xFFFF0000) == 0x3C1C0000;
                    if is_lui_gp && is_mips_boundary(i) {
                        let next_is_addiu_gp = (next_word & 0xFFFF0000) == 0x279C0000;
                        if next_is_addiu_gp {
                            found.insert(addr);
                        }
                    }
                }
            }
        }

        // 6b. Scan for endbr64 in all executable sections (not just .text)
        // This catches .plt.sec and .plt.got entries
        for sh in &elf.section_headers {
            if sh.sh_flags & 0x4 == 0 {
                continue;
            } // not executable
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == ".text" {
                continue;
            } // already scanned
            let fo = sh.sh_offset as usize;
            let sz = sh.sh_size as usize;
            if fo + sz > data.len() {
                continue;
            }
            let sec_bytes = &data[fo..fo + sz];
            for i in (0..sz.saturating_sub(4)).step_by(1) {
                if sec_bytes[i] == 0xF3
                    && sec_bytes[i + 1] == 0x0F
                    && sec_bytes[i + 2] == 0x1E
                    && sec_bytes[i + 3] == 0xFA
                {
                    found.insert(sh.sh_addr + i as u64);
                }
            }
        }

        // 7. Gap analysis: scan gaps between known functions for valid prologues.
        if text_fo + text_size as usize <= data.len() {
            let text_bytes = &data[text_fo..text_fo + text_size as usize];
            let mut sorted_addrs: Vec<u64> = found
                .iter()
                .filter(|a| **a >= text_addr && **a < text_end)
                .copied()
                .collect();
            sorted_addrs.sort();

            for window in sorted_addrs.windows(2) {
                let gap_start = window[0];
                let gap_end = window[1];
                let gap_size = gap_end - gap_start;
                // Only analyze gaps > 16 bytes (room for a real function)
                if gap_size < 32 || gap_size > 2048 {
                    continue;
                }
                // Scan inside the gap for function prologues after terminators
                let start_idx = (gap_start - text_addr) as usize;
                let end_idx = (gap_end - text_addr) as usize;
                if end_idx > text_bytes.len() {
                    continue;
                }
                let mut i = start_idx;
                while i + 4 < end_idx {
                    let b = text_bytes[i];
                    // Look for RET (C3) or unconditional JMP (E9/EB/FF) followed by valid code
                    if matches!(b, 0xC3 | 0xCC) {
                        // Skip NOP/INT3/alignment padding (require 2+ padding bytes)
                        let mut j = i + 1;
                        while j < end_idx && matches!(text_bytes[j], 0x90 | 0xCC | 0x00) {
                            j += 1;
                        }
                        // Also skip multi-byte NOPs: 66 90, 0f 1f XX, 66 2e 0f 1f
                        while j + 1 < end_idx && text_bytes[j] == 0x66 && text_bytes[j + 1] == 0x90
                        {
                            j += 2;
                        }
                        while j + 2 < end_idx && text_bytes[j] == 0x0F && text_bytes[j + 1] == 0x1F
                        {
                            j += 3;
                        }
                        if j < end_idx && j >= i + 2 {
                            // require 2+ padding bytes
                            let candidate = text_addr + j as u64;
                            if !found.contains(&candidate) {
                                // Verify: must start with a strong prologue pattern
                                let fb = text_bytes[j];
                                let fb1 = if j + 1 < end_idx {
                                    text_bytes[j + 1]
                                } else {
                                    0
                                };
                                let valid_start = matches!(
                                    (fb, fb1),
                                    (0x55, 0x48) | (0x55, 0x53) | (0x55, 0x41) | // push rbp; ...
                                    (0x53, 0x48) | (0x53, 0x55) |                 // push rbx; ...
                                    (0x41, 0x54) | (0x41, 0x55) | (0x41, 0x56) | (0x41, 0x57) | // push r12-r15
                                    (0x48, 0x83) | (0x48, 0x81) |                 // sub rsp
                                    (0xF3, 0x0F) // endbr64
                                );
                                if valid_start {
                                    found.insert(candidate);
                                }
                            }
                            i = j;
                            continue;
                        }
                    }
                    i += 1;
                }
            }
        }

        // 7b. MIPS gap analysis: scan gaps between known functions for prologues after JR RA.
        if matches!(arch, rsleigh_api::Architecture::MIPS32) {
            if text_fo + text_size as usize <= data.len() {
                let text_bytes = &data[text_fo..text_fo + text_size as usize];
                let mut sorted_addrs: Vec<u64> = found
                    .iter()
                    .filter(|a| **a >= text_addr && **a < text_end)
                    .copied()
                    .collect();
                sorted_addrs.sort();

                for window in sorted_addrs.windows(2) {
                    let gap_start = window[0];
                    let gap_end = window[1];
                    let gap_size = gap_end - gap_start;
                    if gap_size < 16 || gap_size > 4096 {
                        continue;
                    }
                    let start_idx = (gap_start - text_addr) as usize;
                    let end_idx = (gap_end - text_addr) as usize;
                    if end_idx + 4 > text_bytes.len() {
                        continue;
                    }

                    // Scan for JR RA (0x03E00008) + delay slot, then prologue
                    let mut i = start_idx;
                    while i + 12 <= end_idx {
                        let word =
                            u32::from_be_bytes(text_bytes[i..i + 4].try_into().unwrap_or([0; 4]));
                        if word == 0x03E00008 {
                            // JR RA
                            // Skip delay slot + any NOP padding
                            let mut j = i + 8; // past JR RA + delay slot
                            while j + 4 <= end_idx {
                                let w = u32::from_be_bytes(
                                    text_bytes[j..j + 4].try_into().unwrap_or([0; 4]),
                                );
                                if w == 0x00000000 {
                                    j += 4;
                                } else {
                                    break;
                                }
                            }
                            if j + 8 <= end_idx && j % 4 == 0 {
                                let candidate_word = u32::from_be_bytes(
                                    text_bytes[j..j + 4].try_into().unwrap_or([0; 4]),
                                );
                                let is_prologue = (candidate_word & 0xFFFF0000) == 0x27BD0000
                                    && (candidate_word & 0x8000) != 0
                                    || (candidate_word & 0xFFFF0000) == 0x3C1C0000;
                                if is_prologue {
                                    let candidate_addr = text_addr + j as u64;
                                    if !found.contains(&candidate_addr) {
                                        found.insert(candidate_addr);
                                    }
                                }
                            }
                            i = j;
                        } else {
                            i += 4;
                        }
                    }
                }
            }
        }

        // Step 5 (decoder-based CALL discovery) already covers recursive descent.
        // No separate pass needed.
    }

    // Filter: remove addresses in PLT range that aren't PLT entries
    // and sort results
    let mut result: Vec<(u64, String)> = found
        .into_iter()
        .map(|addr| {
            // Try to resolve PLT names from dynamic relocations
            let plt_name = resolve_plt_name(elf, addr);
            let name = plt_name.unwrap_or_else(|| format!("FUN_{:08x}", addr));
            (addr, name)
        })
        .collect();
    result.sort_by_key(|(addr, _)| *addr);
    result
}

/// Try to resolve a PLT entry address to its import name via .rela.plt relocations.
fn resolve_plt_name(elf: &goblin::elf::Elf, addr: u64) -> Option<String> {
    // Check if addr is in a PLT section
    let in_plt = elf.section_headers.iter().any(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        name.starts_with(".plt") && addr >= sh.sh_addr && addr < sh.sh_addr + sh.sh_size
    });
    if !in_plt {
        return None;
    }

    // Find which PLT slot this is (by index)
    let plt_sec = elf.section_headers.iter().find(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        name == ".plt.sec" || name == ".plt"
    })?;
    let entry_size = if plt_sec.sh_entsize > 0 {
        plt_sec.sh_entsize
    } else {
        16
    };
    let plt_name = elf.shdr_strtab.get_at(plt_sec.sh_name).unwrap_or("");
    let base = if plt_name == ".plt.sec" {
        plt_sec.sh_addr
    } else {
        plt_sec.sh_addr + entry_size
    };
    if addr < base {
        return None;
    }
    let idx = ((addr - base) / entry_size) as usize;

    // Match against .rela.plt relocations
    for rel in &elf.pltrelocs {
        // The PLT index corresponds to the relocation index
        let sym = &elf.dynsyms.get(rel.r_sym)?;
        let name = elf.dynstrtab.get_at(sym.st_name)?;
        if !name.is_empty() {
            // Count which relocation this is
            let rel_idx = elf
                .pltrelocs
                .iter()
                .position(|r| r.r_offset == rel.r_offset)?;
            if rel_idx == idx {
                return Some(name.to_string());
            }
        }
    }
    None
}
