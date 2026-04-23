//! Probe: dump SEH records from a PE64 binary.
//!
//! Usage: `cargo run -p test-harness --example dump_seh -- <path-to-pe64>`
//!
//! Useful for validating the PyVMProtect-class SEH analyser against real
//! obfuscated binaries.  Prints one record per line plus a handler-address
//! summary at the end.

use rsleigh_decompile::seh_static::{
    analyse_all_handlers, extract_all_patches, handler_addresses, parse_pe64_seh,
};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: dump_seh <path-to-pe64>");
        std::process::exit(2);
    };
    let bytes = std::fs::read(&path).expect("read PE");
    let recs  = parse_pe64_seh(&bytes);

    println!("{} SEH records", recs.len());
    for r in &recs {
        let handler = r.handler.map(|h| format!("{:#x}", h)).unwrap_or_else(|| "—".into());
        let scope   = r.scope_table.map(|s| format!("{:#x}", s)).unwrap_or_else(|| "—".into());
        let tag = match (r.has_ehandler(), r.has_uhandler(), r.has_chaininfo()) {
            (true, _, _) => "EH",
            (_, true, _) => "UH",
            (_, _, true) => "CHAIN",
            _            => "unwind-only",
        };
        println!("  {:#x}..{:#x}  v{}  flags=0x{:02x} {:11} handler={} scope={}",
                 r.func_begin, r.func_end, r.version, r.flags, tag, handler, scope);
    }

    let addrs = handler_addresses(&recs);
    println!("\n{} unique handler addresses:", addrs.len());
    for a in &addrs {
        println!("  {:#x}", a);
    }

    println!("\n--- handler analysis ---");
    let analyses = analyse_all_handlers(&bytes);
    for (va, a) in &analyses {
        let mut tags: Vec<&str> = Vec::new();
        if a.redirects_rip       { tags.push("REDIRECT_RIP"); }
        if a.skips_rip           { tags.push("SKIP_RIP"); }
        if a.mutates_context     { tags.push("CTX_MUTATE"); }
        if a.reads_exception_info{ tags.push("READS_EXC_INFO"); }
        if a.calls_wpm           { tags.push("WriteProcessMemory"); }
        if a.calls_vprotect      { tags.push("VirtualProtect"); }
        if a.uses_rep_movs       { tags.push("REP_MOVS"); }
        if a.registers_runtime_tables { tags.push("RtlAddFunctionTable"); }
        if a.reads_dispatcher_context { tags.push("DISP_CTX"); }
        let smc = if a.is_smc_candidate() { "  [SMC]" } else { "" };
        let rip = a.resumption_va.map(|r| format!(" resume={:#x}", r)).unwrap_or_default();
        let calls = if a.iat_calls.is_empty() { String::new() }
                    else { format!(" calls=[{}]", a.iat_calls.join(", ")) };
        println!("  {:#x}  insn={:3}  [{}]{}{}{}",
                 va, a.insn_count, tags.join(","), smc, rip, calls);
    }

    println!("\n--- extracted patches ---");
    let patches = extract_all_patches(&bytes);
    if patches.is_empty() {
        println!("  (none — handlers emit no statically-resolvable writes)");
    } else {
        for p in &patches {
            let preview: String = p.bytes.iter().take(16)
                .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            let more = if p.bytes.len() > 16 { " .." } else { "" };
            println!("  patch @ {:#x}  len={:4}  from handler {:#x}  [{}{}]",
                     p.target_va, p.bytes.len(), p.handler_va, preview, more);
        }
    }
}
