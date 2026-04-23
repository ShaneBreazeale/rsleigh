//! Probe: dump SEH records from a PE64 binary.
//!
//! Usage: `cargo run -p test-harness --example dump_seh -- <path-to-pe64>`
//!
//! Useful for validating the PyVMProtect-class SEH analyser against real
//! obfuscated binaries.  Prints one record per line plus a handler-address
//! summary at the end.

use rsleigh_decompile::seh_static::{handler_addresses, parse_pe64_seh};

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
}
