//! rsleigh CLI — decompile any binary to C-like pseudocode.
//!
//! Usage:
//!   rsleigh <binary>                    # list functions
//!   rsleigh <binary> <func>             # decompile one function
//!   rsleigh <binary> --all              # decompile all functions
//!   rsleigh <binary> --json             # list functions as JSON
//!   rsleigh <binary> <func> --json      # decompile as JSON
//!   rsleigh <binary> --disasm <func>    # disassemble (P-code)

use std::path::Path;

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
        std::process::exit(1);
    }

    let binary_path = &args[1];
    let json_mode = args.iter().any(|a| a == "--json");
    let all_mode = args.iter().any(|a| a == "--all");
    let disasm_mode = args.iter().any(|a| a == "--disasm");

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
    "deregister_tm_clones", "register_tm_clones", "frame_dummy",
    "__do_global_dtors_aux", "__libc_csu_init", "__libc_csu_fini",
    "_dl_relocate_static_pie", "__do_global_ctors_aux",
];

fn run(binary_path: &str, args: &[String], json_mode: bool, all_mode: bool, disasm_mode: bool) {
    let data = match std::fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => { eprintln!("Error: cannot read {}: {}", binary_path, e); std::process::exit(1); }
    };
    let path = Path::new(binary_path);
    let obj = match goblin::Object::parse(&data) {
        Ok(o) => o,
        Err(e) => { eprintln!("Error: cannot parse binary: {}", e); std::process::exit(1); }
    };

    let (arch, segs, symbols) = match parse_binary(&obj, &data) {
        Some(r) => r,
        None => { eprintln!("Error: unsupported binary format"); std::process::exit(1); }
    };

    // Determine which functions to process
    let func_args: Vec<&str> = args[2..].iter()
        .filter(|a| !a.starts_with("--"))
        .map(|a| a.as_str())
        .collect();

    if func_args.is_empty() && !all_mode && !disasm_mode {
        // List functions
        let funcs: Vec<(&str, u64)> = symbols.iter()
            .filter(|(_, n)| !n.starts_with('_') && !n.starts_with("dyld")
                && !HIDDEN.contains(&n.as_str()) && !n.is_empty())
            .map(|(a, n)| (n.as_str(), *a))
            .collect();

        if json_mode {
            let entries: Vec<serde_json::Value> = funcs.iter()
                .map(|(name, addr)| serde_json::json!({"name": name, "address": format!("0x{:x}", addr)}))
                .collect();
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "binary": binary_path,
                "arch": format!("{:?}", arch),
                "functions": entries,
            })).unwrap());
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
        symbols.iter()
            .filter(|(_, n)| !n.starts_with('_') && !n.starts_with("dyld")
                && !HIDDEN.contains(&n.as_str()) && !n.is_empty())
            .map(|(_, n)| n.clone())
            .collect()
    } else {
        func_args.iter().map(|s| s.to_string()).collect()
    };

    let mut dec = rsleigh_api::Decoder::new(arch);

    if disasm_mode {
        // Disassembly mode
        for name in &targets {
            if let Some((addr, _)) = symbols.iter().find(|(_, n)| n == name) {
                let func_addr = *addr;
                let insts = decode_func(func_addr, &symbols, &segs, &data, &mut dec);
                if json_mode {
                    let entries: Vec<serde_json::Value> = insts.iter()
                        .map(|(a, inst)| serde_json::json!({
                            "address": format!("0x{:x}", a),
                            "disassembly": inst.disassembly,
                            "length": inst.len,
                            "pcode_ops": inst.ops.len(),
                        }))
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "function": name, "instructions": entries
                    })).unwrap());
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

    // Decompile mode
    let mut results: Vec<serde_json::Value> = Vec::new();

    for name in &targets {
        if let Some((addr, _)) = symbols.iter().find(|(_, n)| n == name) {
            let func_addr = *addr;
            let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decompile_func(func_addr, &symbols, &segs, &data, &mut dec, arch, path)
            })) {
                Ok(o) => o,
                Err(_) => "// decompilation failed (stack overflow)\n".to_string(),
            };

            if json_mode {
                results.push(serde_json::json!({
                    "function": name,
                    "address": format!("0x{:x}", func_addr),
                    "pseudocode": output.trim(),
                }));
            } else {
                println!("// {}", name);
                for line in output.lines() {
                    if !line.trim().is_empty() {
                        println!("{}", line);
                    }
                }
                println!();
            }
        } else {
            eprintln!("Function '{}' not found", name);
        }
    }

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "binary": binary_path,
            "arch": format!("{:?}", arch),
            "functions": results,
        })).unwrap());
    }
}

fn decode_func(
    fa: u64, symbols: &[(u64, String)], segs: &[(u64, u64, u64)],
    data: &[u8], dec: &mut rsleigh_api::Decoder,
) -> Vec<(u64, pcode_ir::Instruction)> {
    let off = segs.iter().find_map(|(va, sz, fo)| {
        if fa >= *va && fa < va + sz { Some(fo + (fa - va)) } else { None }
    });
    let Some(off) = off else { return vec![]; };
    let max = 4096.min(data.len() - off as usize);
    let bytes = &data[off as usize..off as usize + max];
    let next_func = symbols.iter().filter(|(a, _)| *a > fa).map(|(a, _)| *a).min()
        .unwrap_or(fa + max as u64);
    let decode_max = ((next_func - fa) as usize).min(max);

    let mut insts = Vec::new();
    let mut io = 0;
    while io < decode_max {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dec.decode(&bytes[io..], fa + io as u64))) {
            Ok(Ok(inst)) => {
                let l = inst.len as usize;
                if l == 0 { io += 1; continue; }
                insts.push((fa + io as u64, inst));
                io += l;
            }
            Ok(Err(_)) => break,
            Err(_) => { io += 1; }
        }
    }
    insts
}

fn decompile_func(
    fa: u64, symbols: &[(u64, String)], segs: &[(u64, u64, u64)],
    data: &[u8], dec: &mut rsleigh_api::Decoder,
    arch: rsleigh_api::Architecture, path: &Path,
) -> String {
    let insts = decode_func(fa, symbols, segs, data, dec);
    if insts.is_empty() { return "// no instructions\n".to_string(); }
    rsleigh_decompile::decompile_with_binary(arch, &insts, Some(data), Some(path))
}

fn parse_binary(obj: &goblin::Object, _data: &[u8]) -> Option<(rsleigh_api::Architecture, Vec<(u64, u64, u64)>, Vec<(u64, String)>)> {
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
                    for sec in secs { segs.push((sec.0.addr, sec.0.size, sec.0.offset as u64)); }
                }
            }
            let mut syms = Vec::new();
            if let Some(ref st) = m.symbols {
                for s in st.iter() {
                    if let Ok((name, nlist)) = s {
                        if nlist.n_type & 0xe == 0xe && nlist.n_value != 0 {
                            syms.push((nlist.n_value, name.strip_prefix('_').unwrap_or(name).to_string()));
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
            let segs = elf.section_headers.iter()
                .filter(|sh| sh.sh_flags & 0x4 != 0)
                .map(|sh| (sh.sh_addr, sh.sh_size, sh.sh_offset))
                .collect();
            let mut syms = Vec::new();
            for sym in elf.syms.iter() {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        if !name.is_empty() { syms.push((sym.st_value, name.to_string())); }
                    }
                }
            }
            for sym in elf.dynsyms.iter() {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() { syms.push((sym.st_value, name.to_string())); }
                    }
                }
            }
            Some((arch, segs, syms))
        }
        goblin::Object::PE(pe) => {
            if !pe.is_64 { return None; }
            let base = pe.image_base as u64;
            let segs = pe.sections.iter()
                .filter(|s| s.characteristics & 0x20000000 != 0)
                .map(|s| (base + s.virtual_address as u64, s.virtual_size as u64, s.pointer_to_raw_data as u64))
                .collect();
            let mut syms = Vec::new();
            for exp in pe.exports.iter() {
                if let Some(name) = exp.name {
                    if exp.rva != 0 { syms.push((base + exp.rva as u64, name.to_string())); }
                }
            }
            Some((rsleigh_api::Architecture::X86_64, segs, syms))
        }
        _ => None,
    }
}
