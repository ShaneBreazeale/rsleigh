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
        eprintln!("  rsleigh <binary> --sigs <file.json> Load extra signatures");
        std::process::exit(1);
    }

    let binary_path = &args[1];
    let json_mode = args.iter().any(|a| a == "--json");
    let all_mode = args.iter().any(|a| a == "--all");
    let disasm_mode = args.iter().any(|a| a == "--disasm");

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

    let (arch, segs, mut symbols) = match parse_binary(&obj, &data) {
        Some(r) => r,
        None => { eprintln!("Error: unsupported binary format"); std::process::exit(1); }
    };

    // For stripped PE binaries: discover functions from entry point + CALL targets
    if symbols.is_empty() {
        if let goblin::Object::PE(pe) = &obj {
            let base = pe.image_base as u64;
            let entry = base + pe.header.optional_header.unwrap().standard_fields.address_of_entry_point as u64;
            symbols = discover_pe_functions(entry, &segs, &data, arch);
        }
    }

    // For stripped ELF binaries: discover functions via entry point, CALL scanning, prologues
    // Also trigger for ELF with only import symbols (dynsym but no symtab)
    let is_elf_stripped = if let goblin::Object::Elf(elf) = &obj {
        elf.syms.len() == 0 || symbols.iter().all(|(_, n)| n.starts_with("FUN_"))
    } else { false };
    if is_elf_stripped || (symbols.is_empty() && matches!(&obj, goblin::Object::Elf(_))) {
        if let goblin::Object::Elf(elf) = &obj {
            let discovered = discover_elf_functions(elf, &segs, &data, arch);
            // Merge: keep existing named symbols, add discovered ones
            let existing: std::collections::BTreeSet<u64> = symbols.iter().map(|(a, _)| *a).collect();
            for (addr, name) in discovered {
                if !existing.contains(&addr) {
                    symbols.push((addr, name));
                }
            }
        }
    }

    // Determine which functions to process
    // Skip --flag arguments and their values (e.g., --sigs path.json)
    let sigs_arg_idx = args.iter().position(|a| a == "--sigs");
    let func_args: Vec<&str> = args[2..].iter().enumerate()
        .filter(|(i, a)| {
            if a.starts_with("--") { return false; }
            // Skip the value after --sigs
            if let Some(si) = sigs_arg_idx {
                if *i + 2 == si + 1 { return false; }
            }
            true
        })
        .map(|(_, a)| a.as_str())
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
            let func_addr = if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                symbols.iter().find(|(_, n)| n == name).map(|(a, _)| *a)
            };
            if let Some(func_addr) = func_addr {
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

    // Decompile mode — two-pass for interprocedural type propagation
    // Pass 1: quick decompile all targets to learn parameter/return types
    if all_mode && targets.len() > 1 {
        let mut learned: Vec<rsleigh_decompile::LearnedFuncType> = Vec::new();
        let mut callsite_returns: Vec<(u64, &'static str)> = Vec::new();

        for name in &targets {
            let func_addr = if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                symbols.iter().find(|(_, n)| n == name).map(|(a, _)| *a)
            };
            if let Some(func_addr) = func_addr {
                let insts = decode_func(func_addr, &symbols, &segs, &data, &mut dec);
                if !insts.is_empty() {
                    // Extract learned types from this function
                    if let Some(lt) = rsleigh_decompile::extract_learned_types(arch, &insts, Some(&data)) {
                        learned.push(lt);
                    }
                    // Infer callee return types from how this function uses call results
                    let returns = rsleigh_decompile::infer_returns_from_callsites(arch, &insts, Some(&data));
                    callsite_returns.extend(returns);
                }
            }
        }

        // Merge call-site inferred returns into learned types
        callsite_returns.sort_by_key(|(a, _)| *a);
        callsite_returns.dedup_by_key(|(a, _)| *a);
        for (addr, ret_type) in &callsite_returns {
            // Only add if we don't already have a return type for this function
            if !learned.iter().any(|lt| lt.addr == *addr && lt.return_type.is_some()) {
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
    }

    // Pass 2: full decompilation with learned types available
    let mut results: Vec<serde_json::Value> = Vec::new();

    for name in &targets {
        // Support hex addresses like 0x1400013f0
        let func_addr = if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
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
            // Exported/defined symbols
            if let Some(ref st) = m.symbols {
                for s in st.iter() {
                    if let Ok((name, nlist)) = s {
                        if nlist.n_type & 0xe == 0xe && nlist.n_value != 0 {
                            syms.push((nlist.n_value, name.strip_prefix('_').unwrap_or(name).to_string()));
                        }
                    }
                }
            }
            // Parse LC_FUNCTION_STARTS — gives ALL function entry points as ULEB128 deltas.
            // This is the Mach-O equivalent of PE .pdata — the most reliable function discovery.
            let text_vmaddr = m.segments.iter()
                .find(|s| s.name().ok() == Some("__TEXT"))
                .map(|s| s.vmaddr)
                .unwrap_or(0);
            if text_vmaddr > 0 {
                for lc in &m.load_commands {
                    if let goblin::mach::load_command::CommandVariant::FunctionStarts(ref fs) = lc.command {
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
                                    if pos >= end { break; }
                                    let b = _data[pos] as u64;
                                    pos += 1;
                                    delta |= (b & 0x7f) << shift;
                                    shift += 7;
                                    if b & 0x80 == 0 { break; }
                                }
                                if delta == 0 { break; }
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
                        let sname = std::str::from_utf8(&sec.sectname).unwrap_or("").trim_end_matches('\0');
                        // __objc_stubs: each entry is a small stub (ADRP+LDR+BR on ARM64,
                        // JMP on x86_64). Every stub_size-aligned address is a function.
                        if sname == "__objc_stubs" || sname == "__stubs" {
                            let _soff = sec.offset as usize;
                            let ssize = sec.size as usize;
                            let saddr = sec.addr;
                            // Determine stub size: ARM64=12 bytes, x86_64=8 bytes
                            let stub_size: usize = if matches!(arch, rsleigh_api::Architecture::AArch64) { 12 } else { 8 };
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
                                    _data[soff+pos..soff+pos+4].try_into().unwrap_or([0;4]));
                                let count = u32::from_le_bytes(
                                    _data[soff+pos+4..soff+pos+8].try_into().unwrap_or([0;4]));
                                let entsize = (entsize_flags & 0x3FFFFFFF) as usize;
                                let is_relative = entsize_flags & 0x80000000 != 0;

                                if count > 1000 || entsize == 0 || entsize > 64 { pos += 8; continue; }
                                let _list_start = pos;

                                for m_idx in 0..count as usize {
                                    let m_off = soff + pos + 8 + m_idx * entsize;
                                    if m_off + entsize > _data.len() { break; }

                                    if is_relative && entsize >= 12 {
                                        // Relative method_t: int32_t name, int32_t types, int32_t imp
                                        // imp is relative to its own address
                                        let imp_field_addr = saddr + (pos + 8 + m_idx * entsize + 8) as u64;
                                        let imp_rel = i32::from_le_bytes(
                                            _data[m_off+8..m_off+12].try_into().unwrap_or([0;4]));
                                        let imp = imp_field_addr.wrapping_add(imp_rel as i64 as u64);
                                        if !syms.iter().any(|(a, _)| *a == imp) {
                                            syms.push((imp, format!("objc_method_{:x}", imp)));
                                        }
                                    } else if !is_relative && entsize >= 24 {
                                        // Absolute method_t: ptr name, ptr types, ptr imp
                                        let imp = u64::from_le_bytes(
                                            _data[m_off+16..m_off+24].try_into().unwrap_or([0;8]));
                                        if imp > 0 && !syms.iter().any(|(a, _)| *a == imp) {
                                            syms.push((imp, format!("objc_method_{:x}", imp)));
                                        }
                                    }
                                }
                                pos += 8 + count as usize * entsize;
                                // Align to 4 bytes
                                if pos % 4 != 0 { pos += 4 - (pos % 4); }
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
            // Detect architecture from PE machine type
            let arch = match pe.header.coff_header.machine {
                0xAA64 => rsleigh_api::Architecture::AArch64,  // ARM64
                0x8664 => rsleigh_api::Architecture::X86_64,   // AMD64
                0x014C => rsleigh_api::Architecture::X86_32,   // i386
                0x01C4 => rsleigh_api::Architecture::ARM32,    // ARMv7
                _ => if pe.is_64 { rsleigh_api::Architecture::X86_64 }
                     else { rsleigh_api::Architecture::X86_32 },
            };
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
            Some((arch, segs, syms))
        }
        _ => None,
    }
}

/// Discover functions in a stripped PE by recursive descent from entry point.
/// Follows direct CALL targets to find function boundaries.
fn discover_pe_functions(
    entry: u64, segs: &[(u64, u64, u64)], data: &[u8], arch: rsleigh_api::Architecture,
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
            if func_addr >= *va && func_addr < va + sz { Some(fo + (func_addr - va)) } else { None }
        });
        let Some(off) = off else { continue };
        let max = 4096.min(data.len().saturating_sub(off as usize));
        if max == 0 { continue; }
        let bytes = &data[off as usize..off as usize + max];

        let mut io = 0usize;
        while io < max {
            let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec.decode(&bytes[io..], func_addr + io as u64)
            }));
            match ok {
                Ok(Ok(inst)) => {
                    let l = inst.len as usize;
                    if l == 0 { io += 1; continue; }
                    // Look for CALL with direct target
                    for op in &inst.ops {
                        if let pcode_ir::PcodeOp::Call { dest, .. } = op {
                            if dest.space == pcode_ir::AddressSpaceId::Ram {
                                let call_target = dest.offset;
                                // Only follow targets in executable segments
                                let in_seg = segs.iter().any(|(va, sz, _)| call_target >= *va && call_target < va + sz);
                                if in_seg && !found.contains(&call_target) {
                                    found.insert(call_target);
                                    queue.push_back(call_target);
                                }
                            }
                        }
                    }
                    // Stop at RET
                    if inst.ops.iter().any(|op| matches!(op, pcode_ir::PcodeOp::Return { .. })) {
                        break;
                    }
                    io += l;
                }
                Ok(Err(_)) => break,
                Err(_) => { io += 1; }
            }
        }
    }

    // Phase 2a: Parse .pdata exception directory for PE64 (gives exact function boundaries)
    if let Ok(obj) = goblin::Object::parse(data) {
        if let goblin::Object::PE(pe) = &obj {
            if pe.is_64 {
                let base = pe.image_base as u64;
                for sec in &pe.sections {
                    let name = std::str::from_utf8(&sec.name).unwrap_or("").trim_end_matches('\0');
                    if name == ".pdata" {
                        let fo = sec.pointer_to_raw_data as usize;
                        let sz = sec.virtual_size.min(sec.size_of_raw_data) as usize;
                        if fo + sz <= data.len() {
                            // Entry size depends on architecture:
                            // x86-64: 12 bytes (BeginAddress:4, EndAddress:4, UnwindData:4)
                            // ARM64:  8 bytes (BeginAddress:4, UnwindData:4)
                            let pe_off_local = u32::from_le_bytes(
                                data[0x3c..0x40].try_into().unwrap_or([0;4])) as usize;
                            let machine = u16::from_le_bytes([
                                data[pe_off_local+4], data[pe_off_local+5]
                            ]);
                            let entry_size: usize = if machine == 0xAA64 { 8 } else { 12 };

                            let mut off = 0;
                            while off + entry_size <= sz {
                                let begin_rva = u32::from_le_bytes([
                                    data[fo+off], data[fo+off+1], data[fo+off+2], data[fo+off+3]
                                ]) as u64;
                                if begin_rva == 0 { break; }
                                let func_va = base + begin_rva;
                                if !found.contains(&func_va) {
                                    let in_seg = segs.iter().any(|(va, sz, _)| func_va >= *va && func_va < va + sz);
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

    let is_aarch64 = matches!(arch,
        rsleigh_api::Architecture::AArch64 | rsleigh_api::Architecture::ARM32);

    // Phase 2b: Prologue scanning — find functions not reached by direct CALL.
    // Scan executable sections for common function prologues:
    //   55 8B EC       push ebp; mov ebp, esp  (x86-32 standard)
    //   55 89 E5       push ebp; mov esp, ebp  (GCC variant)
    //   48 89 5C 24    mov [rsp+...], rbx      (x86-64 MS ABI)
    //   48 83 EC       sub rsp, imm8           (x86-64 leaf)
    for (seg_va, seg_sz, seg_fo) in segs {
        let fo = *seg_fo as usize;
        let sz = (*seg_sz as usize).min(data.len().saturating_sub(fo));
        if fo + sz > data.len() { continue; }
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
                    let valid_boundary = off == 0 || matches!(bytes[off - 1], 0xC3 | 0xCC | 0x90 | 0x00);
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
            if fo + sz > data.len() { continue; }
            let bytes = &data[fo..fo + sz];

            let mut off = 0usize;
            while off + 4 <= sz {
                let va = seg_va + off as u64;
                if !found.contains(&va) {
                    let insn = u32::from_le_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]]);

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
                    let is_sub_sp = (insn & 0xFF0003E0) == 0xD10003E0
                        && ((insn >> 5) & 0x1F) == 31;

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
                        let prev_insn = u32::from_le_bytes([bytes[off-4], bytes[off-3], bytes[off-2], bytes[off-1]]);
                        prev_insn == 0xD65F03C0  // RET
                            || prev_insn == 0x00000000  // padding
                            || prev_insn == 0xD503201F  // NOP
                            || (prev_insn >> 26) == 0b000101  // B (unconditional branch)
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
        if fo + sz > data.len() { continue; }
        let bytes = &data[fo..fo + sz];

        if is_aarch64 {
            // AArch64: BL imm26 — instruction format: 1001_01xx_xxxx_xxxx_xxxx_xxxx_xxxx_xxxx
            // Top 6 bits = 100101, bottom 26 bits = signed offset (in instructions, × 4)
            let mut off = 0usize;
            while off + 4 <= sz {
                let insn = u32::from_le_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]]);
                if (insn >> 26) == 0b100101 { // BL
                    let imm26 = insn & 0x03FF_FFFF;
                    // Sign-extend 26-bit to 64-bit, multiply by 4
                    let offset = if imm26 & 0x0200_0000 != 0 {
                        ((imm26 | 0xFC00_0000) as i32 as i64) * 4
                    } else {
                        (imm26 as i64) * 4
                    };
                    let target = (seg_va + off as u64).wrapping_add(offset as u64);
                    let in_seg = segs.iter().any(|(va, sz, _)| target >= *va && target < va + sz);
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
                        bytes[off+1], bytes[off+2], bytes[off+3], bytes[off+4]
                    ]);
                    let target = (seg_va + off as u64 + 5).wrapping_add(disp as i64 as u64);
                    let in_seg = segs.iter().any(|(va, sz, _)| target >= *va && target < va + sz);
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
    let is_pe64 = goblin::Object::parse(data).ok()
        .and_then(|o| if let goblin::Object::PE(pe) = o { Some(pe.is_64) } else { None })
        .unwrap_or(false);
    if is_pe64 {
    for (seg_va, seg_sz, seg_fo) in segs {
        let fo = *seg_fo as usize;
        let sz = (*seg_sz as usize).min(data.len().saturating_sub(fo));
        if fo + sz > data.len() { continue; }
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
            if !pe.is_64 { /* skip PE32 */ } else {
            let _base = pe.image_base as u64;
            // Identify executable address range
            let mut text_start = u64::MAX;
            let mut text_end = 0u64;
            for seg in segs.iter() {
                text_start = text_start.min(seg.0);
                text_end = text_end.max(seg.0 + seg.1);
            }

            for sec in &pe.sections {
                let name = std::str::from_utf8(&sec.name).unwrap_or("").trim_end_matches('\0');
                if name == ".rdata" || name == ".data" || name == "_RDATA" {
                    let fo = sec.pointer_to_raw_data as usize;
                    let sz = sec.virtual_size.min(sec.size_of_raw_data) as usize;
                    if fo + sz > data.len() { continue; }
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
                                data[fo+off..fo+off+8].try_into().unwrap_or([0;8]));
                            if ptr >= text_start && ptr < text_end {
                                vtable_ptrs.push(ptr);
                                consecutive += 1;
                            } else {
                                if consecutive >= 2 {
                                    for &vptr in &vtable_ptrs[vtable_ptrs.len()-consecutive..] {
                                        found.insert(vptr);
                                    }
                                }
                                consecutive = 0;
                            }
                            off += ptr_size;
                        }
                        if consecutive >= 2 {
                            for &vptr in &vtable_ptrs[vtable_ptrs.len()-consecutive..] {
                                found.insert(vptr);
                            }
                        }
                    }

                    // Phase 4b: Single function pointers with strict prologue verification.
                    let mut off = 0usize;
                    while off + ptr_size <= sz {
                        let ptr = u64::from_le_bytes(
                            data[fo+off..fo+off+8].try_into().unwrap_or([0;8]));

                        if ptr >= text_start && ptr < text_end && !found.contains(&ptr) {
                            let target_fo = segs.iter().find_map(|(va, sz, sfo)| {
                                if ptr >= *va && ptr < va + sz { Some(sfo + (ptr - va)) } else { None }
                            });
                            if let Some(target_fo) = target_fo {
                                let tfo = target_fo as usize;
                                if tfo + 3 <= data.len() {
                                    let (b0, b1, b2) = (data[tfo], data[tfo+1], data[tfo+2]);
                                    let looks_like_func =
                                        (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC)     // sub rsp, imm8
                                        || (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC)   // sub rsp, imm32
                                        || (b0 == 0x55 && b1 == 0x48)                 // push rbp; REX
                                        || (b0 == 0x48 && b1 == 0x89 && (b2 == 0x5C || b2 == 0x7C)) // mov [rsp+N]
                                        || (b0 == 0xFF && b1 == 0x25)                 // JMP [rip+disp]
                                        || b0 == 0xE9                                 // JMP rel32
                                        || (b0 == 0x55 && b1 == 0x8B && b2 == 0xEC);  // push ebp; mov
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

    let sorted: Vec<u64> = found.into_iter().collect();
    sorted.iter().enumerate().map(|(_i, addr)| {
        (*addr, format!("FUN_{:08x}", addr))
    }).collect()
}

/// Discover functions in a stripped ELF binary.
/// Uses entry point, CALL scanning, prologue patterns, PLT enumeration, and .init_array.
fn discover_elf_functions(
    elf: &goblin::elf::Elf, segs: &[(u64, u64, u64)], data: &[u8], arch: rsleigh_api::Architecture,
) -> Vec<(u64, String)> {
    use std::collections::BTreeSet;

    let mut found = BTreeSet::new();

    // 1. Entry point
    let entry = elf.header.e_entry;
    if entry != 0 { found.insert(entry); }

    // 2. .init and .fini section addresses
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if (name == ".init" || name == ".fini") && sh.sh_addr != 0 {
            found.insert(sh.sh_addr);
        }
        // .init_array / .fini_array contain function pointers
        if (name == ".init_array" || name == ".fini_array") && sh.sh_size > 0 {
            let fo = sh.sh_offset as usize;
            let count = (sh.sh_size / 8) as usize;
            for i in 0..count {
                if fo + i * 8 + 8 <= data.len() {
                    let ptr = u64::from_le_bytes(data[fo + i * 8..fo + i * 8 + 8].try_into().unwrap_or([0; 8]));
                    if ptr != 0 && ptr != u64::MAX {
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
    let text_section = elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text"
    });

    if let Some(text) = text_section {
        let text_addr = text.sh_addr;
        let text_size = text.sh_size;
        let text_fo = text.sh_offset as usize;
        let text_end = text_addr + text_size;

        // 5. Exhaustive E8 CALL rel32 scanning in .text
        if text_fo + text_size as usize <= data.len() {
            let text_bytes = &data[text_fo..text_fo + text_size as usize];
            for i in 0..text_bytes.len().saturating_sub(5) {
                if text_bytes[i] == 0xE8 {
                    // CALL rel32
                    let rel = i32::from_le_bytes(text_bytes[i+1..i+5].try_into().unwrap_or([0; 4]));
                    let target = (text_addr as i64 + i as i64 + 5 + rel as i64) as u64;
                    if target >= text_addr && target < text_end && target != text_addr + i as u64 + 5 {
                        found.insert(target);
                    }
                }
            }
        }

        // 6. Prologue pattern scanning in .text
        if text_fo + text_size as usize <= data.len() {
            let text_bytes = &data[text_fo..text_fo + text_size as usize];
            for i in 0..text_bytes.len().saturating_sub(4) {
                let addr = text_addr + i as u64;
                if found.contains(&addr) { continue; } // already found

                // Pattern: push rbp; mov rbp, rsp (55 48 89 e5)
                if text_bytes[i] == 0x55 && i + 3 < text_bytes.len()
                    && text_bytes[i+1] == 0x48 && text_bytes[i+2] == 0x89 && text_bytes[i+3] == 0xe5 {
                    // Verify alignment: must be preceded by a ret (C3), nop (90), int3 (CC), or at section start
                    if i == 0 || matches!(text_bytes[i-1], 0xC3 | 0x90 | 0xCC | 0x00) {
                        found.insert(addr);
                    }
                }
                // Pattern: push rbp; mov rbp, rsp (alternate: 55 48 8b ec)
                if text_bytes[i] == 0x55 && i + 3 < text_bytes.len()
                    && text_bytes[i+1] == 0x48 && text_bytes[i+2] == 0x8b && text_bytes[i+3] == 0xec {
                    if i == 0 || matches!(text_bytes[i-1], 0xC3 | 0x90 | 0xCC | 0x00) {
                        found.insert(addr);
                    }
                }
                // Pattern: sub rsp, N (48 83 ec NN) — leaf function without frame pointer
                if text_bytes[i] == 0x48 && i + 3 < text_bytes.len()
                    && text_bytes[i+1] == 0x83 && text_bytes[i+2] == 0xEC {
                    if i == 0 || matches!(text_bytes[i-1], 0xC3 | 0x90 | 0xCC | 0x00) {
                        found.insert(addr);
                    }
                }
                // Pattern: endbr64 (f3 0f 1e fa) — CET-enabled function entry
                if text_bytes[i] == 0xF3 && i + 3 < text_bytes.len()
                    && text_bytes[i+1] == 0x0F && text_bytes[i+2] == 0x1E && text_bytes[i+3] == 0xFA {
                    if i == 0 || matches!(text_bytes[i-1], 0xC3 | 0x90 | 0xCC | 0x00) {
                        found.insert(addr);
                    }
                }
            }
        }

        // 7. Recursive CALL descent from all found entry points
        let mut queue: std::collections::VecDeque<u64> = found.iter().copied().collect();
        let mut visited = std::collections::HashSet::new();
        let mut dec = rsleigh_api::Decoder::new(arch);

        while let Some(func_addr) = queue.pop_front() {
            if !visited.insert(func_addr) { continue; }
            let off = segs.iter().find_map(|(va, sz, fo)| {
                if func_addr >= *va && func_addr < va + sz { Some(fo + (func_addr - va)) } else { None }
            });
            let Some(off) = off else { continue };
            let max = 4096.min(data.len().saturating_sub(off as usize));
            if max == 0 { continue; }
            let bytes = &data[off as usize..off as usize + max];

            let mut pos = 0;
            for _ in 0..500 {
                if pos >= bytes.len() { break; }
                if let Ok(inst) = dec.decode(&bytes[pos..], func_addr + pos as u64) {
                    let sz = inst.len as usize;
                    if sz == 0 { break; }

                    // Check for CALL instructions
                    let dis = &inst.disassembly;
                    if dis.starts_with("CALL ") {
                        if let Some(target_str) = dis.split_whitespace().nth(1) {
                            if let Some(hex) = target_str.strip_prefix("0x") {
                                if let Ok(target) = u64::from_str_radix(hex, 16) {
                                    if target >= text_addr && target < text_end && !found.contains(&target) {
                                        found.insert(target);
                                        queue.push_back(target);
                                    }
                                }
                            }
                        }
                    }

                    // Stop at RET
                    if dis.starts_with("RET") { break; }
                    pos += sz;
                } else {
                    break;
                }
            }
        }
    }

    // Filter: remove addresses in PLT range that aren't PLT entries
    // and sort results
    let mut result: Vec<(u64, String)> = found.into_iter().map(|addr| {
        // Try to resolve PLT names from dynamic relocations
        let plt_name = resolve_plt_name(elf, addr);
        let name = plt_name.unwrap_or_else(|| format!("FUN_{:08x}", addr));
        (addr, name)
    }).collect();
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
    if !in_plt { return None; }

    // Find which PLT slot this is (by index)
    let plt_sec = elf.section_headers.iter().find(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        name == ".plt.sec" || name == ".plt"
    })?;
    let entry_size = if plt_sec.sh_entsize > 0 { plt_sec.sh_entsize } else { 16 };
    let plt_name = elf.shdr_strtab.get_at(plt_sec.sh_name).unwrap_or("");
    let base = if plt_name == ".plt.sec" { plt_sec.sh_addr } else { plt_sec.sh_addr + entry_size };
    if addr < base { return None; }
    let idx = ((addr - base) / entry_size) as usize;

    // Match against .rela.plt relocations
    for rel in &elf.pltrelocs {
        // The PLT index corresponds to the relocation index
        let sym = &elf.dynsyms.get(rel.r_sym)?;
        let name = elf.dynstrtab.get_at(sym.st_name)?;
        if !name.is_empty() {
            // Count which relocation this is
            let rel_idx = elf.pltrelocs.iter().position(|r| r.r_offset == rel.r_offset)?;
            if rel_idx == idx {
                return Some(name.to_string());
            }
        }
    }
    None
}
