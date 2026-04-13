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
            let arch = if pe.is_64 {
                rsleigh_api::Architecture::X86_64
            } else {
                rsleigh_api::Architecture::X86_32
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
                            // Each RUNTIME_FUNCTION is 12 bytes: BeginAddress(4), EndAddress(4), UnwindData(4)
                            let mut off = 0;
                            while off + 12 <= sz {
                                let begin_rva = u32::from_le_bytes([
                                    data[fo+off], data[fo+off+1], data[fo+off+2], data[fo+off+3]
                                ]) as u64;
                                if begin_rva == 0 { break; }
                                let func_va = base + begin_rva;
                                if !found.contains(&func_va) {
                                    // Verify the address is in an executable segment
                                    let in_seg = segs.iter().any(|(va, sz, _)| func_va >= *va && func_va < va + sz);
                                    if in_seg {
                                        found.insert(func_va);
                                    }
                                }
                                off += 12;
                            }
                        }
                    }
                }
            }
        }
    }

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
                    // push rbx (53) or push rdi (57) at boundary with REX or sub rsp following
                    || (off + 2 <= sz && (bytes[off] == 0x53 || bytes[off] == 0x41)
                        && boundary && off > 0
                        && (bytes[off+1] == 0x48 || bytes[off+1] == 0x56 || bytes[off+1] == 0x57));

                if is_prologue {
                    // Verify: the byte before should be a RET (C3), INT3 (CC), NOP (90), or start of section
                    let valid_boundary = off == 0 || matches!(bytes[off - 1], 0xC3 | 0xCC | 0x90 | 0x00);
                    if valid_boundary {
                        found.insert(va);
                    }
                }
            }
            off += 1;
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
                        // JMP [rip+disp32]: FF 25 xx xx xx xx (import thunks only)
                        // These are 6-byte stubs: FF 25 [disp32] followed by NOP/INT3 padding
                        (off + 6 <= sz && bytes[off] == 0xFF && bytes[off+1] == 0x25
                            && (off + 6 >= sz || matches!(bytes[off + 6], 0xCC | 0x90 | 0x00
                                | 0xFF | 0x48 | 0x55)));

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
            let base = pe.image_base as u64;
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
                    let ptr_size = if pe.is_64 { 8 } else { 4 };

                    let mut off = 0usize;
                    while off + ptr_size <= sz {
                        let ptr = if pe.is_64 {
                            u64::from_le_bytes(data[fo+off..fo+off+8].try_into().unwrap_or([0;8]))
                        } else {
                            u32::from_le_bytes(data[fo+off..fo+off+4].try_into().unwrap_or([0;4])) as u64
                        };

                        // Check if pointer targets executable code
                        if ptr >= text_start && ptr < text_end && !found.contains(&ptr) {
                            // Verify: target should look like the start of a function
                            // (not the middle of an instruction)
                            let target_fo = segs.iter().find_map(|(va, sz, sfo)| {
                                if ptr >= *va && ptr < va + sz { Some(sfo + (ptr - va)) } else { None }
                            });
                            if let Some(target_fo) = target_fo {
                                let tfo = target_fo as usize;
                                if tfo + 2 <= data.len() {
                                    let b0 = data[tfo];
                                    // Accept if it starts with a reasonable instruction
                                    // Strict: only accept targets that start with known
                                    // function prologues (not arbitrary instructions)
                                    let b1 = if tfo + 1 < data.len() { data[tfo + 1] } else { 0 };
                                    let b2 = if tfo + 2 < data.len() { data[tfo + 2] } else { 0 };
                                    let looks_like_func =
                                        // sub rsp, imm8 (48 83 EC)
                                        (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC)
                                        // sub rsp, imm32 (48 81 EC)
                                        || (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC)
                                        // push rbp (55) followed by REX
                                        || (b0 == 0x55 && (b1 == 0x48 || b1 == 0x57 || b1 == 0x56))
                                        // push rbx/rsi/rdi at boundary
                                        || (b0 == 0x53 || b0 == 0x56 || b0 == 0x57)
                                            && (tfo == 0 || matches!(data[tfo-1], 0xC3 | 0xCC | 0x90))
                                        // mov [rsp+N], reg (48 89 5C/7C 24)
                                        || (b0 == 0x48 && b1 == 0x89 && (b2 == 0x5C || b2 == 0x7C))
                                        // JMP thunks
                                        || (b0 == 0xFF && b1 == 0x25) || b0 == 0xE9
                                        // push rbp; mov ebp, esp (32-bit)
                                        || (b0 == 0x55 && b1 == 0x8B && b2 == 0xEC);
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
