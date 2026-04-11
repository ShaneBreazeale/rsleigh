/// Compare rsleigh decompiler output for a binary.
/// Usage: cargo run -p test-harness --example compare -- <binary> [func1 func2 ...]
/// Supports: ELF (x86-64, AArch64, ARM32, MIPS32), Mach-O (x86-64, AArch64), PE (x86-64)

fn main() {
    let t = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .unwrap();
    match t.join() {
        Ok(()) => {}
        Err(_) => eprintln!("Thread panicked (likely stack overflow in decoder)"),
    }
}

/// Runtime-internal symbols to hide from auto-discovery.
const HIDDEN_SYMS: &[&str] = &[
    "deregister_tm_clones", "register_tm_clones", "frame_dummy",
    "__do_global_dtors_aux", "__libc_csu_init", "__libc_csu_fini",
    "_dl_relocate_static_pie", "__do_global_ctors_aux",
];

fn run() {
    let binary_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: compare <binary> [func1 func2 ...]");
        std::process::exit(1);
    });
    let data = match std::fs::read(&binary_path) {
        Ok(d) => d,
        Err(e) => { eprintln!("Could not read {}: {}", binary_path, e); return; }
    };
    let path = std::path::Path::new(&binary_path);

    let obj = goblin::Object::parse(&data).unwrap();

    // Auto-detect architecture and extract segments + symbols
    let (arch, segs, symbols) = match &obj {
        goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
            let arch = match m.header.cputype() {
                7 | 0x01000007 => rsleigh_api::Architecture::X86_64,  // CPU_TYPE_X86_64
                12 | 0x0100000c => rsleigh_api::Architecture::AArch64, // CPU_TYPE_ARM64
                _ => { eprintln!("Unsupported Mach-O CPU type: {}", m.header.cputype()); return; }
            };
            let mut segs = Vec::new();
            for seg in &m.segments {
                if let Ok(secs) = seg.sections() {
                    for sec in secs {
                        segs.push((sec.0.addr, sec.0.size, sec.0.offset as u64));
                    }
                }
            }
            let mut syms: Vec<(u64, String)> = Vec::new();
            if let Some(ref st) = m.symbols {
                for s in st.iter() {
                    if let Ok((name, nlist)) = s {
                        if nlist.n_type & 0xe == 0xe && nlist.n_value != 0 {
                            let clean = name.strip_prefix('_').unwrap_or(name);
                            syms.push((nlist.n_value, clean.to_string()));
                        }
                    }
                }
            }
            (arch, segs, syms)
        }
        goblin::Object::Elf(elf) => {
            let arch = match elf.header.e_machine {
                0x3E => rsleigh_api::Architecture::X86_64,   // EM_X86_64
                0x03 => rsleigh_api::Architecture::X86_32,   // EM_386
                0xB7 => rsleigh_api::Architecture::AArch64,  // EM_AARCH64
                0x28 => rsleigh_api::Architecture::ARM32,    // EM_ARM
                0x08 => rsleigh_api::Architecture::MIPS32,   // EM_MIPS
                0xF3 => rsleigh_api::Architecture::RiscV64,  // EM_RISCV
                m => { eprintln!("Unsupported ELF machine: {:#x}", m); return; }
            };
            let segs: Vec<(u64, u64, u64)> = elf.section_headers.iter()
                .filter(|sh| sh.sh_flags & 0x4 != 0) // SHF_EXECINSTR
                .map(|sh| (sh.sh_addr, sh.sh_size, sh.sh_offset))
                .collect();
            let mut syms: Vec<(u64, String)> = Vec::new();
            for sym in elf.syms.iter() {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            syms.push((sym.st_value, name.to_string()));
                        }
                    }
                }
            }
            for sym in elf.dynsyms.iter() {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            syms.push((sym.st_value, name.to_string()));
                        }
                    }
                }
            }
            (arch, segs, syms)
        }
        goblin::Object::PE(pe) => {
            let arch = if pe.is_64 {
                rsleigh_api::Architecture::X86_64
            } else {
                rsleigh_api::Architecture::X86_32
            };
            let base = pe.image_base as u64;
            let segs: Vec<(u64, u64, u64)> = pe.sections.iter()
                .filter(|s| s.characteristics & 0x20000000 != 0) // IMAGE_SCN_MEM_EXECUTE
                .map(|s| (
                    base + s.virtual_address as u64,
                    s.virtual_size as u64,
                    s.pointer_to_raw_data as u64,
                ))
                .collect();
            let mut syms: Vec<(u64, String)> = Vec::new();
            // PE exports as function symbols
            for export in pe.exports.iter() {
                if let Some(name) = export.name {
                    if export.rva != 0 {
                        syms.push((base + export.rva as u64, name.to_string()));
                    }
                }
            }
            // If no exports, discover functions from entry point + CALL targets
            if syms.is_empty() {
                let entry = base + pe.entry as u64;
                syms.push((entry, "entry".to_string()));
                // Scan .text for E8 (CALL rel32) to discover function addresses
                for seg in &segs {
                    let (va, sz, fo) = *seg;
                    let fo = fo as usize;
                    let sz = (sz as usize).min(data.len().saturating_sub(fo));
                    for i in 0..sz.saturating_sub(5) {
                        if data[fo + i] == 0xE8 {
                            let rel = i32::from_le_bytes([
                                data[fo+i+1], data[fo+i+2], data[fo+i+3], data[fo+i+4],
                            ]);
                            let call_site = va + i as u64;
                            let target = (call_site as i64 + 5 + rel as i64) as u64;
                            if target >= va && target < va + sz as u64 && target != call_site + 5 {
                                syms.push((target, format!("func_{:x}", target)));
                            }
                        }
                    }
                }
                syms.sort_by_key(|s| s.0);
                syms.dedup_by_key(|s| s.0);
                eprintln!("Discovered {} functions from CALL targets", syms.len());
            }
            (arch, segs, syms)
        }
        _ => { eprintln!("Unsupported binary format"); return; }
    };

    eprintln!("Architecture: {:?}, {} segments, {} symbols", arch, segs.len(), symbols.len());

    let mut dec = rsleigh_api::Decoder::new(arch);

    let decompile_func = |fa: u64, dec: &mut rsleigh_api::Decoder| -> String {
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if fa >= *va && fa < va + sz { Some(fo + (fa - va)) } else { None }
        });
        let Some(off) = off else { return String::new(); };
        let max = 4096.min(data.len() - off as usize);
        let bytes = &data[off as usize..off as usize + max];
        let mut io = 0usize;
        let mut insts = Vec::new();
        let next_func = symbols.iter()
            .filter(|(a, _)| *a > fa)
            .map(|(a, _)| *a)
            .min()
            .unwrap_or(fa + max as u64);
        let decode_max = ((next_func - fa) as usize).min(max);

        while io < decode_max {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec.decode(&bytes[io..], fa + io as u64)
            }));
            match result {
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
        rsleigh_decompile::decompile_with_binary(arch, &insts, Some(&data), Some(path))
    };

    let cli_funcs: Vec<String> = std::env::args().skip(2).collect();
    let target_funcs: Vec<String> = if cli_funcs.is_empty() {
        symbols.iter()
            .filter(|(_, n)| !n.starts_with('_') && !n.starts_with("dyld") && !n.is_empty()
                && !HIDDEN_SYMS.contains(&n.as_str()))
            .map(|(_, n)| n.clone())
            .collect()
    } else {
        cli_funcs
    };

    for name in &target_funcs {
        if let Some((addr, _)) = symbols.iter().find(|(_, n)| n == name.as_str()) {
            let func_addr = *addr;
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decompile_func(func_addr, &mut dec)
            })) {
                Ok(o) => o,
                Err(_) => {
                    println!("=== {} (CRASHED) ===\n---", name);
                    continue;
                }
            };
            let inst_count = output.lines().filter(|l| !l.trim().is_empty()).count();
            println!("=== {} ({} lines) ===", name, inst_count);
            for line in output.lines() {
                if !line.trim().is_empty() {
                    println!("  {}", line);
                }
            }
            println!("---");
        } else {
            println!("=== {} === (not found)", name);
        }
    }
}
