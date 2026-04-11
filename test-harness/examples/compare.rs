/// Compare rsleigh decompiler output against Ghidra for a test binary.
/// Usage: cargo run -p test-harness --example compare

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

fn run() {
    let binary_path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/compare_test".to_string());
    let binary_path = binary_path.as_str();
    let data = match std::fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Could not read {}: {}", binary_path, e);
            eprintln!("Compile it first:");
            eprintln!("  cc -arch x86_64 -g -O0 -c -o /tmp/compare_test.o /tmp/compare_test.c");
            eprintln!("  cc -arch x86_64 -g -O0 -o /tmp/compare_test /tmp/compare_test.o");
            eprintln!("  dsymutil /tmp/compare_test");
            return;
        }
    };
    let path = std::path::Path::new(binary_path);

    // Parse binary (Mach-O or ELF)
    let obj = goblin::Object::parse(&data).unwrap();
    let (segs, symbols): (Vec<(u64, u64, u64)>, Vec<(u64, String)>) = match &obj {
        goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
            let mut segs = Vec::new();
            for seg in &m.segments {
                for sec_result in seg.sections() {
                    for sec in sec_result {
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
            (segs, syms)
        }
        goblin::Object::Elf(elf) => {
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
            // Also get dynamic symbols for imports
            for sym in elf.dynsyms.iter() {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            syms.push((sym.st_value, name.to_string()));
                        }
                    }
                }
            }
            (segs, syms)
        }
        _ => {
            eprintln!("Unsupported binary format");
            return;
        }
    };

    let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_64);

    let decompile_func = |fa: u64, dec: &mut rsleigh_api::Decoder| -> String {
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if fa >= *va && fa < va + sz {
                Some(fo + (fa - va))
            } else {
                None
            }
        });
        let Some(off) = off else {
            return String::new();
        };
        let max = 2048.min(data.len() - off as usize);
        let bytes = &data[off as usize..off as usize + max];
        let mut io = 0usize;
        let mut insts = Vec::new();
        // Find the next function's start address to bound decoding
        let next_func = symbols.iter()
            .filter(|(a, _)| *a > fa)
            .map(|(a, _)| *a)
            .min()
            .unwrap_or(fa + max as u64);
        let func_max = (next_func - fa) as usize;
        let decode_max = func_max.min(max);

        while io < decode_max {
            // Catch panics from individual instruction decodes (stack overflow)
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec.decode(&bytes[io..], fa + io as u64)
            }));
            match result {
                Ok(Ok(inst)) => {
                    let l = inst.len as usize;
                    if l == 0 { io += 1; continue; } // avoid infinite loop
                    insts.push((fa + io as u64, inst));
                    io += l;
                }
                Ok(Err(_)) => break,
                Err(_) => { io += 1; } // skip bad instruction
            }
        }
        rsleigh_decompile::decompile_with_binary(
            rsleigh_api::Architecture::X86_64,
            &insts,
            Some(&data),
            Some(path),
        )
    };

    // If specific functions are named on the command line, use those.
    // Otherwise decompile all non-underscore symbols.
    let cli_funcs: Vec<String> = std::env::args().skip(2).collect();
    let target_funcs: Vec<String> = if cli_funcs.is_empty() {
        symbols.iter()
            .filter(|(_, n)| !n.starts_with('_') && !n.starts_with("dyld") && !n.is_empty())
            .map(|(_, n)| n.clone())
            .collect()
    } else {
        cli_funcs
    };

    for name in &target_funcs {
        if let Some((addr, _)) = symbols.iter().find(|(_, n)| n == name.as_str()) {
            let func_addr = *addr;
            // Flush before decompiling in case the decoder aborts
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decompile_func(func_addr, &mut dec)
            })) {
                Ok(o) => o,
                Err(_) => {
                    println!("=== {} (CRASHED — stack overflow in decoder) ===\n---", name);
                    continue;
                }
            };
            // Count instructions from the decompiled output (avoids redundant decode pass)
            let inst_count = output.lines().filter(|l| !l.trim().is_empty()).count();
            println!("=== {} ({} instructions) ===", name, inst_count);
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
