/// Compare rsleigh decompiler output against Ghidra for a test binary.
/// Usage: cargo run -p test-harness --example compare

fn main() {
    let t = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(run)
        .unwrap();
    t.join().unwrap();
}

fn run() {
    let binary_path = "/tmp/compare_test";
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

    // Parse Mach-O
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
        _ => {
            eprintln!("Not Mach-O");
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
            match dec.decode(&bytes[io..], fa + io as u64) {
                Ok(inst) => {
                    let l = inst.len as usize;
                    insts.push((fa + io as u64, inst));
                    io += l;
                }
                Err(_) => break,
            }
        }
        rsleigh_decompile::decompile_with_binary(
            rsleigh_api::Architecture::X86_64,
            &insts,
            Some(&data),
            Some(path),
        )
    };

    let target_funcs = [
        "add",
        "sub",
        "factorial",
        "sum_array",
        "string_length",
        "manhattan_distance",
        "day_name",
        "list_sum",
        "binary_search",
        "apply",
        "main",
    ];

    for name in &target_funcs {
        if let Some((addr, _)) = symbols.iter().find(|(_, n)| n == name) {
            let output = decompile_func(*addr, &mut dec);
            println!("=== {} ({} instructions) ===", name,
                /* count instructions in the function */
                {
                    let off = segs.iter().find_map(|(va, sz, fo)| {
                        if *addr >= *va && *addr < va+sz { Some(fo+(addr-va)) } else { None }
                    }).unwrap_or(0);
                    let max = 2048.min(data.len() - off as usize);
                    let bytes = &data[off as usize..off as usize + max];
                    let mut cnt = 0usize;
                    let mut io2 = 0usize;
                    let mut dec2 = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_64);
                    let mut saw_ret = false;
                    while io2 < max {
                        if let Ok(inst) = dec2.decode(&bytes[io2..], addr + io2 as u64) {
                            let r = inst.ops.iter().any(|o| matches!(o, rsleigh_api::PcodeOp::Return{..}));
                            io2 += inst.len as usize;
                            cnt += 1;
                            if r { if saw_ret { break; } saw_ret = true;
                                let na = addr + io2 as u64;
                                if symbols.iter().any(|(a,_)| *a == na) { break; }
                            }
                        } else { break; }
                    }
                    cnt
                });
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
