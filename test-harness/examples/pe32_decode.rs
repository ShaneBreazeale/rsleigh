/// Decode a 32-bit PE, do linear disasm from entry + discovered CALL targets.
/// Usage: cargo run -p test-harness --example pe32_decode -- <pe32-binary> [--pcode] [--decompile]

fn main() {
    let t = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .unwrap();
    if let Err(_) = t.join() {
        eprintln!("Thread panicked");
    }
}

fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: pe32_decode <binary> [--pcode] [--decompile] [--addr 0xNNNN]");
        return;
    }
    let path = &args[1];
    let show_pcode = args.iter().any(|a| a == "--pcode");
    let show_decompile = args.iter().any(|a| a == "--decompile");
    let specific_addr: Option<u64> = args.iter().position(|a| a == "--addr").and_then(|i| {
        args.get(i + 1).and_then(|s| {
            if s.starts_with("0x") || s.starts_with("0X") {
                u64::from_str_radix(&s[2..], 16).ok()
            } else {
                s.parse().ok()
            }
        })
    });

    let data = std::fs::read(path).unwrap();
    let obj = goblin::Object::parse(&data).unwrap();
    let goblin::Object::PE(pe) = &obj else {
        eprintln!("Not a PE file"); return;
    };

    let image_base = pe.image_base as u64;
    let entry = image_base + pe.entry as u64;

    let text_sec = pe.sections.iter()
        .find(|s| s.characteristics & 0x20000000 != 0)
        .unwrap();
    let text_va = image_base + text_sec.virtual_address as u64;
    let text_end = text_va + text_sec.virtual_size as u64;
    let text_file_off = text_sec.pointer_to_raw_data as usize;

    eprintln!("Image base: 0x{:x}, Entry: 0x{:x}", image_base, entry);
    eprintln!(".text: 0x{:x}..0x{:x}", text_va, text_end);

    let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_32);

    // Helper: VA to file offset
    let va_to_off = |va: u64| -> Option<usize> {
        for sec in &pe.sections {
            let sva = image_base + sec.virtual_address as u64;
            let svend = sva + sec.virtual_size as u64;
            if va >= sva && va < svend {
                return Some(sec.pointer_to_raw_data as usize + (va - sva) as usize);
            }
        }
        None
    };

    // If specific address, just decode from there
    if let Some(addr) = specific_addr {
        eprintln!("\n=== Decoding from 0x{:x} ===", addr);
        decode_func(&data, &mut dec, addr, text_end, &va_to_off, show_pcode);
        if show_decompile {
            let path = std::path::Path::new(&args[1]);
            decompile_func(&data, &mut dec, addr, text_end, &va_to_off, path);
        }
        return;
    }

    // Discover functions by scanning for CALL rel32 (E8 xx xx xx xx)
    let mut func_addrs: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    func_addrs.insert(entry);

    // Scan .text for E8 (CALL rel32) patterns
    let text_bytes = &data[text_file_off..text_file_off + text_sec.size_of_raw_data as usize];
    for i in 0..text_bytes.len().saturating_sub(5) {
        if text_bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes([
                text_bytes[i+1], text_bytes[i+2], text_bytes[i+3], text_bytes[i+4]
            ]);
            let call_site = text_va + i as u64;
            let target = (call_site as i64 + 5 + rel as i64) as u64;
            if target >= text_va && target < text_end && target != call_site + 5 {
                func_addrs.insert(target);
            }
        }
    }

    eprintln!("Discovered {} potential functions", func_addrs.len());

    // Decode entry point + first N discovered functions
    let funcs: Vec<u64> = func_addrs.iter().copied().collect();
    let max_show = if show_decompile { 20 } else { 50 };

    for (i, &addr) in funcs.iter().enumerate().take(max_show) {
        let label = if addr == entry { "ENTRY" } else { "" };
        println!("\n=== func_{:x} {} ===", addr, label);
        decode_func(&data, &mut dec, addr, text_end, &va_to_off, show_pcode);
        if show_decompile {
            let path = std::path::Path::new(&args[1]);
            println!("--- decompiled ---");
            decompile_func(&data, &mut dec, addr, text_end, &va_to_off, path);
        }
    }

    if funcs.len() > max_show {
        eprintln!("... {} more functions not shown", funcs.len() - max_show);
    }
}

fn decode_func(
    data: &[u8],
    dec: &mut rsleigh_api::Decoder,
    start: u64,
    end: u64,
    va_to_off: &dyn Fn(u64) -> Option<usize>,
    show_pcode: bool,
) {
    let Some(off) = va_to_off(start) else {
        println!("  (address not in any section)");
        return;
    };

    let mut addr = start;
    let mut count = 0;
    while addr < end && count < 200 {
        let Some(file_off) = va_to_off(addr) else { break; };
        if file_off >= data.len() { break; }
        let remaining = &data[file_off..data.len().min(file_off + 16)];
        if remaining.is_empty() { break; }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dec.decode(remaining, addr)
        }));

        match result {
            Ok(Ok(inst)) => {
                if inst.len == 0 { break; }
                let hex: String = remaining[..inst.len as usize].iter()
                    .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                println!("  0x{:08x}: {:24} {}", addr, hex, inst.disassembly);
                if show_pcode {
                    for (j, op) in inst.ops.iter().enumerate() {
                        println!("              [{j}] {op:?}");
                    }
                }
                // Stop at RET
                let dis = inst.disassembly.to_uppercase();
                if dis.starts_with("RET") || dis == "INT3" {
                    break;
                }
                addr += inst.len;
                count += 1;
            }
            Ok(Err(_)) => {
                println!("  0x{:08x}: {:02x} ???", addr, remaining[0]);
                break;
            }
            Err(_) => {
                println!("  0x{:08x}: (panic)", addr);
                break;
            }
        }
    }
}

fn decompile_func(
    data: &[u8],
    dec: &mut rsleigh_api::Decoder,
    start: u64,
    end: u64,
    va_to_off: &dyn Fn(u64) -> Option<usize>,
    path: &std::path::Path,
) {
    let mut addr = start;
    let mut insts = Vec::new();

    loop {
        let Some(file_off) = va_to_off(addr) else { break; };
        if file_off >= data.len() { break; }
        let remaining = &data[file_off..data.len().min(file_off + 16)];
        if remaining.is_empty() { break; }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dec.decode(remaining, addr)
        }));

        match result {
            Ok(Ok(inst)) => {
                if inst.len == 0 { break; }
                let dis = inst.disassembly.to_uppercase();
                let l = inst.len;
                insts.push((addr, inst));
                if dis.starts_with("RET") {
                    break;
                }
                addr += l;
            }
            _ => break,
        }
        if insts.len() > 500 { break; }
    }

    if insts.is_empty() {
        println!("  (no instructions decoded)");
        return;
    }

    let output = rsleigh_decompile::decompile_with_binary(
        rsleigh_api::Architecture::X86_32,
        &insts,
        Some(data),
        Some(path),
    );
    for line in output.lines() {
        if !line.trim().is_empty() {
            println!("  {}", line);
        }
    }
}
