/// Extract discoverable functions from a binary.
/// Usage: cargo run -p test-harness --example extract-functions -- <binary>
/// Outputs: JSON with [{"addr": 0x..., "name": "...", "complexity": N}, ...]

fn main() {
    let binary_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: extract-functions <binary>");
        std::process::exit(1);
    });

    let data = match std::fs::read(&binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Could not read {}: {}", binary_path, e);
            return;
        }
    };

    let obj = match goblin::Object::parse(&data) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to parse binary: {}", e);
            return;
        }
    };

    let mut functions = Vec::new();

    // Extract from symbol table
    match &obj {
        goblin::Object::Elf(elf) => {
            for sym in elf.syms.iter() {
                if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    && sym.st_type() == goblin::elf::sym::STT_FUNC
                    && sym.st_value > 0
                {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        if !name.is_empty() && !name.starts_with("_") {
                            functions.push(serde_json::json!({
                                "addr": format!("0x{:x}", sym.st_value),
                                "name": name,
                                "size": sym.st_size,
                            }));
                        }
                    }
                }
            }
        }
        goblin::Object::PE(_pe) => {
            // PE export parsing is complex; for now just note that we'd extract exports
            // rsleigh-decompile's symbol discovery handles PE imports/exports
        }
        _ => {}
    }

    // Sort by address
    functions.sort_by_key(|f| {
        u64::from_str_radix(f["addr"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap_or(0)
    });

    // Pick 5-10 diverse functions: first, middle, complex ones by size
    let selected = if functions.len() > 10 {
        let mut picked = vec![functions[0].clone()];
        picked.push(functions[functions.len() / 2].clone());
        picked.push(functions[functions.len() - 1].clone());
        // Add largest functions
        let mut by_size = functions.clone();
        by_size.sort_by_key(|f| -(f["size"].as_u64().unwrap_or(0) as i64));
        for i in 0..2.min(by_size.len()) {
            if !picked.contains(&by_size[i]) {
                picked.push(by_size[i].clone());
            }
        }
        picked
    } else {
        functions
    };

    println!("{}", serde_json::to_string_pretty(&selected).unwrap());
}
