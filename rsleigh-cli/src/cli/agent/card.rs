use super::*;

mod analysis;

pub(super) fn run(binary_path: &str, data: &[u8], args: &[String]) -> Result<u8, String> {
    let _execution = execution_scope(args)?;
    let values = [
        "--instruction-cursor",
        "--operation-cursor",
        "--limit",
        "--analysis-cache",
        "--max-decode-instructions",
        "--max-ssa-work",
        "--deadline-ms",
    ];
    let mut targets = Vec::new();
    let mut i = 2;
    while i < args.len() {
        if values.contains(&args[i].as_str()) {
            i += 2;
            continue;
        }
        match args[i].as_str() {
            "--card" | "--json" | "--pcode" | "--decompile" => {}
            a if a.starts_with("--") => return Err(format!("unsupported card option: {a}")),
            _ => targets.push(args[i].as_str()),
        }
        i += 1;
    }
    if targets.len() != 1 {
        return Err("--card requires exactly one function name or address".to_string());
    }
    let obj = parse_object_lenient(data).map_err(|e| e.to_string())?;
    let (arch, segs, symbols) =
        agent_symbols(&obj, data).ok_or("unsupported binary format or architecture")?;
    let address = resolve_target(targets[0], &symbols)?;
    let name = symbols
        .iter()
        .find(|(a, _)| *a == address)
        .map(|(_, n)| n.clone())
        .unwrap_or_else(|| format!("FUN_{address:x}"));
    let (prepared, metrics) = analysis::prepare(
        binary_path,
        data,
        args,
        arch,
        address,
        &name,
        &obj,
        &segs,
        &symbols,
    )?;
    let analysis::Analysis {
        instructions,
        pseudocode,
        imports,
        strings,
        mut warnings,
        mut diagnostics,
    } = prepared;
    if instructions.is_empty() {
        let error = "no decodable instructions at requested address";
        diagnostics.push(diagnostic("decode", "no_instructions", error));
        emit(
            &json!({"schema":"rsleigh.card/v2", "status":"failed", "error":error,
            "file":{"sha256":compute_sha256(data)}, "function":{"name":name,"address":format!("0x{address:x}")},
            "diagnostics":diagnostics, "metrics":metrics, "instructions":[], "operations":[]}),
        );
        return Ok(1);
    }
    let include_pcode = args.iter().any(|a| a == "--pcode");
    let include_pseudocode = args.iter().any(|a| a == "--decompile");
    let instruction_cursor = number_arg(args, "--instruction-cursor", 0)?;
    let operation_cursor = number_arg(args, "--operation-cursor", 0)?;
    if !include_pcode && operation_cursor != 0 {
        return Err("--operation-cursor requires --pcode".to_string());
    }
    let total_ops = instructions
        .iter()
        .map(|inst| inst.operations.len())
        .sum::<usize>();
    if instruction_cursor > instructions.len() || operation_cursor > total_ops {
        return Err("cursor is beyond the end of this function's evidence".to_string());
    }
    let instruction_end = instruction_cursor
        .saturating_add(AGENT_CARD_MAX_INSTRUCTIONS)
        .min(instructions.len());
    let operation_end = operation_cursor
        .saturating_add(AGENT_CARD_MAX_PCODE_OPS)
        .min(total_ops);
    let instruction_page: Vec<_> = instructions
        .iter()
        .enumerate()
        .skip(instruction_cursor)
        .take(AGENT_CARD_MAX_INSTRUCTIONS)
        .map(|(index, inst)| {
            let addr = inst.address;
            let bytes = segs
                .iter()
                .find_map(|(va, size, offset)| {
                    let delta = addr.checked_sub(*va)?;
                    if delta >= *size {
                        return None;
                    }
                    let start = usize::try_from(offset.checked_add(delta)?).ok()?;
                    data.get(start..start.checked_add(inst.len as usize)?)
                })
                .map(|b| b.iter().map(|b| format!("{b:02x}")).collect::<String>());
            json!({"index":index, "address":format!("0x{addr:x}"), "length":inst.len,
                "bytes":bytes, "disassembly":inst.disassembly,
                "constructor":inst.constructor})
        })
        .collect();
    let operations: Vec<_> = if include_pcode {
        instructions.iter().enumerate().flat_map(|(instruction_index,inst)| {
            let addr=inst.address;
            inst.operations.iter().enumerate().map(move |(operation_index,op)| (instruction_index,addr,operation_index,op))
        }).enumerate().skip(operation_cursor).take(AGENT_CARD_MAX_PCODE_OPS)
        .map(|(index,(instruction_index,addr,operation_index,op))| json!({
            "index":index, "instruction_index":instruction_index, "address":format!("0x{addr:x}"),
            "operation_index":operation_index, "operation":op, "op":format!("{op:?}")
        })).collect()
    } else {
        Vec::new()
    };
    let mut pseudo_end = pseudocode.len().min(AGENT_CARD_MAX_PSEUDOCODE_BYTES);
    while !pseudocode.is_char_boundary(pseudo_end) {
        pseudo_end -= 1;
    }
    if instruction_cursor != 0 || instruction_end < instructions.len() {
        warnings.push(
            "disassembly is a page of the function; inspect pagination for omitted evidence".into(),
        );
    }
    if include_pcode && (operation_cursor != 0 || operation_end < total_ops) {
        warnings.push(
            "P-code is a page of the function; inspect pagination for omitted evidence".into(),
        );
    }
    if include_pseudocode && pseudo_end < pseudocode.len() {
        warnings.push("pseudocode truncated at 4096 bytes".into());
    }
    let status = evidence_status(true, &diagnostics);
    let (_, imagebase) = agent_format_and_base(&obj, &segs);
    let payload = json!({
        "schema":"rsleigh.card/v2", "status":status, "tool_version":env!("CARGO_PKG_VERSION"),
        "file":{"path":binary_path,"sha256":compute_sha256(data),"arch":format!("{arch:?}"),"imagebase":format!("0x{imagebase:x}")},
        "function":{"name":name,"address":format!("0x{address:x}"),
            "size":instructions.last().map(|i| i.address + i.len - address).unwrap_or(0),
            "complexity":1 + instructions.iter().flat_map(|i| &i.operations).filter(|o| matches!(o,pcode_ir::PcodeOp::CBranch{..})).count(),
            "calling_convention":agent_calling_convention(arch,&obj)},
        "imports":imports,"strings":strings,
        "metrics":metrics,"metadata_stage":"decompile", "trust":agent_trust_json(), "warnings":warnings,"diagnostics":diagnostics,
        "instructions":instruction_page,"operations":operations,"operation_stage":"raw-pcode/v1",
        "pagination":{
            "instructions":page(instruction_cursor,instruction_end,instructions.len(),AGENT_CARD_MAX_INSTRUCTIONS),
            "operations":if include_pcode { page(operation_cursor,operation_end,total_ops,AGENT_CARD_MAX_PCODE_OPS) } else { Value::Null }
        },
        "pseudocode":if include_pseudocode { json!({"stage":"decompile","confidence":"hypothesis",
            "text":&pseudocode[..pseudo_end],"bytes_total":pseudocode.len(),"bytes_cap":AGENT_CARD_MAX_PSEUDOCODE_BYTES,
            "truncated":pseudo_end < pseudocode.len()}) } else { Value::Null }
    });
    if args.iter().any(|a| a == "--json") {
        emit(&payload);
    } else {
        render_text(&payload);
    }
    Ok(status_exit(status))
}

pub(super) fn resolve_target(target: &str, symbols: &[(u64, String)]) -> Result<u64, String> {
    target
        .strip_prefix("0x")
        .or_else(|| target.strip_prefix("0X"))
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .or_else(|| symbols.iter().find(|(_, n)| n == target).map(|(a, _)| *a))
        .ok_or_else(|| format!("function '{target}' not found"))
}

fn page(start: usize, end: usize, total: usize, cap: usize) -> Value {
    json!({"cursor":start,"returned":end-start,"total":total,"cap":cap,
        "truncated":start != 0 || end < total,"next_cursor":if end < total { Some(end) } else { None }})
}

/// Text and JSON share the exact evidence model, caps, and status.
fn render_text(card: &Value) {
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    println!(
        "# {}  addr={}  size={}  complexity={}  cc={}",
        s(&card["function"]["name"]),
        s(&card["function"]["address"]),
        card["function"]["size"],
        card["function"]["complexity"],
        s(&card["function"]["calling_convention"])
    );
    println!(
        "status: {}\nbinary sha256: {}",
        s(&card["status"]),
        s(&card["file"]["sha256"])
    );
    println!("imports: {}\nstrings: {}", card["imports"], card["strings"]);
    println!("constructor spans:");
    for inst in card["instructions"].as_array().unwrap() {
        if !inst["constructor"].is_null() {
            println!("  {}: {}", s(&inst["address"]), inst["constructor"]);
        }
    }
    println!("trust: decoder/P-code=primary; pseudocode=hypothesis; findings=leads\nwarnings[]:");
    for warning in card["warnings"].as_array().unwrap() {
        println!("  - {}", s(warning));
    }
    println!("diagnostics: {}", card["diagnostics"]);
    println!("metrics: {}", card["metrics"]);
    println!("\n## disasm (first 40 instructions per page)");
    for inst in card["instructions"].as_array().unwrap() {
        println!("{}  {}", s(&inst["address"]), s(&inst["disassembly"]));
    }
    println!("pagination: {}", card["pagination"]["instructions"]);
    if !card["pagination"]["operations"].is_null() {
        println!("\n## p-code (first 120 ops per page)");
        for op in card["operations"].as_array().unwrap() {
            println!(
                "{}:{}  {}",
                s(&op["address"]),
                op["operation_index"],
                s(&op["op"])
            );
        }
        println!("pagination: {}", card["pagination"]["operations"]);
    }
    if !card["pseudocode"].is_null() {
        println!(
            "\n## pseudocode (hypothesis; max 4096 bytes)\n{}",
            s(&card["pseudocode"]["text"])
        );
        if card["pseudocode"]["truncated"] == true {
            println!("// ... pseudocode truncated by --card output budget");
        }
    }
}
