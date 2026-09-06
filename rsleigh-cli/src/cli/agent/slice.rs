use super::*;
use rsleigh_api::Architecture;
use rsleigh_decompile::slice::selector::{self, Selector};

fn address(value: &str) -> Result<u64, String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or("selector addresses require a 0x-prefixed hexadecimal address")?;
    u64::from_str_radix(value, 16).map_err(|_| "invalid selector instruction address".into())
}

fn parse_selector(args: &[String]) -> Result<Selector, String> {
    let var = value_arg(args, "--var")?;
    let call = value_arg(args, "--call-site")?;
    let argument = value_arg(args, "--arg")?;
    let condition = value_arg(args, "--condition")?;
    let at = value_arg(args, "--at")?;
    let returns = args.iter().filter(|a| a.as_str() == "--return").count();
    if usize::from(var.is_some())
        + usize::from(call.is_some())
        + usize::from(condition.is_some())
        + returns
        != 1
    {
        return Err("select exactly one root: --var ID, --call-site ADDRESS --arg INDEX, --return [--at ADDRESS], or --condition ADDRESS".into());
    }
    if argument.is_some() != call.is_some() {
        return Err("--call-site and --arg must be used together".into());
    }
    if at.is_some() && returns != 1 {
        return Err("--at requires --return".into());
    }
    if let Some(var) = var {
        Ok(Selector::Variable {
            var_id: var
                .parse()
                .map_err(|_| "--var requires an unsigned SSA variable ID")?,
        })
    } else if let Some(call) = call {
        Ok(Selector::CallArgument {
            address: address(call)?,
            index: argument
                .unwrap()
                .parse()
                .map_err(|_| "--arg requires a zero-based unsigned argument index")?,
        })
    } else if let Some(condition) = condition {
        Ok(Selector::Condition {
            address: address(condition)?,
        })
    } else {
        Ok(Selector::Return {
            address: at.map(address).transpose()?,
        })
    }
}

pub(super) fn run(data: &[u8], args: &[String]) -> Result<u8, String> {
    let _execution = execution_scope(args)?;
    let target = value_arg(args, "--ssa-slice")?.ok_or("--ssa-slice requires a function")?;
    let selector = parse_selector(args)?;
    let max_nodes = number_arg(args, "--max-nodes", 64)?;
    let max_depth = number_arg(args, "--max-depth", 16)?;
    let obj = parse_object_lenient(data).map_err(|e| e.to_string())?;
    let (arch, _segs, symbols) =
        agent_symbols(&obj, data).ok_or("unsupported binary format or architecture")?;
    let address = card::resolve_target(target, &symbols)?;
    let (snapshot, mut metrics) = cache::analyze(data, address, arch, args)?;
    let snapshot = match snapshot {
        cache::Outcome::Complete(snapshot) => snapshot,
        cache::Outcome::Stopped {
            instructions,
            diagnostics,
        } => {
            let status = if instructions.is_empty() {
                "failed"
            } else {
                "partial"
            };
            let total = instructions.len();
            let evidence:Vec<_>=instructions.into_iter().take(AGENT_CARD_MAX_INSTRUCTIONS).map(|i|
                json!({"address":format!("0x{:x}",i.address),"length":i.len,"disassembly":i.disassembly,"constructor":i.constructor})).collect();
            emit(
                &json!({"schema":"rsleigh.ssa-slice/v3","status":status,"error":"analysis execution limit reached",
                "file_sha256":compute_sha256(data),"function_address":format!("0x{address:x}"),"tool_version":env!("CARGO_PKG_VERSION"),
                "selector":selector,"slice":Value::Null,"diagnostics":diagnostics,"metrics":metrics,
                "evidence":{"instructions":evidence,"decoded_total":total,"truncated":total>AGENT_CARD_MAX_INSTRUCTIONS}}),
            );
            return Ok(status_exit(status));
        }
    };
    let snapshot = std::rc::Rc::new(snapshot);
    let ssa = &snapshot.ssa;
    let instructions = &snapshot.instructions;
    let mut diagnostics = snapshot.diagnostics.clone();
    let operations: Vec<_> = instructions
        .iter()
        .map(|i| (i.address, i.operations.as_slice()))
        .collect();
    let cc = rsleigh_decompile::detect_cc(arch, Some(data));
    let selection = if matches!(selector, Selector::CallArgument { .. })
        && matches!(arch, Architecture::MIPS32 | Architecture::RiscV64)
    {
        Err(selector::SelectionError {code:"unsupported_root", message:"integer argument selectors are not yet supported for this architecture's calling convention".into(), candidates:vec![]})
    } else {
        selector::resolve_operations(&ssa, &operations, selector.clone(), cc)
    };
    let selection = match selection {
        Ok(selection) => selection,
        Err(error) => {
            emit(&json!({"schema":"rsleigh.ssa-slice/v3","status":"failed",
                "file_sha256":compute_sha256(data),"function_address":format!("0x{address:x}"),
                "tool_version":env!("CARGO_PKG_VERSION"),"snapshot":"post-fold/v3",
                "selector":selector,"selection_error":error,"error":error.message,"metrics":metrics}));
            return Ok(1);
        }
    };
    let mut snapshots =
        std::collections::BTreeMap::from([(address, std::rc::Rc::clone(&snapshot))]);
    let mut function_metrics = std::collections::BTreeMap::from([(address, metrics.clone())]);
    let mut partial_functions = Vec::new();
    let known_functions: std::collections::HashSet<_> =
        symbols.iter().map(|(address, _)| *address).collect();
    let imports = build_import_map(&obj, data);
    let limits = rsleigh_decompile::slice::interprocedural::Limits {
        max_nodes,
        max_depth,
        max_call_depth: number_arg(args, "--max-call-depth", 2)?,
        max_functions: number_arg(args, "--max-functions", 16)?,
        max_work: number_arg(args, "--max-traversal-work", 100_000)?,
    };
    let slice = rsleigh_decompile::slice::interprocedural::backward(
        address,
        rsleigh_decompile::ir::VarId(selection.root),
        std::rc::Rc::clone(&snapshot),
        cc,
        &imports,
        limits,
        |target| {
            if matches!(arch, Architecture::MIPS32 | Architecture::RiscV64) {
                return Err("unsupported_calling_convention: helper-call traversal is not yet supported for this architecture".into());
            }
            if let Some(snapshot) = snapshots.get(&target) {
                return Ok(std::rc::Rc::clone(snapshot));
            }
            if !known_functions.contains(&target) {
                return Err(format!(
                    "0x{target:x}: target is not a discovered function entry"
                ));
            }
            let (outcome, child_metrics) = cache::analyze(data, target, arch, args)?;
            function_metrics.insert(target, child_metrics);
            let child = match outcome {
                cache::Outcome::Complete(snapshot) => snapshot,
                cache::Outcome::Stopped {
                    instructions,
                    diagnostics,
                } => {
                    let total = instructions.len();
                    let evidence: Vec<_> = instructions.into_iter().take(AGENT_CARD_MAX_INSTRUCTIONS).map(|i|
                        json!({"address":format!("0x{:x}",i.address),"length":i.len,"disassembly":i.disassembly,"constructor":i.constructor})).collect();
                    partial_functions.push(json!({"function_address":target,"instructions":evidence,"decoded_total":total,"diagnostics":diagnostics,"truncated":total>AGENT_CARD_MAX_INSTRUCTIONS}));
                    return Err(format!("0x{target:x}: analysis execution limit"));
                }
            };
            if !child.diagnostics.is_empty()
                || child.ssa.diagnostics.iter().any(|d| {
                    matches!(
                        d.severity,
                        rsleigh_decompile::ir::Severity::Warn
                            | rsleigh_decompile::ir::Severity::Error
                    )
                })
            {
                return Err(format!("0x{target:x}: callee analysis is incomplete"));
            }
            let child = std::rc::Rc::new(child);
            snapshots.insert(target, std::rc::Rc::clone(&child));
            Ok(child)
        },
    )?;
    let origins: std::collections::BTreeSet<_> = slice
        .nodes
        .iter()
        .flat_map(|n| {
            n.node
                .origins
                .operations
                .iter()
                .map(move |origin| (n.function_address, *origin))
        })
        .collect();
    let evidence: Vec<_> = origins.into_iter().map(|(function_address, origin)| {
        let snapshot = snapshots.get(&function_address).ok_or("origin function missing from traversal")?;
        let instruction = snapshot.instructions.binary_search_by_key(&origin.instruction_address, |i| i.address)
            .ok().map(|i| &snapshot.instructions[i]).ok_or("origin instruction missing from snapshot")?;
        let operation = instruction.operations.get(origin.operation_index).ok_or("origin operation missing from snapshot")?;
        Ok(json!({"function_address":function_address,"snapshot_id":function_metrics[&function_address]["snapshot_id"],
            "origin":origin,"operation":operation,"op":format!("{operation:?}"),"disassembly":instruction.disassembly}))
    }).collect::<Result<_, String>>()?;
    for (function_address, snapshot) in &snapshots {
        for diag in &snapshot.ssa.diagnostics {
            diagnostics.push(json!({"stage":"ssa","code":format!("{:?}",diag.kind),"function_address":function_address,
                "severity":format!("{:?}",diag.severity),"address":diag.addr.map(|a| format!("0x{a:x}")),"message":diag.detail}));
        }
    }
    if slice.nodes.is_empty() {
        let instructions: Vec<_> = snapshot.instructions.iter().take(AGENT_CARD_MAX_INSTRUCTIONS).map(|i|
            json!({"address":format!("0x{:x}",i.address),"length":i.len,"disassembly":i.disassembly,"constructor":i.constructor})).collect();
        partial_functions.push(json!({"function_address":address,"instructions":instructions,
            "decoded_total":snapshot.instructions.len(),"truncated":snapshot.instructions.len()>AGENT_CARD_MAX_INSTRUCTIONS}));
    }
    metrics["execution"] = json!(rsleigh_decompile::budget::metrics());
    let functions: Vec<_> = function_metrics.iter().map(|(function_address, metrics)| json!({"function_address":function_address,"snapshot_id":metrics["snapshot_id"]})).collect();
    metrics["functions"] = json!(function_metrics.into_iter().map(|(function_address, metrics)| json!({"function_address":function_address,"metrics":metrics})).collect::<Vec<_>>());
    let status = if slice.complete && diagnostics.is_empty() {
        "ok"
    } else {
        "partial"
    };
    emit(&json!({"schema":"rsleigh.ssa-slice/v3","status":status,
        "file_sha256":compute_sha256(data),"tool_version":env!("CARGO_PKG_VERSION"),
        "function_address":format!("0x{address:x}"),"arch":format!("{arch:?}"),
        "snapshot":"post-fold/v3","diagnostics":diagnostics,"selection":selection,"slice":slice,"metrics":metrics,
        "evidence":{"snapshot_id":metrics["snapshot_id"],"operations":evidence,"operation_stage":"raw-pcode/v1",
            "origins_per_node_limit":rsleigh_decompile::provenance::MAX_ORIGINS,"functions":functions,"partial_functions":partial_functions},
        "scope":"bounded expression, exact-location memory, and helper-call dependencies; remaining aliases, side effects, and traversal limits are explicit boundaries"}));
    Ok(status_exit(status))
}
