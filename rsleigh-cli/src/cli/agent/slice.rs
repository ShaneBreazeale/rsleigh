use super::*;

pub(super) fn run(data: &[u8], args: &[String]) -> Result<u8, String> {
    let target = value_arg(args, "--ssa-slice")?.ok_or("--ssa-slice requires a function")?;
    let root = value_arg(args, "--var")?
        .ok_or("--ssa-slice requires --var ID (from --ssa-json)")?
        .parse::<u32>()
        .map_err(|_| "--var requires an unsigned SSA variable ID")?;
    let max_nodes = number_arg(args, "--max-nodes", 64)?;
    let max_depth = number_arg(args, "--max-depth", 16)?;
    let obj = parse_object_lenient(data).map_err(|e| e.to_string())?;
    let (arch, _segs, symbols) =
        agent_symbols(&obj, data).ok_or("unsupported binary format or architecture")?;
    let address = card::resolve_target(target, &symbols)?;
    let (insts, mut diagnostics) = ssa_instructions(data, address)?;
    let ssa = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rsleigh_decompile::folded_ssa(arch, &insts, Some(data))
    }))
    .map_err(|_| "SSA construction or folding panicked")?;
    let slice = rsleigh_decompile::slice::backward_slice(
        &ssa,
        rsleigh_decompile::ir::VarId(root),
        max_nodes,
        max_depth,
    )?;
    for diag in &ssa.diagnostics {
        diagnostics.push(json!({"stage":"ssa","code":format!("{:?}",diag.kind),
            "severity":format!("{:?}",diag.severity),"address":diag.addr.map(|a| format!("0x{a:x}")),"message":diag.detail}));
    }
    let status = if slice.complete && diagnostics.is_empty() {
        "ok"
    } else {
        "partial"
    };
    emit(&json!({"schema":"rsleigh.ssa-slice/v1","status":status,
        "file_sha256":compute_sha256(data),"tool_version":env!("CARGO_PKG_VERSION"),
        "function_address":format!("0x{address:x}"),"arch":format!("{arch:?}"),
        "snapshot":"post-fold/v1","diagnostics":diagnostics,"slice":slice,
        "scope":"intra-function expression dependencies; memory, calls, and user operations are unresolved boundaries"}));
    Ok(status_exit(status))
}
