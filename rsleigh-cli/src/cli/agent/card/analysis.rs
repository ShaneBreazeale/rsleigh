//! Reusable full card evidence, independent of page cursors and rendering.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct Analysis {
    pub instructions: Vec<cache::DecodedInstruction>,
    pub pseudocode: String,
    pub imports: Vec<String>,
    pub strings: Vec<String>,
    pub warnings: Vec<String>,
    pub diagnostics: Vec<Value>,
}

fn auxiliary_inputs(binary_path: &Path) -> Result<Value, String> {
    let mut dsym = binary_path.as_os_str().to_os_string();
    dsym.push(".dSYM");
    let dsym = Path::new(&dsym)
        .join("Contents/Resources/DWARF")
        .join(binary_path.file_name().unwrap_or_default());
    let fingerprints = [binary_path.with_extension("pdb"), dsym]
        .into_iter()
        .map(|path| match std::fs::read(&path) {
            Ok(bytes) => Ok(json!({"path":path,"sha256":compute_sha256(&bytes)})),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(json!({"path":path,"missing":true}))
            }
            Err(e) => Err(format!(
                "cannot fingerprint debug input {}: {e}",
                path.display()
            )),
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!(fingerprints))
}

fn validate(analysis: &Analysis) -> Result<(), String> {
    if analysis.instructions.is_empty() || !analysis.diagnostics.is_empty() {
        return Err("incomplete card analysis".into());
    }
    if analysis
        .instructions
        .windows(2)
        .any(|w| w[0].address >= w[1].address)
        || analysis.instructions.iter().any(|i| i.len == 0)
    {
        return Err("invalid cached instruction sequence".into());
    }
    Ok(())
}

pub(super) fn prepare(
    binary_path: &str,
    data: &[u8],
    args: &[String],
    arch: rsleigh_api::Architecture,
    address: u64,
    name: &str,
    obj: &goblin::Object,
    segs: &[(u64, u64, u64)],
    symbols: &[(u64, String)],
) -> Result<(Analysis, Value), String> {
    let mut metrics =
        json!({"cache":"disabled","decode_builds":0,"ssa_builds":0,"decoded_instructions":0});
    let mut location = None;
    // A deadline of zero does no decode or SSA work, including on a cache hit.
    if rsleigh_decompile::budget::poll("cache").is_ok() {
        let aux = auxiliary_inputs(Path::new(binary_path))?;
        let mut identity = cache::identity(data, address, arch, "card-analysis/v3", aux)?;
        identity["function_name"] = json!(name);
        let key = compute_sha256(&serde_json::to_vec(&identity).unwrap());
        metrics["snapshot_id"] = json!(key);
        if let Some(dir) = value_arg(args, "--analysis-cache")? {
            let root = Path::new(dir).join(&key);
            metrics["cache"] = json!("miss");
            match cache::load_bytes(&root, &identity).and_then(|bytes| {
                let analysis: Analysis =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                validate(&analysis)?;
                Ok(analysis)
            }) {
                Ok(mut analysis) => {
                    metrics["cache"] = json!("hit");
                    if let Err(stop) = rsleigh_decompile::budget::poll("cache") {
                        analysis
                            .diagnostics
                            .push(json!({"stage":stop.stage,"code":"execution_limit","stop":stop}));
                    }
                    metrics["execution"] = json!(rsleigh_decompile::budget::metrics());
                    return Ok((analysis, metrics));
                }
                Err(reason) => metrics["cache_miss_reason"] = json!(reason),
            }
            location = Some((root, identity));
        }
    }
    let mut diagnostics = Vec::new();
    metrics["decode_builds"] = json!(1);
    let instructions = decode_func_raw_with_diagnostics(
        address,
        symbols,
        segs,
        data,
        &mut rsleigh_api::Decoder::new(arch),
        &mut diagnostics,
    );
    metrics["decoded_instructions"] = json!(instructions.len());
    let pseudocode = if !instructions.is_empty() && rsleigh_decompile::budget::stopped().is_none() {
        metrics["ssa_builds"] = json!(1);
        recover_decompile(
            || {
                rsleigh_decompile::decompile_with_binary(
                    arch,
                    &instructions,
                    Some(data),
                    Some(Path::new(binary_path)),
                )
            },
            &mut diagnostics,
        )
    } else {
        String::new()
    };
    let _ = rsleigh_decompile::budget::poll("decompile");
    if let Some(stop) = rsleigh_decompile::budget::stopped() {
        // Cancellation is an execution boundary, not a decompiler defect.
        diagnostics.retain(|d| d["code"] != "decompile_panicked");
        if !diagnostics.iter().any(|d| d["code"] == "execution_limit") {
            diagnostics.push(json!({"stage":stop.stage,"code":"execution_limit","stop":stop}));
        }
        metrics["cache_write_skipped"] = json!("execution_limit");
    }
    let meta = rsleigh_decompile::analysis::extract_function_meta(name, address, &pseudocode);
    let import_names: std::collections::HashSet<_> =
        build_import_map(obj, data).into_values().collect();
    let mut imports: Vec<_> = meta
        .calls
        .into_iter()
        .filter(|c| import_names.contains(c))
        .collect();
    imports.sort();
    imports.dedup();
    let mut warnings: Vec<String> = agent_arch_warnings(arch)
        .into_iter()
        .map(str::to_string)
        .collect();
    if instructions
        .iter()
        .flat_map(|(_, i)| &i.ops)
        .any(|o| matches!(o, pcode_ir::PcodeOp::CallInd { .. }))
    {
        warnings.push(
            "indirect call appears in raw P-code; target resolution is not guaranteed".into(),
        );
    }
    let mut analysis = Analysis {
        instructions: cache::decoded(instructions),
        pseudocode,
        imports,
        strings: meta.strings.into_iter().take(5).collect(),
        warnings,
        diagnostics,
    };
    if let Some((root, identity)) = location {
        if validate(&analysis).is_ok() && rsleigh_decompile::budget::stopped().is_none() {
            // Debug readers consume companion files; changes during analysis
            // must not publish a snapshot under an obsolete fingerprint.
            let unchanged = auxiliary_inputs(Path::new(binary_path))?
                == identity["auxiliary_inputs"]
                && std::fs::read(binary_path)
                    .is_ok_and(|bytes| compute_sha256(&bytes) == identity["binary_sha256"]);
            if unchanged {
                cache::publish_bytes(
                    &root,
                    &identity,
                    serde_json::to_vec(&analysis).map_err(|e| e.to_string())?,
                    &mut metrics,
                );
            } else {
                metrics["cache_write_skipped"] = json!("analysis_inputs_changed");
            }
        } else if metrics["cache_write_skipped"].is_null() {
            metrics["cache_write_skipped"] = json!("incomplete_analysis");
        }
    }
    if let Some(stop) = rsleigh_decompile::budget::stopped() {
        if !analysis
            .diagnostics
            .iter()
            .any(|d| d["code"] == "execution_limit")
        {
            analysis
                .diagnostics
                .push(json!({"stage":stop.stage,"code":"execution_limit","stop":stop}));
        }
    }
    metrics["execution"] = json!(rsleigh_decompile::budget::metrics());
    Ok((analysis, metrics))
}
