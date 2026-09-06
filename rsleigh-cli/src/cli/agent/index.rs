use super::*;
use std::io::Write;
use std::path::PathBuf;

const ARTIFACTS: [&str; 4] = [
    "functions.json",
    "xrefs.json",
    "imports.json",
    "findings.ndjson",
];

pub(super) fn build(
    binary_path: &str,
    data: &[u8],
    args: &[String],
    out_dir: &str,
) -> Result<u8, String> {
    let limit = requested_agent_limit(args, AGENT_INDEX_MAX_FUNCTIONS, AGENT_INDEX_MAX_FUNCTIONS);
    let analysis = build_agent_analysis(binary_path, data, limit, AGENT_INDEX_MAX_FINDINGS)?;
    let status = analysis_status(&analysis);
    let functions = json!({"schema":"rsleigh.functions/v1","source":binary_path,
        "count":analysis.functions.len(),"total_discovered":analysis.total_functions,
        "truncated":analysis.functions.len() < analysis.total_functions,
        "functions":analysis.functions.iter().map(agent_function_json).collect::<Vec<_>>()});
    let names: std::collections::HashMap<_, _> = analysis
        .functions
        .iter()
        .map(|f| (f.address, f.name.as_str()))
        .collect();
    let mut called_by: std::collections::HashMap<u64, Vec<Value>> =
        std::collections::HashMap::new();
    for caller in &analysis.functions {
        for target in &caller.direct_targets {
            called_by
                .entry(*target)
                .or_default()
                .push(json!({"name":caller.name,"addr":format!("0x{:x}",caller.address)}));
        }
    }
    let xrefs = json!({"schema":"rsleigh.xrefs/v1","source":binary_path,
        "scope":"returned function subset; direct calls only",
        "functions":analysis.functions.iter().map(|f| json!({
            "name":f.name,"addr":format!("0x{:x}",f.address),
            "calls":f.direct_targets.iter().map(|t| json!({"name":names.get(t).copied().unwrap_or("unknown"),"addr":format!("0x{t:x}")})).collect::<Vec<_>>(),
            "called_by":called_by.get(&f.address).cloned().unwrap_or_default()
        })).collect::<Vec<_>>()});
    let imports = json!({"schema":"rsleigh.imports/v1","source":binary_path,
        "imports":analysis.imports.iter().map(|(a,n)| json!({"name":n,"addr":format!("0x{a:x}")})).collect::<Vec<_>>()});
    let mut ndjson = String::new();
    for f in &analysis.findings {
        ndjson.push_str(&serde_json::to_string(f).map_err(|e| e.to_string())?);
        ndjson.push('\n');
    }
    let artifacts = vec![
        (
            "functions.json",
            serde_json::to_vec_pretty(&functions).unwrap(),
        ),
        ("xrefs.json", serde_json::to_vec_pretty(&xrefs).unwrap()),
        ("imports.json", serde_json::to_vec_pretty(&imports).unwrap()),
        ("findings.ndjson", ndjson.into_bytes()),
    ];
    let manifest = json!({
        "schema":"rsleigh.index/v2","status":status,"source":binary_path,
        "file":file_identity(binary_path,data,&analysis), "tool_version":env!("CARGO_PKG_VERSION"),
        "analysis_options":{"function_limit":limit,"finding_limit":AGENT_INDEX_MAX_FINDINGS,
            "strings_per_function":5,"ranking":"incoming_calls,complexity,size,address",
            "smt":false,"metadata":"decompile_with_binary"},
        "trust":agent_trust_json(),"warnings":agent_arch_warnings(analysis.arch),
        "limits":{"functions_returned":analysis.functions.len(),"functions_total":analysis.total_functions,
            "functions_cap":AGENT_INDEX_MAX_FUNCTIONS,"findings_returned":analysis.findings.len(),
            "findings_total":analysis.total_findings,"findings_cap":AGENT_INDEX_MAX_FINDINGS}
    });
    let manifest = publish(Path::new(out_dir), manifest, &artifacts)
        .map_err(|e| format!("cannot publish index: {e}"))?;
    emit(&manifest);
    Ok(status_exit(status))
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Readers pin root/index.json once. A writer never modifies any published
/// generation; its only replacement is the final atomic manifest rename.
fn publish(
    root: &Path,
    mut manifest: Value,
    artifacts: &[(&str, Vec<u8>)],
) -> std::io::Result<Value> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(root.join("generations"))?;
    let (generation, directory) = loop {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = format!(
            "{stamp}-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        );
        let directory = root.join("generations").join(&name);
        match std::fs::create_dir(&directory) {
            Ok(()) => break (name, directory),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let mut files = Vec::new();
    for (name, bytes) in artifacts {
        write_new(&directory.join(name), bytes)?;
        files.push(
            json!({"name":name,"path":format!("generations/{generation}/{name}"),
            "sha256":compute_sha256(bytes),"size":bytes.len()}),
        );
    }
    manifest["generation"] = json!(generation);
    manifest["files"] = json!(files);
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    // Keep the completed manifest in its generation as well as at the root.
    write_new(&directory.join("index.json"), &bytes)?;
    sync_directory(&directory)?;
    sync_directory(&root.join("generations"))?;
    let pending = root.join(format!(".index-{generation}.tmp"));
    write_new(&pending, &bytes)?;
    if let Err(e) = std::fs::rename(&pending, root.join("index.json")) {
        let _ = std::fs::remove_file(&pending);
        return Err(e);
    }
    sync_directory(root)?;
    Ok(manifest)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}
#[cfg(not(unix))]
fn sync_directory(_: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(super) fn verify(data: &[u8], out_dir: &str) -> Result<u8, String> {
    let root = Path::new(out_dir);
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()));
    let manifest_bytes = read(&root.join("index.json"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("invalid index manifest: {e}"))?;
    if manifest["schema"] != "rsleigh.index/v2" {
        return Err("expected rsleigh.index/v2".into());
    }
    if manifest["file"]["hashes"]["sha256"] != compute_sha256(data) {
        return Err("index binary SHA-256 does not match input".into());
    }
    if manifest["tool_version"] != env!("CARGO_PKG_VERSION") {
        return Err("index tool version differs; rebuild before reuse".into());
    }
    let generation = manifest["generation"]
        .as_str()
        .ok_or("missing generation")?;
    if generation.is_empty() || !generation.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return Err("invalid generation identifier".into());
    }
    let generation_manifest = read(&root.join("generations").join(generation).join("index.json"))?;
    if generation_manifest != manifest_bytes {
        return Err("published manifest differs from completed generation".into());
    }
    let files = manifest["files"]
        .as_array()
        .ok_or("missing artifact manifest")?;
    if files.len() != ARTIFACTS.len() {
        return Err("incomplete artifact manifest".into());
    }
    for name in ARTIFACTS {
        let matches: Vec<_> = files.iter().filter(|f| f["name"] == name).collect();
        if matches.len() != 1 {
            return Err(format!("missing or duplicate artifact: {name}"));
        }
        let record = matches[0];
        let expected_path = format!("generations/{generation}/{name}");
        if record["path"] != expected_path {
            return Err(format!("invalid artifact path for {name}"));
        }
        let bytes = read(&root.join(PathBuf::from(expected_path)))?;
        if record["size"].as_u64() != Some(bytes.len() as u64)
            || record["sha256"] != compute_sha256(&bytes)
        {
            return Err(format!("artifact checksum or size mismatch: {name}"));
        }
        if name == "findings.ndjson" {
            for line in bytes.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
                let f: Value =
                    serde_json::from_slice(line).map_err(|e| format!("invalid finding: {e}"))?;
                if f["schema"] != "rsleigh.finding/v1" {
                    return Err("invalid finding schema".into());
                }
            }
        } else {
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|e| format!("invalid {name}: {e}"))?;
            let kind = name.trim_end_matches(".json");
            if value["schema"] != format!("rsleigh.{kind}/v1") {
                return Err(format!("invalid schema: {name}"));
            }
        }
    }
    let status = manifest["status"]
        .as_str()
        .ok_or("missing analysis status")?;
    if !["ok", "partial", "failed"].contains(&status) {
        return Err("invalid analysis status".into());
    }
    emit(
        &json!({"schema":"rsleigh.index-verification/v1","status":"ok","valid":true,
        "analysis_status":status,"generation":generation,"file_sha256":compute_sha256(data),"artifacts_verified":files.len()}),
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_artifact_write_keeps_previous_manifest() {
        let root = std::env::temp_dir().join(format!(
            "rsleigh-index-publish-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = publish(&root, json!({"schema":"test"}), &[("first", vec![1])]).unwrap();
        let original = std::fs::read(root.join("index.json")).unwrap();
        // First new artifact succeeds; the next fails because its parent is absent.
        assert!(publish(
            &root,
            json!({"schema":"test"}),
            &[("first", vec![2]), ("missing/second", vec![3])]
        )
        .is_err());
        assert_eq!(std::fs::read(root.join("index.json")).unwrap(), original);
        assert_eq!(
            std::fs::read(root.join(first["files"][0]["path"].as_str().unwrap())).unwrap(),
            vec![1]
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
