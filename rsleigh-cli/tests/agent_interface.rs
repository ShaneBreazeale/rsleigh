use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

#[path = "../../test-harness/fixtures/agent-re/seed.rs"]
mod re_seed;
#[path = "../../test-harness/fixtures/agent-re/traversal.rs"]
mod re_traversal;

#[test]
fn native_memory_and_helper_dependencies_retain_scoped_evidence_and_cache_reuse() {
    let (root, binary) = fixture();
    std::fs::write(&binary, re_traversal::binary()).unwrap();
    for (function, site, store) in [("0x401040", "0x401050", 0x401043u64), ("0x401060", "0x40106f", 0x401060)] {
        let (code, value) = invoke(&binary, &["--ssa-slice", function, "--return", "--at", site]);
        assert!(matches!(code, 0 | 2), "{value}");
        assert_eq!(value["slice"]["nodes"][0]["constant"], 73, "{value}");
        assert_eq!(value["slice"]["complete"], true, "{value}");
        assert!(value["evidence"]["operations"].as_array().unwrap().iter().any(|o|
            o["origin"]["instruction_address"] == store && o["operation"]["opcode"] == "store"));
    }
    let cache = root.join("cache");
    let args = ["--ssa-slice", "0x401000", "--return", "--at", "0x40100a", "--analysis-cache", cache.to_str().unwrap()];
    let (code, first) = invoke(&binary, &args);
    assert!(matches!(code, 0 | 2), "{first}");
    assert_eq!(first["slice"]["complete"], true, "{first}");
    assert_eq!(first["slice"]["contexts"].as_array().unwrap().len(), 2, "{first}");
    assert!(first["slice"]["nodes"].as_array().unwrap().iter().any(|n|
        n["function_address"] == 0x401020u64 && n["links"].as_array().unwrap().iter().any(|l| l["kind"] == "argument_binding")));
    assert!(first["slice"]["nodes"].as_array().unwrap().iter().any(|n|
        n["function_address"] == 0x401000u64 && n["constant"] == 17));
    let mut warm_args = args.to_vec();
    warm_args.extend(["--max-ssa-work", "0", "--max-decode-instructions", "0"]);
    let (_, warm) = invoke(&binary, &warm_args);
    assert_eq!(first["slice"], warm["slice"], "{warm}");
    assert_eq!(first["evidence"], warm["evidence"]);
    assert_eq!(warm["metrics"]["execution"]["ssa_work"], 0);
    assert_eq!(warm["metrics"]["execution"]["decode_instructions"], 0);
    assert!(warm["metrics"]["functions"].as_array().unwrap().iter().all(|f| f["metrics"]["cache"] == "hit"));
    for (flag, limit, reason) in [("--max-call-depth", "0", "call_depth_limit"), ("--max-functions", "1", "function_limit")] {
        let mut limited = args.to_vec(); limited.extend([flag, limit]);
        let (_, value) = invoke(&binary, &limited);
        assert_eq!(value["slice"]["complete"], false);
        assert!(value["slice"]["nodes"].as_array().unwrap().iter().any(|n| n["boundary"] == reason));
    }
    let (_, recursive) = invoke(&binary, &["--ssa-slice", "0x401080", "--return", "--at", "0x401085"]);
    assert!(recursive["slice"]["nodes"].as_array().unwrap().iter().any(|n| n["boundary"] == "recursion_limit"), "{recursive}");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_ambiguous_memory_keeps_its_boundary_after_copy_folding() {
    let (root, binary) = fixture();
    let mut bytes = re_traversal::binary();
    // sub esp,4; mov [esp],73; mov [ecx],eax; mov eax,[esp]; add esp,4; ret.
    // ECX can point to the stack slot, so the intervening write invalidates it.
    let code = b"\x83\xec\x04\xc7\x04\x24\x49\x00\x00\x00\x89\x01\x8b\x04\x24\x83\xc4\x04\xc3";
    bytes[0x240..0x240 + code.len()].copy_from_slice(code);
    std::fs::write(&binary, bytes).unwrap();
    let (code, value) = invoke(&binary, &["--ssa-slice", "0x401040", "--return", "--at", "0x401052"]);
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["slice"]["complete"], false);
    assert!(value["slice"]["nodes"].as_array().unwrap().iter().any(|n| n["boundary"] == "ambiguous_alias"), "{value}");
    let (_, limited) = invoke(&binary, &["--ssa-slice", "0x401040", "--return", "--at", "0x401052", "--max-traversal-work", "0"]);
    assert_eq!(limited["slice"]["stops"][0], "traversal_work_limit");
    assert!(limited["evidence"]["partial_functions"][0]["instructions"].as_array().unwrap().len() > 0);
    std::fs::remove_dir_all(root).unwrap();
}

fn build_minimal_pe32() -> Vec<u8> {
    let mut buf = vec![0u8; 0x400];
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    let pe = 0x80usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());

    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
    buf[opt + 4..opt + 8].copy_from_slice(&0x200u32.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 24..opt + 28].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    buf[opt + 40..opt + 42].copy_from_slice(&5u16.to_le_bytes());
    buf[opt + 48..opt + 50].copy_from_slice(&5u16.to_le_bytes());
    buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    buf[opt + 72..opt + 76].copy_from_slice(&0x10_0000u32.to_le_bytes());
    buf[opt + 76..opt + 80].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 80..opt + 84].copy_from_slice(&0x10_0000u32.to_le_bytes());
    buf[opt + 84..opt + 88].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());

    let section = opt + 0xe0;
    buf[section..section + 8].copy_from_slice(b".text\0\0\0");
    buf[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    buf[0x200..].fill(0x90);
    // push ebp; mov ebp,esp; xor eax,eax; test eax,eax; jne +1; ret; ret
    buf[0x200..0x20b].copy_from_slice(&[
        0x55, 0x89, 0xe5, 0x31, 0xc0, 0x85, 0xc0, 0x75, 0x01, 0xc3, 0xc3,
    ]);
    buf
}

fn fixture() -> (PathBuf, PathBuf) {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rsleigh-agent-interface-{}-{nonce}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let binary = root.join("sample.exe");
    std::fs::write(&binary, build_minimal_pe32()).unwrap();
    (root, binary)
}

#[test]
fn agent_brief_is_bounded_and_trust_labeled() {
    let (root, binary) = fixture();
    let output = Command::new(RSLEIGH_BIN)
        .arg(&binary)
        .args(["--agent-brief", "--limit", "1"])
        .output()
        .expect("run --agent-brief");
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "rsleigh.agent-brief/v1");
    assert_eq!(value["file"]["stage"], "file");
    assert_eq!(value["file"]["confidence"], "proved");
    assert!(value["functions"].as_array().unwrap().len() <= 1);
    assert_eq!(value["limits"]["functions_cap"], 100);
    assert_eq!(value["limits"]["findings_cap"], 50);
    assert_eq!(value["limits"]["pseudocode_bytes"], 0);
    assert_eq!(value["trust"]["primary"][1], "pcode");
    assert_eq!(value["next"].as_array().unwrap().len(), 3);
    assert!(value["functions"][0].get("pseudocode").is_none());
}

#[test]
fn function_card_labels_and_caps_evidence_layers() {
    let (root, binary) = fixture();
    let output = Command::new(RSLEIGH_BIN)
        .arg(&binary)
        .args(["0x401000", "--card", "--pcode", "--decompile"])
        .output()
        .expect("run --card");
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("# FUN_"), "{stdout}");
    assert!(stdout.contains("warnings[]:"), "{stdout}");
    assert!(stdout.contains("constructor spans:"), "{stdout}");
    assert!(
        stdout.contains("## disasm (first 40 instructions per page)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("## p-code (first 120 ops per page)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("## pseudocode (hypothesis; max 4096 bytes)"),
        "{stdout}"
    );
}

#[test]
fn index_writes_reusable_machine_readable_artifacts() {
    let (root, binary) = fixture();
    let index = root.join("index");
    let output = Command::new(RSLEIGH_BIN)
        .arg(&binary)
        .arg("--index")
        .arg(&index)
        .args(["--limit", "1"])
        .output()
        .expect("run --index");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest = json_file(&index.join("index.json"));
    assert_eq!(manifest["schema"], "rsleigh.index/v2");
    assert_eq!(
        manifest["file"]["hashes"]["sha256"],
        hash(&std::fs::read(&binary).unwrap())
    );
    assert_eq!(manifest["analysis_options"]["function_limit"], 1);
    for record in manifest["files"].as_array().unwrap() {
        let bytes = std::fs::read(index.join(record["path"].as_str().unwrap())).unwrap();
        assert_eq!(record["sha256"], hash(&bytes));
        assert_eq!(record["size"], bytes.len());
    }
    let functions = json_file(&artifact(&index, &manifest, "functions.json"));
    assert_eq!(functions["schema"], "rsleigh.functions/v1");
    assert!(functions["functions"].as_array().unwrap().len() <= 1);
    let (code, verified) = invoke(&binary, &["--verify-index", index.to_str().unwrap()]);
    assert_eq!(code, 0, "{verified}");
    assert_eq!(verified["artifacts_verified"], 4);
    std::fs::remove_dir_all(root).unwrap();
}

fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
fn json_file(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn artifact(root: &Path, manifest: &serde_json::Value, name: &str) -> PathBuf {
    let f = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap();
    root.join(f["path"].as_str().unwrap())
}
fn invoke(binary: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let output = Command::new(RSLEIGH_BIN)
        .arg(binary)
        .args(args)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().expect("CLI must exit normally"), json)
}

#[test]
fn brief_to_card_preserves_binary_and_instruction_evidence() {
    let (root, binary) = fixture();
    let (code, brief) = invoke(&binary, &["--agent-brief", "--limit", "1"]);
    assert_eq!(code, 0, "{brief}");
    let addr = brief["functions"][0]["addr"].as_str().unwrap();
    let (code, card) = invoke(
        &binary,
        &[addr, "--card", "--json", "--pcode", "--decompile"],
    );
    assert_eq!(code, 0, "{card}");
    assert_eq!(card["schema"], "rsleigh.card/v2");
    assert_eq!(card["function"]["address"], addr);
    assert_eq!(card["file"]["sha256"], brief["file"]["hashes"]["sha256"]);
    assert_eq!(card["instructions"][0]["address"], "0x401000");
    assert_eq!(card["instructions"][0]["bytes"], "55"); // push ebp
    assert!(card["instructions"][0]["disassembly"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("push"));
    assert_eq!(card["operations"][0]["address"], "0x401000");
    assert_eq!(card["operations"][0]["operation_index"], 0);
    assert!(card["operations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|op| op["op"].as_str().unwrap().contains("Store")));
    assert_eq!(card["pseudocode"]["confidence"], "hypothesis");
    let text = Command::new(RSLEIGH_BIN)
        .arg(&binary)
        .args([addr, "--card", "--pcode", "--decompile"])
        .output()
        .unwrap();
    let text = String::from_utf8(text.stdout).unwrap();
    for inst in card["instructions"].as_array().unwrap() {
        assert!(text.contains(inst["disassembly"].as_str().unwrap()));
    }
    assert!(text.contains(card["pseudocode"]["text"].as_str().unwrap()));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn instruction_and_operation_pages_cover_full_evidence_without_duplicates() {
    let (root, binary) = fixture();
    let mut bytes = build_minimal_pe32();
    // Forty add-immediates produce >120 P-code operations and remain one function.
    for i in 0..40 {
        bytes[0x20b + i * 3..0x20e + i * 3].copy_from_slice(&[0x83, 0xc0, 0x01]);
    }
    std::fs::write(&binary, bytes).unwrap();
    let mut instruction_cursor = 0usize;
    let mut operation_cursor = 0usize;
    let mut instruction_indices = Vec::new();
    let mut operations = Vec::new();
    let mut instruction_done = false;
    let mut operation_done = false;
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages < 100, "pagination must terminate");
        let (code, card) = invoke(
            &binary,
            &[
                "0x401000",
                "--card",
                "--json",
                "--pcode",
                "--instruction-cursor",
                &instruction_cursor.to_string(),
                "--operation-cursor",
                &operation_cursor.to_string(),
            ],
        );
        assert!(code == 0 || code == 2, "{card}");
        let ip = &card["pagination"]["instructions"];
        let op = &card["pagination"]["operations"];
        assert!(card["instructions"].as_array().unwrap().len() <= 40);
        assert!(card["operations"].as_array().unwrap().len() <= 120);
        if !instruction_done {
            instruction_indices.extend(
                card["instructions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| i["index"].as_u64().unwrap()),
            );
            instruction_cursor = ip["next_cursor"]
                .as_u64()
                .unwrap_or(ip["total"].as_u64().unwrap()) as usize;
            instruction_done = ip["next_cursor"].is_null();
        }
        if !operation_done {
            operations.extend(card["operations"].as_array().unwrap().iter().cloned());
            operation_cursor = op["next_cursor"]
                .as_u64()
                .unwrap_or(op["total"].as_u64().unwrap()) as usize;
            operation_done = op["next_cursor"].is_null();
        }
        if instruction_done && operation_done {
            break;
        }
    }
    assert!(pages > 1);
    assert!(operations.len() > 120);
    assert_eq!(
        instruction_indices,
        (0..instruction_cursor as u64).collect::<Vec<_>>()
    );
    assert_eq!(
        operations
            .iter()
            .map(|op| op["index"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        (0..operation_cursor as u64).collect::<Vec<_>>()
    );
    // Compare each paged operation to the independent full P-code dump.
    let (_, full) = invoke(&binary, &["--pcode-json", "0x401000"]);
    let expected: Vec<_> = full["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|i| {
            i["ops"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(move |(op_index, op)| (i["address"].clone(), op_index, op["op"].clone()))
        })
        .collect();
    assert_eq!(operations.len(), expected.len());
    for (actual, (addr, index, op)) in operations.iter().zip(expected) {
        assert_eq!(actual["address"], addr);
        assert_eq!(actual["operation_index"], index);
        assert_eq!(actual["op"], op);
    }
    let (code, error) = invoke(
        &binary,
        &[
            "0x401000",
            "--card",
            "--json",
            "--instruction-cursor",
            "999999",
        ],
    );
    assert_eq!(code, 1);
    assert_eq!(error["status"], "failed");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_and_missing_targets_return_machine_readable_failures() {
    let (root, binary) = fixture();
    for args in [
        vec!["missing", "--card", "--json"],
        vec!["0xffffff", "--card", "--json"],
        vec!["--index"],
        vec!["--card"],
        vec!["--agent-brief", "--limit", "oops"],
    ] {
        let (code, error) = invoke(&binary, &args);
        assert_eq!(code, 1, "{args:?}: {error}");
        assert_eq!(error["status"], "failed");
        assert!(error["diagnostics"].as_array().unwrap().len() > 0);
    }
    std::fs::write(&binary, b"not a binary").unwrap();
    for args in [
        vec!["--agent-brief"],
        vec!["0x401000", "--card", "--json"],
        vec!["--index", root.to_str().unwrap()],
    ] {
        let (code, error) = invoke(&binary, &args);
        assert_eq!(code, 1);
        assert_eq!(error["status"], "failed");
        assert!(error["error"].is_string());
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn decode_failure_preserves_evidence_and_labels_partial_analysis() {
    let (root, binary) = fixture();
    let mut bytes = build_minimal_pe32();
    // A lone two-byte opcode prefix at the end is an incomplete instruction.
    bytes[0x3ff] = 0x0f;
    std::fs::write(&binary, bytes).unwrap();
    let (code, card) = invoke(&binary, &["0x401000", "--card", "--json", "--pcode"]);
    assert_eq!(code, 2, "{card}");
    assert_eq!(card["status"], "partial");
    assert_eq!(card["instructions"][0]["bytes"], "55");
    assert!(card["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["stage"] == "decode" && d["code"] == "decode_failed"));
    let (code, brief) = invoke(&binary, &["--agent-brief", "--limit", "1"]);
    assert_eq!(code, 2, "{brief}");
    assert_eq!(brief["functions"][0]["status"], "partial");
    assert!(!brief["functions"][0]["diagnostics"]
        .as_array()
        .unwrap()
        .is_empty());
    let cache = root.join("cache");
    for _ in 0..2 {
        let (code, slice) = invoke(
            &binary,
            &[
                "--ssa-slice",
                "0x401000",
                "--var",
                "0",
                "--analysis-cache",
                cache.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 2, "{slice}");
        assert_eq!(slice["metrics"]["cache"], "miss");
        assert_eq!(
            slice["metrics"]["cache_write_skipped"],
            "incomplete_or_unsupported_snapshot"
        );
    }
    assert!(
        !cache.exists(),
        "incomplete decode must not publish a cache entry"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn index_verification_rejects_stale_missing_and_corrupt_evidence() {
    let (root, binary) = fixture();
    let index = root.join("index");
    let args = ["--index", index.to_str().unwrap(), "--limit", "1"];
    let (code, first) = invoke(&binary, &args);
    assert_eq!(code, 0, "{first}");
    let old_functions = artifact(&index, &first, "functions.json");
    let old_bytes = std::fs::read(&old_functions).unwrap();
    let (code, second) = invoke(&binary, &args);
    assert_eq!(code, 0, "{second}");
    assert_ne!(first["generation"], second["generation"]);
    assert_eq!(std::fs::read(old_functions).unwrap(), old_bytes);
    let verify = ["--verify-index", index.to_str().unwrap()];
    assert_eq!(invoke(&binary, &verify).0, 0);
    let original = std::fs::read(&binary).unwrap();
    let mut changed = original.clone();
    changed[0x200] = 0x90;
    std::fs::write(&binary, changed).unwrap();
    let (code, error) = invoke(&binary, &verify);
    assert_eq!(code, 1);
    assert!(error["error"].as_str().unwrap().contains("SHA-256"));
    std::fs::write(&binary, original).unwrap();
    let findings = artifact(&index, &second, "findings.ndjson");
    let contents = std::fs::read(&findings).unwrap();
    std::fs::write(&findings, b"corrupt").unwrap();
    assert_eq!(invoke(&binary, &verify).0, 1);
    std::fs::write(&findings, contents).unwrap();
    std::fs::remove_file(findings).unwrap();
    assert_eq!(invoke(&binary, &verify).0, 1);
    // Even an intact older generation must not mask incomplete current evidence.
    assert!(index
        .join("generations")
        .join(first["generation"].as_str().unwrap())
        .exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn index_write_failure_has_nonzero_exit() {
    let (root, binary) = fixture();
    let index = root.join("not-a-directory");
    std::fs::write(&index, b"existing file").unwrap();
    let (code, error) = invoke(
        &binary,
        &["--index", index.to_str().unwrap(), "--limit", "1"],
    );
    assert_eq!(code, 1);
    assert_eq!(error["status"], "failed");
    assert_eq!(std::fs::read(index).unwrap(), b"existing file");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ssa_dump_variable_can_be_queried_with_matching_identity() {
    let (root, binary) = fixture();
    let (_, ssa) = invoke(&binary, &["--ssa-json", "0x401000"]);
    let constant = ssa["vars"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["expr"].as_str().unwrap().starts_with("Const("))
        .expect("fixture has constants");
    let var = constant["id"].as_u64().unwrap().to_string();
    let (code, slice) = invoke(
        &binary,
        &["--ssa-slice", "0x401000", "--var", &var, "--max-nodes", "8"],
    );
    assert!(code == 0 || code == 2, "{slice}");
    assert_eq!(slice["schema"], "rsleigh.ssa-slice/v3");
    assert_eq!(slice["file_sha256"], hash(&std::fs::read(&binary).unwrap()));
    assert_eq!(slice["slice"]["root"], constant["id"]);
    assert_eq!(slice["slice"]["nodes"][0]["var_id"], constant["id"]);
    assert_eq!(slice["slice"]["nodes"][0]["kind"], "constant");
    assert_eq!(slice["slice"]["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(slice["slice"]["limits"]["max_nodes"], 8);
    let (code, error) = invoke(&binary, &["--ssa-slice", "0x401000", "--var", "4294967295"]);
    assert_eq!(code, 1);
    assert!(error["error"].as_str().unwrap().contains("does not exist"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn semantic_selectors_answer_ground_truth_tasks_and_match_variable_slices() {
    let (root, binary) = fixture();
    std::fs::write(&binary, re_seed::binary()).unwrap();
    for task in re_seed::tasks() {
        let function = format!("0x{:x}", task.function);
        let mut query = vec!["--ssa-slice".to_string(), function.clone()];
        match task.selector {
            re_seed::Selector::Return(site) => {
                query.extend(["--return".into(), "--at".into(), format!("0x{site:x}")])
            }
            re_seed::Selector::Argument(site, index) => query.extend([
                "--call-site".into(),
                format!("0x{site:x}"),
                "--arg".into(),
                index.to_string(),
            ]),
            re_seed::Selector::Condition(site) => {
                query.extend(["--condition".into(), format!("0x{site:x}")])
            }
        }
        let (code, selected) = invoke(
            &binary,
            &query.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert!(matches!(code, 0 | 2), "{}: {selected}", task.id);
        assert_eq!(selected["selection"]["root"], selected["slice"]["root"]);
        assert_eq!(selected["selection"]["calling_convention"], "Cdecl32");
        if let Some(expected) = task.constant {
            assert_eq!(
                selected["slice"]["nodes"][0]["constant"], expected,
                "{}",
                task.id
            );
        } else {
            assert!(
                selected["slice"]["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n["boundary"].as_str() == task.boundary),
                "{}: {selected}",
                task.id
            );
            assert_eq!(selected["slice"]["complete"], false);
        }
        let id = selected["selection"]["root"].as_u64().unwrap().to_string();
        let (_, by_id) = invoke(&binary, &["--ssa-slice", &function, "--var", &id]);
        assert_eq!(selected["slice"], by_id["slice"], "{}", task.id);
        assert_eq!(selected["file_sha256"], by_id["file_sha256"]);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn semantic_selector_errors_do_not_guess_roots() {
    let (root, binary) = fixture();
    std::fs::write(&binary, re_seed::binary()).unwrap();
    for (args, expected) in [
        (
            vec!["--ssa-slice", "0x401040", "--return"],
            "ambiguous_target",
        ),
        (
            vec!["--ssa-slice", "0x401000", "--return", "--at", "0xdeadbeef"],
            "missing_target",
        ),
        (
            vec!["--ssa-slice", "0x401000", "--condition", "0x401000"],
            "unsupported_root",
        ),
        (
            vec![
                "--ssa-slice",
                "0x401020",
                "--call-site",
                "0x401024",
                "--arg",
                "9",
            ],
            "unsupported_root",
        ),
    ] {
        let (code, value) = invoke(&binary, &args);
        assert_eq!(code, 1, "{value}");
        assert_eq!(value["selection_error"]["code"], expected, "{value}");
        assert!(value.get("slice").is_none());
        if expected == "ambiguous_target" {
            assert_eq!(
                value["selection_error"]["candidates"],
                serde_json::json!(["0x401049", "0x40104f"])
            );
        }
    }
    for flags in [
        vec!["--return", "--var", "0"],
        vec!["--return", "--return"],
        vec!["--arg", "0"],
        vec!["--call-site", "0x401024"],
        vec!["--var", "0", "--at", "0x401000"],
        vec!["--condition", "401042"],
        vec!["--call-site", "0x401024", "--arg", "-1"],
    ] {
        let mut args = vec!["--ssa-slice", "0x401020"];
        args.extend(flags);
        let (code, value) = invoke(&binary, &args);
        assert_eq!(code, 1, "{value}");
        assert_eq!(value["status"], "failed");
    }
    let (code, value) = invoke(&binary, &["--ssa-slice", "0x401000", "--return"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["slice"]["nodes"][0]["constant"], 7);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cached_followup_reuses_ssa_and_recovers_from_corrupt_or_interrupted_generations() {
    let (root, binary) = fixture();
    std::fs::write(&binary, re_seed::binary()).unwrap();
    let cache = root.join("cache");
    let args = [
        "--ssa-slice",
        "0x401020",
        "--call-site",
        "0x401024",
        "--arg",
        "0",
        "--analysis-cache",
        cache.to_str().unwrap(),
    ];
    let (code, first) = invoke(&binary, &args);
    assert!(matches!(code, 0 | 2), "{first}");
    assert_eq!(first["metrics"]["cache"], "miss");
    assert_eq!(first["metrics"]["ssa_builds"], 1);
    let (_, second) = invoke(&binary, &args);
    assert_eq!(second["metrics"]["cache"], "hit", "{second}");
    assert_eq!(second["metrics"]["decode_builds"], 0);
    assert_eq!(second["metrics"]["ssa_builds"], 0);
    assert_eq!(first["slice"], second["slice"]);
    assert_eq!(first["evidence"], second["evidence"]);
    assert_eq!(first["selection"], second["selection"]);
    let key = cache.join(first["metrics"]["snapshot_id"].as_str().unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(key.join("index.json")).unwrap()).unwrap();
    assert!(matches!(manifest["identity"]["tool_build"]["kind"].as_str(),Some("macho_uuid"|"elf_build_id"|"sha256")));
    assert!(!manifest["identity"]["tool_build"]["id"].as_str().unwrap().is_empty());
    assert_eq!(manifest["identity"]["architecture"], "X86_32");
    let payload = key.join(manifest["files"][0]["path"].as_str().unwrap());
    std::fs::write(&payload, b"corrupt").unwrap();
    let (_, recovered) = invoke(&binary, &args);
    assert_eq!(recovered["metrics"]["cache"], "miss");
    assert_eq!(recovered["slice"], first["slice"]);
    assert!(recovered["metrics"]["cache_miss_reason"]
        .as_str()
        .unwrap()
        .contains("checksum"));
    assert_eq!(invoke(&binary, &args).1["metrics"]["cache"], "hit");
    // Even internally consistent manifests from another executable build
    // cannot be accepted for this key.
    let mut stale: serde_json::Value =
        serde_json::from_slice(&std::fs::read(key.join("index.json")).unwrap()).unwrap();
    stale["identity"]["tool_build"]["id"] = serde_json::json!("0".repeat(64));
    let stale_bytes = serde_json::to_vec_pretty(&stale).unwrap();
    let stale_generation = key
        .join("generations")
        .join(stale["generation"].as_str().unwrap());
    std::fs::write(key.join("index.json"), &stale_bytes).unwrap();
    std::fs::write(stale_generation.join("index.json"), &stale_bytes).unwrap();
    let (_, rebuilt) = invoke(&binary, &args);
    assert_eq!(rebuilt["metrics"]["cache"], "miss");
    assert!(rebuilt["metrics"]["cache_miss_reason"]
        .as_str()
        .unwrap()
        .contains("identity"));
    // Unpublished and incomplete generations never act as cache hits.
    std::fs::remove_file(key.join("index.json")).unwrap();
    std::fs::create_dir(key.join("generations/123-456-0")).unwrap();
    std::fs::write(key.join("generations/123-456-0/snapshot.json"), b"{}").unwrap();
    assert_eq!(invoke(&binary, &args).1["metrics"]["cache"], "miss");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn slice_origins_resolve_to_typed_card_operations_in_the_same_binary() {
    let (root, binary) = fixture();
    std::fs::write(&binary, re_seed::binary()).unwrap();
    for task in re_seed::tasks() {
        let function = format!("0x{:x}", task.function);
        let flags: Vec<String> = match task.selector {
            re_seed::Selector::Return(site) => vec!["--return".into(), "--at".into(), format!("0x{site:x}")],
            re_seed::Selector::Argument(site, index) => vec!["--call-site".into(), format!("0x{site:x}"), "--arg".into(), index.to_string()],
            re_seed::Selector::Condition(site) => vec!["--condition".into(), format!("0x{site:x}")],
        };
        let mut args = vec!["--ssa-slice", function.as_str()];
        args.extend(flags.iter().map(String::as_str));
        let (_, slice) = invoke(&binary, &args);
        let (_, card) = invoke(&binary, &["--card", &function, "--json", "--pcode"]);
        assert_eq!(slice["schema"], "rsleigh.ssa-slice/v3");
        assert_eq!(card["schema"], "rsleigh.card/v2");
        assert_eq!(slice["file_sha256"], card["file"]["sha256"]);
        assert_eq!(slice["evidence"]["snapshot_id"], slice["metrics"]["snapshot_id"]);
        assert_eq!(slice["metrics"]["snapshot_id"].as_str().unwrap().len(), 64);
        let evidence = slice["evidence"]["operations"].as_array().unwrap();
        for node in slice["slice"]["nodes"].as_array().unwrap() {
            let origins = node["origins"]["operations"].as_array().unwrap();
            assert!(origins.len() <= 32);
            assert_eq!(origins.is_empty(), !node["origins_unavailable"].is_null());
            for origin in origins {
                let raw = evidence.iter().find(|op| &op["origin"] == origin).unwrap();
                let address = format!("0x{:x}", origin["instruction_address"].as_u64().unwrap());
                let card_op = card["operations"].as_array().unwrap().iter().find(|op|
                    op["address"] == address && op["operation_index"] == origin["operation_index"]
                ).unwrap();
                assert_eq!(raw["operation"], card_op["operation"]);
                assert_eq!(raw["op"], card_op["op"]);
                assert!(raw["operation"]["opcode"].is_string());
            }
        }
        if task.id == "return-seven" {
            assert!(evidence.iter().any(|op| op["origin"]["instruction_address"] == 0x401000u64
                && op["operation"]["opcode"] == "copy" && op["operation"]["input"]["offset"] == 7));
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cache_identity_tracks_binary_and_analysis_options_but_not_output_limits() {
    let (root, binary) = fixture();
    let original = re_seed::binary();
    std::fs::write(&binary, &original).unwrap();
    let cache = root.join("cache");
    let args = [
        "--ssa-slice",
        "0x401000",
        "--return",
        "--analysis-cache",
        cache.to_str().unwrap(),
    ];
    let (_, first) = invoke(&binary, &args);
    let mut limited = args.to_vec();
    limited.extend(["--max-nodes", "1"]);
    assert_eq!(invoke(&binary, &limited).1["metrics"]["cache"], "hit");
    let mut changed = original.clone();
    changed[0x201] = 8;
    std::fs::write(&binary, &changed).unwrap();
    let (_, different) = invoke(&binary, &args);
    assert_eq!(different["metrics"]["cache"], "miss");
    assert_ne!(
        first["metrics"]["snapshot_id"],
        different["metrics"]["snapshot_id"]
    );
    assert_eq!(different["slice"]["nodes"][0]["constant"], 8);
    std::fs::write(&binary, &original).unwrap();
    let output = Command::new(RSLEIGH_BIN)
        .arg(&binary)
        .args(args)
        .env("RSLEIGH_OPAQUE_FOLD", "1")
        .output()
        .unwrap();
    let options: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(options["metrics"]["cache"], "miss");
    assert_ne!(
        options["metrics"]["snapshot_id"],
        first["metrics"]["snapshot_id"]
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn execution_limits_preserve_decoded_evidence_and_never_publish_stopped_snapshots() {
    let (root, binary) = fixture();
    std::fs::write(&binary, re_seed::binary()).unwrap();
    for (flag, value, reason, expected_code) in [
        ("--max-decode-instructions", "2", "decode_limit", 2),
        ("--max-ssa-work", "1", "ssa_work_limit", 2),
        ("--deadline-ms", "0", "deadline", 1),
    ] {
        let cache = root.join(flag);
        for card in [false, true] {
            let mut args = if card {
                vec!["0x401000", "--card", "--json", "--pcode", "--decompile"]
            } else {
                vec!["--ssa-slice", "0x401000", "--return"]
            };
            args.extend([flag, value, "--analysis-cache", cache.to_str().unwrap()]);
            let (code, result) = invoke(&binary, &args);
            assert_eq!(code, expected_code, "{result}");
            assert_eq!(
                result["metrics"]["execution"]["stop"]["reason"], reason,
                "{result}"
            );
            let evidence = if card {
                &result["instructions"]
            } else {
                &result["evidence"]["instructions"]
            };
            if expected_code == 2 {
                assert!(!evidence.as_array().unwrap().is_empty(), "{result}");
            }
            if flag == "--max-decode-instructions" {
                assert_eq!(evidence.as_array().unwrap().len(), 2);
            }
            assert!(
                !cache.exists(),
                "stopped work must never be published: {result}"
            );
        }
    }
    // Fully cached analysis performs no new decode/SSA work, even at zero allowance.
    let cache = root.join("warm");
    for card in [false, true] {
        let mut args = if card {
            vec!["0x401000", "--card", "--json"]
        } else {
            vec!["--ssa-slice", "0x401000", "--return"]
        };
        args.extend(["--analysis-cache", cache.to_str().unwrap()]);
        assert_eq!(invoke(&binary, &args).0, 0);
        args.extend(["--max-decode-instructions", "0", "--max-ssa-work", "0"]);
        let (code, warm) = invoke(&binary, &args);
        assert_eq!(code, 0, "{warm}");
        assert_eq!(warm["metrics"]["cache"], "hit");
        assert_eq!(warm["metrics"]["execution"]["decode_instructions"], 0);
        assert_eq!(warm["metrics"]["execution"]["ssa_work"], 0);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cached_card_pages_preserve_operations_and_track_companion_debug_inputs() {
    let (root, binary) = fixture();
    let mut bytes = build_minimal_pe32();
    for i in 0..40 {
        bytes[0x20b + i * 3..0x20e + i * 3].copy_from_slice(&[0x83, 0xc0, 0x01]);
    }
    std::fs::write(&binary, bytes).unwrap();
    let cache = root.join("cache");
    let args = [
        "0x401000",
        "--card",
        "--json",
        "--pcode",
        "--analysis-cache",
        cache.to_str().unwrap(),
    ];
    let (code, first) = invoke(&binary, &args);
    assert_eq!(code, 0, "{first}");
    let cursor = first["pagination"]["operations"]["next_cursor"]
        .as_u64()
        .unwrap()
        .to_string();
    let mut page = args.to_vec();
    page.extend(["--operation-cursor", &cursor, "--decompile"]);
    let (_, warm) = invoke(&binary, &page);
    assert_eq!(warm["metrics"]["cache"], "hit", "{warm}");
    assert_eq!(warm["metrics"]["ssa_builds"], 0);
    assert_eq!(warm["metrics"]["decode_builds"], 0);
    assert_eq!(
        warm["operations"][0]["index"].as_u64().unwrap(),
        cursor.parse::<u64>().unwrap()
    );
    let (_, uncached) = invoke(
        &binary,
        &[
            "0x401000",
            "--card",
            "--json",
            "--pcode",
            "--operation-cursor",
            &cursor,
            "--decompile",
        ],
    );
    assert_eq!(warm["operations"], uncached["operations"]);
    assert_eq!(warm["pseudocode"], uncached["pseudocode"]);
    let pdb = binary.with_extension("pdb");
    std::fs::write(&pdb, b"invalid PDB, still an analysis input").unwrap();
    let (_, changed) = invoke(&binary, &args);
    assert_eq!(changed["metrics"]["cache"], "miss");
    assert_ne!(
        changed["metrics"]["snapshot_id"],
        first["metrics"]["snapshot_id"]
    );
    std::fs::remove_file(pdb).unwrap();
    let mut bundle = binary.as_os_str().to_os_string();
    bundle.push(".dSYM");
    let dwarf = Path::new(&bundle)
        .join("Contents/Resources/DWARF")
        .join(binary.file_name().unwrap());
    std::fs::create_dir_all(dwarf.parent().unwrap()).unwrap();
    std::fs::write(&dwarf, b"invalid DWARF, still an analysis input").unwrap();
    let (_, changed) = invoke(&binary, &args);
    assert_eq!(changed["metrics"]["cache"], "miss");
    assert_ne!(
        changed["metrics"]["snapshot_id"],
        first["metrics"]["snapshot_id"]
    );
    std::fs::remove_file(dwarf).unwrap();
    assert_eq!(invoke(&binary, &args).1["metrics"]["cache"], "hit");
    std::fs::remove_dir_all(root).unwrap();
}
