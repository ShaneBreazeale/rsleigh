use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

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
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rsleigh-agent-interface-{}-{nonce}",
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
    assert_eq!(card["schema"], "rsleigh.card/v1");
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
    assert_eq!(slice["schema"], "rsleigh.ssa-slice/v1");
    assert_eq!(slice["file_sha256"], hash(&std::fs::read(&binary).unwrap()));
    assert_eq!(slice["slice"]["root"], constant["id"]);
    assert_eq!(slice["slice"]["nodes"][0]["var_id"], constant["id"]);
    assert_eq!(slice["slice"]["nodes"][0]["kind"], "constant");
    assert_eq!(slice["slice"]["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(slice["slice"]["max_nodes"], 8);
    let (code, error) = invoke(&binary, &["--ssa-slice", "0x401000", "--var", "4294967295"]);
    assert_eq!(code, 1);
    assert!(error["error"].as_str().unwrap().contains("does not exist"));
    std::fs::remove_dir_all(root).unwrap();
}
