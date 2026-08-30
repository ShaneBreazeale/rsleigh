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
        stdout.contains("## disasm (first 40 instructions)"),
        "{stdout}"
    );
    assert!(stdout.contains("## p-code (first 120 ops)"), "{stdout}");
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
    for name in [
        "index.json",
        "functions.json",
        "xrefs.json",
        "findings.ndjson",
        "imports.json",
    ] {
        assert!(Path::new(&index.join(name)).is_file(), "missing {name}");
    }
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(index.join("functions.json")).unwrap()).unwrap();
    assert_eq!(functions["schema"], "rsleigh.functions/v1");
    assert!(functions["functions"].as_array().unwrap().len() <= 1);
    for line in std::fs::read_to_string(index.join("findings.ndjson"))
        .unwrap()
        .lines()
    {
        let finding: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(finding["schema"], "rsleigh.finding/v1");
    }
    let _ = std::fs::remove_dir_all(&root);
}
