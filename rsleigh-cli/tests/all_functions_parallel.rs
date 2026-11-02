//! `--all` decompiles on `--jobs` threads, streams one JSON document in
//! target order, and prints the same output whatever the thread count.
//! Fixture: test-harness/fixtures/elf/jump_tables (stripped x86-64 ELF).

use serde_json::Value;
use std::process::Command;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-harness/fixtures/elf/jump_tables/jump_tables.elf"
);

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rsleigh"))
        .arg(FIXTURE)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
    )
}

#[test]
fn parallel_output_matches_one_thread() {
    for mode in [&["--all"][..], &["--all", "--json"][..]] {
        let one = run(&[mode, &["--jobs", "1"]].concat());
        let four = run(&[mode, &["--jobs", "4"]].concat());
        assert_eq!(one, four, "{mode:?}");
    }
}

#[test]
fn streamed_json_is_one_document_with_a_status_per_function() {
    let (code, text) = run(&["--all", "--json", "--jobs", "4"]);
    let doc: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}:\n{text}"));
    let functions = doc["functions"].as_array().unwrap();
    assert!(functions.len() >= 3, "{doc}");
    for f in functions {
        assert!(
            matches!(f["status"].as_str(), Some("ok" | "partial")),
            "{f}"
        );
        assert!(f["pseudocode"].is_string(), "{f}");
    }
    let partial = functions.iter().any(|f| f["status"] == "partial");
    assert_eq!(code, if partial { 2 } else { 0 }, "{doc}");
}
