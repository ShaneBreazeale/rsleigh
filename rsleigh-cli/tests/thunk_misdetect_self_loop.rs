//! Regression: rsleigh was misdetecting `FUN_140123110` (clang-ar PE)
//! as an empty thunk. The function has a real body (two direct
//! calls and a final self-loop Branch) but an upstream filter
//! produced 0 body lines, so the "empty body → emit thunk" heuristic
//! at printer.rs fired. It scanned blocks for a `Branch(BlockId)`
//! whose target address ≠ function entry — the terminal self-loop
//! block (Branch(B2), B2.addr = 0x140123123) matched — and emitted
//! `return func_140123123(); // thunk`, erasing the real calls.
//!
//! Fix: thunk emission must require BOTH (a) the body is empty AND
//! (b) no block contains a Call (terminator or stmt). A function
//! with real calls isn't a thunk even if its output got elided.
//!
//! Fixture: clang-apply-replacements.exe FUN_140123110.

use std::path::Path;
use std::process::Command;

const CLANG_AR: &str = "/tmp/clang-ar/clang-apply-replacements.exe";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture_available() -> bool {
    if Path::new(CLANG_AR).exists() { return true; }
    if std::env::var_os("RSLEIGH_REQUIRE_CLANG_AR_FIXTURE").is_some() {
        panic!("clang-apply-replacements fixture missing at {CLANG_AR}");
    }
    eprintln!("[skip] clang-apply-replacements fixture missing at {CLANG_AR}");
    false
}

#[test]
fn func_with_calls_not_emitted_as_thunk() {
    if !fixture_available() { return; }
    let out = Command::new(RSLEIGH_BIN)
        .args([CLANG_AR, "0x140123110"])
        .output()
        .expect("rsleigh invocation");
    assert!(out.status.success(), "rsleigh failed:\n{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).expect("UTF-8");

    // Must NOT emit a `// thunk` comment — function has real calls.
    assert!(
        !text.contains("// thunk"),
        "function with real calls misdetected as thunk:\n{text}"
    );
    // Target address 0x140123123 is a self-loop block, not a thunk target.
    assert!(
        !text.contains("func_140123123"),
        "self-loop block address emitted as fake thunk target:\n{text}"
    );
}
