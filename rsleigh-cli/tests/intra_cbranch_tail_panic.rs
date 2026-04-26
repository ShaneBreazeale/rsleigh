//! Regression: SSA builder's AArch64-CSEL-style intra-instruction
//! `CBranch` detection assumed the branch was never the last op of
//! the instruction group (an else-path + a final post-op always
//! followed). Real P-code on some clang-ar functions has a trailing
//! `CBranch` with no following op, and `&inst_ops[cb_idx+1..last_idx]`
//! panicked with "slice index starts at 5 but ends at 4".
//!
//! Fix: require `cb_idx + 1 < inst_ops.len()` before entering the
//! CSEL path; otherwise fall through to the regular per-op handler.
//!
//! Fixture: clang-apply-replacements.exe FUN_14002d718.

use std::path::Path;
use std::process::Command;

const CLANG_AR: &str = "/tmp/clang-ar/clang-apply-replacements.exe";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture_available() -> bool {
    if Path::new(CLANG_AR).exists() {
        return true;
    }
    if std::env::var_os("RSLEIGH_REQUIRE_CLANG_AR_FIXTURE").is_some() {
        panic!("clang-apply-replacements fixture missing at {CLANG_AR}");
    }
    eprintln!("[skip] clang-apply-replacements fixture missing at {CLANG_AR}");
    false
}

#[test]
fn trailing_cbranch_does_not_panic() {
    if !fixture_available() {
        return;
    }
    let out = Command::new(RSLEIGH_BIN)
        .args([CLANG_AR, "0x14002d718"])
        .output()
        .expect("rsleigh invocation");
    assert!(
        out.status.success(),
        "rsleigh crashed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    assert!(
        !text.contains("decompilation failed (stack overflow)") && !text.contains("panicked"),
        "rsleigh reported failure in output:\n{text}"
    );
    // Body must have more than the comment + `}` — the Ghidra counterpart
    // is ~90 lines; regressing to empty means the panic bypass reintroduced.
    assert!(
        text.lines().count() > 3,
        "body too short, likely short-circuited by empty decomp path:\n{text}"
    );
}
