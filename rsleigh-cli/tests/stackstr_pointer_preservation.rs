//! Regression: `#STACKSTR` collapse pass was matching `X = "...";` too
//! broadly and eating `*(T*)(DAT_...) = "literal";` global-pointer-table
//! initializers. On git-repack FUN_004de45c this collapsed 4 real stores
//! into one `// stack string: "..."` comment, dropping Ghidra-parity output.
//!
//! Fix: STACKSTR must skip lines whose LHS begins with `*(` — those are
//! pointer writes, not stack-slot inits.

use std::path::Path;
use std::process::Command;

const GIT_REPACK: &str = "/tmp/git-repack/git-repack";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture_available() -> bool {
    if Path::new(GIT_REPACK).exists() {
        return true;
    }
    if std::env::var_os("RSLEIGH_REQUIRE_GIT_REPACK_FIXTURE").is_some() {
        panic!("git-repack fixture missing at {GIT_REPACK}");
    }
    eprintln!("[skip] git-repack fixture missing at {GIT_REPACK}");
    false
}

#[test]
fn global_pointer_string_inits_survive_stackstr_pass() {
    if !fixture_available() {
        return;
    }
    let out = Command::new(RSLEIGH_BIN)
        .args([GIT_REPACK, "0x4de45c"])
        .output()
        .expect("rsleigh invocation");
    assert!(
        out.status.success(),
        "rsleigh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("UTF-8");

    for needle in [
        "\"gone\"",
        "\"ahead %d\"",
        "\"behind %d\"",
        "\"ahead %d, behind %d\"",
    ] {
        assert!(
            text.contains(needle),
            "missing string literal {needle} — STACKSTR may be eating pointer writes again\n{text}"
        );
    }
    assert!(
        !text.contains("// stack string: \"gone"),
        "STACKSTR collapsed global-pointer writes into a stack-string comment\n{text}"
    );
}
