//! Regression: pathological deep `Var`/`BinOp`/`Phi`/`Ternary` chains
//! in SSA could overflow Rust's stack inside `format_var`'s recursive
//! traversal — even on the 256 MB-stacked decompile thread. Affected
//! funcs printed `fatal runtime error: stack overflow, aborting` to
//! stderr and produced no output.
//!
//! Fix: thread-local depth counter caps `format_var` recursion at 256
//! and emits `<deep>` past the limit. Real expressions almost never
//! exceed depth ~30; the cap is loose enough that legit code never
//! trips it but tight enough to keep stack usage bounded.
//!
//! Fixture: nano FUN_0004d108 (ARM32 stripped ELF) used to crash; now
//! decompiles to actual body lines.

use std::path::Path;
use std::process::Command;

const NANO: &str = "/tmp/nano/nano";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn nano_available() -> bool {
    if Path::new(NANO).exists() {
        return true;
    }
    if std::env::var_os("RSLEIGH_REQUIRE_NANO_FIXTURE").is_some() {
        panic!("nano fixture missing at {NANO}");
    }
    eprintln!("[skip] nano fixture missing at {NANO}");
    false
}

#[test]
fn format_var_depth_does_not_blow_stack() {
    if !nano_available() {
        return;
    }
    let out = Command::new(RSLEIGH_BIN)
        .args([NANO, "0x4d108"])
        .output()
        .expect("rsleigh invocation");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("stack overflow") && !stderr.contains("fatal runtime error"),
        "rsleigh stack-overflowed on FUN_0004d108:\nSTDERR:\n{stderr}"
    );
    assert!(out.status.success(), "rsleigh exited non-zero:\n{stderr}");
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    // Body must have more than the comment + signature + close brace.
    assert!(
        text.lines().count() > 3,
        "body too short, decomp may have short-circuited:\n{text}"
    );
}
