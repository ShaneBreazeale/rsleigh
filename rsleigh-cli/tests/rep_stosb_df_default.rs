//! Regression: x86-64 REP STOSB (and family) expands to a P-code
//! loop whose body computes the advance direction as `1 - 2*DF`.
//! DF (x86 direction flag, register offset 522) is guaranteed 0 on
//! function entry by the System V + Win64 ABIs. When fold sees DF
//! as `Expr::Unknown`, the arithmetic can't evaluate and the output
//! leaks `(uint8_t)DF` into expressions:
//!
//!   *(uint32_t*)(lVar1 - 1 * (uint8_t)DF) = param_1;
//!
//! Fix: seed uninitialized reads of x86 DF with `Const(0, 1)` so
//! the direction expression collapses to `+1` (forward).
//!
//! Fixture: clang-apply-replacements.exe FUN_1401271f0 (memset-like
//! via REP STOSB).

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
fn rep_stosb_df_does_not_leak() {
    if !fixture_available() {
        return;
    }
    let out = Command::new(RSLEIGH_BIN)
        .args([CLANG_AR, "0x1401271f0"])
        .output()
        .expect("rsleigh invocation");
    assert!(
        out.status.success(),
        "rsleigh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("UTF-8");

    // The raw `DF` identifier must not leak into output.
    assert!(
        !text.contains("(uint8_t)DF") && !text.contains(" DF ") && !text.contains("*DF"),
        "direction flag leaked into output:\n{text}"
    );
}
