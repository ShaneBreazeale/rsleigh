//! Regression for flag-subexpression leak in compound conditions.
//!
//! Before fix: `NotEq(OF, SF)` appearing as a sub-expression of BoolAnd
//! in a CBranch condition left raw flag names in the output:
//!   `if (foo != 0 && OF != SF) { ... }`
//!
//! Fix must recover the inner `NotEq(OF, SF)` → `a < b` (SLess) even
//! when it's not the top-level expression of the condition.
//!
//! Integration test: decompile FUN_0042d620 runtime.saveblockevent
//! on bed fixture. Skip when fixture absent (see
//! RSLEIGH_REQUIRE_BED_FIXTURE env var).

use std::path::Path;
use std::process::Command;

const BED_FIXTURE: &str = "/tmp/bed/bed_v0.2.8_linux_amd64/bed";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture_available() -> bool {
    if Path::new(BED_FIXTURE).exists() { return true; }
    if std::env::var_os("RSLEIGH_REQUIRE_BED_FIXTURE").is_some() {
        panic!("bed fixture missing at {BED_FIXTURE}");
    }
    eprintln!("[skip] bed fixture missing at {BED_FIXTURE}");
    false
}

fn decompile(addr: &str) -> String {
    let out = Command::new(RSLEIGH_BIN)
        .args([BED_FIXTURE, addr])
        .output()
        .expect("rsleigh invocation");
    assert!(out.status.success(), "rsleigh failed:\n{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF-8")
}

#[test]
fn sub_expression_of_sf_not_leaked_in_compound_cond() {
    if !fixture_available() { return; }
    let out = decompile("0x42d620");
    assert!(
        !out.contains("OF != SF") && !out.contains("OF == SF"),
        "raw flag names leaked in compound condition\n{out}"
    );
}

#[test]
fn sub_expression_of_sf_not_leaked_in_any_subexpr() {
    if !fixture_available() { return; }
    // Scan several other funcs that historically have flag-pattern
    // CBranches; the fix must generalize.
    for addr in ["0x42d620", "0x455b60", "0x46b020"] {
        let out = decompile(addr);
        assert!(
            !out.contains("OF != SF") && !out.contains("OF == SF")
                && !out.contains("OV != NG") && !out.contains("OV == NG"),
            "{addr}: raw flag pair leaked\n{out}"
        );
    }
}
