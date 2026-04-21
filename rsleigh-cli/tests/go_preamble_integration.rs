//! CLI-level regression for Go stack-check preamble shape detection.
//!
//! Retroactive test for commit 758d283 (Go preamble `CMP RSP, [R14+0x18]`
//! preempt variant) and the original `[R14+0x10]` stackguard variant.
//!
//! decode_func currently lives in rsleigh-cli/src/main.rs and is not
//! exposed for unit testing (see .opt/ideas.md: "extract preamble matcher
//! to lib"). Until that refactor lands, we test at integration level
//! using a bundled fixture binary.
//!
//! Fixture: /tmp/bed/bed_v0.2.8_linux_amd64/bed (Go 1.23.3, stripped).
//! If the fixture is absent, each test emits a warning and passes — CI
//! that wants to enforce these can set `RSLEIGH_REQUIRE_BED_FIXTURE=1`.

use std::path::Path;
use std::process::Command;

const BED_FIXTURE: &str = "/tmp/bed/bed_v0.2.8_linux_amd64/bed";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture_available() -> bool {
    if Path::new(BED_FIXTURE).exists() {
        return true;
    }
    if std::env::var_os("RSLEIGH_REQUIRE_BED_FIXTURE").is_some() {
        panic!("bed fixture missing at {BED_FIXTURE}, RSLEIGH_REQUIRE_BED_FIXTURE set");
    }
    eprintln!("[skip] bed fixture missing at {BED_FIXTURE}");
    false
}

fn run(args: &[&str]) -> String {
    let out = Command::new(RSLEIGH_BIN)
        .args(args)
        .output()
        .expect("rsleigh CLI invocation");
    assert!(out.status.success(), "rsleigh failed:\n{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("rsleigh output is UTF-8")
}

/// Go emits CMP RSP, [R14+0x10] (g.stackguard0) at function entry for
/// standard stack-check preamble. Decode-range extender must skip past
/// this 10-byte preamble so the real function body is disassembled.
/// Regression guard against someone "cleaning up" the 0x10/0x18 match
/// back to a single value.
#[test]
fn go_preamble_stackguard_variant_0x10_extends_decode_range() {
    if !fixture_available() { return; }
    // FUN_004af120 os_Remove has the 0x10 shape. It's a thin thunk but
    // the decode sweep must still pass the preamble.
    let out = run(&[BED_FIXTURE, "--disasm", "0x4af120"]);
    let nlines = out.lines().count();
    assert!(
        nlines > 3,
        "0x10 variant truncated: {nlines} lines of disasm (expected >3)\n{out}"
    );
}

/// Go emits CMP RSP, [R14+0x18] (g.preempt) variant for cooperative-
/// preemption functions. Must decode body past the preamble.
#[test]
fn go_preamble_preempt_variant_0x18_extends_decode_range() {
    if !fixture_available() { return; }
    // FUN_00426780 runtime_mheap_allocMSpanLocked uses the preempt
    // variant. Before commit 758d283 this truncated to a 5-line stub.
    let out = run(&[BED_FIXTURE, "0x426780"]);
    let nlines = out.lines().count();
    assert!(
        nlines > 10,
        "0x18 variant truncated: {nlines} lines of decompile (expected >10)\n{out}"
    );
    // Specifically check that the body is NOT a one-line thunk.
    assert!(
        !out.contains("// thunk"),
        "0x18 variant decoded only the preamble → empty thunk\n{out}"
    );
}
