//! End-to-end CLI integration for `--smt-explore`.
//!
//! Drives the rsleigh binary against three host-built C fixtures
//! and asserts each path SATs the expected SinkKind.
//!
//! Build dependency: `test-harness/fixtures/smt/build.sh` must have
//! produced binaries in `test-harness/fixtures/smt/bin/`. Tests skip
//! cleanly when the directory is missing — CI without a host C
//! compiler still passes.
//!
//! SMT-feature dependency: this test only runs the live SAT prover
//! when the binary is built with `--features smt`. Without it,
//! solve() returns Unsupported and the test emits a [skip] note.

use std::path::Path;
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture(name: &str) -> Option<String> {
    for rel in [
        format!("test-harness/fixtures/smt/bin/{name}"),
        format!("../test-harness/fixtures/smt/bin/{name}"),
    ] {
        if Path::new(&rel).exists() {
            return Some(rel);
        }
    }
    eprintln!("[skip] {name} fixture missing — run test-harness/fixtures/smt/build.sh");
    None
}

fn run_explore(bin: &str, func: &str) -> String {
    let out = Command::new(RSLEIGH_BIN)
        .args([bin, "--smt-explore", func])
        .output()
        .expect("rsleigh invocation");
    assert!(
        out.status.success(),
        "rsleigh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8")
}

fn assert_reachable_or_skip_no_smt(stdout: &str, label: &str) {
    if stdout.contains("smt feature not enabled at build time") {
        eprintln!("[skip-no-smt] {label}: rebuild with --features smt to exercise solver");
        return;
    }
    assert!(
        stdout.contains("REACHABLE"),
        "{label} did not produce REACHABLE verdict:\n{stdout}"
    );
}

#[test]
fn recv_strcpy_stack_buffer_reachable() {
    let Some(bin) = fixture("recv_strcpy") else { return };
    let out = run_explore(&bin, "vuln_recv_strcpy");
    assert!(
        out.contains("recv -> strcpy"),
        "missing recv->strcpy path label:\n{out}"
    );
    assert!(out.contains("StackBuffer"), "missing StackBuffer kind:\n{out}");
    assert_reachable_or_skip_no_smt(&out, "recv_strcpy");
}

#[test]
fn read_system_command_injection_reachable() {
    let Some(bin) = fixture("read_system") else { return };
    let out = run_explore(&bin, "vuln_read_system");
    assert!(out.contains("read -> system"), "missing read->system path:\n{out}");
    assert!(out.contains("Command"), "missing Command kind:\n{out}");
    assert_reachable_or_skip_no_smt(&out, "read_system");
}

#[test]
fn fgets_printf_format_string_reachable() {
    let Some(bin) = fixture("fgets_printf") else { return };
    let out = run_explore(&bin, "vuln_fgets_printf");
    assert!(out.contains("fgets -> printf"), "missing fgets->printf path:\n{out}");
    assert!(out.contains("FormatArg"), "missing FormatArg kind:\n{out}");
    assert_reachable_or_skip_no_smt(&out, "fgets_printf");
}
