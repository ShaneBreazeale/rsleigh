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
fn heartbleed_shape_lengtharg_reachable() {
    // recv(_, buf, 1024, 0); len = (buf[0] << 8) | buf[1];
    // memcpy(dst, buf+2, len)  // dst is 64-byte stack alloca.
    //
    // v6.W1 strict bound classified this NotReachable because the
    // legitimate buf-content lineage shared a call_return bridge
    // through recv.out. v7.W3 allows Region match when the shared
    // region is the SOURCE's specific region (not generic Param/
    // StackFrame), which preserves the FP guard while admitting the
    // Heartbleed-shape true positive.
    let Some(bin) = fixture("heartbleed_shape") else { return };
    let out = run_explore(&bin, "vuln_heartbleed");
    assert!(out.contains("recv -> memcpy"), "missing recv->memcpy path:\n{out}");
    assert!(out.contains("LengthArg"), "missing LengthArg kind:\n{out}");
    assert_reachable_or_skip_no_smt(&out, "heartbleed_shape");
}

#[test]
fn fgets_printf_format_string_reachable() {
    let Some(bin) = fixture("fgets_printf") else { return };
    let out = run_explore(&bin, "vuln_fgets_printf");
    assert!(out.contains("fgets -> printf"), "missing fgets->printf path:\n{out}");
    assert!(out.contains("FormatArg"), "missing FormatArg kind:\n{out}");
    assert_reachable_or_skip_no_smt(&out, "fgets_printf");
}

#[test]
fn v10_inter_procedural_reachable_via_summaries() {
    // outer(sock) → fill_buf(buf, sock)::recv  +
    //                copy_into(buf, dst)::strcpy
    // v1 (no --smt-summaries): NoSinkFound at outer.
    // v2 (--smt-summaries):    REACHABLE with non-empty call_chain.
    let Some(bin) = fixture("wrapped_recv_strcpy") else { return };

    let v1 = Command::new(RSLEIGH_BIN)
        .args([&bin, "--smt-explore", "outer"])
        .output()
        .expect("rsleigh invocation");
    let v1_out = String::from_utf8(v1.stdout).expect("utf-8");
    if v1_out.contains("smt feature not enabled at build time") {
        eprintln!("[skip-no-smt] V10 wrapped: rebuild with --features smt");
        return;
    }
    assert!(
        v1_out.contains("NoSinkFound"),
        "v1 (no --smt-summaries) should not see the wrapped sink:\n{v1_out}"
    );

    let v2 = Command::new(RSLEIGH_BIN)
        .args([&bin, "--smt-explore", "outer", "--smt-summaries"])
        .output()
        .expect("rsleigh invocation");
    let v2_out = String::from_utf8(v2.stdout).expect("utf-8");
    assert!(
        v2_out.contains("recv -> strcpy"),
        "v2 missing recv->strcpy:\n{v2_out}"
    );
    assert!(
        v2_out.contains("REACHABLE"),
        "v2 should be REACHABLE via summary synthesis:\n{v2_out}"
    );
    assert!(
        v2_out.contains("via ["),
        "v2 should render call_chain trace:\n{v2_out}"
    );
}
