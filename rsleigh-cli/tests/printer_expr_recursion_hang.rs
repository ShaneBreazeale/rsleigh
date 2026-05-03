//! Regression for printer::expr_has_tracked_reg unmemoized recursion.
//!
//! Pre-fix: `expr_has_tracked_reg` recurses into `Expr::BinOp`'s left
//! and right operands by VarId without a visited set or memo, so a
//! shared-subexpression DAG (typical of unrolled crypto rounds — long
//! arithmetic chains where each result feeds multiple successors)
//! produces an exponential walk that hangs the printer indefinitely.
//!
//! Surfaced via M2 firmware triage: function at 0x0001591c in
//! tdpServer (TP-Link AX6000 v2) is an unrolled crypto round. The
//! per-function bisect across 710 funcs in tdpServer flagged this as
//! the only printer hang in the binary, but it took out --vulnscan,
//! --callgraph, --xrefs, and --smt-explore on the whole image.
//!
//! See `test-harness/fixtures/printer-hangs/NOTICE.md`.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture() -> Option<String> {
    for rel in [
        "test-harness/fixtures/printer-hangs/tdpserver_0x1591c_arm32.bin",
        "../test-harness/fixtures/printer-hangs/tdpserver_0x1591c_arm32.bin",
    ] {
        if Path::new(rel).exists() {
            return Some(rel.to_string());
        }
    }
    eprintln!("[skip] hang fixture missing");
    None
}

#[test]
fn printer_does_not_hang_on_crypto_round_dag() {
    let Some(bin) = fixture() else { return };

    // Spawn the rsleigh CLI in --raw arm32 mode, decompile the
    // single function. A correct build returns in well under 5s on
    // any reasonable host. Pre-fix the process never exits — kill
    // it after the budget and report failure.
    let budget = Duration::from_secs(15);

    // Discard child stdout/stderr — piping without draining would
    // deadlock the test once the OS pipe buffer fills, masking a
    // genuine pass as a 15s "hang".
    let mut child = Command::new(RSLEIGH_BIN)
        .args([&bin, "--raw", "arm32", "FUN_00000000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rsleigh");

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let elapsed = start.elapsed();
                assert!(
                    status.success(),
                    "rsleigh exited non-zero in {:.1}s: {:?}",
                    elapsed.as_secs_f64(),
                    status
                );
                eprintln!(
                    "[ok] decompile finished in {:.2}s",
                    elapsed.as_secs_f64()
                );
                return;
            }
            Ok(None) => {
                if start.elapsed() > budget {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "rsleigh hung > {}s on tdpserver crypto-round fixture — \
                         expr_has_tracked_reg unmemoized recursion regressed",
                        budget.as_secs()
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("waitpid error: {e}"),
        }
    }
}
