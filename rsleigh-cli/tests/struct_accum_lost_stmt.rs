//! Regression for cross-line DCE alias-aware self-ref check.
//!
//! Pre-fix bug: post_process cross-line DCE compared LHS/RHS textually
//! before recognizing DWARF-renamed stack-slot aliases. For
//! `struct_accum`, the DWARF source name `total` got applied to write
//! sites while reads still spelled as `local_c` (raw stack slot
//! name). Two writes:
//!     total = local_c + *(pairs[i].x);
//!     total = local_c - lVar1->field_4;
//! ...with `}` (end of for-loop) following the second. The DCE
//! treated `total = ...` as a clean overwrite (RHS reads `local_c`,
//! not `total`) and dropped the second arithmetic statement entirely
//! — the `pairs[i].y` subtract vanished from output.
//!
//! Fix: extend `reads_var_outside_lhs` in the cross-line DCE block
//! with a reverse-alias map (friendly_name -> raw_var_name). When
//! sym=`total`, its raw forms (`local_c`, `sp->field_c`) also count
//! as reads.

use std::path::Path;
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture() -> Option<&'static str> {
    let p = "target/decomp-bench/pseudocode_core_O0";
    if Path::new(p).exists() {
        Some(p)
    } else {
        eprintln!("[skip] bench fixture missing — run scripts/decomp-regress.py");
        None
    }
}

#[test]
fn struct_accum_keeps_both_arithmetic_writes() {
    let Some(fixture) = fixture() else {
        return;
    };
    let out = Command::new(RSLEIGH_BIN)
        .args([fixture, "struct_accum"])
        .output()
        .expect("rsleigh invocation");
    assert!(
        out.status.success(),
        "rsleigh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("UTF-8");

    // The function has two arithmetic updates per iteration:
    //   total += pairs[i].x  → `total = total + ...`
    //   total -= pairs[i].y  → `total = total - ...`
    // Both must survive post_process. Pre-fix, the subtract vanished.
    let plus_lines = text
        .lines()
        .filter(|l| l.contains("total = total +") || l.contains("total = total + *("))
        .count();
    let minus_lines = text
        .lines()
        .filter(|l| l.contains("total = total -") || l.contains("total = total - "))
        .count();

    assert!(
        plus_lines >= 1,
        "missing `total = total + ...` add stmt:\n{}",
        text
    );
    assert!(
        minus_lines >= 1,
        "missing `total = total - ...` subtract stmt — \
         cross-line DCE dropped it (pre-fix regression):\n{}",
        text
    );
}
