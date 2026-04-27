//! Regression: struct_accum loop body must not duplicate the `.x` load.
//!
//! Source:
//!     total += pairs[i].x;   // *(pairs + i*8 + 0)
//!     total -= pairs[i].y;   // *(pairs + i*8 + 4)
//!
//! Pre-fix output (post the cross-line DCE fix) emitted:
//!     total = total + *(pairs + local_0 * 8) + *(pairs + local_0 * 8) - *(pairs + local_0 * 8 + 4);
//!
//! Three `*(...)` deref terms instead of two. Root cause: Store path in
//! print_stmt_tracked inserts `val_expr` (full expression) into
//! `tracker.stack_alias` even when the store is emitted as a real C
//! statement. The next stmt reading the same stack slot inlines that
//! expression, so the second store's RHS becomes
//! `(total + .x) - .y` instead of `total - .y`. The downstream
//! `fold_loop_accumulator_updates` then concatenates `+ .x` with
//! `+ .x - .y`, yielding the duplicate term.

use std::path::Path;
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture() -> Option<String> {
    for rel in [
        "target/decomp-bench/pseudocode_core_O0",
        "../target/decomp-bench/pseudocode_core_O0",
    ] {
        if Path::new(rel).exists() {
            return Some(rel.to_string());
        }
    }
    eprintln!("[skip] bench fixture missing — run scripts/decomp-regress.py");
    None
}

#[test]
fn struct_accum_loop_body_has_exactly_two_derefs() {
    let Some(fixture) = fixture() else {
        return;
    };
    let out = Command::new(RSLEIGH_BIN)
        .args([fixture.as_str(), "struct_accum"])
        .output()
        .expect("rsleigh invocation");
    assert!(
        out.status.success(),
        "rsleigh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("UTF-8");

    // Locate the inner loop body (between `for (` and the matching `}`).
    let loop_body: String = text
        .lines()
        .skip_while(|l| !l.trim_start().starts_with("for ("))
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('}'))
        .collect::<Vec<_>>()
        .join("\n");

    let deref_count = loop_body.matches("*(").count();
    assert_eq!(
        deref_count, 2,
        "expected exactly 2 derefs in loop body (`pairs[i].x` and `pairs[i].y`); \
         got {} — duplicate-load bug.\nLoop body:\n{}",
        deref_count, loop_body
    );
}
