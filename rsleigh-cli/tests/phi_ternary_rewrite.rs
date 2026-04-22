//! Regression for campaign `phi-ternary-merge`.
//!
//! Conditional (non-loop) 2-way merges where both paths assign
//! different values to the same register used to render via
//! `phi(a, b)` + a lossy `#PHI_CLEANUP` that substituted the first
//! argument — breaking semantics when the arms were distinct.
//!
//! Fix: fold-time `rewrite_conditional_phi_to_ternary` mutates the
//! Phi expr to `Expr::Ternary(cond, then, else)` when the merge
//! has a dominating `CBranch` and preds cleanly partition between
//! its arms. Printer's existing Ternary rendering then emits
//! `(cond) ? t : e` — semantically correct.
//!
//! Additionally: the rewrite now collapses `Ternary(c, x, x)` when
//! both arms resolve through Var-chains to the same leaf
//! (same-named SSA copies) — previously leaked as noise like
//! `(lVar6 == 0) ? lVar1 : lVar1`.

use std::path::Path;
use std::process::Command;

const BED: &str = "/tmp/bed/bed_v0.2.8_linux_amd64/bed";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn bed_available() -> bool {
    if Path::new(BED).exists() { return true; }
    if std::env::var_os("RSLEIGH_REQUIRE_BED_FIXTURE").is_some() {
        panic!("bed fixture missing at {BED}");
    }
    eprintln!("[skip] bed fixture missing at {BED}");
    false
}

fn decompile(addr: &str) -> String {
    let out = Command::new(RSLEIGH_BIN)
        .args([BED, addr])
        .output()
        .expect("rsleigh invocation");
    assert!(out.status.success(), "rsleigh failed:\n{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF-8")
}

#[test]
fn no_phi_function_leaks_in_output() {
    if !bed_available() { return; }
    // Scan a handful of funcs known to have merges; none should emit
    // a `phi(` call-like expression anywhere.
    for addr in ["0x42d620", "0x455b60", "0x46b020", "0x46c7e0"] {
        let text = decompile(addr);
        assert!(
            !text.contains("phi("),
            "{addr}: raw `phi(...)` leaked into output\n{text}"
        );
    }
}

#[test]
fn conditional_merge_emits_ternary_on_bed() {
    if !bed_available() { return; }
    // FUN_0046b020 has `(puVar9 == 0) ? 0 : lVar2` — a conditional
    // merge where the two arms are clearly distinct. After the
    // rewrite the ternary must survive to the final output.
    let text = decompile("0x46b020");
    assert!(
        text.contains(") ? ") && text.contains(" : "),
        "no ternary found in output — rewrite not firing\n{text}"
    );
}

#[test]
fn same_var_ternary_collapses_to_bare_var() {
    if !bed_available() { return; }
    // `(cond) ? lVar1 : lVar1` pattern. Both arms resolve to the
    // same name through Var-chains; the Ternary collapse must emit
    // the bare var instead of a self-identity conditional.
    let text = decompile("0x42d620");
    for line in text.lines() {
        let t = line.trim();
        // Scan for `(X) ? Y : Y` with Y being the same identifier
        // on both sides of the colon.
        if let Some(qpos) = t.find(") ? ") {
            let after_q = &t[qpos + 4..];
            if let Some(colon) = after_q.find(" : ") {
                let then_tok = after_q[..colon].trim();
                let else_tok_end = after_q[colon + 3..].find(|c: char| !c.is_ascii_alphanumeric() && c != '_');
                let else_tok = match else_tok_end {
                    Some(n) => after_q[colon + 3..colon + 3 + n].trim(),
                    None => after_q[colon + 3..].trim_end_matches(';').trim(),
                };
                assert!(
                    then_tok != else_tok || then_tok.is_empty(),
                    "self-identity ternary leaked: `{t}` (both arms = `{then_tok}`)"
                );
            }
        }
    }
}
