//! Regression: x86-64 bool-return idiom
//!
//!   xor eax, eax        ; EAX = 0  (4-byte write)
//!   cmp byte [addr], 0  ; set flags
//!   setne al            ; AL = !ZF  (1-byte write — must propagate into EAX)
//!   ret
//!
//! SSA used to keep stale EAX = 0 after the AL write, so the return
//! read saw Const(0) instead of the bool result. Fix propagates
//! sub-register writes up to existing parent aliases by blending:
//! `new_parent = (old & 0xFFFF_FF00) | Zext(AL, parent.size)`.
//!
//! Fixture: clang-apply-replacements.exe `__scrt_is_ucrt_dll_in_use`
//! (Ghidra: `return DAT_1401e5180 != 0;`).

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
fn x86_64_setne_bool_reaches_return() {
    if !fixture_available() {
        return;
    }
    let out = Command::new(RSLEIGH_BIN)
        .args([CLANG_AR, "0x1400eb54c"])
        .output()
        .expect("rsleigh invocation");
    assert!(
        out.status.success(),
        "rsleigh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("UTF-8");

    // Must NOT be a bare `return 0;` — that's the stale-EAX regression.
    for line in text.lines() {
        let t = line.trim();
        if t == "return 0;" {
            panic!("stale EAX leaked through SETNE — body reduced to `return 0;`\n{text}");
        }
    }

    // Must reference the compared address or at least a Load — proves
    // the cmp operand survived into the final expression.
    assert!(
        text.contains("1401e5180")
            || text.contains("DAT_")
            || text.contains("!= 0")
            || text.contains("Load")
            || text.contains("*("),
        "return expression doesn't reference the memory compare:\n{text}"
    );
}
