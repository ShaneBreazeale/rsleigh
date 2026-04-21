//! Regression: SiMBA 1-var simplifier was using test points {0, 1, 0x42},
//! all of which collapse `(x & 0xFF00FF00FF00FF00) >> 8` to 0 — the
//! classic bswap64 upper-mask shift. SiMBA then concluded the expression
//! was linear with c0=c1=0 and folded the whole IntLsr to `Const(0)`,
//! wiping the upper-half swap from the output.
//!
//! Fix: verify against `0xFFFFFFFFFFFFFFFF` — any bit-masking non-linearity
//! fails the linear reconstruction check and SiMBA correctly bails.
//!
//! Fixture: git-repack FUN_0049ae98 (AArch64 bswap64 helper).

use std::path::Path;
use std::process::Command;

const GIT_REPACK: &str = "/tmp/git-repack/git-repack";
const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture_available() -> bool {
    if Path::new(GIT_REPACK).exists() { return true; }
    if std::env::var_os("RSLEIGH_REQUIRE_GIT_REPACK_FIXTURE").is_some() {
        panic!("git-repack fixture missing at {GIT_REPACK}");
    }
    eprintln!("[skip] git-repack fixture missing at {GIT_REPACK}");
    false
}

#[test]
fn bswap64_upper_half_shift_survives_simba() {
    if !fixture_available() { return; }
    let out = Command::new(RSLEIGH_BIN)
        .args([GIT_REPACK, "0x49ae98"])
        .output()
        .expect("rsleigh invocation");
    assert!(out.status.success(), "rsleigh failed:\n{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).expect("UTF-8");

    // Must mention both the upper mask (0xff00...00) and a right shift —
    // presence of both proves SiMBA didn't zero out the upper half.
    // Printer may render large consts as hex literal or DAT_<hex> glob —
    // either form proves the upper mask survived SiMBA.
    assert!(
        text.contains("ff00ff00ff00ff00"),
        "upper bswap mask ff00ff00ff00ff00 missing — SiMBA likely zeroed the `>> 8` half\n{text}"
    );
    assert!(
        text.contains(" >> 8") || text.contains(">>8"),
        "no `>> 8` operation — bswap byte-swap half got folded out\n{text}"
    );
    // Must have at least one OR — bswap is a union of shifted halves.
    assert!(
        text.contains(" | "),
        "no OR operator — bswap halves not joined\n{text}"
    );
}
