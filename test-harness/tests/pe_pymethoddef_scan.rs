//! Regression: PE64 Python C-extensions must expose their registered methods.
//!
//! Python extensions publish methods through a `PyMethodDef` array in a data
//! section rather than a linker export. The fixture `crackmev3.pyd` is a
//! PyVMProtect-obfuscated binary whose section names are randomised; none of
//! the vanilla heuristics (`.rdata` name match, vtable scan, .pdata) finds the
//! single user-facing method it registers, `_ttokwy5gsm @ 0x180014cf0`.
//!
//! Before the PyMethodDef scanner landed, the CLI listing was:
//!
//!     1 functions:
//!       0x1800150f0  PyInit_crackmev3
//!
//! After:
//!
//!     8 functions:
//!       0x1800150f0  PyInit_crackmev3
//!       0x18000b900  _guard_init
//!       0x18000b9a0  _guard_token
//!       0x18000b940  _guard_verify
//!       0x18000b9e0  _runtime_meta
//!       0x18000b9d0  _segment_load
//!       0x180014cf0  _ttokwy5gsm
//!       0x18000bae0  __name__

use std::path::PathBuf;
use std::process::Command;

fn locate_fixture() -> Option<PathBuf> {
    // Cargo sets CARGO_MANIFEST_DIR to the test-harness crate root.
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = base.join("fixtures").join("crackmev3.pyd");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn locate_binary() -> PathBuf {
    // target/release/deps/<test-xxx>  ->  target/release/rsleigh
    let here = std::env::current_exe().expect("exe path");
    let mut p = here.parent().unwrap().parent().unwrap().to_path_buf();
    p.push("rsleigh");
    p
}

#[test]
fn pymethoddef_scan_finds_ttokwy5gsm() {
    let Some(fixture) = locate_fixture() else {
        eprintln!("skipping: crackmev3.pyd fixture not staged");
        return;
    };
    let binary = locate_binary();
    if !binary.exists() {
        eprintln!("skipping: rsleigh CLI not built at {:?}", binary);
        return;
    }

    let out = Command::new(&binary)
        .arg(&fixture)
        .output()
        .expect("run rsleigh");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The primary function that motivated the PyMethodDef scanner.
    assert!(
        stdout.contains("0x180014cf0  _ttokwy5gsm"),
        "expected PyMethodDef scan to surface `_ttokwy5gsm @ 0x180014cf0`, got:\n{stdout}",
    );
    // The relaxed underscore filter should no longer hide explicit exports.
    assert!(
        stdout.contains("_guard_verify"),
        "expected `_guard_verify` export to survive underscore filter, got:\n{stdout}",
    );
    // Core export still lists.
    assert!(
        stdout.contains("0x1800150f0  PyInit_crackmev3"),
        "PyInit_crackmev3 missing:\n{stdout}",
    );
}
