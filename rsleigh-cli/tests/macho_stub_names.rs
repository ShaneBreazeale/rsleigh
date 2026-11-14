//! Regression: the function listing named every Mach-O `__stubs` entry
//! `objc_stub_<addr>` instead of the import it calls (`strlen`, `puts`, ...),
//! and walked x86-64 stubs with an 8-byte stride although they are 6 bytes
//! (`jmp *disp32(%rip)`), so every stub after the first sat at a wrong address.
//!
//! Fix: `parse_binary` names `__stubs` entries from the indirect symbol table
//! via `imports::resolve_imports`, which already sizes stubs from their opcode.
//!
//! Fixtures: `smt/bin/fgets_printf` (arm64, 12-byte stubs) and
//! `macho/stubs_x86_64` (built from `macho/stubs.c`, 6-byte stubs).

use std::path::PathBuf;
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-harness/fixtures")
        .join(rel)
}

/// `(address, name)` pairs from `rsleigh <binary>`.
fn listing(rel: &str) -> Vec<(u64, String)> {
    let out = Command::new(RSLEIGH_BIN)
        .arg(fixture(rel))
        .arg("--no-fid-auto")
        .output()
        .expect("run rsleigh");
    assert!(out.status.success(), "rsleigh failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let addr = u64::from_str_radix(it.next()?.strip_prefix("0x")?, 16).ok()?;
            Some((addr, it.next()?.to_string()))
        })
        .collect()
}

fn assert_stubs_named(rel: &str, imports: &[&str], stub_size: u64) {
    let funcs = listing(rel);
    let leftovers: Vec<_> = funcs
        .iter()
        .filter(|(_, n)| n.starts_with("objc_stub_") || n.starts_with("stub_"))
        .collect();
    assert!(leftovers.is_empty(), "{rel}: unnamed stubs {leftovers:x?}");

    let mut stubs: Vec<(u64, &str)> = imports
        .iter()
        .map(|want| {
            let (addr, _) = funcs
                .iter()
                .find(|(_, n)| n == want)
                .unwrap_or_else(|| panic!("{rel}: no `{want}` in listing {funcs:x?}"));
            (*addr, *want)
        })
        .collect();
    stubs.sort();
    for pair in stubs.windows(2) {
        assert_eq!(
            pair[1].0 - pair[0].0,
            stub_size,
            "{rel}: `{}` and `{}` are not adjacent {stub_size}-byte stubs",
            pair[0].1,
            pair[1].1
        );
    }
}

#[test]
fn arm64_stubs_named_after_imports() {
    assert_stubs_named("smt/bin/fgets_printf", &["fgets", "printf"], 12);
}

#[test]
fn x86_64_stubs_use_six_byte_stride() {
    assert_stubs_named("macho/stubs_x86_64", &["atoi", "printf", "puts", "strlen"], 6);
}
