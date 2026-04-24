//! End-to-end: x86-64 `mov eax, IMM; syscall` pattern emits NT API annotation.
//!
//! Synthesizes a minimal raw byte stream with the canonical Windows direct-
//! syscall gadget (`B8 19 00 00 00 0F 05 C3` = `mov eax, 0x19; syscall; ret`)
//! and feeds it through rsleigh CLI `--raw x86-64`. The printer must annotate
//! the syscall with the Win11 24H2 NT API name for the constant.

use std::io::Write;
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

#[test]
fn mov_eax_const_then_syscall_emits_nt_api_hint() {
    // mov eax, 0x19     ; B8 19 00 00 00
    // syscall           ; 0F 05
    // ret               ; C3
    let bytes: &[u8] = &[
        0xB8, 0x19, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3,
    ];
    let tmp = tempfile_bytes(bytes);
    let out = Command::new(RSLEIGH_BIN)
        .args([tmp.to_str().unwrap(), "--raw", "x86-64", "--all"])
        .output()
        .expect("rsleigh invocation");
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    assert!(
        text.contains("syscall 0x19") || text.contains("NtAllocateVirtualMemory"),
        "expected syscall 0x19 / NtAllocateVirtualMemory annotation in output:\n{text}"
    );
}

fn tempfile_bytes(bytes: &[u8]) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("rsleigh-syscall-test-{}.bin", std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create tmp");
    f.write_all(bytes).expect("write bytes");
    path
}
