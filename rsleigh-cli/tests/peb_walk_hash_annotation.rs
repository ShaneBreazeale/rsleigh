//! End-to-end: a 32-bit constant matching a known ROR13 API hash gets
//! annotated in the decompiled output. The PEB-walk resolver pattern
//! emits `cmp <reg>, <hash>; je <handler>` chains for each export
//! candidate; the constant in that comparison is the API the shellcode
//! is searching for. The printer must surface that meaning.

use std::io::Write;
use std::process::Command;

use rsleigh_decompile::peb_walk::ror13_api;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

#[test]
fn const_matching_ror13_api_hash_is_annotated() {
    let target = "VirtualAlloc";
    let h = ror13_api(target);
    let h_le = h.to_le_bytes();

    // mov eax, <h>     ; B8 LL LL LL LL
    // cmp eax, <h>     ; 3D LL LL LL LL
    // ret              ; C3
    let mut bytes: Vec<u8> = vec![0xB8];
    bytes.extend_from_slice(&h_le);
    bytes.push(0x3D);
    bytes.extend_from_slice(&h_le);
    bytes.push(0xC3);

    let tmp = tempfile_bytes(&bytes);
    let out = Command::new(RSLEIGH_BIN)
        .args([tmp.to_str().unwrap(), "--raw", "x86-64", "--all"])
        .output()
        .expect("rsleigh invocation");
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    let needle = format!("ROR13(\"{}\")", target);
    assert!(
        text.contains(&needle),
        "expected ROR13 annotation for {} in output:\n{}",
        target, text
    );
}

fn tempfile_bytes(bytes: &[u8]) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("rsleigh-peb-walk-test-{}.bin", std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create tmp");
    f.write_all(bytes).expect("write bytes");
    path
}
