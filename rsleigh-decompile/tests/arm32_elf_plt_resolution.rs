//! Regression for ARM32 ELF PLT name resolution.
//!
//! Pre-fix: `imports::resolve_elf` handled x86/x86-64/AArch64 PLT
//! formats but had no decoder for the ARM32 (EM_ARM = 0x28) format.
//! Result: `--callgraph` / `--search --api` / `--xrefs` could not
//! see calls to libc primitives like `recvfrom` on stripped ARM32
//! binaries. Surfaced via M2 firmware triage on TP-Link AX6000 v2
//! tdpServer (ELF32 ARM EABI5).
//!
//! ARM32 PLT entry format observed in glibc-linked ARM ELF:
//!   add r12, pc, #0, #12     ; e28fc600 — r12 = pc + 0
//!   add r12, r12, #imm       ; e28cca?? — page-relative GOT base
//!   ldr pc, [r12, #N]!       ; e5bcf0?? — final GOT offset
//!
//! GOT slot loaded = (stub_addr + 8) + add_imm + ldr_imm.
//!
//! This test confirms `resolve_imports` returns the right
//! `recvfrom@plt` address for tdpServer when the firmware fixture
//! is present. Skips otherwise so CI without the firmware blob
//! still passes.

use std::path::Path;

#[test]
fn tdpserver_arm32_plt_resolves_recvfrom() {
    let candidates = [
        "/tmp/tplink_ax6000_extract/ubi_root/431909977/rootfs_ubifs/usr/bin/tdpServer",
    ];
    let path = match candidates.iter().find(|p| Path::new(p).exists()) {
        Some(p) => *p,
        None => {
            eprintln!("[skip] tdpServer fixture missing — extract TP-Link AX6000 v2 firmware first");
            return;
        }
    };
    let data = std::fs::read(path).expect("read tdpServer");
    let map = rsleigh_decompile::imports::resolve_imports(&data);

    // Expected: recvfrom PLT stub at 0x125d8 (computed from
    // R_ARM_JUMP_SLOT @ 0x3f218 / GOT entry index 131).
    let recvfrom_addr = map
        .iter()
        .find(|(_, name)| name.as_str() == "recvfrom")
        .map(|(addr, _)| *addr);

    assert_eq!(
        recvfrom_addr,
        Some(0x125d8),
        "recvfrom@plt should resolve to 0x125d8; map has: {:?}",
        recvfrom_addr,
    );
}

/// A second sanity check: the resolved address MUST NOT be the
/// known false-positive 0x121b0. Pre-fix that was where rsleigh's
/// resolver landed (via some other code path that was unaware of
/// ARM PLT format). Pinning it here so a partial fix (resolving
/// to 0x125d8 AND keeping the 0x121b0 ghost) still fails.
#[test]
fn tdpserver_arm32_plt_does_not_alias_recvfrom_to_121b0() {
    let path = "/tmp/tplink_ax6000_extract/ubi_root/431909977/rootfs_ubifs/usr/bin/tdpServer";
    if !Path::new(path).exists() {
        eprintln!("[skip] tdpServer fixture missing");
        return;
    }
    let data = std::fs::read(path).expect("read tdpServer");
    let map = rsleigh_decompile::imports::resolve_imports(&data);
    assert_ne!(
        map.get(&0x121b0).map(String::as_str),
        Some("recvfrom"),
        "0x121b0 should NOT be labeled recvfrom — that's the pre-fix mislabel"
    );
}
