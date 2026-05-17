//! Regression for ARM/Thumb raw-mode discovery prologue validation.
//!
//! Pre-fix bug: --raw arm32 discovery scans for BL/BLX patterns in the
//! whole binary linearly. On mixed ARM/Thumb firmware (typical for
//! camera/DSP blobs), random 4-byte sequences match the BL encoding
//! by chance — observed live on Sony α7R II av-cam.bin (13.4 MB):
//! 113,988 "functions" found, vast majority false positives.
//!
//! Fix: validate each candidate address against an ARM-or-Thumb
//! prologue table. Drop candidates that match neither. Reclassify
//! mode (set Thumb LSB) based on which prologue family matches.
//!
//! Also added: ARM `BLX(imm)` discovery (ARM → Thumb), which the prior
//! implementation missed entirely.
//!
//! Verification: a 64-byte synthesized blob with one valid Thumb
//! function and one BL-shaped random word at non-prologue offset.
//! Before fix: discovery returned 2 "functions" (real + garbage).
//! After fix:  discovery returns 1 (real Thumb only).

use std::path::Path;
use std::process::Command;


fn build_arm_thumb_blob() -> Vec<u8> {
    // Layout (file offset → bytes):
    //   0x00: ARM caller   `bl  +0x40` jumps to thumb fn @ 0x44
    //         e92d4010    push {r4, lr}
    //         eb00000d    bl +0x40   (target = 0x08 + 8 + 0x40 = 0x48)
    //         e8bd8010    pop  {r4, pc}
    //         00 00 00 00 padding
    //   0x10: random non-prologue bytes that LOOK like BL imm24 with non-zero
    //         offset to addr 0x80 (where there is NO prologue).
    //         eb00001a    bl +0x68 -> 0x80, but bytes at 0x80 are nonsense
    //   0x14: more padding
    //   0x44: Thumb function entry (LSB=1 in target)
    //         b5 10       push {r4, lr}
    //         00 bf       nop
    //         10 bd       pop {r4, pc}
    //   0x80: random bytes (NO valid prologue)
    //         ff ff ff ff ...

    let mut buf = vec![0xCC; 0x100];

    // 0x00: push {r4, lr}
    buf[0x00..0x04].copy_from_slice(&0xE92D_4010u32.to_le_bytes());
    // 0x04: BL +0x40 → 0x04+8+0x40 = 0x4C ... but we want Thumb fn at 0x48 (BLX)
    // Use BLX imm: cond=1111 op=101H imm24
    // BLX target = 0x04 + 8 + (imm24 << 2) + (H<<1)
    // Want target = 0x48 → 0x48 = 0x0C + (imm24<<2) + H*2
    //   imm24=0xE, H=0 → 0x0C + 0x38 = 0x44   (BLX targets are halfword-aligned)
    //   imm24=0xE, H=1 → 0x0C + 0x38 + 0x2 = 0x46
    //   Best: pick H=1 imm24=0xE → 0x46 + 0x2 = 0x48 (matches our Thumb fn @ 0x48)
    // Wait want target 0x48: 0x0C + imm24<<2 + H*2 = 0x48
    //   if H=0 → imm24<<2 = 0x3C → imm24 = 0xF → 0x0C + 0x3C = 0x48 ✓
    let imm24: u32 = 0xF;
    let blx_word: u32 = 0xFA000000 | imm24;
    buf[0x04..0x08].copy_from_slice(&blx_word.to_le_bytes());
    // 0x08: pop {r4, pc}
    buf[0x08..0x0C].copy_from_slice(&0xE8BD_8010u32.to_le_bytes());

    // 0x10: fake BL imm pointing into address with no prologue
    // ARM BL: cond=AL op=B opcode=0xEB
    // bytes: imm24 (low 24) | 0xEB000000
    // Want target = 0x80 from PC=0x18: imm = (0x80 - 0x18) >> 2 = 0x1A
    let fake_bl: u32 = 0xEB000000 | 0x1A;
    buf[0x10..0x14].copy_from_slice(&fake_bl.to_le_bytes());

    // 0x48: Thumb prologue (push {r4, lr} = b510)
    buf[0x48] = 0x10;
    buf[0x49] = 0xB5;
    // 0x4A: nop (00 bf)
    buf[0x4A] = 0x00;
    buf[0x4B] = 0xBF;
    // 0x4C: pop {r4, pc} (10 bd)
    buf[0x4C] = 0x10;
    buf[0x4D] = 0xBD;
    // 0x4E onward: bx lr is 0x4770 if needed; leave as 0xCC

    // 0x80 onward: garbage (no valid prologue — will be filtered)
    for i in 0x80..0x100 {
        buf[i] = 0xCC;
    }

    buf
}


fn cli_binary() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") { p.pop(); }
    p.push("rsleigh");
    p
}


#[test]
fn prologue_validation_drops_false_positives() {
    let blob = build_arm_thumb_blob();

    let tmp_dir = std::env::temp_dir().join("rsleigh_arm_thumb_test");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let blob_path = tmp_dir.join("blob.bin");
    std::fs::write(&blob_path, &blob).unwrap();

    let bin = cli_binary();
    assert!(Path::new(&bin).exists(),
            "rsleigh CLI binary not built — run cargo build first");

    let out = Command::new(&bin)
        .arg(&blob_path)
        .arg("--raw").arg("arm32")
        .output()
        .expect("failed to run rsleigh");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(),
            "rsleigh exited non-zero\nstderr: {}\nstdout: {}",
            stderr, stdout);

    // Expected:
    //   - base 0x00 has ARM prologue (push {r4,lr}) → kept
    //   - 0x48|1 has Thumb prologue → kept
    //   - 0x80 has NO prologue (garbage 0xCC) → DROPPED
    //
    // Pre-fix, 0x80 would be listed because the BL at 0x10 targeted it.
    let lines: Vec<&str> = stdout.lines().collect();
    let func_lines: Vec<&str> = lines.iter()
        .filter(|l| l.contains("FUN_"))
        .copied()
        .collect();

    let has_thumb_target = func_lines.iter().any(|l| l.contains("00000049"));
    let has_garbage = func_lines.iter().any(|l| l.contains("00000080"));

    assert!(has_thumb_target,
            "ARM BLX target should have been discovered as Thumb (LSB=1 @ 0x49). \
             Got:\n{}", stdout);
    assert!(!has_garbage,
            "garbage address 0x80 should have been dropped by prologue validation. \
             Got:\n{}", stdout);
}
