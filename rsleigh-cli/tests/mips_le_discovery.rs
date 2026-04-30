//! Regression for MIPS little-endian (mipsel) function discovery.
//!
//! Pre-fix bug: discover_elf_functions hardcoded `u32::from_be_bytes`
//! on every MIPS path (JAL/BAL scan, prologue scan, vtable check,
//! gap analysis). Little-endian MIPS samples lost almost all
//! discoverable functions — observed live on a stripped 633K
//! Mirai-class ELF: 36 functions discovered (BE-decoded) vs ~2550
//! after switching every read to ELF-endian-aware `read_u32_elf`.
//!
//! Fix landed in commit 81a62ff. This test pins the behaviour by
//! constructing a tiny ELF32 LSB MIPS image whose `.text` contains
//! a JAL into another aligned slot. The discoverer must follow
//! that JAL and surface BOTH the entry point AND the JAL target.

use std::path::Path;
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

/// Hand-assemble a minimal ELF32 LSB MIPS image:
///   - one `.text` section spanning two functions
///   - entry at 0x00400000 -> JAL 0x00400020 + NOP + JR RA + NOP
///   - second function at 0x00400020 -> JR RA + NOP
fn build_mipsel_elf() -> Vec<u8> {
    let text_addr: u32 = 0x0040_0000;
    let text_size: u32 = 0x40;

    // MIPS instruction encoding (little-endian on disk):
    //   JAL imm26: 0x0c000000 | (target >> 2)
    //     target=0x00400020 -> imm26 = 0x00100008
    //     word = 0x0c100008  -> bytes 08 00 10 0c
    //   NOP: 0x00000000
    //   JR RA: 0x03e00008  -> bytes 08 00 e0 03
    let jal_target = (text_addr + 0x20) >> 2;
    let jal_word: u32 = 0x0c00_0000 | jal_target;
    let mut text = Vec::with_capacity(text_size as usize);
    text.extend_from_slice(&jal_word.to_le_bytes());      // 0x00: JAL 0x00400020
    text.extend_from_slice(&0u32.to_le_bytes());           // 0x04: NOP (delay slot)
    text.extend_from_slice(&0x03e00008u32.to_le_bytes());  // 0x08: JR RA
    text.extend_from_slice(&0u32.to_le_bytes());           // 0x0c: NOP (delay slot)
    text.resize(0x20, 0);                                  // padding to second function
    text.extend_from_slice(&0x03e00008u32.to_le_bytes());  // 0x20: JR RA  (second func)
    text.extend_from_slice(&0u32.to_le_bytes());           // 0x24: NOP
    text.resize(text_size as usize, 0);

    // Layout:
    //   ehdr   0x00..0x34  (52 bytes)
    //   shdrs  0x34..0xac  (3 * 40 bytes)
    //   shstr  0xac..0xbd  (17 bytes ".text\0.shstrtab\0")
    //   pad    0xbd..0xc0
    //   .text  0xc0..0x100 (text_size bytes)
    let mut buf: Vec<u8> = vec![
        0x7f, b'E', b'L', b'F', 1, 1, 1, 0, // EI_CLASS=32, EI_DATA=LSB
        0, 0, 0, 0, 0, 0, 0, 0,
        2, 0,                               // e_type = ET_EXEC
        8, 0,                               // e_machine = EM_MIPS
        1, 0, 0, 0,                         // e_version
    ];
    buf.extend_from_slice(&text_addr.to_le_bytes());      // e_entry
    buf.extend_from_slice(&0u32.to_le_bytes());            // e_phoff
    buf.extend_from_slice(&0x34u32.to_le_bytes());         // e_shoff
    buf.extend_from_slice(&0u32.to_le_bytes());            // e_flags
    buf.extend_from_slice(&[0x34, 0]);                     // e_ehsize
    buf.extend_from_slice(&[0, 0]);                        // e_phentsize
    buf.extend_from_slice(&[0, 0]);                        // e_phnum
    buf.extend_from_slice(&[0x28, 0]);                     // e_shentsize = 40
    buf.extend_from_slice(&[3, 0]);                        // e_shnum = 3
    buf.extend_from_slice(&[2, 0]);                        // e_shstrndx = 2

    // shdr[0] NULL
    buf.extend(std::iter::repeat(0).take(40));
    // shdr[1] .text  name=1 type=PROGBITS(1) flags=AX(6) addr=text_addr
    buf.extend_from_slice(&1u32.to_le_bytes());        // sh_name
    buf.extend_from_slice(&1u32.to_le_bytes());        // sh_type
    buf.extend_from_slice(&6u32.to_le_bytes());        // sh_flags = ALLOC|EXEC
    buf.extend_from_slice(&text_addr.to_le_bytes());   // sh_addr
    buf.extend_from_slice(&0xc0u32.to_le_bytes());     // sh_offset
    buf.extend_from_slice(&text_size.to_le_bytes());   // sh_size
    buf.extend_from_slice(&0u32.to_le_bytes());        // sh_link
    buf.extend_from_slice(&0u32.to_le_bytes());        // sh_info
    buf.extend_from_slice(&4u32.to_le_bytes());        // sh_addralign
    buf.extend_from_slice(&0u32.to_le_bytes());        // sh_entsize
    // shdr[2] .shstrtab name=7 type=STRTAB(3) offset=0xac size=0x11
    buf.extend_from_slice(&7u32.to_le_bytes());
    buf.extend_from_slice(&3u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0xacu32.to_le_bytes());
    buf.extend_from_slice(&0x11u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // .shstrtab @ 0xac
    assert_eq!(buf.len(), 0xac);
    buf.extend_from_slice(b"\0.text\0.shstrtab\0");
    // pad to 0xc0
    buf.extend_from_slice(&[0u8; 3]);
    assert_eq!(buf.len(), 0xc0);
    buf.extend_from_slice(&text);

    buf
}

#[test]
fn mipsel_jal_target_discovered() {
    let elf = build_mipsel_elf();
    let mut path = std::env::temp_dir();
    path.push("rsleigh_mipsel_discovery_test.elf");
    std::fs::write(&path, &elf).expect("write tmp ELF");
    assert!(Path::new(&path).exists());

    let out = Command::new(RSLEIGH_BIN)
        .arg(&path)
        .output()
        .expect("rsleigh invocation");
    let _ = std::fs::remove_file(&path);

    assert!(
        out.status.success(),
        "rsleigh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8");

    // Must surface BOTH the entry function (0x00400000) AND the JAL
    // target (0x00400020). Pre-fix BE-only scan misses 0x00400020
    // entirely on this LE image.
    assert!(
        stdout.contains("0x00400000"),
        "missing entry function:\n{}",
        stdout
    );
    assert!(
        stdout.contains("0x00400020"),
        "JAL target not discovered — endian-aware fix regressed:\n{}",
        stdout
    );
}
