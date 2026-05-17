//! Regression for carved-PE function discovery.
//!
//! Pre-fix bug: PEs carved from an installer overlay retain a
//! Security data-directory pointing to an Authenticode blob that
//! sits AFTER the carved file's EOF. goblin's strict `Object::parse`
//! rejects them with
//!     "Malformed entity: End of attribute certificates table is after
//!      the end of the PE binary"
//! so EVERY mode that goes through `parse_binary` (--summary, --search,
//! plain function-list, --vulnscan, --callgraph, …) exits with
//! "Unsupported format" and 0 functions on otherwise-valid carved PEs.
//!
//! Hit live on Sony Update_ILCE7RM2V401.exe — the `FirmwareData_*.dat`
//! and `UserFirmUpTool.exe` records inside its Packman container both
//! carry the truncated cert-table. --summary returned 0 functions
//! despite the binary having ~300 valid functions.
//!
//! Fix: `parse_object_lenient` retries with
//! `pe::options::ParseOptions { parse_attribute_certificates: false }`.
//! Also: discovery now ALWAYS supplements PE exports (used to be
//! gated on `symbols.is_empty()`, so a DLL with 3 exports kept 3 funcs
//! even when ~hundreds of CALL-reachable funcs existed).

use std::path::Path;
use std::process::Command;

fn build_pe_with_truncated_cert_table() -> Vec<u8> {
    // Minimal PE32 (i386 GUI executable).
    // Layout:
    //   0x000: DOS header (only e_lfanew matters)
    //   0x080: PE signature "PE\0\0"
    //   0x084: COFF header (machine = 0x014C, 1 section, optional header size)
    //   0x098: Optional header (PE32)
    //     - Entry point RVA = 0x1000 (start of .text)
    //     - Image base = 0x00400000
    //     - 16 data directories — Security (index 4) points PAST EOF
    //   0x178: Section header (.text)
    //   0x200: .text contents (one byte: RET = 0xC3)
    //
    // File size = 0x400 (1 page) so the Security dir at file offset 0x10000
    // is clearly beyond EOF.

    let mut buf = vec![0u8; 0x400];

    // -- DOS header --
    buf[0..2].copy_from_slice(b"MZ");
    // e_lfanew at offset 0x3C. Goblin requires it strictly > 0x40
    // (the end of the e_lfanew field itself), so use 0x80 to leave
    // room for a DOS stub region.
    let pe_off: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());

    // -- PE signature at pe_off --
    let pe_off = pe_off as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

    // -- COFF header (20 bytes) at pe_off + 4 --
    let coff = pe_off + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // machine = i386
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // num sections
    // TimeDateStamp + symtab fields = 0
    let opt_size: u16 = 0xE0; // PE32 optional header size
    buf[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
    // Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
    buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());

    // -- Optional header at 0x58 --
    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    buf[opt + 2] = 14; // major linker version
    // SizeOfCode = 0x200 (one section, raw size)
    buf[opt + 4..opt + 8].copy_from_slice(&0x200u32.to_le_bytes());
    // AddressOfEntryPoint = 0x1000
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    // BaseOfCode = 0x1000
    buf[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    // BaseOfData = 0x2000
    buf[opt + 24..opt + 28].copy_from_slice(&0x2000u32.to_le_bytes());
    // ImageBase = 0x00400000
    buf[opt + 28..opt + 32].copy_from_slice(&0x00400000u32.to_le_bytes());
    // SectionAlignment = 0x1000, FileAlignment = 0x200
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    // OS major/minor, image major/minor, subsystem major/minor
    buf[opt + 40..opt + 42].copy_from_slice(&5u16.to_le_bytes());
    buf[opt + 48..opt + 50].copy_from_slice(&5u16.to_le_bytes());
    // SizeOfImage = 0x2000 (1 section aligned)
    buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    // SizeOfHeaders = 0x200
    buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    // Subsystem = WINDOWS_CUI (3)
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    // SizeOfStackReserve/Commit/HeapReserve/Commit
    buf[opt + 72..opt + 76].copy_from_slice(&0x100000u32.to_le_bytes());
    buf[opt + 76..opt + 80].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 80..opt + 84].copy_from_slice(&0x100000u32.to_le_bytes());
    buf[opt + 84..opt + 88].copy_from_slice(&0x1000u32.to_le_bytes());
    // NumberOfRvaAndSizes = 16
    buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());

    // Data directories start at opt + 96 (each 8 bytes: RVA + Size)
    // Index 4 = IMAGE_DIRECTORY_ENTRY_SECURITY — file-offset (NOT RVA)
    // Point it at 0x00010000 with size 0x100 — well past EOF (file is 0x400 bytes).
    let security_dir = opt + 96 + 4 * 8;
    buf[security_dir..security_dir + 4].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    buf[security_dir + 4..security_dir + 8].copy_from_slice(&0x100u32.to_le_bytes());

    // -- Section header at 0x108 (opt + 0xE0 = 0x44+20+0xE0 = 0x138)... wait recompute
    // opt = 0x58, opt_size = 0xE0, so section headers begin at 0x58 + 0xE0 = 0x138.
    let sh = opt + opt_size as usize;
    buf[sh..sh + 8].copy_from_slice(b".text\0\0\0");
    buf[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
    buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    buf[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    buf[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    // Characteristics = CODE | EXECUTE | READ
    buf[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // -- .text contents at file offset 0x200 --
    // Single byte RET. Discovery will at minimum find the entry point.
    buf[0x200] = 0xC3;

    buf
}

fn cli_binary() -> std::path::PathBuf {
    // tests/ binaries live alongside the `rsleigh` bin built by cargo.
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // drop test binary name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("rsleigh");
    path
}

#[test]
fn truncated_cert_table_does_not_block_discovery() {
    let pe = build_pe_with_truncated_cert_table();

    // Sanity: strict goblin parse MUST reject this (so the test would
    // be meaningless if it didn't actually trigger the bug shape).
    let strict = goblin::Object::parse(&pe);
    assert!(
        strict.is_err(),
        "fixture no longer triggers the cert-table bug shape — \
         strict parse succeeded, test invariant broken"
    );

    // Write fixture to disk and run rsleigh --summary on it.
    let tmp_dir = std::env::temp_dir().join("rsleigh_pe_cert_test");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let pe_path = tmp_dir.join("truncated_cert.exe");
    std::fs::write(&pe_path, &pe).unwrap();

    let bin = cli_binary();
    assert!(
        Path::new(&bin).exists(),
        "rsleigh CLI binary not found at {:?} — run `cargo build -p rsleigh-cli` first",
        bin
    );

    let out = Command::new(&bin)
        .arg(&pe_path)
        .arg("--summary")
        .output()
        .expect("failed to run rsleigh");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        out.status.success(),
        "rsleigh exited non-zero on carved-PE input.\nstderr: {}\nstdout: {}",
        stderr,
        stdout
    );

    // Discovery should surface at least the entry point.
    let n_funcs_line = stderr
        .lines()
        .find(|l| l.contains("functions in"))
        .unwrap_or("");
    let n: usize = n_funcs_line
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        n >= 1,
        "expected at least 1 discovered function, got {} (stderr: {})",
        n,
        stderr
    );
}
