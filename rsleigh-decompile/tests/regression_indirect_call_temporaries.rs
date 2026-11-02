//! An indirect call whose target is a P-code temporary printed as
//! `(*tmp_0)(...)`, naming a value that is never declared or assigned:
//! 2,704 of CrashLoggerSSE's undeclared identifiers. Most are MSVC's
//! `__fastfail` (`mov ecx, 5; int 0x29`, a `swi(0x29)` user-op used as the
//! call target); the rest are calls through a loaded pointer such as a
//! virtual call `call [rax+8]`.

use rsleigh_api::{Architecture, Decoder};

fn decompile(bytes: &[u8]) -> String {
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let address = 0x1000 + offset as u64;
        let inst = decoder.decode(&bytes[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    rsleigh_decompile::decompile(Architecture::X86_64, &instructions)
}

#[test]
fn int_0x29_prints_as_fastfail() {
    // mov ecx, 5 ; int 0x29 ; ret
    let output = decompile(&[0xb9, 0x05, 0x00, 0x00, 0x00, 0xcd, 0x29, 0xc3]);
    assert!(!output.contains("tmp_"), "\n{output}");
    assert!(output.contains("__fastfail(5);"), "\n{output}");
}

#[test]
fn call_through_a_loaded_pointer_prints_the_load() {
    // mov rax, [rcx] ; call qword ptr [rax+8] ; ret
    let output = decompile(&[0x48, 0x8b, 0x01, 0xff, 0x50, 0x08, 0xc3]);
    assert!(!output.contains("tmp_"), "\n{output}");
    // Offset 8 of the loaded vtable, as `+ 0x8` or a typed `->field_8`.
    assert!(
        ["+ 8", "+ 0x8", "->field_8"]
            .iter()
            .any(|t| output.contains(t)),
        "\n{output}"
    );
}
