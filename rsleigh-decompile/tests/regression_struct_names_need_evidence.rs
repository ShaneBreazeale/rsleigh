//! Known Win32 struct names were attached to any variable whose accessed
//! offsets overlapped the struct's, so a `std::string` move in CrashLoggerSSE
//! printed `puVar1->lpDesktop` / `lpTitle` (STARTUPINFOW) and the result did
//! not compile (morluto/rea discussion 3858, Update 2). Offsets 0, 8, 0x10,
//! 0x18 are shared by nearly every 8-byte-aligned struct; without evidence
//! from an API that takes the struct, the fields keep their offset names.

use rsleigh_api::{Architecture, Decoder};

fn decompile_in_pe(bytes: &[u8]) -> String {
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let address = 0x1000 + offset as u64;
        let inst = decoder.decode(&bytes[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    // The printer only needs to see a PE image header to enable Win32 names.
    let mut image = vec![0u8; 0x200];
    image[..2].copy_from_slice(b"MZ");
    rsleigh_decompile::decompile_with_binary(Architecture::X86_64, &instructions, Some(&image), None)
}

#[test]
fn string_like_layout_is_not_named_startupinfo() {
    // mov rax, [rcx] ; mov rdx, [rcx+0x10] ; mov r8, [rcx+0x18]
    // mov [rcx+0x10], 0 (qword) ; mov qword [rcx+0x18], 15 ; add rax, rdx
    // add rax, r8 ; ret
    let output = decompile_in_pe(&[
        0x48, 0x8b, 0x01, 0x48, 0x8b, 0x51, 0x10, 0x4c, 0x8b, 0x41, 0x18, 0x48, 0xc7, 0x41,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x41, 0x18, 0x0f, 0x00, 0x00, 0x00, 0x48,
        0x01, 0xd0, 0x4c, 0x01, 0xc0, 0xc3,
    ]);
    for name in ["lpDesktop", "lpTitle", "lpReserved", "->cb", "STARTUPINFO"] {
        assert!(!output.contains(name), "`{name}` from offsets alone:\n{output}");
    }
}
