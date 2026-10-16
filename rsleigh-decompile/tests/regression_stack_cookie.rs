//! MSVC `/GS` epilogue: `mov rcx, [rsp+N]; xor rcx, rsp; call
//! __security_check_cookie; ret`. The check returns nothing and preserves
//! RAX, but it was treated as producing the return value, so functions
//! printed `return func_X(lVar ^ RSP - N); // stack cookie` and lost what
//! they actually return. Its `RSP` operands were also the largest group of
//! undeclared names left on CrashLoggerSSE.

use rsleigh_api::{Architecture, Decoder};

/// sub rsp, 0x38 ; mov rax, [rip+0x100] ; xor rax, rsp ; mov [rsp+0x28], rax
/// mov eax, 42 ; mov rcx, [rsp+0x28] ; xor rcx, rsp ; call 0x2000
/// add rsp, 0x38 ; ret
#[rustfmt::skip]
const BYTES: &[u8] = &[
    0x48, 0x83, 0xec, 0x38,
    0x48, 0x8b, 0x05, 0x00, 0x01, 0x00, 0x00,
    0x48, 0x31, 0xe0,
    0x48, 0x89, 0x44, 0x24, 0x28,
    0xb8, 0x2a, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x4c, 0x24, 0x28,
    0x48, 0x31, 0xe1,
    0xe8, 0xdb, 0x0f, 0x00, 0x00,
    0x48, 0x83, 0xc4, 0x38,
    0xc3,
];

fn decompile() -> String {
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < BYTES.len() {
        let address = 0x1000 + offset as u64;
        let inst = decoder.decode(&BYTES[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    rsleigh_decompile::decompile(Architecture::X86_64, &instructions)
}

#[test]
fn cookie_check_does_not_replace_the_return_value() {
    let output = decompile();
    assert!(
        output.contains("return 42;") || output.contains("return 0x2a;"),
        "\n{output}"
    );
}

#[test]
fn cookie_set_and_check_leave_no_stack_pointer_behind() {
    let output = decompile();
    assert!(!output.contains("RSP"), "\n{output}");
}
