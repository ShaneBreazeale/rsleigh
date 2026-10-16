//! A register loaded through a pointer must keep its assignment. A text rule
//! that hides register-to-register copies (`EAX = param_0;`) also matched
//! `EAX = param_0->field_48;`, because it only checked the `param_` prefix,
//! so the load vanished and the register was read without ever being set:
//! the "variables read before they are set" in morluto/rea discussion 3858.

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

/// Every `xVarN` the body reads is assigned somewhere in it.
fn read_before_set(output: &str) -> Vec<String> {
    let body = output.split_once(") {").map_or(output, |(_, b)| b);
    let mut unset = Vec::new();
    for word in body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        // `iVar1`, `puVar2`, ...: a lowercase prefix, `Var`, then digits.
        let is_var = word.find("Var").is_some_and(|at| {
            at > 0
                && word[..at].bytes().all(|b| b.is_ascii_lowercase())
                && word.len() > at + 3
                && word[at + 3..].bytes().all(|b| b.is_ascii_digit())
        });
        if is_var && !body.contains(&format!("{word} = ")) && !unset.contains(&word.to_string()) {
            unset.push(word.to_string());
        }
    }
    unset
}

#[test]
fn load_through_a_parameter_keeps_its_assignment() {
    // mov eax, [rdi+0x48] ; mov [rdi+0x50], esi ; movzx ecx, byte [rdi+0x60]
    // add eax, ecx ; ret
    let output = decompile(&[
        0x8b, 0x47, 0x48, 0x89, 0x77, 0x50, 0x0f, 0xb6, 0x4f, 0x60, 0x01, 0xc8, 0xc3,
    ]);
    assert!(
        output.contains("field_48"),
        "load of +0x48 dropped:\n{output}"
    );
    assert_eq!(read_before_set(&output), Vec::<String>::new(), "\n{output}");
}

#[test]
fn vtable_load_keeps_its_assignment() {
    // mov rax, [rcx] ; call qword ptr [rax+8] ; ret
    let output = decompile(&[0x48, 0x8b, 0x01, 0xff, 0x50, 0x08, 0xc3]);
    assert_eq!(read_before_set(&output), Vec::<String>::new(), "\n{output}");
}
