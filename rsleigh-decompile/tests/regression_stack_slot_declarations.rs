//! Every stack slot the pseudocode names must be declared. Slots named
//! `local_N` by the stack-pointer rewrites were never declared ("use of
//! undeclared identifier 'local_50'" was the most common compile error on
//! CrashLoggerSSE; morluto/rea discussion 3858, Update 1). Most of them stand
//! for the slot's address (`*(void **)local_50 = x`, `f(local_50 - 8)`), so
//! they are declared as byte arrays, which decay to that address.

use rsleigh_api::{Architecture, Decoder};
use std::collections::BTreeSet;

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

/// `local_N` names used in the body that no declaration introduces.
fn undeclared_locals(output: &str) -> BTreeSet<String> {
    let names = |text: &str| -> BTreeSet<String> {
        let mut found = BTreeSet::new();
        for (at, _) in text.match_indices("local_") {
            let before = text[..at].bytes().last();
            if before.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_') {
                continue;
            }
            let len = text[at + 6..]
                .bytes()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            if len > 0 {
                found.insert(text[at..at + 6 + len].to_string());
            }
        }
        found
    };
    let is_decl = |l: &str| {
        let t = l.trim();
        l.starts_with("    ")
            && t.ends_with(';')
            && !t.contains(['=', '(', '+', '-'])
            && !t.starts_with("return")
    };
    let declared: BTreeSet<String> = output
        .lines()
        .filter(|l| is_decl(l))
        .flat_map(|l| names(l))
        .collect();
    let used: BTreeSet<String> = output
        .lines()
        .filter(|l| !is_decl(l))
        .flat_map(|l| names(l))
        .collect();
    used.difference(&declared).cloned().collect()
}

#[test]
fn address_taken_stack_slot_is_declared() {
    // sub rsp, 0x38 ; lea rcx, [rsp+0x20] ; call 0x1100 ; mov eax, [rsp+0x20]
    // add rsp, 0x38 ; ret
    let output = decompile(&[
        0x48, 0x83, 0xec, 0x38, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0xe8, 0xf3, 0x00, 0x00, 0x00, 0x8b,
        0x44, 0x24, 0x20, 0x48, 0x83, 0xc4, 0x38, 0xc3,
    ]);
    assert!(output.contains("local_"), "no stack slot named:\n{output}");
    assert_eq!(undeclared_locals(&output), BTreeSet::new(), "\n{output}");
}
