//! A masked comparison must keep its parentheses: in C, `x & m == k` means
//! `x & (m == k)`. GNU `ls` 0x3e10 printed `iVar3 & 0xf000 != 16384`
//! (reported in morluto/rea discussion 3858, Update 1).

use rsleigh_api::{Architecture, Decoder};

/// ```text
/// mov eax, edi
/// and eax, 0xf000
/// cmp eax, 0x4000
/// jne .zero
/// mov eax, 1
/// ret
/// .zero:
/// xor eax, eax
/// ret
/// ```
#[rustfmt::skip]
const BYTES: &[u8] = &[
    0x89, 0xf8,
    0x25, 0x00, 0xf0, 0x00, 0x00,
    0x3d, 0x00, 0x40, 0x00, 0x00,
    0x75, 0x06,
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xc3,
    0x31, 0xc0,
    0xc3,
];

#[test]
fn masked_comparison_keeps_its_parentheses() {
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < BYTES.len() {
        let address = 0x1000 + offset as u64;
        let inst = decoder.decode(&BYTES[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    let output = rsleigh_decompile::decompile(Architecture::X86_64, &instructions);
    let condition = output
        .lines()
        .find(|l| {
            l.trim_start().starts_with("if (") && (l.contains("0x4000") || l.contains("16384"))
        })
        .unwrap_or_else(|| panic!("no masked test in:\n{output}"));
    assert_eq!(
        condition.matches('(').count(),
        condition.matches(')').count(),
        "unbalanced condition: {condition}\n{output}"
    );
    for cmp in [" == ", " != "] {
        let unwrapped = condition
            .match_indices(cmp)
            .any(|(at, _)| condition[..at].trim_end().ends_with("0xf000"));
        assert!(
            !unwrapped,
            "`& 0xf000{cmp}` binds as `& (0xf000{cmp}...)`: {condition}"
        );
    }
}
