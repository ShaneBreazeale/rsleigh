//! `base->field_N` is only valid C when `base` is declared as a pointer to a
//! struct with that field. rsleigh printed it on `long` parameters, so half
//! the functions in CrashLoggerSSE failed to compile ("member reference type
//! 'long' is not a pointer"; morluto/rea discussion 3858, Update 1).
//!
//! A base whose accesses fit one layout gets a synthesized struct type; a
//! base whose accesses overlap prints Ghidra-style `*(T *)(base + N)`. The
//! same holds for stores, which printed as `param_0[80] = ...` on a `long`.

use rsleigh_api::{Architecture, Decoder};
use std::collections::HashMap;

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

/// Declared type of every parameter and local, from the signature and the
/// declaration block.
fn declared_types(output: &str) -> HashMap<String, String> {
    let mut types = HashMap::new();
    let mut declare = |decl: &str| {
        let decl = decl.trim().trim_end_matches(';');
        let split = decl
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        if split > 0 {
            types.insert(decl[split..].to_string(), decl[..split].trim().to_string());
        }
    };
    let signature = output.lines().find(|l| l.contains('(')).unwrap_or("");
    if let (Some(open), Some(close)) = (signature.find('('), signature.rfind(')')) {
        signature[open + 1..close].split(',').for_each(&mut declare);
    }
    for line in output.lines().filter(|l| l.starts_with("    ") && l.trim_end().ends_with(';')) {
        let t = line.trim();
        if !t.contains('=') && !t.contains('(') && !t.starts_with("return") {
            declare(t);
        }
    }
    types
}

/// Bases used with `->` or `[N]` that are not declared as pointers.
fn arrow_on_non_pointer(output: &str) -> Vec<String> {
    let types = declared_types(output);
    let mut bad = Vec::new();
    let uses = output.match_indices("->").chain(output.match_indices('['));
    for (at, _) in uses {
        let base_start = output[..at]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let base = &output[base_start..at];
        if base.is_empty() || output[..at].ends_with("struct ") {
            continue;
        }
        if !types.get(base).is_some_and(|t| t.contains('*')) {
            bad.push(base.to_string());
        }
    }
    bad
}

#[test]
fn consistent_field_accesses_get_a_struct_pointer_type() {
    // mov eax, [rdi+0x48] ; mov [rdi+0x50], esi ; movzx ecx, byte [rdi+0x60]
    // add eax, ecx ; ret
    let output = decompile(&[
        0x8b, 0x47, 0x48, 0x89, 0x77, 0x50, 0x0f, 0xb6, 0x4f, 0x60, 0x01, 0xc8, 0xc3,
    ]);
    assert_eq!(arrow_on_non_pointer(&output), Vec::<String>::new(), "\n{output}");
    assert!(output.contains("struct "), "no struct type declared:\n{output}");
    for field in ["->field_50 = param_1", "->field_60"] {
        assert!(output.contains(field), "missing `{field}`:\n{output}");
    }
}

#[test]
fn overlapping_field_accesses_print_as_casts() {
    // mov eax, [rdi+0x10] ; movzx ecx, byte [rdi+0x12] ; add eax, ecx ; ret
    // A 4-byte field at 0x10 overlaps a 1-byte field at 0x12.
    let output = decompile(&[0x8b, 0x47, 0x10, 0x0f, 0xb6, 0x4f, 0x12, 0x01, 0xc8, 0xc3]);
    assert_eq!(arrow_on_non_pointer(&output), Vec::<String>::new(), "\n{output}");
    assert!(output.contains("+ 0x12)"), "byte at 0x12 not cast-dereferenced:\n{output}");
}
