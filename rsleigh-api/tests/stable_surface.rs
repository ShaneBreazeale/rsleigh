//! Stable surface contract — audit P2 #2.
//!
//! Pins the public types and functions documented as stable in the
//! crate-level `# Stability` block. If a refactor accidentally renames
//! or deletes one of these, this test fails to compile and forces a
//! conscious bump/deprecation cycle. Functional behavior is checked
//! elsewhere — this file is purely a name-and-shape contract.

#![allow(unused_imports, dead_code)]

use rsleigh_api::{
    AddressSpaceId, Architecture, DecodeError, Decoder, Instruction, PcodeOp, Varnode,
};

/// Compile-time proof that the documented architecture variants are
/// reachable. New arches may be added without breaking semver as long
/// as existing variants stay.
fn _arch_variants_present() {
    let _ = Architecture::X86_64;
    let _ = Architecture::X86_32;
    let _ = Architecture::AArch64;
    let _ = Architecture::ARM32;
    let _ = Architecture::MIPS32;
    let _ = Architecture::RiscV64;
}

/// Decoder constructor + decode signature pinned.
fn _decoder_shape(bytes: &[u8], addr: u64) -> Result<Instruction, DecodeError> {
    let mut dec = Decoder::new(Architecture::X86_64);
    dec.decode(bytes, addr)
}

/// pcode-ir re-exports used by stable embedders pinned by name.
fn _pcode_re_exports() {
    let _: Option<&PcodeOp> = None;
    let _: Option<Varnode> = None;
    let _: Option<AddressSpaceId> = None;
    let _: Option<Instruction> = None;
    let _: Result<(), DecodeError> = Ok(());
}

#[test]
fn stable_surface_smoke() {
    let mut dec = Decoder::new(Architecture::X86_64);
    let inst = dec.decode(&[0x48, 0x89, 0xd8], 0x1000).expect("MOV RAX,RBX");
    assert_eq!(inst.len, 3);
    assert!(inst.disassembly.contains("MOV"));

    // addr_size / register_name on Architecture are part of the
    // stable surface.
    assert_eq!(Architecture::X86_64.addr_size(), 8);
    assert_eq!(Architecture::ARM32.addr_size(), 4);
    assert!(Architecture::X86_64.register_name(0, 8).is_some());

    // Decoder::architecture returns the configured arch.
    assert_eq!(dec.architecture(), Architecture::X86_64);

    // Audit P2 #3 — Instruction.constructor is part of the surface.
    // Generated crates do not yet populate it; the field must default
    // to None so it doesn't break legacy callers.
    assert!(
        inst.constructor.is_none(),
        "constructor span should default to None until codegen wiring lands"
    );
}
