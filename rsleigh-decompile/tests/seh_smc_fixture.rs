//! End-to-end tests against source-controlled, executable Windows PE fixtures.
#![cfg(feature = "experimental")]

use rsleigh_decompile::seh_static::{
    apply_patches, extract_all_patches, parse_pe64_seh, smc_fixpoint_seh_only,
};

fn check_fixture(image: &[u8]) {
    let pe = goblin::pe::PE::parse(image).unwrap();
    assert!(pe.is_64);
    let export_rva = |name: &str| {
        pe.exports
            .iter()
            .find(|export| export.name == Some(name))
            .unwrap_or_else(|| panic!("missing export {name}"))
            .rva as u64
    };
    let payload_rva = export_rva("payload");
    let handler_va = pe.image_base as u64 + export_rva("smc_handler");
    let protected_va = pe.image_base as u64 + export_rva("protected_fault");
    let section = pe
        .sections
        .iter()
        .find(|s| {
            payload_rva >= s.virtual_address as u64
                && payload_rva < (s.virtual_address + s.virtual_size) as u64
        })
        .unwrap();
    assert_eq!(section.characteristics & 0xa0000000, 0xa0000000);
    let payload_offset = section.pointer_to_raw_data as usize
        + (payload_rva - section.virtual_address as u64) as usize;
    let before = [0xb8, 0, 0, 0, 0, 0xc3];
    let after = [0xb8, 42, 0, 0, 0, 0xc3];
    assert_eq!(&image[payload_offset..payload_offset + 6], &before);

    let records = parse_pe64_seh(image);
    let handlers: Vec<_> = records.iter().filter(|r| r.handler.is_some()).collect();
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0].func_begin, protected_va);
    assert_eq!(handlers[0].handler, Some(handler_va));

    let patches = extract_all_patches(image);
    assert_eq!(patches.len(), 1, "unexpected patches: {patches:?}");
    assert_eq!(patches[0].handler_va, handler_va);
    assert_eq!(patches[0].target_va, pe.image_base as u64 + payload_rva + 1);
    assert_eq!(patches[0].bytes, [42]);

    let mut expected = image.to_vec();
    expected[payload_offset + 1] = 42;
    let mut patched = image.to_vec();
    assert_eq!(apply_patches(&mut patched, &patches), 1);
    assert_eq!(patched, expected, "only the expected byte may change");
    assert_eq!(&patched[payload_offset..payload_offset + 6], &after);

    let result = smc_fixpoint_seh_only(image, 4);
    assert!(result.converged);
    assert_eq!(result.iterations, 2);
    assert_eq!(result.patches.len(), 1);
    assert_eq!(result.image, expected);
    // This fixture changes a return value; it does not reveal new functions.
    assert!(result.newly_discovered_fns.is_empty());
}

#[test]
fn seh_smc_direct_fixture() {
    check_fixture(include_bytes!(
        "../../test-harness/fixtures/seh-smc/direct.exe"
    ));
}

#[test]
fn seh_smc_indirect_fixture() {
    check_fixture(include_bytes!(
        "../../test-harness/fixtures/seh-smc/indirect.exe"
    ));
}
