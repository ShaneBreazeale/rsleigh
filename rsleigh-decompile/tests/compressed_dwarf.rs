use rsleigh_decompile::dwarf::{parse_dwarf, parse_struct_fields};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../test-harness/fixtures/elf/compressed_dwarf/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn function_names(binary: &[u8]) -> Vec<(u64, Vec<String>)> {
    let mut names: Vec<_> = parse_dwarf(binary)
        .into_iter()
        .map(|(addr, info)| (addr, info.param_names))
        .collect();
    names.sort();
    names
}

fn field_names(binary: &[u8]) -> Vec<(u64, String)> {
    let mut names: Vec<_> = parse_struct_fields(binary).into_iter().collect();
    names.sort();
    names
}

#[test]
fn plain_fixture_has_dwarf_names() {
    let plain = fixture("plain.elf");
    assert!(function_names(&plain)
        .iter()
        .any(|(_, params)| params == &["left", "right"]));
    assert!(field_names(&plain).iter().any(|(_, name)| name == "next"));
}

#[test]
fn compressed_debug_sections_give_the_same_names() {
    let plain = fixture("plain.elf");
    for name in ["zlib.elf", "zstd.elf"] {
        let compressed = fixture(name);
        assert_eq!(function_names(&compressed), function_names(&plain), "{name}");
        assert_eq!(field_names(&compressed), field_names(&plain), "{name}");
    }
}
