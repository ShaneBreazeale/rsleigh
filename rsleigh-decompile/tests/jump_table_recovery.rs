//! Jump tables whose base is set far before the jump, and tables with more
//! than 256 entries, are recovered.
//! Fixture: test-harness/fixtures/elf/jump_tables (stripped x86-64 ELF).

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::jump_table::{find, ImageMemory, JumpTable};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-harness/fixtures/elf/jump_tables/jump_tables.elf"
);
/// Start and size of `.text`.
const TEXT: (u64, usize) = (0x4016c4, 0xad);
/// The computed jump in far_base, wide_table and offset_index.
const FAR_BASE_JUMP: u64 = 0x40170a;
const WIDE_TABLE_JUMP: u64 = 0x401733;
const OFFSET_INDEX_JUMP: u64 = 0x401760;

fn tables() -> Vec<JumpTable> {
    let image = std::fs::read(FIXTURE).unwrap();
    let memory = ImageMemory::new(&image);
    let bytes = memory.read(TEXT.0, TEXT.1).unwrap();
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let address = TEXT.0 + offset as u64;
        let inst = decoder.decode(&bytes[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    find(&instructions, &|va, len| memory.read(va, len))
}

fn table_at(jump: u64) -> JumpTable {
    tables()
        .into_iter()
        .find(|t| t.jump == jump)
        .unwrap_or_else(|| panic!("no table recovered for the jump at {jump:#x}"))
}

#[test]
fn table_base_set_twenty_instructions_before_the_jump() {
    // lea rdx, [table] ; 20 x nop ; cmp edi, 2 ; ja ; ... ; jmp rax
    assert_eq!(table_at(FAR_BASE_JUMP).targets.len(), 3);
}

#[test]
fn table_with_more_than_256_entries_keeps_every_entry() {
    // cmp edi, 299 ; ja: 300 entries, the last one a case of its own.
    let table = table_at(WIDE_TABLE_JUMP);
    assert_eq!(table.targets.len(), 300);
    assert_ne!(table.targets[299], table.targets[298]);
}

#[test]
fn index_built_by_add_and_overwritten_by_the_table_load() {
    // add edi, 5 ; cmp edi, 2 ; ja ; movsxd rdi, [rdx + rdi*4] ; add rdi, rdx ; jmp rdi
    let table = table_at(OFFSET_INDEX_JUMP);
    assert_eq!(table.targets.len(), 3);
}

/// MSVC x64 image base and the RVA of the synthetic tables below.
const IMAGE_BASE: u64 = 0x1_8000_0000;
const TABLE_RVA: u64 = 0x2000;

/// Decode `code` at `IMAGE_BASE + 0x1000` and recover its tables from a
/// table of image-relative (RVA) entries at `IMAGE_BASE + TABLE_RVA`.
fn msvc_tables(code: &[u8], rvas: &[u32]) -> Vec<JumpTable> {
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        let address = IMAGE_BASE + 0x1000 + offset as u64;
        let inst = decoder.decode(&code[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    let table: Vec<u8> = rvas.iter().flat_map(|r| r.to_le_bytes()).collect();
    let table_va = IMAGE_BASE + TABLE_RVA;
    find(&instructions, &|va, len| {
        let start = usize::try_from(va.checked_sub(table_va)?).ok()?;
        table.get(start..start + len).map(<[u8]>::to_vec)
    })
}

/// mov eax,1 ; ret / mov eax,2 ; ret / mov eax,3 ; ret
const CASES: [u8; 18] = [
    0xb8, 0x01, 0, 0, 0, 0xc3, 0xb8, 0x02, 0, 0, 0, 0xc3, 0xb8, 0x03, 0, 0, 0, 0xc3,
];

#[test]
fn msvc_image_relative_table_with_bounds_check() {
    // cmp ecx,2 ; ja default ; mov eax,ecx ; lea r8,[ImageBase]
    // mov eax,[r8+rax*4+0x2000] ; add rax,r8 ; jmp rax ; 3 cases ; default
    let mut code = vec![
        0x83, 0xf9, 0x02, // cmp ecx, 2
        0x77, 0x28, // ja +0x28 -> default at 0x102d
        0x89, 0xc8, // mov eax, ecx
        0x4c, 0x8d, 0x05, 0xf2, 0xef, 0xff, 0xff, // lea r8, [rip-0x100e] = ImageBase
        0x41, 0x8b, 0x84, 0x80, 0x00, 0x20, 0x00, 0x00, // mov eax, [r8+rax*4+0x2000]
        0x4c, 0x01, 0xc0, // add rax, r8
        0xff, 0xe0, // jmp rax
    ];
    code.extend_from_slice(&CASES);
    code.extend_from_slice(&[0x31, 0xc0, 0xc3]); // default: xor eax,eax ; ret
    let tables = msvc_tables(&code, &[0x101b, 0x1021, 0x1027]);
    let [table] = tables.as_slice() else {
        panic!("expected one table: {tables:?}");
    };
    assert_eq!(table.jump, IMAGE_BASE + 0x1019);
    assert_eq!(
        table.targets,
        [0x101b, 0x1021, 0x1027].map(|rva| IMAGE_BASE + rva)
    );
}

#[test]
fn msvc_image_relative_table_with_signed_unguarded_index() {
    // #27's shape: movsx rax, byte [rdx+0x48] ; lea r8,[ImageBase]
    // mov eax,[r8+rax*4+0x2000] ; add rax,r8 ; jmp rax
    let mut code = vec![
        0x48, 0x0f, 0xbe, 0x42, 0x48, // movsx rax, byte ptr [rdx+0x48]
        0x4c, 0x8d, 0x05, 0xf4, 0xef, 0xff, 0xff, // lea r8, [rip-0x100c] = ImageBase
        0x41, 0x8b, 0x84, 0x80, 0x00, 0x20, 0x00, 0x00, // mov eax, [r8+rax*4+0x2000]
        0x4c, 0x01, 0xc0, // add rax, r8
        0xff, 0xe0, // jmp rax
    ];
    code.extend_from_slice(&CASES);
    let tables = msvc_tables(&code, &[0x1019, 0x101f, 0x1025]);
    let [table] = tables.as_slice() else {
        panic!("expected one table: {tables:?}");
    };
    assert_eq!(
        table.targets,
        [0x1019, 0x101f, 0x1025].map(|rva| IMAGE_BASE + rva)
    );
}

#[test]
fn unrecovered_jump_is_named_in_the_pseudocode() {
    // #27: without the image the table cannot be read, so the jump stays
    // unresolved; the output says so instead of just ending.
    let code = [
        0x48, 0x0f, 0xbe, 0x42, 0x48, // movsx rax, byte ptr [rdx+0x48]
        0x4c, 0x8d, 0x05, 0xf4, 0xef, 0xff, 0xff, // lea r8, [rip-0x100c]
        0x41, 0x8b, 0x84, 0x80, 0x00, 0x20, 0x00, 0x00, // mov eax, [r8+rax*4+0x2000]
        0x4c, 0x01, 0xc0, // add rax, r8
        0xff, 0xe0, // jmp rax
    ];
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        let address = 0x1000 + offset as u64;
        let inst = decoder.decode(&code[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    let (text, diagnostics) = rsleigh_decompile::decompile_with_diagnostics(
        Architecture::X86_64,
        &instructions,
        None,
        None,
    );
    assert!(
        diagnostics.iter().any(|d| d.kind
            == rsleigh_decompile::ir::DiagKind::UnrecoveredIndirectJump
            && d.addr == Some(0x1017)),
        "{diagnostics:?}"
    );
    assert!(
        text.contains("    // indirect jump at 0x1017: targets not recovered\n}"),
        "{text}"
    );
}
