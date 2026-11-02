//! Regressions from an external rsleigh-vs-Ghidra check (morluto/rea#1389):
//! control that leaves a function through a jump, and values that reach a
//! shared return from several paths, must survive into the pseudocode.

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::decompile;

fn decode_x64(bytes: &[u8], base: u64) -> Vec<(u64, pcode_ir::Instruction)> {
    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = base + off as u64;
        let Ok(inst) = dec.decode(&bytes[off..], addr) else {
            break;
        };
        off += inst.len as usize;
        insts.push((addr, inst));
    }
    insts
}

/// Decompile on a large stack, several times: hash-map order varies per
/// map instance, so one run can pass by luck.
fn decompile_x64(bytes: &'static [u8], base: u64) -> Vec<String> {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            let insts = decode_x64(bytes, base);
            (0..6)
                .map(|_| decompile(Architecture::X86_64, &insts))
                .collect()
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn plt_style_slot_jump_returns_the_callee() {
    // jmp [rip+0x1ffa]   ; slot 0x3000
    // push 0xc           ; lazy-binding path, not reached from the entry
    // jmp 0x800
    static BYTES: [u8; 16] = [
        0xff, 0x25, 0xfa, 0x1f, 0x00, 0x00, 0x68, 0x0c, 0x00, 0x00, 0x00, 0xe9, 0xf0, 0xf7, 0xff,
        0xff,
    ];
    for text in decompile_x64(&BYTES, 0x1000) {
        assert!(text.contains("return func_3000();"), "{text}");
        assert!(!text.contains("func_800"), "lazy path leaked: {text}");
    }
}

#[test]
fn direct_jump_out_of_the_body_is_a_tail_call() {
    // mov edi, 5 ; jmp 0x5000
    static BYTES: [u8; 10] = [0xbf, 0x05, 0x00, 0x00, 0x00, 0xe9, 0xf6, 0x3f, 0x00, 0x00];
    for text in decompile_x64(&BYTES, 0x1000) {
        assert!(text.contains("func_5000(5)"), "{text}");
    }
}

#[test]
fn jump_through_a_loaded_pointer_calls_through_it() {
    // mov rdx, [rdi] ; jmp qword ptr [rdx + 0x28]
    // The pointer is read at a computed address. Its unique-space offset
    // must not be printed as a direct call target (morluto/rea#1389).
    static BYTES: [u8; 6] = [0x48, 0x8b, 0x17, 0xff, 0x62, 0x28];
    for text in decompile_x64(&BYTES, 0x1000) {
        // The body follows the signature, after any struct definitions.
        let body = text.split_once(") {").map_or("", |(_, b)| b);
        assert!(!body.contains("func_"), "{text}");
        assert!(body.contains("(*"), "{text}");
    }
}

/// A minimal ELF: `.text` at 0x1000 holding `code`, and a writable `.data`
/// at 0x3000 of 16 zero bytes. No symbols or relocations.
fn elf_with_data_slots(code: &[u8]) -> Vec<u8> {
    let shstrtab = b"\0.text\0.data\0.shstrtab\0";
    let (text_off, data_off, sh_off) = (0x80u64, 0xa0u64, 0xc0u64);
    let mut elf = vec![0u8; sh_off as usize];
    elf[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86-64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[40..48].copy_from_slice(&sh_off.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum
    elf[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx
    elf[0x40..0x40 + shstrtab.len()].copy_from_slice(shstrtab);
    elf[text_off as usize..text_off as usize + code.len()].copy_from_slice(code);
    // (name, type, flags, addr, offset, size)
    let sections: [(u32, u32, u64, u64, u64, u64); 4] = [
        (0, 0, 0, 0, 0, 0),
        (1, 1, 0x6, 0x1000, text_off, code.len() as u64), // AX
        (7, 1, 0x3, 0x3000, data_off, 16),                // WA
        (13, 3, 0, 0, 0x40, shstrtab.len() as u64),
    ];
    for (name, kind, flags, addr, offset, size) in sections {
        elf.extend_from_slice(&name.to_le_bytes());
        elf.extend_from_slice(&kind.to_le_bytes());
        for field in [flags, addr, offset, size] {
            elf.extend_from_slice(&field.to_le_bytes());
        }
        elf.extend_from_slice(&[0; 8]); // link, info
        elf.extend_from_slice(&1u64.to_le_bytes()); // addralign
        elf.extend_from_slice(&0u64.to_le_bytes()); // entsize
    }
    elf
}

#[test]
fn calls_through_data_slots_call_through_the_pointer() {
    // call qword ptr [0x3000] ; jmp qword ptr [0x3008]
    // Both slots are in writable .data and are not imports: the targets are
    // pointers stored there, not functions at 0x3000 and 0x3008 (rsleigh#17).
    static CODE: [u8; 12] = [
        0xff, 0x15, 0xfa, 0x1f, 0x00, 0x00, 0xff, 0x25, 0xfc, 0x1f, 0x00, 0x00,
    ];
    let elf = elf_with_data_slots(&CODE);
    let text = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            let insts = decode_x64(&CODE, 0x1000);
            rsleigh_decompile::decompile_with_binary(Architecture::X86_64, &insts, Some(&elf), None)
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(!text.contains("func_300"), "{text}");
    assert!(text.contains("(*DAT_00003000)("), "{text}");
    assert!(text.contains("(*DAT_00003008)("), "{text}");
}

#[test]
fn shared_return_keeps_each_path_value() {
    //   cmp edi, 1 ; jle L2
    //   mov eax, 1 ; jmp L3
    // L2: mov eax, 2
    // L3: ret
    static BYTES: [u8; 18] = [
        0x83, 0xff, 0x01, 0x7e, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb8, 0x02, 0x00,
        0x00, 0x00, 0xc3,
    ];
    for text in decompile_x64(&BYTES, 0x1000) {
        assert!(text.contains("? 2 : 1"), "{text}");
    }
}

/// GCC 16.2 -O1 -fno-pie of:
///   if (argc < 2) { puts(usage); return 2; }
///   for (h = 5381, p = argv[1]; *p; p++) h = h * 33 + *p;
///   if (h % 7 == 0) { puts("match"); return 0; }
///   puts("no match"); return 1;
/// Three paths set EAX and jump to one `add rsp, 8; ret`.
static GCC_O1_MAIN: [u8; 146] = [
    0x48, 0x83, 0xec, 0x08, 0x83, 0xff, 0x01, 0x7e, 0x67, 0x48, 0x8b, 0x4e, 0x08, 0x0f, 0xb6, 0x11,
    0x84, 0xd2, 0x74, 0x48, 0xb8, 0x05, 0x15, 0x00, 0x00, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x89, 0xc6, 0xc1, 0xe6, 0x05, 0x01, 0xf0, 0x0f, 0xb6, 0xd2, 0x01, 0xd0, 0x48, 0x83, 0xc1, 0x01,
    0x0f, 0xb6, 0x11, 0x84, 0xd2, 0x75, 0xe9, 0x89, 0xc1, 0x48, 0x69, 0xc9, 0x25, 0x49, 0x92, 0x24,
    0x48, 0xc1, 0xe9, 0x20, 0x89, 0xc2, 0x29, 0xca, 0xd1, 0xea, 0x01, 0xca, 0xc1, 0xea, 0x02, 0x8d,
    0x0c, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x29, 0xd1, 0x39, 0xc8, 0x74, 0x25, 0xbf, 0x38, 0x03, 0x20,
    0x00, 0xe8, 0x4a, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08, 0xc3,
    0xbf, 0x20, 0x03, 0x20, 0x00, 0xe8, 0x36, 0x00, 0x00, 0x00, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xeb,
    0xea, 0xbf, 0x32, 0x03, 0x20, 0x00, 0xe8, 0x25, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0xeb, 0xd9,
];

#[test]
fn gcc_o1_main_returns_its_exit_code_variable() {
    for text in decompile_x64(&GCC_O1_MAIN, 0x2013a0) {
        let last_return = text
            .lines()
            .rev()
            .find_map(|l| l.trim().strip_prefix("return "))
            .unwrap_or_else(|| panic!("no return: {text}"));
        let value = last_return.trim_end_matches(';');
        assert!(
            value.parse::<i64>().is_err(),
            "join of 2/1/0 printed as one constant: {text}"
        );
        for code in ["= 2;", "= 1;", "= 0;"] {
            assert!(text.contains(code), "missing {code}: {text}");
        }
        // argv[1] is loaded into RCX; it is not argc.
        assert!(!text.contains("*param_0"), "{text}");
        assert!(!text.contains("*(param_0)"), "{text}");
        // The multiply-high sequence is `h % 7`, and both outcomes of that
        // test survive: puts("match") and the shared puts("no match") path.
        assert!(text.contains("% 7 == 0"), "{text}");
        assert!(text.matches("func_201450(").count() >= 4, "{text}");
        // The loop is h = h * 33 + c over the characters: the shift-add is a
        // multiply, the pointer advances, the next character is loaded, and
        // the loop tests that loaded value rather than reading memory again.
        assert!(text.contains("do {") && text.contains("* 33"), "{text}");
        assert!(text.contains("++") || text.contains(" + 1;"), "{text}");
        let c = text
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_suffix(" = *i;")
                    .or(l.trim().strip_suffix(" = *puVar2;"))
            })
            .unwrap_or_else(|| panic!("no character load: {text}"));
        assert!(text.contains(&format!("}} while ({c} != 0);")), "{text}");
        assert!(text.contains(&format!("if ({c} == 0)")), "{text}");
    }
}

#[test]
fn repeated_decompiles_print_identical_text() {
    // Every HashMap gets fresh hash keys, so iteration-order leaks show up
    // as differing text across repeated runs in one process (rsleigh#7).
    let texts = decompile_x64(&GCC_O1_MAIN, 0x2013a0);
    assert!(texts.windows(2).all(|w| w[0] == w[1]), "{texts:#?}");
}

#[test]
fn cold_part_fde_is_detected_as_mid_frame() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-harness/fixtures/elf/cold_split/cold_split.elf"
    );
    let layout = rsleigh_decompile::eh_frame::fde_layout(&std::fs::read(path).unwrap());
    // check.cold starts inside check's frame; check and _start are entries.
    assert!(layout.mid_frame.contains(&0x401254), "{layout:?}");
    assert!(!layout.mid_frame.contains(&0x40127a), "{layout:?}");
    assert!(!layout.mid_frame.contains(&0x401260), "{layout:?}");
    assert_eq!(layout.extents.get(&0x401254), Some(&0x401260));
}
