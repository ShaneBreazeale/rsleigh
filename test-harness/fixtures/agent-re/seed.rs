//! Original hand-encoded x86-32 fixtures, licensed under the repository license.
//! See seed.asm for address-by-address ground truth. No compiler is required.
#![allow(dead_code)]

#[derive(Clone, Copy)]
pub enum Selector {
    Return(u64),
    Argument(u64, usize),
    Condition(u64),
}

pub struct Task {
    pub id: &'static str,
    pub question: &'static str,
    pub function: u64,
    pub selector: Selector,
    pub constant: Option<u64>,
    pub boundary: Option<&'static str>,
}

pub fn tasks() -> Vec<Task> {
    vec![
        Task {
            id: "return-seven",
            question: "What value does this function return?",
            function: 0x401000,
            selector: Selector::Return(0x401005),
            constant: Some(7),
            boundary: None,
        },
        Task {
            id: "first-call-arg-zero",
            question: "What is argument zero at the first helper call?",
            function: 0x401020,
            selector: Selector::Argument(0x401024, 0),
            constant: Some(11),
            boundary: None,
        },
        Task {
            id: "first-call-arg-one",
            question: "What is argument one at the first helper call?",
            function: 0x401020,
            selector: Selector::Argument(0x401024, 1),
            constant: Some(22),
            boundary: None,
        },
        Task {
            id: "second-call-arg-zero",
            question: "What is argument zero at the second call to the same helper?",
            function: 0x401020,
            selector: Selector::Argument(0x401030, 0),
            constant: Some(33),
            boundary: None,
        },
        Task {
            id: "branch-input-unknown",
            question: "Is the conditional branch determined without knowing the incoming eax?",
            function: 0x401040,
            selector: Selector::Condition(0x401042),
            constant: None,
            boundary: Some("unknown_value"),
        },
        Task {
            id: "first-return-site",
            question: "What value is returned at the first return instruction?",
            function: 0x401040,
            selector: Selector::Return(0x401049),
            constant: Some(1),
            boundary: None,
        },
        Task {
            id: "second-return-site",
            question: "What value is returned at the second return instruction?",
            function: 0x401040,
            selector: Selector::Return(0x40104f),
            constant: Some(2),
            boundary: None,
        },
        Task {
            id: "memory-unknown",
            question: "Can the loaded return value be determined without the pointed-to memory?",
            function: 0x401060,
            selector: Selector::Return(0x401062),
            constant: None,
            boundary: Some("unmodeled_memory"),
        },
    ]
}

pub fn binary() -> Vec<u8> {
    let mut buf = vec![0u8; 0x400];
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    let pe = 0x80usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());

    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
    buf[opt + 4..opt + 8].copy_from_slice(&0x200u32.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 24..opt + 28].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    buf[opt + 40..opt + 42].copy_from_slice(&5u16.to_le_bytes());
    buf[opt + 48..opt + 50].copy_from_slice(&5u16.to_le_bytes());
    buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    buf[opt + 72..opt + 76].copy_from_slice(&0x10_0000u32.to_le_bytes());
    buf[opt + 76..opt + 80].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 80..opt + 84].copy_from_slice(&0x10_0000u32.to_le_bytes());
    buf[opt + 84..opt + 88].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    // Named exports establish exact function starts for the CLI's function map.
    buf[opt + 96..opt + 100].copy_from_slice(&0x1100u32.to_le_bytes());
    buf[opt + 100..opt + 104].copy_from_slice(&0xa0u32.to_le_bytes());

    let section = opt + 0xe0;
    buf[section..section + 8].copy_from_slice(b".text\0\0\0");
    buf[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    buf[0x200..].fill(0x90);
    for (offset, code) in [
        (0x00, &b"\xb8\x07\x00\x00\x00\xc3"[..]),
        (0x20, &b"\x6a\x16\x6a\x0b\xe8\x57\x00\x00\x00\x83\xc4\x08\x6a\x2c\x6a\x21\xe8\x4b\x00\x00\x00\x83\xc4\x08\xc3"[..]),
        (0x40, &b"\x85\xc0\x75\x06\xb8\x01\x00\x00\x00\xc3\xb8\x02\x00\x00\x00\xc3"[..]),
        (0x60, &b"\x8b\x01\xc3"[..]),
        (0x80, &b"\xb8\x09\x00\x00\x00\xc3"[..]),
    ] {
        buf[0x200 + offset..0x200 + offset + code.len()].copy_from_slice(code);
    }
    buf[0x300..0x3a0].fill(0);
    for (offset, value) in [
        (16, 1u32),
        (20, 5),
        (24, 5),
        (28, 0x1128),
        (32, 0x113c),
        (36, 0x1150),
    ] {
        buf[0x300 + offset..0x304 + offset].copy_from_slice(&value.to_le_bytes());
    }
    let mut name_offset = 0x360;
    for (index, (rva, name)) in [
        (0x1000u32, "constant"),
        (0x1020, "calls"),
        (0x1040, "condition"),
        (0x1060, "load"),
        (0x1080, "helper"),
    ]
    .iter()
    .enumerate()
    {
        buf[0x328 + index * 4..0x32c + index * 4].copy_from_slice(&rva.to_le_bytes());
        buf[0x33c + index * 4..0x340 + index * 4]
            .copy_from_slice(&(name_offset as u32 + 0xe00).to_le_bytes());
        buf[0x350 + index * 2..0x352 + index * 2].copy_from_slice(&(index as u16).to_le_bytes());
        buf[name_offset..name_offset + name.len()].copy_from_slice(name.as_bytes());
        name_offset += name.len() + 1;
    }
    buf
}
