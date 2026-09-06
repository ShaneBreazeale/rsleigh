//! Original, deterministic native fixtures (Apache-2.0).
//! Instruction comments and expected values are the ground truth; no compiler
//! or decompiled pseudocode is used to construct an answer. See corpus.md.
use super::seed::{self, Selector};
use rsleigh_api::Architecture;

#[derive(Clone, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Answer {
    Constant(u64),
    Unknown(&'static str),
    Helper(u64),
    Comparison(u64),
    Dispatch(u64),
}
pub struct Task {
    pub id: &'static str,
    pub question: &'static str,
    pub fixture: &'static str,
    pub architecture: Architecture,
    pub data: Vec<u8>,
    pub text_offset: usize,
    pub function: u64,
    pub selector: Selector,
    pub answer: Answer,
    pub evidence_addresses: Vec<u64>,
}
impl Task {
    pub fn architecture_name(&self) -> &'static str {
        match self.architecture {
            Architecture::X86_32 => "x86-32",
            Architecture::X86_64 => "x86-64",
            Architecture::AArch64 => "aarch64",
            Architecture::ARM32 => "arm32",
            Architecture::MIPS32 => "mips32",
            Architecture::RiscV64 => "riscv64",
        }
    }
}

// A section-backed ELF with one executable segment and explicit STT_FUNC
// symbols. Both class widths and both byte orders are encoded intentionally.
fn elf(arch: Architecture, functions: &[(usize, &[u8])]) -> Vec<u8> {
    let wide = matches!(
        arch,
        Architecture::X86_64 | Architecture::AArch64 | Architecture::RiscV64
    );
    let be = arch == Architecture::MIPS32;
    let machine = match arch {
        Architecture::X86_64 => 62,
        Architecture::AArch64 => 183,
        Architecture::ARM32 => 40,
        Architecture::MIPS32 => 8,
        Architecture::RiscV64 => 243,
        _ => unreachable!(),
    };
    let mut b = vec![0; 0x800 + 5 * if wide { 64 } else { 40 }];
    fn num(b: &mut [u8], at: usize, width: usize, n: u64, be: bool) {
        for i in 0..width {
            b[at + i] = (n >> (8 * if be { width - 1 - i } else { i })) as u8;
        }
    }
    b[..7].copy_from_slice(&[
        0x7f,
        b'E',
        b'L',
        b'F',
        if wide { 2 } else { 1 },
        if be { 2 } else { 1 },
        1,
    ]);
    let mut set = |at, width, value| num(&mut b, at, width, value, be);
    set(16, 2, 2);
    set(18, 2, machine);
    set(20, 4, 1);
    if wide {
        for (at, w, v) in [
            (24, 8, 0x401000),
            (32, 8, 64),
            (40, 8, 0x800),
            (52, 2, 64),
            (54, 2, 56),
            (56, 2, 1),
            (58, 2, 64),
            (60, 2, 5),
            (62, 2, 4),
            (64, 4, 1),
            (68, 4, 5),
            (72, 8, 0x400),
            (80, 8, 0x401000),
            (88, 8, 0x401000),
            (96, 8, 0x100),
            (104, 8, 0x100),
            (112, 8, 0x100),
        ] {
            set(at, w, v);
        }
    } else {
        for (at, w, v) in [
            (24, 4, 0x401000),
            (28, 4, 52),
            (32, 4, 0x800),
            (40, 2, 52),
            (42, 2, 32),
            (44, 2, 1),
            (46, 2, 40),
            (48, 2, 5),
            (50, 2, 4),
            (52, 4, 1),
            (56, 4, 0x400),
            (60, 4, 0x401000),
            (64, 4, 0x401000),
            (68, 4, 0x100),
            (72, 4, 0x100),
            (76, 4, 5),
            (80, 4, 0x100),
        ] {
            set(at, w, v);
        }
        if arch == Architecture::ARM32 {
            set(36, 4, 0x05000000);
        } // EABI5, ARM mode
    }
    let text_size = functions
        .iter()
        .map(|(offset, code)| offset + code.len())
        .max()
        .unwrap() as u64;
    if wide {
        num(&mut b, 96, 8, text_size, be);
        num(&mut b, 104, 8, text_size, be);
    } else {
        num(&mut b, 68, 4, text_size, be);
        num(&mut b, 72, 4, text_size, be);
    }
    let sym_size = if wide { 24 } else { 16 };
    let strings = b"\0entry\0helper\0";
    b[0x500..0x500 + strings.len()].copy_from_slice(strings);
    let sections = b"\0.text\0.strtab\0.symtab\0.shstrtab\0";
    b[0x700..0x700 + sections.len()].copy_from_slice(sections);
    if arch == Architecture::X86_64 {
        b[0x400..0x400 + text_size as usize].fill(0x90);
    }
    for (i, &(offset, code)) in functions.iter().enumerate() {
        b[0x400 + offset..0x400 + offset + code.len()].copy_from_slice(code);
        let at = 0x600 + (i + 1) * sym_size;
        num(&mut b, at, 4, if i == 0 { 1 } else { 7 }, be);
        if wide {
            b[at + 4] = 0x12;
            num(&mut b, at + 6, 2, 1, be);
            num(&mut b, at + 8, 8, 0x401000 + offset as u64, be);
            num(&mut b, at + 16, 8, code.len() as u64, be);
        } else {
            num(&mut b, at + 4, 4, 0x401000 + offset as u64, be);
            num(&mut b, at + 8, 4, code.len() as u64, be);
            b[at + 12] = 0x12;
            num(&mut b, at + 14, 2, 1, be);
        }
    }
    for (i, (name, kind, flags, address, offset, size, link, info, align, entry)) in [
        (1, 1, 6, 0x401000, 0x400, text_size, 0, 0, 4, 0),
        (7, 3, 0, 0, 0x500, strings.len() as u64, 0, 0, 1, 0),
        (
            15,
            2,
            0,
            0,
            0x600,
            ((functions.len() + 1) * sym_size) as u64,
            2,
            1,
            if wide { 8 } else { 4 },
            sym_size as u64,
        ),
        (23, 3, 0, 0, 0x700, sections.len() as u64, 0, 0, 1, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x800 + (i + 1) * if wide { 64 } else { 40 };
        num(&mut b, at, 4, name, be);
        num(&mut b, at + 4, 4, kind, be);
        if wide {
            for (o, v) in [
                (8, flags),
                (16, address),
                (24, offset),
                (32, size),
                (48, align),
                (56, entry),
            ] {
                num(&mut b, at + o, 8, v, be);
            }
            num(&mut b, at + 40, 4, link, be);
            num(&mut b, at + 44, 4, info, be);
        } else {
            for (o, v) in [
                (8, flags),
                (12, address),
                (16, offset),
                (20, size),
                (24, link),
                (28, info),
                (32, align),
                (36, entry),
            ] {
                num(&mut b, at + o, 4, v, be);
            }
        }
    }
    b
}
fn words(words: &[u32], be: bool) -> Vec<u8> {
    words
        .iter()
        .flat_map(|n| if be { n.to_be_bytes() } else { n.to_le_bytes() })
        .collect()
}

pub fn tasks() -> Vec<Task> {
    let mut tasks: Vec<_> = seed::tasks()
        .into_iter()
        .enumerate()
        .map(|(i, t)| Task {
            id: t.id,
            question: t.question,
            fixture: "seed.exe",
            architecture: Architecture::X86_32,
            data: seed::binary(),
            text_offset: 0x200,
            function: t.function,
            selector: t.selector,
            answer: t
                .constant
                .map(Answer::Constant)
                .unwrap_or_else(|| Answer::Unknown(t.boundary.unwrap())),
            evidence_addresses: vec![
                [
                    0x401000, 0x401022, 0x401020, 0x40102e, 0x401040, 0x401044, 0x40104a, 0x401060,
                ][i],
            ],
        })
        .collect();
    let traversal = super::traversal::binary();
    for (id, question, function, site, answer, evidence) in [
        (
            "stack-spill",
            "Which store supplies the reloaded stack value?",
            0x401040,
            0x401050,
            Answer::Constant(73),
            vec![0x401043, 0x40104a],
        ),
        (
            "global-store",
            "Which constant-address store supplies the loaded value?",
            0x401060,
            0x40106f,
            Answer::Constant(73),
            vec![0x401060, 0x40106a],
        ),
        (
            "helper-return",
            "What value dependency crosses the helper call and return?",
            0x401000,
            0x40100a,
            Answer::Helper(22),
            vec![0x401000, 0x401002, 0x401020, 0x401024],
        ),
        (
            "recursive-boundary",
            "Can the recursively defined result be recovered within the bounded traversal?",
            0x401080,
            0x401085,
            Answer::Unknown("recursion_limit"),
            vec![0x401080],
        ),
    ] {
        tasks.push(Task {
            id,
            question,
            fixture: "traversal.exe",
            architecture: Architecture::X86_32,
            data: traversal.clone(),
            text_offset: 0x200,
            function,
            selector: Selector::Return(site),
            answer,
            evidence_addresses: evidence,
        });
    }
    let mut ambiguous = traversal;
    // sub esp,4; mov [esp],73; mov [ecx],eax; mov eax,[esp]; add esp,4; ret.
    // ECX may alias ESP: value must stay unknown.
    let code = b"\x83\xec\x04\xc7\x04\x24\x49\x00\x00\x00\x89\x01\x8b\x04\x24\x83\xc4\x04\xc3";
    ambiguous[0x240..0x240 + code.len()].copy_from_slice(code);
    tasks.push(Task {
        id: "ambiguous-store",
        question: "Does an unknown pointer write invalidate the stack value?",
        fixture: "ambiguous.exe",
        architecture: Architecture::X86_32,
        data: ambiguous,
        text_offset: 0x200,
        function: 0x401040,
        selector: Selector::Return(0x401052),
        answer: Answer::Unknown("ambiguous_alias"),
        evidence_addresses: vec![0x40104c],
    });
    // x86-64: movabs rax,0x401020; call rax; ret. helper: mov eax,9; ret.
    let dispatch = elf(
        Architecture::X86_64,
        &[
            (0, b"\x48\xb8\x20\x10\x40\x00\x00\x00\x00\x00\xff\xd0\xc3"),
            (0x20, b"\xb8\x09\x00\x00\x00\xc3"),
        ],
    );
    tasks.push(Task {
        id: "x64-dispatch",
        question: "Which helper does the constant function pointer dispatch to?",
        fixture: "dispatch.elf",
        architecture: Architecture::X86_64,
        data: dispatch,
        text_offset: 0x400,
        function: 0x401000,
        selector: Selector::Return(0x40100c),
        answer: Answer::Dispatch(0x401020),
        evidence_addresses: vec![0x40100a],
    });
    // AArch64: mov w2,17; add w2,w2,5; bl 0x401020; ret.
    let length = elf(
        Architecture::AArch64,
        &[
            (
                0,
                &words(&[0x52800222, 0x11001442, 0x94000006, 0xd65f03c0], false),
            ),
            (0x20, &words(&[0x52800120, 0xd65f03c0], false)),
        ],
    );
    tasks.push(Task {
        id: "aarch64-length",
        question: "What length reaches argument two after adding the five-byte header?",
        fixture: "length.elf",
        architecture: Architecture::AArch64,
        data: length,
        text_offset: 0x400,
        function: 0x401000,
        selector: Selector::Argument(0x401008, 2),
        answer: Answer::Constant(22),
        evidence_addresses: vec![0x401000, 0x401004],
    });
    // ARM mode: cmp r0,7; bne 0x401010; mov r0,1; bx lr; mov r0,2; bx lr.
    let comparison = elf(
        Architecture::ARM32,
        &[(
            0,
            &words(
                &[
                    0xe3500007, 0x1a000001, 0xe3a00001, 0xe12fff1e, 0xe3a00002, 0xe12fff1e,
                ],
                false,
            ),
        )],
    );
    tasks.push(Task {
        id: "arm-comparison",
        question: "Which constant is compared with the unknown input before branching?",
        fixture: "comparison.elf",
        architecture: Architecture::ARM32,
        data: comparison,
        text_offset: 0x400,
        function: 0x401000,
        selector: Selector::Condition(0x401004),
        answer: Answer::Comparison(7),
        evidence_addresses: vec![0x401000],
    });
    // Big-endian MIPS32: addiu v0,zero,42; jr ra; nop (delay slot).
    let mips = elf(
        Architecture::MIPS32,
        &[(0, &words(&[0x2402002a, 0x03e00008, 0], true))],
    );
    tasks.push(Task {
        id: "mips-return",
        question: "What constant is placed in v0 before returning?",
        fixture: "return-mips.elf",
        architecture: Architecture::MIPS32,
        data: mips,
        text_offset: 0x400,
        function: 0x401000,
        selector: Selector::Return(0x401004),
        answer: Answer::Constant(42),
        evidence_addresses: vec![0x401000],
    });
    // RISC-V64: addi a0,zero,29; jalr zero,0(ra).
    let riscv = elf(
        Architecture::RiscV64,
        &[(0, &words(&[0x01d00513, 0x00008067], false))],
    );
    tasks.push(Task {
        id: "riscv-return",
        question: "What constant reaches the a0 return register?",
        fixture: "return-riscv.elf",
        architecture: Architecture::RiscV64,
        data: riscv,
        text_offset: 0x400,
        function: 0x401000,
        selector: Selector::Return(0x401004),
        answer: Answer::Constant(29),
        evidence_addresses: vec![0x401000],
    });
    tasks
}
