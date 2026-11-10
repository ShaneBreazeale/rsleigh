//! Regression tests for decode and lift bugs reported against the public
//! `Decoder` API. Each test names the GitHub issue it covers.

use rsleigh_api::{AddressSpaceId, Architecture, DecodeError, Decoder, PcodeOp, Varnode};

/// The generated matchers recurse through prefix constructors; give them the
/// same headroom the in-crate decoder tests use.
fn with_decoder_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .expect("spawn decoder test")
        .join()
        .expect("decoder test panicked");
}

const AMD_3DNOW_OPS: [u8; 24] = [
    0x0c, 0x0d, 0x1c, 0x1d, 0x8a, 0x8e, 0x90, 0x94, 0x96, 0x97, 0x9a, 0x9e, 0xa0, 0xa4, 0xa6, 0xa7,
    0xaa, 0xae, 0xb0, 0xb4, 0xb6, 0xb7, 0xbb, 0xbf,
];

/// #26: `0F 0F /r ib` with a suffix byte naming no 3DNow! operation used to
/// recurse until the stack overflowed, because the `instrPhase` context bit
/// was packed onto the last bit of `suffix3D`.
#[test]
fn issue_26_unknown_3dnow_suffix_is_an_error_not_a_stack_overflow() {
    with_decoder_stack(|| {
        for arch in [Architecture::X86_64, Architecture::X86_32] {
            let mut decoder = Decoder::new(arch);
            for modrm in [0xc0u8, 0x08] {
                for suffix in 0..=u8::MAX {
                    let result = decoder.decode(&[0x0f, 0x0f, modrm, suffix], 0x1000);
                    if AMD_3DNOW_OPS.contains(&suffix) {
                        let inst = result.unwrap_or_else(|e| {
                            panic!("{arch:?} 0f 0f {modrm:02x} {suffix:02x}: {e:?}")
                        });
                        assert_eq!(inst.len, 4, "{arch:?} {}", inst.disassembly);
                    } else {
                        assert!(
                            matches!(result, Err(DecodeError::UnknownInstruction)),
                            "{arch:?} 0f 0f {modrm:02x} {suffix:02x}: {result:?}"
                        );
                    }
                }
            }

            let pi2fd = decoder.decode(&[0x0f, 0x0f, 0xc0, 0x0d], 0x1000).unwrap();
            assert_eq!(pi2fd.disassembly, "PI2FD MM0, MM0");

            // Cut short before the suffix byte.
            assert!(decoder.decode(&[0xf0, 0x0f, 0x0f], 0x1000).is_err());
            assert!(decoder.decode(&[0x0f, 0x0f, 0xc0], 0x1000).is_err());

            // Behind any prefix the decoder must return, known op or not.
            for prefix in [
                0x66u8, 0xf0, 0xf2, 0xf3, 0x67, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65,
            ] {
                for suffix in [0x90u8, 0x28] {
                    let _ = decoder.decode(&[prefix, 0x0f, 0x0f, 0xc0, suffix], 0x1000);
                }
            }
            let segment = decoder
                .decode(&[0x2e, 0x0f, 0x0f, 0xc0, 0x90], 0x1000)
                .expect("pfcmpge behind a segment prefix");
            assert_eq!(segment.disassembly, "PFCMPGE MM0, MM0");
        }
    });
}

/// The single RAM load an indirect jump or call makes, and the varnode it
/// then branches to.
fn indirect_target(ops: &[PcodeOp]) -> (Varnode, Varnode, Varnode) {
    let loads: Vec<_> = ops
        .iter()
        .filter_map(|op| match op {
            PcodeOp::Load {
                out,
                space: AddressSpaceId::Ram,
                ptr,
            } => Some((*out, *ptr)),
            _ => None,
        })
        .collect();
    let [(loaded, ptr)] = loads.as_slice() else {
        panic!("expected one RAM load: {ops:?}");
    };
    let mut dest = ops
        .iter()
        .find_map(|op| match op {
            PcodeOp::BranchInd { dest } | PcodeOp::CallInd { dest } => Some(*dest),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no indirect branch: {ops:?}"));
    // `call [dest]` copies the loaded value into a local first.
    while let Some(input) = ops.iter().find_map(|op| match op {
        PcodeOp::Copy { out, input } if *out == dest => Some(*input),
        _ => None,
    }) {
        dest = input;
    }
    (*loaded, *ptr, dest)
}

/// #24: `jmp [reg + disp]` must load its target, as `call [reg + disp]`
/// does, prefixed or not; the jump used to branch to a RAM varnode at the
/// address temporary's offset.
#[test]
fn issue_24_jump_through_computed_operand_loads_its_target() {
    with_decoder_stack(|| {
        for (arch, bytes) in [
            (Architecture::X86_32, &[0xffu8, 0x63, 0x0c][..]), // jmp [ebx+0xc]
            (Architecture::X86_32, &[0xff, 0x53, 0x0c][..]),   // call [ebx+0xc]
            (Architecture::X86_32, &[0x3e, 0xff, 0x63, 0x0c][..]), // ds jmp [ebx+0xc]
            (
                Architecture::X86_32,
                &[0xff, 0x24, 0x85, 0x00, 0x10, 0x40, 0x00][..],
            ), // jmp [eax*4+0x401000]
            (Architecture::X86_64, &[0xff, 0x60, 0x08][..]),   // jmp [rax+0x8]
            (Architecture::X86_64, &[0xff, 0x50, 0x08][..]),   // call [rax+0x8]
            (Architecture::X86_64, &[0x48, 0xff, 0x60, 0x08][..]), // rex.W jmp [rax+0x8]
            (Architecture::X86_64, &[0x41, 0xff, 0x60, 0x08][..]), // jmp [r8+0x8]
            (Architecture::X86_64, &[0x3e, 0xff, 0x60, 0x08][..]), // notrack jmp [rax+0x8]
            (
                Architecture::X86_64,
                &[0x48, 0xff, 0x24, 0xc5, 0, 0x10, 0x40, 0][..],
            ), // jmp [rax*8+0x401000]
        ] {
            let inst = Decoder::new(arch)
                .decode_unoptimized(bytes, 0x1000)
                .unwrap();
            let (loaded, ptr, dest) = indirect_target(&inst.ops);
            assert_eq!(
                dest, loaded,
                "{arch:?} {}: {:?}",
                inst.disassembly, inst.ops
            );
            // The address is computed by this instruction; the load reads it.
            assert!(
                inst.ops
                    .iter()
                    .any(|op| format!("{op:?}").contains(&format!("out: {ptr:?}"))),
                "{arch:?} {}: load address never written: {:?}",
                inst.disassembly,
                inst.ops
            );

            // The optimiser must keep the address computation alive.
            let optimized = Decoder::new(arch).decode(bytes, 0x1000).unwrap();
            let (loaded, _, dest) = indirect_target(&optimized.ops);
            assert_eq!(dest, loaded, "{arch:?} {}", optimized.disassembly);
        }
    });
}

/// #25: `jmp [rax]` / `jmp [rsp]` must load the target from the cell the
/// register points at, as `call [rax]` does.
#[test]
fn issue_25_jump_through_register_cell_loads_its_target() {
    with_decoder_stack(|| {
        for (arch, bytes, reg) in [
            (Architecture::X86_64, &[0xffu8, 0x20][..], 0x00), // jmp [rax]
            (Architecture::X86_64, &[0xff, 0x10][..], 0x00),   // call [rax]
            (Architecture::X86_64, &[0xff, 0x24, 0x24][..], 0x20), // jmp [rsp]
            (Architecture::X86_64, &[0x48, 0xff, 0x20][..], 0x00), // rex.W jmp [rax]
            (Architecture::X86_32, &[0xff, 0x20][..], 0x00),   // jmp [eax]
            (Architecture::X86_32, &[0xff, 0x24, 0x24][..], 0x10), // jmp [esp]
        ] {
            let inst = Decoder::new(arch).decode(bytes, 0x1000).unwrap();
            let (loaded, ptr, dest) = indirect_target(&inst.ops);
            assert_eq!(
                dest, loaded,
                "{arch:?} {}: {:?}",
                inst.disassembly, inst.ops
            );
            assert_eq!(
                (ptr.space, ptr.offset),
                (AddressSpaceId::Register, reg),
                "{arch:?} {}: {:?}",
                inst.disassembly,
                inst.ops
            );
        }
    });
}

fn thumb_decoder() -> Decoder {
    let mut decoder = Decoder::new(Architecture::ARM32);
    decoder.set_arm_thumb(true);
    decoder
}

/// #21: MOVW (T3) / MOVT (T1) build `imm16 = imm4:i:imm3:imm8` from both
/// halfwords. The parse-time value used to read `imm4` from the second
/// halfword, so the p-code moved a different constant than it displayed.
#[test]
fn issue_21_thumb2_movw_movt_immediate() {
    with_decoder_stack(|| {
        let mut decoder = thumb_decoder();
        for (bytes, addr, imm) in [
            ([0x40u8, 0xf2, 0x28, 0x70], 0x0800_01a0u64, 0x728u64), // movw r0,#0x728
            ([0x45, 0xf2, 0x00, 0x40], 0x0800_057c, 0x5400),        // movw r0,#0x5400
            ([0xc4, 0xf2, 0x00, 0x00], 0x0800_0580, 0x4000),        // movt r0,#0x4000
            ([0x4f, 0xf6, 0xff, 0x71], 0x0800_0000, 0xffff),        // movw r1,#0xffff
        ] {
            let inst = decoder.decode_unoptimized(&bytes, addr).unwrap();
            let consts: Vec<u64> = inst
                .ops
                .iter()
                .filter_map(|op| match op {
                    PcodeOp::Subpiece { input, .. } | PcodeOp::Copy { input, .. }
                        if input.space == AddressSpaceId::Const =>
                    {
                        Some(input.offset)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                consts.first(),
                Some(&imm),
                "{}: {:?}",
                inst.disassembly,
                inst.ops
            );
            assert!(
                inst.disassembly.contains(&format!("{imm:#x}")),
                "{}",
                inst.disassembly
            );
        }
    });
}

/// #22: BL (T1) and B.W (T4) targets come from `S:I1:I2:imm10:imm11`, the
/// first two from the first halfword. The p-code read them from the second.
#[test]
fn issue_22_thumb2_bl_and_wide_branch_targets() {
    with_decoder_stack(|| {
        let mut decoder = thumb_decoder();
        for (bytes, addr, target) in [
            ([0x00u8, 0xf0, 0x08, 0xf8], 0x0800_01dcu64, 0x0800_01f0u64), // bl 0x80001f0
            ([0xff, 0xf7, 0x62, 0xbf], 0x0800_04fe, 0x0800_03c6),         // b.w 0x80003c6
            ([0xff, 0xf7, 0xfe, 0xff], 0x0800_1000, 0x0800_1000),         // bl . (self)
            ([0x00, 0xf4, 0x00, 0xd0], 0x0800_0000, 0x0700_0004),         // bl, S=1, J1=J2=0
        ] {
            let inst = decoder.decode_unoptimized(&bytes, addr).unwrap();
            let dest = inst
                .ops
                .iter()
                .find_map(|op| match op {
                    PcodeOp::Call { dest } | PcodeOp::Branch { dest }
                        if dest.space == AddressSpaceId::Ram =>
                    {
                        Some(dest.offset)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{}: {:?}", inst.disassembly, inst.ops));
            assert_eq!(dest, target, "{}: {:?}", inst.disassembly, inst.ops);
            assert!(
                inst.disassembly.contains(&format!("{target:#x}")),
                "{}",
                inst.disassembly
            );
        }
    });
}

fn has_cbranch(ops: &[PcodeOp]) -> bool {
    ops.iter().any(|op| matches!(op, PcodeOp::CBranch { .. }))
}

/// #23: IT hands its condition to the instructions it governs through
/// `globalset(inst_next, condit)`. That state used to be dropped between
/// decodes, so `it pl; bx lr` lifted `bx lr` as an unconditional return.
#[test]
fn issue_23_thumb_it_block_lifts_governed_instructions_as_conditional() {
    with_decoder_stack(|| {
        let mut decoder = thumb_decoder();
        let it = decoder
            .decode_unoptimized(&[0x58, 0xbf], 0x0800_04f6)
            .unwrap(); // it pl
        assert_eq!(it.len, 2, "{}", it.disassembly);
        let bx = decoder
            .decode_unoptimized(&[0x70, 0x47], 0x0800_04f8)
            .unwrap(); // bx lr
        assert!(has_cbranch(&bx.ops), "{}: {:?}", bx.disassembly, bx.ops);
        assert!(bx.disassembly.contains("pl"), "{}", bx.disassembly);
        // Decoding the same bytes again gives the same answer.
        let again = decoder
            .decode_unoptimized(&[0x70, 0x47], 0x0800_04f8)
            .unwrap();
        assert_eq!(again.disassembly, bx.disassembly);
        // Re-asserting the mode the decoder is already in keeps the state.
        decoder.set_arm_thumb(true);
        let kept = decoder.decode(&[0x70, 0x47], 0x0800_04f8).unwrap();
        assert!(
            has_cbranch(&kept.ops),
            "{}: {:?}",
            kept.disassembly,
            kept.ops
        );

        // Outside an IT block the same instruction is unconditional.
        let plain = thumb_decoder()
            .decode_unoptimized(&[0x70, 0x47], 0x0800_04f8)
            .unwrap();
        assert!(
            !has_cbranch(&plain.ops),
            "{}: {:?}",
            plain.disassembly,
            plain.ops
        );

        // ite eq; mov r0,#1 (eq); mov r0,#0 (ne); bx lr (after the block).
        let mut decoder = thumb_decoder();
        let base = 0x0800_1000u64;
        let code: [[u8; 2]; 4] = [[0x0c, 0xbf], [0x01, 0x20], [0x00, 0x20], [0x70, 0x47]];
        let insts: Vec<_> = code
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                decoder
                    .decode_unoptimized(bytes, base + 2 * i as u64)
                    .unwrap()
            })
            .collect();
        assert!(has_cbranch(&insts[1].ops), "{}", insts[1].disassembly);
        assert!(
            insts[1].disassembly.contains("eq"),
            "{}",
            insts[1].disassembly
        );
        assert!(has_cbranch(&insts[2].ops), "{}", insts[2].disassembly);
        assert!(
            insts[2].disassembly.contains("ne"),
            "{}",
            insts[2].disassembly
        );
        assert!(
            !has_cbranch(&insts[3].ops),
            "{}: {:?}",
            insts[3].disassembly,
            insts[3].ops
        );
    });
}
