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
