//! Regression tests for decode and lift bugs reported against the public
//! `Decoder` API. Each test names the GitHub issue it covers.

use rsleigh_api::{Architecture, DecodeError, Decoder};

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
