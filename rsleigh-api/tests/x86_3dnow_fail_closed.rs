use rsleigh_api::{Architecture, DecodeError, Decoder};

const THREE_D_NOW_REGISTER_FORM: &[u8] = &[0x0f, 0x0f, 0xc0, 0x0c];

#[test]
fn x86_64_3dnow_escape_fails_closed() {
    let mut decoder = Decoder::new(Architecture::X86_64);

    assert!(matches!(
        decoder.decode(THREE_D_NOW_REGISTER_FORM, 0x1000),
        Err(DecodeError::UnknownInstruction)
    ));
}

#[test]
fn x86_32_3dnow_escape_fails_closed() {
    let mut decoder = Decoder::new(Architecture::X86_32);

    assert!(matches!(
        decoder.decode(THREE_D_NOW_REGISTER_FORM, 0x1000),
        Err(DecodeError::UnknownInstruction)
    ));
}

#[test]
fn ordinary_x86_64_decode_is_unchanged() {
    std::thread::Builder::new()
        .name("x86-64-legacy-mov-control".into())
        .stack_size(256 * 1024 * 1024)
        .spawn(|| {
            let mut decoder = Decoder::new(Architecture::X86_64);

            let instruction = decoder
                .decode(&[0x48, 0x89, 0xd8], 0x1000)
                .expect("MOV RAX,RBX should still decode");
            assert_eq!(instruction.len, 3);
            assert!(instruction.disassembly.contains("MOV"));
        })
        .expect("legacy MOV control thread should spawn")
        .join()
        .expect("legacy MOV control thread should complete without panic");
}
