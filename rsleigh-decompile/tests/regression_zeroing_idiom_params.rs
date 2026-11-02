//! `xorps xmm0, xmm0` (and `pxor`) zero a register; reading it is not using
//! an argument. The XMM0 entry value was named `fparam_0` and the function
//! got a spurious `float` parameter, which the printer then also returned:
//! `long func_18006a500(long param_0, long param_1, float fparam_0)` in
//! CrashLoggerSSE (morluto/rea discussion 3858).

use rsleigh_api::{Architecture, Decoder};

fn decompile(bytes: &[u8]) -> String {
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let address = 0x1000 + offset as u64;
        let inst = decoder.decode(&bytes[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    rsleigh_decompile::decompile(Architecture::X86_64, &instructions)
}

fn signature(output: &str) -> &str {
    rsleigh_decompile::signature_line(output).unwrap_or("")
}

#[test]
fn zeroing_idiom_is_not_a_float_parameter() {
    // xorps xmm0, xmm0 ; movups [rdi], xmm0 ; ret
    let output = decompile(&[0x0f, 0x57, 0xc0, 0x0f, 0x11, 0x07, 0xc3]);
    assert!(!signature(&output).contains("fparam"), "\n{output}");
    assert!(!output.contains("return fparam"), "\n{output}");
}

#[test]
fn real_float_parameters_are_kept() {
    // addss xmm0, xmm1 ; ret
    let output = decompile(&[0xf3, 0x0f, 0x58, 0xc1, 0xc3]);
    let sig = signature(&output);
    assert!(
        sig.contains("fparam_0") && sig.contains("fparam_1"),
        "\n{output}"
    );
}
