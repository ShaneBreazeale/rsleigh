use rsleigh_api::{Architecture, Decoder};

fn main() {
    let mut dec = Decoder::new(Architecture::AArch64);

    let tests: Vec<(&str, Vec<u8>)> = vec![
        // CMP w0, w1 = 6b01001f
        ("CMP w0, w1", vec![0x1f, 0x00, 0x01, 0x6b]),
        // CSETM w8, lt = 5a9fa3e8 (CSINV w8, wzr, wzr, ge)
        ("CSETM w8, lt", vec![0xe8, 0xa3, 0x9f, 0x5a]),
        // CSINC w0, w8, wzr, le = 1a9fd500
        ("CSINC w0, w8, wzr, le", vec![0x00, 0xd5, 0x9f, 0x1a]),
        // CSEL w8, w0, w2, lt = 1a82b008
        ("CSEL w8, w0, w2, lt", vec![0x08, 0xb0, 0x82, 0x1a]),
        // CMP w0, #0 = 7100001f
        ("CMP w0, #0", vec![0x1f, 0x00, 0x00, 0x71]),
        // CNEG w0, w0, mi = 5a8044e0 (actually CSNEG)
        ("CNEG w0, w0, mi", vec![0x00, 0x44, 0x80, 0x5a]),
    ];

    for (label, bytes) in &tests {
        match dec.decode(bytes, 0x1000) {
            Ok(inst) => {
                println!("=== {} ===", label);
                println!("Disasm: {}", inst.disassembly);
                println!("Ops ({}):", inst.ops.len());
                for (i, op) in inst.ops.iter().enumerate() {
                    println!("  [{i}] {:?}", op);
                }
                println!();
            }
            Err(e) => println!("{}: Error: {e:?}\n", label),
        }
    }
}
