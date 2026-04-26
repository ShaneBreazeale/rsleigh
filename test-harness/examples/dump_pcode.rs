use rsleigh_api::{Architecture, Decoder};

fn main() {
    let mut dec = Decoder::new(Architecture::X86_64);

    let tests: Vec<(&str, Vec<u8>)> = vec![
        ("SUBSS XMM1, XMM0", vec![0xF3, 0x0F, 0x5C, 0xC8]),
        ("MULSS XMM1, XMM2", vec![0xF3, 0x0F, 0x59, 0xCA]),
        ("ADDSD XMM0, XMM1", vec![0xF2, 0x0F, 0x58, 0xC1]),
        (
            "MOVSD XMM1, [RDI+RCX*8]",
            vec![0xF2, 0x0F, 0x10, 0x0C, 0xCF],
        ),
        (
            "MULSD XMM1, [RSI+RCX*8]",
            vec![0xF2, 0x0F, 0x59, 0x0C, 0xCE],
        ),
        ("XORPD XMM0, XMM0", vec![0x66, 0x0F, 0x57, 0xC0]),
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
