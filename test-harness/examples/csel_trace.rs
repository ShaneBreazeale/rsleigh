use rsleigh_api::{Decoder, Architecture};
fn main() {
    let mut dec = Decoder::new(Architecture::AArch64);
    
    // Test cases with different Rd/Rn/Rm combinations
    let tests: Vec<(&str, Vec<u8>)> = vec![
        // CSEL w0, w1, w2, lt (Rd=w0, Rn=w1, Rm=w2 — all different)
        ("CSEL w0, w1, w2, lt", vec![0x20, 0xb0, 0x82, 0x1a]),
        // CSEL w0, w0, w2, lt (Rd=Rn=w0, Rm=w2 — then-val is same as dest)
        ("CSEL w0, w0, w2, lt", vec![0x00, 0xb0, 0x82, 0x1a]),
        // CSEL x0, x1, x2, eq (64-bit version)
        ("CSEL x0, x1, x2, eq", vec![0x20, 0x00, 0x82, 0x9a]),
        // CSINV (CSETM uses this): csetm w8, lt = csinv w8, wzr, wzr, ge
        ("CSETM w8, lt", vec![0xe8, 0xa3, 0x9f, 0x5a]),
        // CNEG w0, w0, mi = csneg w0, w0, w0, pl
        ("CNEG w0, w0, mi", vec![0x00, 0x44, 0x80, 0x5a]),
    ];

    for (label, bytes) in &tests {
        match dec.decode(bytes, 0x1000) {
            Ok(inst) => {
                println!("=== {} ({} ops) ===", label, inst.ops.len());
                println!("Disasm: {}", inst.disassembly);
                for (i, op) in inst.ops.iter().enumerate() {
                    println!("  [{i}] {:?}", op);
                }
                // Check: does any op copy Rn to something?
                println!();
            }
            Err(e) => println!("{}: Error: {:?}\n", label, e),
        }
    }
}
