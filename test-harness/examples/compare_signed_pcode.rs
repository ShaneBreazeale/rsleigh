use rsleigh_api::{Architecture, Decoder};
fn main() {
    let mut dec = Decoder::new(Architecture::AArch64);
    // cmp w0, w1 | csetm w8, lt | csinc w0, w8, wzr, le | ret
    let bytes: Vec<u8> = vec![
        0x1f, 0x00, 0x01, 0x6b, // cmp w0, w1
        0xe8, 0xa3, 0x9f, 0x5a, // csetm w8, lt
        0x00, 0xd5, 0x9f, 0x1a, // csinc w0, w8, wzr, le
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    for i in (0..bytes.len()).step_by(4) {
        let chunk = &bytes[i..i + 4];
        match dec.decode(chunk, 0x1000 + i as u64) {
            Ok(inst) => {
                println!(
                    "=== 0x{:x}: {} ({} ops) ===",
                    0x1000 + i,
                    inst.disassembly,
                    inst.ops.len()
                );
                for (j, op) in inst.ops.iter().enumerate() {
                    println!("  [{j}] {:?}", op);
                }
            }
            Err(e) => println!("Error: {:?}", e),
        }
    }
}
