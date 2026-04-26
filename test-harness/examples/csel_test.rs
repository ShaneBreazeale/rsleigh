use rsleigh_api::{Architecture, Decoder};
fn main() {
    let mut dec = Decoder::new(Architecture::AArch64);
    // Full compare_signed function:
    // cmp w0, w1   (6b01001f)
    // csetm w8, lt (5a9fa3e8)
    // csinc w0, w8, wzr, le (1a9fd500)
    // ret          (d65f03c0)
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
                println!("=== 0x{:x}: {} ===", 0x1000 + i, inst.disassembly);
                for (j, op) in inst.ops.iter().enumerate() {
                    println!("  [{j}] {:?}", op);
                }
            }
            Err(e) => println!("0x{:x}: Error: {:?}", 0x1000 + i, e),
        }
    }
}
