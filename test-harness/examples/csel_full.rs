use rsleigh_api::{Architecture, Decoder};
fn main() {
    let mut dec = Decoder::new(Architecture::AArch64);
    // CSEL w0, w1, w2, lt = 1a82b020
    let bytes = vec![0x20, 0xb0, 0x82, 0x1a];
    match dec.decode(&bytes, 0x1000) {
        Ok(inst) => {
            println!("=== {} ({} ops) ===", inst.disassembly, inst.ops.len());
            for (i, op) in inst.ops.iter().enumerate() {
                println!("  [{i}] {:?}", op);
            }
        }
        Err(e) => println!("Error: {:?}", e),
    }
    println!();
    // CSEL w0, w0, w2, lt = 1a82b000
    let bytes2 = vec![0x00, 0xb0, 0x82, 0x1a];
    match dec.decode(&bytes2, 0x1000) {
        Ok(inst) => {
            println!("=== {} ({} ops) ===", inst.disassembly, inst.ops.len());
            for (i, op) in inst.ops.iter().enumerate() {
                println!("  [{i}] {:?}", op);
            }
        }
        Err(e) => println!("Error: {:?}", e),
    }
}
