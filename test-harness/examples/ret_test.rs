use rsleigh_api::{Architecture, Decoder};
fn main() {
    let mut dec = Decoder::new(Architecture::X86_64);
    // RET = C3
    let bytes = vec![0xC3];
    match dec.decode(&bytes, 0x1000) {
        Ok(inst) => {
            println!("=== {} ===", inst.disassembly);
            for (i, op) in inst.ops.iter().enumerate() {
                println!("  [{i}] {:?}", op);
            }
        }
        Err(e) => println!("Error: {:?}", e),
    }
}
