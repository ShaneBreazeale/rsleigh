use rsleigh_api::{Decoder, Architecture};
fn main() {
    let mut dec = Decoder::new(Architecture::X86_64);
    // XOR EDX, EDX = 31 D2
    let bytes = vec![0x31, 0xD2];
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
    // INC RDX = 48 FF C2
    let bytes2 = vec![0x48, 0xFF, 0xC2];
    match dec.decode(&bytes2, 0x1002) {
        Ok(inst) => {
            println!("=== {} ({} ops) ===", inst.disassembly, inst.ops.len());
            for (i, op) in inst.ops.iter().enumerate() {
                println!("  [{i}] {:?}", op);
            }
        }
        Err(e) => println!("Error: {:?}", e),
    }
}
