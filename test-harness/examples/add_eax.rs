use rsleigh_api::{Architecture, Decoder};
fn main() {
    let mut dec = Decoder::new(Architecture::X86_64);
    // ADD EAX, [RDI+RDX*4] = 03 04 97
    let bytes = vec![0x03, 0x04, 0x97];
    match dec.decode(&bytes, 0x1000) {
        Ok(inst) => {
            println!("=== {} ===", inst.disassembly);
            for (i, op) in inst.ops.iter().enumerate() {
                // Only show ops that write to Register space
                if let Some(out) = pcode_ir::get_output(&op) {
                    if out.space == pcode_ir::AddressSpaceId::Register && out.offset < 200 {
                        println!("  [{i}] {:?}", op);
                    }
                }
            }
        }
        Err(e) => println!("Error: {:?}", e),
    }
}
