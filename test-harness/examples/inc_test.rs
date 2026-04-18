use rsleigh_api::{Decoder, Architecture};
fn main() {
    let mut dec = Decoder::new(Architecture::X86_64);
    // INC EAX = FF C0
    let bytes = vec![0xFF, 0xC0];
    match dec.decode(&bytes, 0x1000) {
        Ok(inst) => {
            println!("=== {} ===", inst.disassembly);
            for (i, op) in inst.ops.iter().enumerate() {
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
