use rsleigh_api::{Decoder, Architecture};

fn main() {
    let t = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let mut dec = Decoder::new(Architecture::X86_64);
            // MOV RAX, [RBP-0x10] = 48 8B 45 F0
            // MOVSXD RCX, [RBP-0x24] = 48 63 4D DC
            // MOV EAX, [RAX+RCX*4] = 8B 04 88
            // CMP EAX, [RBP-0x18] = 3B 45 E8
            let bytes: &[u8] = &[
                0x48, 0x8B, 0x45, 0xF0,   // MOV RAX, [RBP-0x10]
                0x48, 0x63, 0x4D, 0xDC,   // MOVSXD RCX, [RBP-0x24]
                0x8B, 0x04, 0x88,          // MOV EAX, [RAX+RCX*4]
                0x3B, 0x45, 0xE8,          // CMP EAX, [RBP-0x18]
            ];
            let mut offset = 0usize;
            let base = 0x4f7u64;
            while offset < bytes.len() {
                match dec.decode(&bytes[offset..], base + offset as u64) {
                    Ok(inst) => {
                        println!("--- {} (len={}) ---", inst.disassembly, inst.len);
                        for (i, op) in inst.ops.iter().enumerate() {
                            println!("  [{i}] {:?}", op);
                        }
                        offset += inst.len as usize;
                    }
                    Err(_) => { println!("decode error at offset {}", offset); break; }
                }
            }
        })
        .unwrap();
    t.join().unwrap();
}
