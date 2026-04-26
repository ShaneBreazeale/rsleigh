use rsleigh_api::{Architecture, Decoder};

fn main() {
    let t = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let mut dec = Decoder::new(Architecture::X86_64);
            // MOV ECX, 2; CDQ; IDIV ECX
            let bytes: &[u8] = &[
                0xb9, 0x02, 0x00, 0x00, 0x00, // MOV ECX, 0x2
                0x99, // CDQ
                0xf7, 0xf9, // IDIV ECX
            ];
            let mut offset = 0usize;
            let base = 0x1000u64;
            while offset < bytes.len() {
                match dec.decode(&bytes[offset..], base + offset as u64) {
                    Ok(inst) => {
                        println!("--- {} (len={}) ---", inst.disassembly, inst.len);
                        for (i, op) in inst.ops.iter().enumerate() {
                            println!("  [{i}] {:?}", op);
                        }
                        offset += inst.len as usize;
                    }
                    Err(_) => {
                        println!("decode error at offset {}", offset);
                        break;
                    }
                }
            }
        })
        .unwrap();
    t.join().unwrap();
}
