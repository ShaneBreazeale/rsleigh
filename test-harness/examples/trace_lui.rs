fn main() {
    let t = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::MIPS32);
            // lui gp, 0x43 = 0x3C1C0043
            let inst = dec.decode(&[0x3C, 0x1C, 0x00, 0x43], 0x1000).unwrap();
            println!("lui gp, 0x43: {}", inst.disassembly);
            for (i, op) in inst.ops.iter().enumerate() {
                println!("  [{i}] {:?}", op);
            }
            // addiu gp, gp, 0x2480 = 0x279C2480
            let inst2 = dec.decode(&[0x27, 0x9C, 0x24, 0x80], 0x1004).unwrap();
            println!("\naddiu gp, gp, 0x2480: {}", inst2.disassembly);
            for (i, op) in inst2.ops.iter().enumerate() {
                println!("  [{i}] {:?}", op);
            }
        })
        .unwrap();
    t.join().unwrap();
}
