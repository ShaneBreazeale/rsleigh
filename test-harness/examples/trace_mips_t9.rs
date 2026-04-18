fn main() {
    let t = std::thread::Builder::new().stack_size(32*1024*1024).spawn(|| {
        let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::MIPS32);
        // jalr t9 = 0x0320F809
        let inst = dec.decode(&[0x03, 0x20, 0xf8, 0x09], 0x1000).unwrap();
        println!("jalr t9: {}", inst.disassembly);
        for (i, op) in inst.ops.iter().enumerate() {
            println!("  [{i}] {:?}", op);
        }
        // lw t9, -0x7fcc(gp)
        let inst2 = dec.decode(&[0x8f, 0x99, 0x80, 0x34], 0x1004).unwrap();
        println!("\nlw t9, -0x7fcc(gp): {}", inst2.disassembly);
        for (i, op) in inst2.ops.iter().enumerate() {
            println!("  [{i}] {:?}", op);
        }
    }).unwrap();
    t.join().unwrap();
}
