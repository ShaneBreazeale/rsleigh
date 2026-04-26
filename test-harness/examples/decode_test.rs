fn main() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_64);
            // movslq (%rcx,%rax,4), %rax — the jump table load
            // 48 63 04 81
            let movsxd = [0x48u8, 0x63, 0x04, 0x81];
            if let Ok(inst) = dec.decode(&movsxd, 0x4d2) {
                println!("MOVSXD: {} (len={})", inst.disassembly, inst.len);
                for (i, op) in inst.ops.iter().enumerate() {
                    println!("  [{i}] {op:?}");
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
