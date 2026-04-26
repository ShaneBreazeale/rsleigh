use rsleigh_api::{Architecture, Decoder};
fn main() {
    let mut dec = Decoder::new(Architecture::X86_64);
    // sum_array O1: TEST ESI,ESI; JLE; MOV ECX,ESI; XOR EDX,EDX; XOR EAX,EAX; NOP;
    //   ADD EAX,[RDI+RDX*4]; INC RDX; CMP RCX,RDX; JNZ loop; POP RBP; RET; XOR EAX,EAX; POP RBP; RET
    let bytes: Vec<u8> = vec![
        0x55, // PUSH RBP
        0x48, 0x89, 0xe5, // MOV RBP, RSP
        0x85, 0xf6, // TEST ESI, ESI
        0x7e, 0x15, // JLE +0x15 (to xor eax; pop; ret)
        0x89, 0xf1, // MOV ECX, ESI
        0x31, 0xd2, // XOR EDX, EDX
        0x31, 0xc0, // XOR EAX, EAX
        0x90, // NOP
        // loop:
        0x03, 0x04, 0x97, // ADD EAX, [RDI+RDX*4]
        0x48, 0xff, 0xc2, // INC RDX
        0x48, 0x39, 0xd1, // CMP RCX, RDX
        0x75, 0xf4, // JNZ loop (-12)
        0x5d, // POP RBP
        0xc3, // RET
        0x31, 0xc0, // XOR EAX, EAX
        0x5d, // POP RBP
        0xc3, // RET
    ];

    // Decode instructions
    let mut instructions = Vec::new();
    let base = 0x1000u64;
    let mut offset = 0;
    while offset < bytes.len() {
        match dec.decode(&bytes[offset..], base + offset as u64) {
            Ok(inst) => {
                let len = inst.len as usize;
                instructions.push((base + offset as u64, inst));
                offset += len;
            }
            Err(_) => {
                offset += 1;
            }
        }
    }

    println!("Decoded {} instructions:", instructions.len());
    for (addr, inst) in &instructions {
        println!(
            "  0x{:x}: {} ({} ops)",
            addr,
            inst.disassembly,
            inst.ops.len()
        );
    }
}
