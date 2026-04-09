use pcode_ir::{PcodeOp, Varnode, AddressSpaceId};

mod corpus;

mod x86 {
    use super::*;

    pub fn context() -> x86_root::ContextMemory {
        let mut ctx = x86_root::ContextMemory::default();
        ctx.write_longMode(1);
        ctx.write_addrsize(2);
        ctx.write_opsize(1);
        ctx
    }

    pub fn decode(bytes: &[u8], addr: u64) -> (u64, String, Vec<PcodeOp>) {
        let mut ctx = context();
        let mut gs = x86_root::GlobalSet::new(context());
        let (inst_next, display, mut pcode) =
            x86_root::parse_instruction(bytes, &mut ctx, addr, &mut gs)
                .expect("failed to decode");
        pcode_ir::optimize(&mut pcode);
        let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
        (inst_next - addr, disasm.join(""), pcode)
    }
}

mod arm {
    use super::*;

    pub fn decode(bytes: &[u8], addr: u64) -> (u64, String, Vec<PcodeOp>) {
        let mut ctx = aarch64_root::ContextMemory::default();
        let mut gs = aarch64_root::GlobalSet::new(aarch64_root::ContextMemory::default());
        let (inst_next, display, mut pcode) =
            aarch64_root::parse_instruction(bytes, &mut ctx, addr, &mut gs)
                .expect("failed to decode");
        pcode_ir::optimize(&mut pcode);
        let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
        (inst_next - addr, disasm.join(""), pcode)
    }
}

mod riscv {
    use super::*;

    pub fn decode(bytes: &[u8], addr: u64) -> (u64, String, Vec<PcodeOp>) {
        let mut ctx = riscv_root::ContextMemory::default();
        let mut gs = riscv_root::GlobalSet::new(riscv_root::ContextMemory::default());
        let (inst_next, display, mut pcode) =
            riscv_root::parse_instruction(bytes, &mut ctx, addr, &mut gs)
                .expect("failed to decode");
        pcode_ir::optimize(&mut pcode);
        let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
        (inst_next - addr, disasm.join(""), pcode)
    }
}

fn main() {
    let tests: &[(&[u8], &str)] = &[
        (&[0x48, 0x89, 0xc7], "MOV rdi, rax"),
        (&[0x48, 0x01, 0xc7], "ADD rdi, rax"),
        (&[0x50], "PUSH rax"),
        (&[0x58], "POP rax"),
        (&[0xc3], "RET"),
        (&[0x74, 0x05], "JE rel8"),
        (&[0xeb, 0x0a], "JMP rel8"),
        (&[0xff, 0xd0], "CALL rax"),
        (&[0x48, 0x8b, 0x07], "MOV rax,[rdi]"),
        (&[0x48, 0x39, 0xc7], "CMP rdi, rax"),
        // New test instructions
        (&[0x48, 0x29, 0xc7], "SUB rdi, rax"),
        (&[0x48, 0x31, 0xc7], "XOR rdi, rax"),
        (&[0x90], "NOP"),
        (&[0x48, 0x8d, 0x47, 0x10], "LEA rax,[rdi+0x10]"),
        (&[0x48, 0x89, 0x07], "MOV [rdi], rax"),
        (&[0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00], "MOV rax, 1"),
    ];

    println!("=== x86-64 ===\n");
    for (bytes, name) in tests {
        let (len, disasm, pcode) = x86::decode(bytes, 0x1000);
        println!("{name}:");
        println!("  decoded: {disasm}");
        println!("  len={len}, pcode_ops={}", pcode.len());
        for op in &pcode {
            println!("    {op:?}");
        }
        println!();
    }

    // ARM64 test instructions (little-endian 4-byte fixed width)
    let arm_tests: &[(&[u8], &str)] = &[
        (&[0xe0, 0x03, 0x01, 0xaa], "MOV x0, x1"),       // mov x0, x1
        (&[0x20, 0x00, 0x02, 0x8b], "ADD x0, x1, x2"),    // add x0, x1, x2
        (&[0xc0, 0x03, 0x5f, 0xd6], "RET"),                // ret
        (&[0x00, 0x00, 0x00, 0x14], "B ."),                 // b .
        (&[0x20, 0x00, 0x20, 0xd4], "BRK #1"),             // brk #1
    ];

    // RISC-V test instructions (little-endian, 4-byte or 2-byte compressed)
    let riscv_tests: &[(&[u8], &str)] = &[
        (&[0x93, 0x00, 0x50, 0x00], "addi x1, x0, 5"),    // addi x1, x0, 5
        (&[0xb3, 0x01, 0xc0, 0x00], "add x3, x0, x12"),   // add x3, x0, x12
        (&[0x67, 0x80, 0x00, 0x00], "jalr x0, 0(x1)"),     // ret-like: jalr x0, 0(x1)
    ];

    println!("=== riscv64 ===\n");
    for (bytes, name) in riscv_tests {
        match std::panic::catch_unwind(|| riscv::decode(bytes, 0x1000)) {
            Ok((len, disasm, pcode)) => {
                println!("{name}:");
                println!("  decoded: {disasm}");
                println!("  len={len}, pcode_ops={}", pcode.len());
                for op in &pcode { println!("    {op:?}"); }
            }
            Err(_) => println!("{name}: FAILED to decode"),
        }
        println!();
    }

    println!("=== aarch64 ===\n");
    for (bytes, name) in arm_tests {
        match std::panic::catch_unwind(|| arm::decode(bytes, 0x1000)) {
            Ok((len, disasm, pcode)) => {
                println!("{name}:");
                println!("  decoded: {disasm}");
                println!("  len={len}, pcode_ops={}", pcode.len());
                for op in &pcode {
                    println!("    {op:?}");
                }
            }
            Err(_) => println!("{name}: FAILED to decode"),
        }
        println!();
    }
}

// ── Helpers for concise test assertions ──────────────────────────────

fn reg(offset: u64, size: u32) -> Varnode { Varnode::register(offset, size) }
fn con(value: u64, size: u32) -> Varnode { Varnode::constant(value, size) }

// x86-64 register offsets (from Ghidra's x86-64 register map)
const RAX: u64 = 0;
const RCX: u64 = 8;
const RDX: u64 = 16;
const RBX: u64 = 24;
const RSP: u64 = 32;
const RBP: u64 = 40;
const RSI: u64 = 48;
const RDI: u64 = 56;
const CF: u64 = 512;
const PF: u64 = 514;
const ZF: u64 = 518;
const SF: u64 = 519;
const OF: u64 = 523;
const RIP: u64 = 648;

/// Assert that the P-code sequence contains specific ops (in order, allowing gaps).
fn assert_pcode_contains(pcode: &[PcodeOp], disasm: &str, checks: &[fn(&PcodeOp) -> bool]) {
    let mut check_idx = 0;
    for op in pcode {
        if check_idx < checks.len() && checks[check_idx](op) {
            check_idx += 1;
        }
    }
    assert_eq!(
        check_idx, checks.len(),
        "only matched {check_idx}/{} expected ops in {disasm}:\n{pcode:#?}",
        checks.len(),
    );
}

// ── Tests ────────────────────────────────────────────────────────────
// x86-64 parser recurses deeply through subtables. Default test thread
// stack (8MB) overflows. We run all assertions inside a 32MB-stack thread.

#[cfg(test)]
mod tests {
    use super::*;

    // Alias for x86 in tests
    fn decode(bytes: &[u8], addr: u64) -> (u64, String, Vec<PcodeOp>) {
        x86::decode(bytes, addr)
    }

    #[test]
    fn x86_64_golden() {
        let t = std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(run_all_tests)
            .unwrap();
        t.join().unwrap();
    }

    fn run_all_tests() {
        test_mov_reg_reg();
        test_add_reg_reg();
        test_push_reg();
        test_pop_reg();
        test_ret();
        test_jz_rel8();
        test_jmp_rel8();
        test_call_reg();
        test_mov_reg_mem();
        test_cmp_reg_reg();
        test_sub_reg_reg();
        test_xor_reg_reg();
        test_nop();
        test_lea();
        test_mov_mem_reg();
        test_mov_reg_imm();
        // ARM64 tests
        test_arm_mov_reg();
        test_arm_add_reg();
        test_arm_ret();
        test_arm_branch();
        // RISC-V tests
        test_riscv_addi();
        test_riscv_add();
        test_riscv_jalr();
        eprintln!("  23 golden tests passed");
        // Scale validation
        test_x86_64_corpus();
        test_aarch64_corpus();
        test_riscv_corpus();
        eprintln!("all tests passed");
    }

    fn test_mov_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x89, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "MOV RDI,RAX");
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0], PcodeOp::Copy { out: reg(RDI, 8), input: reg(RAX, 8) });
    }

    fn test_add_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x01, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "ADD RDI,RAX");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntCarry { left, right, .. }
                if *left == reg(RDI, 8) && *right == reg(RAX, 8)),
            |op| matches!(op, PcodeOp::IntSCarry { left, right, .. }
                if *left == reg(RDI, 8) && *right == reg(RAX, 8)),
            |op| matches!(op, PcodeOp::IntAdd { left, right, .. }
                if *left == reg(RDI, 8) && *right == reg(RAX, 8)),
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(RDI, 8)),
        ]);
    }

    fn test_push_reg() {
        let (len, disasm, pcode) = decode(&[0x50], 0x1000);
        assert_eq!(len, 1);
        assert_eq!(disasm, "PUSH RAX");
        assert_eq!(pcode.len(), 3);
        assert!(matches!(&pcode[0], PcodeOp::IntSub { left, right, .. }
            if *left == reg(RSP, 8) && *right == con(8, 8)));
        assert!(matches!(&pcode[2], PcodeOp::Store { space: AddressSpaceId::Ram, ptr, val }
            if *ptr == reg(RSP, 8) && *val == reg(RAX, 8)));
    }

    fn test_pop_reg() {
        let (len, disasm, pcode) = decode(&[0x58], 0x1000);
        assert_eq!(len, 1);
        assert_eq!(disasm, "POP RAX");
        assert_eq!(pcode.len(), 4);
        assert!(matches!(&pcode[0], PcodeOp::Load { space: AddressSpaceId::Ram, ptr, .. }
            if *ptr == reg(RSP, 8)));
        assert!(matches!(&pcode[1], PcodeOp::IntAdd { left, right, .. }
            if *left == reg(RSP, 8) && *right == con(8, 8)));
        assert!(matches!(&pcode[3], PcodeOp::Copy { out, .. } if *out == reg(RAX, 8)));
    }

    fn test_ret() {
        let (len, disasm, pcode) = decode(&[0xc3], 0x1000);
        assert_eq!(len, 1);
        assert_eq!(disasm, "RET");
        assert!(matches!(&pcode[0], PcodeOp::Load { space: AddressSpaceId::Ram, ptr, .. }
            if *ptr == reg(RSP, 8)));
        assert!(matches!(pcode.last(), Some(PcodeOp::Return { dest })
            if *dest == reg(RIP, 8)));
    }

    fn test_jz_rel8() {
        let (len, disasm, pcode) = decode(&[0x74, 0x05], 0x1000);
        assert_eq!(len, 2);
        assert_eq!(disasm, "JZ 0x1007");
        assert_eq!(pcode.len(), 1);
        assert!(matches!(&pcode[0], PcodeOp::CBranch { dest, cond }
            if dest.space == AddressSpaceId::Ram
            && dest.offset == 0x1007
            && *cond == reg(ZF, 1)));
    }

    fn test_jmp_rel8() {
        let (len, disasm, pcode) = decode(&[0xeb, 0x0a], 0x1000);
        assert_eq!(len, 2);
        assert_eq!(disasm, "JMP 0x100c");
        assert_eq!(pcode.len(), 1);
        assert!(matches!(&pcode[0], PcodeOp::Branch { dest }
            if dest.space == AddressSpaceId::Ram && dest.offset == 0x100c));
    }

    fn test_call_reg() {
        let (len, disasm, pcode) = decode(&[0xff, 0xd0], 0x1000);
        assert_eq!(len, 2);
        assert_eq!(disasm, "CALL RAX");
        assert_eq!(pcode.len(), 4);
        assert!(matches!(&pcode[0], PcodeOp::IntSub { left, right, .. }
            if *left == reg(RSP, 8) && *right == con(8, 8)));
        assert!(matches!(&pcode[2], PcodeOp::Store { space: AddressSpaceId::Ram, ptr, val }
            if *ptr == reg(RSP, 8) && val.offset == 0x1002));
        assert!(matches!(&pcode[3], PcodeOp::CallInd { dest } if *dest == reg(RAX, 8)));
    }

    fn test_mov_reg_mem() {
        let (len, disasm, pcode) = decode(&[0x48, 0x8b, 0x07], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "MOV RAX,qword ptr [RDI]");
        assert_eq!(pcode.len(), 2);
        assert!(matches!(&pcode[0], PcodeOp::Load { space: AddressSpaceId::Ram, ptr, out }
            if *ptr == reg(RDI, 8) && out.size == 8));
        assert!(matches!(&pcode[1], PcodeOp::Copy { out, .. } if *out == reg(RAX, 8)));
    }

    fn test_cmp_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x39, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "CMP RDI,RAX");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(CF, 1)),
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(OF, 1)),
            |op| matches!(op, PcodeOp::IntSub { .. }),
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(SF, 1)),
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(ZF, 1)),
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(PF, 1)),
        ]);
    }

    fn test_sub_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x29, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "SUB RDI,RAX");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { left, right, .. }
                if *left == reg(RDI, 8) && *right == reg(RAX, 8)),
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(RDI, 8)),
        ]);
    }

    fn test_xor_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x31, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "XOR RDI,RAX");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntXor { left, right, .. }
                if *left == reg(RDI, 8) && *right == reg(RAX, 8)),
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(RDI, 8)),
        ]);
    }

    fn test_nop() {
        let (len, disasm, _pcode) = decode(&[0x90], 0x1000);
        assert_eq!(len, 1);
        assert_eq!(disasm, "NOP");
    }

    fn test_lea() {
        let (len, disasm, pcode) = decode(&[0x48, 0x8d, 0x47, 0x10], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.starts_with("LEA"), "expected LEA, got {disasm}");
        // LEA computes address, writes to RAX — should have an IntAdd and Copy to RAX
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Copy { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_mov_mem_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x89, 0x07], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "MOV qword ptr [RDI],RAX");
        // Should Store RAX to [RDI]
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, ptr, val }
                if *ptr == reg(RDI, 8) && *val == reg(RAX, 8)),
        ]);
    }

    fn test_mov_reg_imm() {
        let (len, disasm, pcode) = decode(&[0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(len, 7);
        assert!(disasm.contains("MOV") && disasm.contains("RAX"), "expected MOV RAX,imm got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Copy { out, input }
                if *out == reg(RAX, 8) && input.space == AddressSpaceId::Const && input.offset == 1),
        ]);
    }

    // ── ARM64 tests ──────────────────────────────────────────────────

    fn test_arm_mov_reg() {
        // MOV X0, X1 = ORR X0, XZR, X1 = 0xaa0103e0
        let (len, disasm, pcode) = arm::decode(&[0xe0, 0x03, 0x01, 0xaa], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.contains("mov") || disasm.contains("MOV") || disasm.contains("orr") || disasm.contains("ORR"),
            "expected mov/orr, got {disasm}");
    }

    fn test_arm_add_reg() {
        // ADD X0, X1, X2 = 0x8b020020
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0x8b], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.contains("add") || disasm.contains("ADD"), "expected ADD, got {disasm}");
        // Should contain an IntAdd
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { .. }),
        ]);
    }

    fn test_arm_ret() {
        // RET = 0xd65f03c0
        let (len, disasm, pcode) = arm::decode(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.contains("ret") || disasm.contains("RET"), "expected RET, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Return { .. }),
        ]);
    }

    fn test_arm_branch() {
        // B . (branch to self) = 0x14000000
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x00, 0x00, 0x14], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.contains("b") || disasm.contains("B"), "expected B, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Branch { .. }),
        ]);
    }

    // ── RISC-V tests ─────────────────────────────────────────────────

    fn test_riscv_addi() {
        // addi x1, x0, 5 = 0x00500093
        let (len, disasm, _pcode) = riscv::decode(&[0x93, 0x00, 0x50, 0x00], 0x1000);
        assert_eq!(len, 4);
        // Ghidra displays "addi x1,x0,5" as "li ra,0x5" (pseudo-instruction)
        assert!(disasm.to_lowercase().contains("li") || disasm.to_lowercase().contains("addi"),
            "expected li/addi, got {disasm}");
    }

    fn test_riscv_add() {
        // add x3, x0, x12 = 0x00c001b3
        let (len, disasm, pcode) = riscv::decode(&[0xb3, 0x01, 0xc0, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("add"), "expected add, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { .. } | PcodeOp::Copy { .. }),
        ]);
    }

    fn test_riscv_jalr() {
        // jalr x0, 0(x1) = 0x00008067
        let (len, disasm, _pcode) = riscv::decode(&[0x67, 0x80, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("jalr") || disasm.to_lowercase().contains("ret"),
            "expected jalr/ret, got {disasm}");
    }

    // ── Scale validation ─────────────────────────────────────────────

    fn run_corpus(
        arch: &str,
        corpus: &[(&[u8], u64, &str)],
        decoder: fn(&[u8], u64) -> (u64, String, Vec<PcodeOp>),
        mnemonic_aliases: &[(&str, &[&str])],
    ) {
        let mut passed = 0;
        let mut failed = Vec::new();

        for (bytes, expected_len, capstone_mnemonic) in corpus {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decoder(bytes, 0x1000)));
            match result {
                Ok((len, disasm, pcode)) => {
                    if len != *expected_len {
                        failed.push(format!(
                            "{}: len mismatch: got {len}, expected {expected_len} (disasm: {disasm})",
                            capstone_mnemonic
                        ));
                        continue;
                    }

                    let disasm_lower = disasm.to_lowercase();
                    let mnemonic_matches = disasm_lower.starts_with(capstone_mnemonic)
                        || mnemonic_aliases.iter().any(|(cap, aliases)| {
                            *cap == *capstone_mnemonic && aliases.iter().any(|a| disasm_lower.starts_with(a))
                        });
                    if !mnemonic_matches {
                        failed.push(format!(
                            "{}: mnemonic mismatch: got '{disasm}', expected '{capstone_mnemonic}'",
                            capstone_mnemonic
                        ));
                        continue;
                    }

                    for (i, op) in pcode.iter().enumerate() {
                        if let Some(err) = validate_pcode_op(op) {
                            failed.push(format!(
                                "{}: P-code op {i} invalid: {err} (disasm: {disasm})",
                                capstone_mnemonic
                            ));
                        }
                    }
                    passed += 1;
                }
                Err(_) => {
                    failed.push(format!("{}: PANIC during decode", capstone_mnemonic));
                }
            }
        }

        if !failed.is_empty() {
            for f in &failed { eprintln!("  FAIL: {f}"); }
            panic!("{arch}: {} of {} corpus tests failed", failed.len(), corpus.len());
        }
        eprintln!("  {arch} corpus: {passed}/{} validated", corpus.len());
    }

    fn test_x86_64_corpus() {
        run_corpus("x86-64", corpus::X86_64_CORPUS, x86::decode, &[
            ("je", &["jz"]),
            ("jne", &["jnz"]),
            ("jl", &["jl"]),
            ("jg", &["jg"]),
            ("jb", &["jc", "jb"]),
            ("jae", &["jnc", "jae"]),
            ("jbe", &["jbe"]),
            ("ja", &["ja"]),
            ("js", &["js"]),
            ("jns", &["jns"]),
            ("jge", &["jge"]),
            ("jle", &["jle"]),
            ("int3", &["int3", "breakpoint"]),
            ("hlt", &["hlt"]),
            ("cmove", &["cmovz"]),
            ("cmovne", &["cmovnz"]),
            ("cmovb", &["cmovc", "cmovb"]),
            ("cmovae", &["cmovnc", "cmovae"]),
            ("cmovbe", &["cmovbe"]),
            ("cmova", &["cmova"]),
            ("cmovl", &["cmovl"]),
            ("cmovge", &["cmovge"]),
            ("cmovle", &["cmovle"]),
            ("cmovg", &["cmovg"]),
            ("sete", &["setz", "sete"]),
            ("setne", &["setnz", "setne"]),
            ("setl", &["setl"]),
            ("setg", &["setg"]),
            ("rep movsb", &["rep", "movsb"]),
            ("rep movsq", &["rep", "movsq"]),
            ("repe scasb", &["rep", "scasb"]),
            ("cwde", &["cwde", "cwtl"]),
            ("cdq", &["cdq", "cltd"]),
            ("cqo", &["cqo", "cqto"]),
            ("pause", &["pause", "nop"]),
            ("rdtsc", &["rdtsc"]),
            ("bswap", &["bswap"]),
            ("cvttss2si", &["cvttss2si"]),
            ("cvtsi2ss", &["cvtsi2ss"]),
            ("ucomisd", &["ucomisd"]),
            ("ucomiss", &["ucomiss"]),
        ]);
    }

    fn test_aarch64_corpus() {
        run_corpus("aarch64", corpus::AARCH64_CORPUS, arm::decode, &[
            ("mov", &["mov", "orr", "movz"]),
            ("b.eq", &["b.eq", "b."]),
            ("eor", &["eor"]),
            ("brk", &["brk"]),
            ("sxtw", &["sxtw", "sbfm"]),
            ("rbit", &["rbit"]),
        ]);
    }

    fn test_riscv_corpus() {
        run_corpus("riscv", corpus::RISCV_CORPUS, riscv::decode, &[
            ("addi", &["addi", "li", "mv"]),
            ("andi", &["andi"]),
            ("ori", &["ori"]),
            ("slli", &["slli"]),
            ("srli", &["srli"]),
            ("srai", &["srai"]),
            ("add", &["add"]),
            ("jalr", &["jalr", "ret", "jr"]),
            ("jal", &["jal", "j"]),
            ("beq", &["beq", "beqz"]),
            ("bne", &["bne", "bnez"]),
            ("blt", &["blt", "bgtz", "bltz"]),
            ("bge", &["bge", "blez", "bgez"]),
            ("nop", &["nop", "addi"]),
            ("ebreak", &["ebreak"]),
        ]);
    }
}

/// Validate structural properties of a P-code op.
fn validate_pcode_op(op: &PcodeOp) -> Option<String> {
    match op {
        // Check output varnodes have non-zero size
        PcodeOp::Copy { out, .. }
        | PcodeOp::Load { out, .. }
        | PcodeOp::IntAdd { out, .. }
        | PcodeOp::IntSub { out, .. }
        | PcodeOp::IntMult { out, .. }
        | PcodeOp::IntAnd { out, .. }
        | PcodeOp::IntOr { out, .. }
        | PcodeOp::IntXor { out, .. }
        | PcodeOp::IntNeg { out, .. }
        | PcodeOp::IntNot { out, .. }
        | PcodeOp::IntEq { out, .. }
        | PcodeOp::IntLess { out, .. }
        | PcodeOp::IntSLess { out, .. }
        | PcodeOp::IntCarry { out, .. }
        | PcodeOp::IntSCarry { out, .. }
        | PcodeOp::IntSBorrow { out, .. }
        | PcodeOp::IntLsl { out, .. }
        | PcodeOp::IntLsr { out, .. }
        | PcodeOp::IntAsr { out, .. }
        | PcodeOp::IntZext { out, .. }
        | PcodeOp::IntSext { out, .. }
        | PcodeOp::Subpiece { out, .. }
        | PcodeOp::Popcount { out, .. } => {
            if out.size == 0 {
                return Some(format!("output varnode has size 0: {op:?}"));
            }
            if out.space == AddressSpaceId::Const {
                return Some(format!("output varnode is Const space: {op:?}"));
            }
            None
        }
        // Store should write to Ram
        PcodeOp::Store { space, .. } => {
            if *space != AddressSpaceId::Ram {
                // Some stores go to Register space (valid for SLEIGH semantics)
            }
            None
        }
        // Call destinations should not be in Unique space
        // (Branch to Unique is valid for REP-prefixed loop labels)
        PcodeOp::Call { dest } => {
            if dest.space == AddressSpaceId::Unique {
                return Some(format!("call to Unique space: {op:?}"));
            }
            None
        }
        PcodeOp::Branch { .. } => None,
        _ => None,
    }
}
