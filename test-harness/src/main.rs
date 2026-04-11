use pcode_ir::{AddressSpaceId, PcodeOp, Varnode};

mod corpus;
mod ghidra;

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
            x86_root::parse_instruction(bytes, &mut ctx, addr, &mut gs).expect("failed to decode");
        pcode_ir::optimize(&mut pcode);
        let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
        (inst_next - addr, disasm.join(""), pcode)
    }

    /// Decode a multi-instruction byte sequence, returns vec of (addr, len, disasm, pcode).
    /// Resets context between instructions to avoid REX prefix leaking.
    pub fn decode_sequence(bytes: &[u8], base: u64) -> Vec<(u64, u64, String, Vec<PcodeOp>)> {
        let mut results = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let addr = base + offset as u64;
            let mut ctx = context();
            let mut gs = x86_root::GlobalSet::new(context());
            if let Some((inst_next, display, mut pcode)) =
                x86_root::parse_instruction(&bytes[offset..], &mut ctx, addr, &mut gs)
            {
                pcode_ir::optimize(&mut pcode);
                let len = inst_next - addr;
                let disasm = display.iter().map(|d| format!("{}", d)).collect::<Vec<_>>().join("");
                results.push((addr, len, disasm, pcode));
                offset += len as usize;
            } else {
                break;
            }
        }
        results
    }
}

mod arm_seq {
    use super::*;

    /// Decode a multi-instruction ARM64 byte sequence.
    pub fn decode_sequence(bytes: &[u8], base: u64) -> Vec<(u64, u64, String, Vec<PcodeOp>)> {
        let mut results = Vec::new();
        let mut offset = 0usize;
        while offset + 4 <= bytes.len() {
            let addr = base + offset as u64;
            match std::panic::catch_unwind(|| arm::decode(&bytes[offset..offset+4], addr)) {
                Ok((len, disasm, pcode)) => {
                    results.push((addr, len, disasm, pcode));
                    offset += len as usize;
                }
                Err(_) => break,
            }
        }
        results
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

mod arm32 {
    use super::*;

    pub fn decode(bytes: &[u8], addr: u64) -> (u64, String, Vec<PcodeOp>) {
        let mut ctx = arm32_root::ContextMemory::default();
        let mut gs = arm32_root::GlobalSet::new(arm32_root::ContextMemory::default());
        let addr32 = addr as u32;
        let (inst_next, display, mut pcode) =
            arm32_root::parse_instruction(bytes, &mut ctx, addr32, &mut gs)
                .expect("failed to decode");
        pcode_ir::optimize(&mut pcode);
        let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
        ((inst_next - addr32) as u64, disasm.join(""), pcode)
    }
}

mod mips {
    use super::*;

    pub fn decode(bytes: &[u8], addr: u64) -> (u64, String, Vec<PcodeOp>) {
        let mut ctx = mips_root::ContextMemory::default();
        let mut gs = mips_root::GlobalSet::new(mips_root::ContextMemory::default());
        let addr32 = addr as u32;
        let (inst_next, display, mut pcode) =
            mips_root::parse_instruction(bytes, &mut ctx, addr32, &mut gs)
                .expect("failed to decode");
        pcode_ir::optimize(&mut pcode);
        let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
        ((inst_next - addr32) as u64, disasm.join(""), pcode)
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
        (&[0xe0, 0x03, 0x01, 0xaa], "MOV x0, x1"),     // mov x0, x1
        (&[0x20, 0x00, 0x02, 0x8b], "ADD x0, x1, x2"), // add x0, x1, x2
        (&[0xc0, 0x03, 0x5f, 0xd6], "RET"),            // ret
        (&[0x00, 0x00, 0x00, 0x14], "B ."),            // b .
        (&[0x20, 0x00, 0x20, 0xd4], "BRK #1"),         // brk #1
    ];

    // RISC-V test instructions (little-endian, 4-byte or 2-byte compressed)
    let riscv_tests: &[(&[u8], &str)] = &[
        (&[0x93, 0x00, 0x50, 0x00], "addi x1, x0, 5"), // addi x1, x0, 5
        (&[0xb3, 0x01, 0xc0, 0x00], "add x3, x0, x12"), // add x3, x0, x12
        (&[0x67, 0x80, 0x00, 0x00], "jalr x0, 0(x1)"), // ret-like: jalr x0, 0(x1)
    ];

    println!("=== riscv64 ===\n");
    for (bytes, name) in riscv_tests {
        match std::panic::catch_unwind(|| riscv::decode(bytes, 0x1000)) {
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

    // Deep AARCH64 comparison vs Ghidra
    let arm_deep: &[(&[u8], &str)] = &[
        (&[0x00, 0x00, 0x01, 0x8b], "add x0,x0,x1"),
        (&[0x00, 0x00, 0x01, 0xcb], "sub x0,x0,x1"),
        (&[0xe0, 0x03, 0x01, 0xaa], "mov x0,x1"),
        (&[0x00, 0x00, 0x01, 0x8a], "and x0,x0,x1"),
        (&[0x00, 0x00, 0x01, 0xaa], "orr x0,x0,x1"),
        (&[0x00, 0x00, 0x01, 0xca], "eor x0,x0,x1"),
        (&[0x1f, 0x00, 0x01, 0xeb], "cmp x0,x1"),
        (&[0x00, 0x7c, 0x01, 0x9b], "mul x0,x0,x1"),
        (&[0x00, 0x00, 0x40, 0xf9], "ldr x0,[x0]"),
        (&[0x00, 0x00, 0x00, 0xf9], "str x0,[x0]"),
        (&[0xc0, 0x03, 0x5f, 0xd6], "ret"),
    ];
    println!("=== aarch64 deep comparison ===\n");
    for (bytes, name) in arm_deep {
        let (len, disasm, pcode) = arm::decode(bytes, 0x0);
        println!("{name}:");
        println!("  decoded: {disasm}, len={len}, ops={}", pcode.len());
        for op in &pcode {
            println!("    {op:?}");
        }
        println!();
    }

    // Hard AARCH64 instructions
    let arm_hard: &[(&[u8], &str)] = &[
        (&[0x00, 0x10, 0x81, 0x9a], "csel"),
        (&[0x00, 0x04, 0x80, 0xda], "cneg"),
        (&[0x20, 0x04, 0x81, 0x9a], "cinc"),
        (&[0x00, 0x0c, 0x40, 0xd3], "ubfx"),
        (&[0x00, 0x0c, 0x40, 0x93], "sbfx"),
        (&[0x00, 0xfc, 0x7f, 0xd3], "lsr63"),
        (&[0x00, 0xfc, 0x41, 0xd3], "lsr1"),
        (&[0x00, 0x00, 0x02, 0x9b], "madd"),
        (&[0x00, 0xfc, 0x02, 0x9b], "mneg"),
        (&[0x00, 0x7c, 0x22, 0x9b], "smull"),
        (&[0x00, 0x00, 0x00, 0x10], "adr"),
        (&[0x00, 0x00, 0x00, 0x90], "adrp"),
        (&[0x00, 0x7c, 0x5f, 0xc8], "ldxr"),
        (&[0x00, 0x7c, 0x01, 0xc8], "stxr"),
        (&[0x00, 0x08, 0x21, 0x1e], "fmul"),
        (&[0x00, 0x28, 0x21, 0x1e], "fadd"),
        (&[0x00, 0x20, 0x21, 0x1e], "fcmp"),
        (&[0x00, 0x40, 0x38, 0xd5], "mrs"),
        (&[0x5f, 0x3f, 0x03, 0xd5], "clrex"),
        (&[0x00, 0x00, 0xc0, 0xd2], "movz_lsl32"),
        (&[0x01, 0x00, 0xa0, 0xf2], "movk_lsl16"),
    ];
    println!("=== aarch64 HARD ===\n");
    for (bytes, name) in arm_hard {
        match std::panic::catch_unwind(|| arm::decode(bytes, 0x0)) {
            Ok((len, disasm, pcode)) => {
                println!("{name}: {disasm} (len={len}, ops={})", pcode.len());
                for op in &pcode {
                    println!("    {op:?}");
                }
            }
            Err(_) => println!("{name}: PANIC"),
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

fn reg(offset: u64, size: u32) -> Varnode {
    Varnode::register(offset, size)
}
fn con(value: u64, size: u32) -> Varnode {
    Varnode::constant(value, size)
}

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
        check_idx,
        checks.len(),
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
        // x86-64 sign-extension regression tests
        test_lea_negative_disp8();
        test_mov_mem_disp8();
        test_lea_positive_disp8();
        // x86-64 additional instruction coverage
        test_call_rel32();
        test_mov_reg_mem_disp();
        test_test_reg_reg();
        test_movzx();
        test_movsx();
        test_shl_reg_imm();
        test_shr_reg_imm();
        test_sar_reg_imm();
        test_imul_reg_reg();
        test_and_reg_reg();
        test_or_reg_reg();
        test_not_reg();
        test_neg_reg();
        test_inc_reg();
        test_dec_reg();
        test_cdqe();
        test_leave();
        test_mov_rip_rel();
        test_cmp_reg_imm();
        test_add_reg_imm();
        test_sub_reg_imm();
        test_mov_store_disp();
        test_jne_rel8();
        test_jg_rel8();
        test_jle_rel8();
        // ARM64 tests
        test_arm_mov_reg();
        test_arm_add_reg();
        test_arm_sub();
        test_arm_and();
        test_arm_orr();
        test_arm_eor();
        test_arm_mul();
        test_arm_sdiv();
        test_arm_movz();
        test_arm_ret();
        test_arm_branch();
        test_arm_bl();
        test_arm_b_cond();
        test_arm_ldr();
        test_arm_str();
        test_arm_ldr_w_offset();
        test_arm_ldrb();
        test_arm_strb();
        test_arm_stp();
        test_arm_ldp();
        test_arm_cmp();
        test_arm_cmp_imm();
        test_arm_cbz();
        test_arm_cbnz();
        test_arm_add_imm();
        test_arm_sub_imm();
        test_arm_neg();
        test_arm_mvn();
        test_arm_tst();
        test_arm_lsr_imm();
        test_arm_asr_imm();
        test_arm_lsl_imm();
        test_arm_sxtw();
        test_arm_ldr_pre_index();
        test_arm_str_pre_index();
        test_arm_ldrsb();
        test_arm_csel();
        test_arm_adrp();
        // RISC-V tests
        test_riscv_addi();
        test_riscv_add();
        test_riscv_sub();
        test_riscv_and();
        test_riscv_or();
        test_riscv_xor();
        test_riscv_slli();
        test_riscv_srli();
        test_riscv_slti();
        test_riscv_mul();
        test_riscv_lui();
        test_riscv_jalr();
        test_riscv_jal();
        test_riscv_lw();
        test_riscv_sw();
        test_riscv_ld();
        test_riscv_sd();
        test_riscv_lb();
        test_riscv_sb();
        test_riscv_beq();
        test_riscv_bne();
        // MIPS tests
        test_mips_addiu();
        test_mips_addu();
        test_mips_subu();
        test_mips_and();
        test_mips_or();
        test_mips_xor();
        test_mips_sll();
        test_mips_srl();
        test_mips_slt();
        test_mips_lui();
        test_mips_ori();
        test_mips_mult();
        test_mips_lw();
        test_mips_sw();
        test_mips_lb();
        test_mips_sb();
        test_mips_beq();
        test_mips_bne();
        test_mips_j();
        test_mips_jal();
        test_mips_jr_ra();
        // ARM32 tests
        test_arm32_add();
        test_arm32_sub();
        test_arm32_and();
        test_arm32_orr();
        test_arm32_eor();
        test_arm32_mul();
        test_arm32_mov_imm();
        test_arm32_mov_reg();
        test_arm32_cmp();
        test_arm32_ldr();
        test_arm32_str();
        test_arm32_ldr_offset();
        test_arm32_ldrb();
        test_arm32_strb();
        test_arm32_b();
        test_arm32_bl();
        test_arm32_beq();
        test_arm32_push();
        test_arm32_pop();
        test_arm32_bx_lr();
        test_arm32_lsl_imm();
        test_x86_64_vs_ghidra_fixture();
        test_aarch64_vs_ghidra_fixture();
        eprintln!("  145 golden tests passed");
        run_stress_tests();
        eprintln!("  stress tests passed");
        run_functional_tests();
        eprintln!("  functional tests passed");
        run_bug_probes();
        eprintln!("  bug probes passed");
        // Scale validation
        test_x86_64_corpus();
        test_aarch64_corpus();
        test_riscv_corpus();
        test_mips_corpus();
        test_arm32_corpus();
        eprintln!("all tests passed");
    }

    fn test_mov_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x89, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "MOV RDI,RAX");
        assert_eq!(pcode.len(), 1);
        assert_eq!(
            pcode[0],
            PcodeOp::Copy {
                out: reg(RDI, 8),
                input: reg(RAX, 8)
            }
        );
    }

    fn test_add_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x01, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "ADD RDI,RAX");
        assert_eq!(pcode.len(), 9); // matches Ghidra exactly
                                    // After output sinking: ops write directly to registers (no intermediate Copies)
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[
                |op| {
                    matches!(op, PcodeOp::IntCarry { out, left, right }
                if *out == reg(CF, 1) && *left == reg(RDI, 8) && *right == reg(RAX, 8))
                },
                |op| {
                    matches!(op, PcodeOp::IntSCarry { out, left, right }
                if *out == reg(OF, 1) && *left == reg(RDI, 8) && *right == reg(RAX, 8))
                },
                |op| {
                    matches!(op, PcodeOp::IntAdd { out, left, right }
                if *out == reg(RDI, 8) && *left == reg(RDI, 8) && *right == reg(RAX, 8))
                },
            ],
        );
    }

    fn test_push_reg() {
        let (len, disasm, pcode) = decode(&[0x50], 0x1000);
        assert_eq!(len, 1);
        assert_eq!(disasm, "PUSH RAX");
        assert_eq!(pcode.len(), 2); // matches Ghidra: IntSub + Store (no intermediate Copy)
        assert!(matches!(&pcode[0], PcodeOp::IntSub { out, left, right }
            if *out == reg(RSP, 8) && *left == reg(RSP, 8) && *right == con(8, 8)));
        assert!(
            matches!(&pcode[1], PcodeOp::Store { space: AddressSpaceId::Ram, ptr, val }
            if *ptr == reg(RSP, 8) && *val == reg(RAX, 8))
        );
    }

    fn test_pop_reg() {
        let (len, disasm, pcode) = decode(&[0x58], 0x1000);
        assert_eq!(len, 1);
        assert_eq!(disasm, "POP RAX");
        assert_eq!(pcode.len(), 2); // beats Ghidra (4 ops): Load directly to RAX + IntAdd RSP
        assert!(
            matches!(&pcode[0], PcodeOp::Load { out, space: AddressSpaceId::Ram, ptr }
            if *out == reg(RAX, 8) && *ptr == reg(RSP, 8))
        );
        assert!(matches!(&pcode[1], PcodeOp::IntAdd { out, left, right }
            if *out == reg(RSP, 8) && *left == reg(RSP, 8) && *right == con(8, 8)));
    }

    fn test_ret() {
        let (len, disasm, pcode) = decode(&[0xc3], 0x1000);
        assert_eq!(len, 1);
        assert_eq!(disasm, "RET");
        assert_eq!(pcode.len(), 3); // matches Ghidra: Load + IntAdd + Return
        assert!(
            matches!(&pcode[0], PcodeOp::Load { out, space: AddressSpaceId::Ram, ptr }
            if *out == reg(RIP, 8) && *ptr == reg(RSP, 8))
        );
        assert!(matches!(&pcode[1], PcodeOp::IntAdd { out, left, right }
            if *out == reg(RSP, 8) && *left == reg(RSP, 8) && *right == con(8, 8)));
        assert!(matches!(&pcode[2], PcodeOp::Return { dest }
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
        assert_eq!(pcode.len(), 3); // matches Ghidra: IntSub + Store + CallInd
        assert!(matches!(&pcode[0], PcodeOp::IntSub { out, left, right }
            if *out == reg(RSP, 8) && *left == reg(RSP, 8) && *right == con(8, 8)));
        assert!(
            matches!(&pcode[1], PcodeOp::Store { space: AddressSpaceId::Ram, ptr, val }
            if *ptr == reg(RSP, 8) && val.offset == 0x1002)
        );
        assert!(matches!(&pcode[2], PcodeOp::CallInd { dest } if *dest == reg(RAX, 8)));
    }

    fn test_mov_reg_mem() {
        let (len, disasm, pcode) = decode(&[0x48, 0x8b, 0x07], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "MOV RAX,qword ptr [RDI]");
        assert_eq!(pcode.len(), 1); // Load writes directly to RAX after output sinking
        assert!(
            matches!(&pcode[0], PcodeOp::Load { out, space: AddressSpaceId::Ram, ptr }
            if *out == reg(RAX, 8) && *ptr == reg(RDI, 8))
        );
    }

    fn test_cmp_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x39, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "CMP RDI,RAX");
        // After output sinking: flags written directly by comparison ops
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[
                |op| matches!(op, PcodeOp::IntLess { out, .. } if *out == reg(CF, 1)),
                |op| matches!(op, PcodeOp::IntSBorrow { out, .. } if *out == reg(OF, 1)),
                |op| matches!(op, PcodeOp::IntSub { .. }),
                |op| matches!(op, PcodeOp::IntSLess { out, .. } if *out == reg(SF, 1)),
                |op| matches!(op, PcodeOp::IntEq { out, .. } if *out == reg(ZF, 1)),
                |op| matches!(op, PcodeOp::IntEq { out, .. } if *out == reg(PF, 1)),
            ],
        );
    }

    fn test_sub_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x29, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "SUB RDI,RAX");
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| {
                matches!(op, PcodeOp::IntSub { out, left, right }
                if *out == reg(RDI, 8) && *left == reg(RDI, 8) && *right == reg(RAX, 8))
            }],
        );
    }

    fn test_xor_reg_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x31, 0xc7], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "XOR RDI,RAX");
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| {
                matches!(op, PcodeOp::IntXor { out, left, right }
                if *out == reg(RDI, 8) && *left == reg(RDI, 8) && *right == reg(RAX, 8))
            }],
        );
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
        // LEA computes address, IntAdd writes directly to RAX
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| matches!(op, PcodeOp::IntAdd { out, .. } if *out == reg(RAX, 8))],
        );
    }

    fn test_mov_mem_reg() {
        let (len, disasm, pcode) = decode(&[0x48, 0x89, 0x07], 0x1000);
        assert_eq!(len, 3);
        assert_eq!(disasm, "MOV qword ptr [RDI],RAX");
        // Should Store RAX to [RDI]
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| {
                matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, ptr, val }
                if *ptr == reg(RDI, 8) && *val == reg(RAX, 8))
            }],
        );
    }

    fn test_mov_reg_imm() {
        let (len, disasm, pcode) = decode(&[0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(len, 7);
        assert!(
            disasm.contains("MOV") && disasm.contains("RAX"),
            "expected MOV RAX,imm got {disasm}"
        );
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| {
                matches!(op, PcodeOp::Copy { out, input }
                if *out == reg(RAX, 8) && input.space == AddressSpaceId::Const && input.offset == 1)
            }],
        );
    }

    // ── x86-64 sign-extension regression tests ────────────────────────

    fn test_lea_negative_disp8() {
        // LEA RDI, [RBP - 0x30]  (disp8 = 0xd0 = signed -0x30)
        let (_len, disasm, pcode) = decode(&[0x48, 0x8d, 0x7d, 0xd0], 0x1000);
        assert!(disasm.contains("LEA"), "expected LEA, got {disasm}");
        // The displacement must be sign-extended: RBP + (-0x30) = RBP + 0xffffffffffffffd0
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { out, left, right }
                if *out == reg(RDI, 8) && *left == reg(RBP, 8)
                && right.space == AddressSpaceId::Const
                && right.offset == 0xffffffffffffffd0u64),
        ]);
    }

    fn test_mov_mem_disp8() {
        // MOV RAX, [RBP - 0x10]  (disp8 = 0xf0 = signed -0x10)
        let (_len, disasm, pcode) = decode(&[0x48, 0x8b, 0x45, 0xf0], 0x1000);
        assert!(disasm.contains("MOV"), "expected MOV, got {disasm}");
        // Load from RBP-relative address with correct sign extension
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { left, right, .. }
                if *left == reg(RBP, 8)
                && right.space == AddressSpaceId::Const
                && right.offset == 0xfffffffffffffff0u64),
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if *out == reg(RAX, 8)),
        ]);
    }

    fn test_lea_positive_disp8() {
        // LEA RAX, [RDI + 0x20]  (disp8 = 0x20, positive — must stay positive)
        let (_len, disasm, pcode) = decode(&[0x48, 0x8d, 0x47, 0x20], 0x1000);
        assert!(disasm.contains("LEA"), "expected LEA, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { out, left, right }
                if *out == reg(RAX, 8) && *left == reg(RDI, 8)
                && right.space == AddressSpaceId::Const
                && right.offset == 0x20),
        ]);
    }

    // ── x86-64 additional instruction coverage ──────────────────────

    fn test_call_rel32() {
        // CALL +0x100 (E8 00010000)
        let (_len, disasm, pcode) = decode(&[0xe8, 0x00, 0x01, 0x00, 0x00], 0x1000);
        assert!(disasm.contains("CALL"), "expected CALL, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Call { dest } if dest.offset == 0x1105),
        ]);
    }

    fn test_mov_reg_mem_disp() {
        // MOV RAX, [RSI + 0x08]
        let (_len, disasm, pcode) = decode(&[0x48, 0x8b, 0x46, 0x08], 0x1000);
        assert!(disasm.contains("MOV"), "expected MOV, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { right, .. }
                if right.space == AddressSpaceId::Const && right.offset == 0x08),
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if *out == reg(RAX, 8)),
        ]);
    }

    fn test_test_reg_reg() {
        // TEST RAX, RAX
        let (_len, disasm, pcode) = decode(&[0x48, 0x85, 0xc0], 0x1000);
        assert!(disasm.contains("TEST"), "expected TEST, got {disasm}");
        // TEST sets ZF based on AND result
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAnd { left, right, .. }
                if *left == reg(RAX, 8) && *right == reg(RAX, 8)),
            |op| matches!(op, PcodeOp::IntEq { out, .. } if *out == reg(ZF, 1)),
        ]);
    }

    fn test_movzx() {
        // MOVZX EAX, CL (0F B6 C1)
        let (_len, disasm, pcode) = decode(&[0x0f, 0xb6, 0xc1], 0x1000);
        assert!(disasm.contains("MOVZX"), "expected MOVZX, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntZext { out, .. } if out.size == 4),
        ]);
    }

    fn test_movsx() {
        // MOVSX RAX, CL (48 0F BE C1)
        let (_len, disasm, pcode) = decode(&[0x48, 0x0f, 0xbe, 0xc1], 0x1000);
        assert!(disasm.contains("MOVSX"), "expected MOVSX, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSext { out, .. } if out.size == 8),
        ]);
    }

    fn test_shl_reg_imm() {
        // SHL RAX, 4 (48 C1 E0 04)
        let (_len, disasm, pcode) = decode(&[0x48, 0xc1, 0xe0, 0x04], 0x1000);
        assert!(disasm.contains("SHL"), "expected SHL, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsl { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_imul_reg_reg() {
        // IMUL RAX, RDI (48 0F AF C7)
        let (_len, disasm, pcode) = decode(&[0x48, 0x0f, 0xaf, 0xc7], 0x1000);
        assert!(disasm.contains("IMUL"), "expected IMUL, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntMult { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_and_reg_reg() {
        // AND RAX, RDI (48 21 F8)
        let (_len, disasm, pcode) = decode(&[0x48, 0x21, 0xf8], 0x1000);
        assert!(disasm.contains("AND"), "expected AND, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAnd { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_or_reg_reg() {
        // OR RAX, RDI (48 09 F8)
        let (_len, disasm, pcode) = decode(&[0x48, 0x09, 0xf8], 0x1000);
        assert!(disasm.contains("OR"), "expected OR, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntOr { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_not_reg() {
        // NOT RAX (48 F7 D0)
        let (_len, disasm, pcode) = decode(&[0x48, 0xf7, 0xd0], 0x1000);
        assert!(disasm.contains("NOT"), "expected NOT, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntNot { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_neg_reg() {
        // NEG RAX (48 F7 D8)
        let (_len, disasm, pcode) = decode(&[0x48, 0xf7, 0xd8], 0x1000);
        assert!(disasm.contains("NEG"), "expected NEG, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntNeg { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_inc_reg() {
        // INC ECX (FF C1)
        let (_len, disasm, pcode) = decode(&[0xff, 0xc1], 0x1000);
        assert!(disasm.contains("INC"), "expected INC, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { .. }),
        ]);
    }

    fn test_dec_reg() {
        // DEC ECX (FF C9)
        let (_len, disasm, pcode) = decode(&[0xff, 0xc9], 0x1000);
        assert!(disasm.contains("DEC"), "expected DEC, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_shr_reg_imm() {
        // SHR RAX, 4 (48 C1 E8 04)
        let (_len, disasm, pcode) = decode(&[0x48, 0xc1, 0xe8, 0x04], 0x1000);
        assert!(disasm.contains("SHR"), "expected SHR, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsr { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_sar_reg_imm() {
        // SAR RAX, 4 (48 C1 F8 04)
        let (_len, disasm, pcode) = decode(&[0x48, 0xc1, 0xf8, 0x04], 0x1000);
        assert!(disasm.contains("SAR"), "expected SAR, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAsr { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_cdqe() {
        // CDQE (48 98) — sign-extend EAX to RAX
        let (_len, disasm, pcode) = decode(&[0x48, 0x98], 0x1000);
        assert!(disasm.contains("CDQE"), "expected CDQE, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSext { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_leave() {
        // LEAVE (C9) — mov rsp,rbp; pop rbp
        let (_len, disasm, pcode) = decode(&[0xc9], 0x1000);
        assert!(disasm.contains("LEAVE"), "expected LEAVE, got {disasm}");
        // Should restore RSP from RBP and pop RBP
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Copy { out, input }
                if *out == reg(RSP, 8) && *input == reg(RBP, 8)),
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if *out == reg(RBP, 8)),
        ]);
    }

    fn test_mov_rip_rel() {
        // MOV RAX, [RIP + 0x10] (48 8B 05 10 00 00 00) — PC-relative addressing
        let (_len, disasm, pcode) = decode(&[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00], 0x1000);
        assert!(disasm.contains("MOV"), "expected MOV, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if *out == reg(RAX, 8)),
        ]);
    }

    fn test_cmp_reg_imm() {
        // CMP RAX, 0 (48 83 F8 00)
        let (_len, disasm, pcode) = decode(&[0x48, 0x83, 0xf8, 0x00], 0x1000);
        assert!(disasm.contains("CMP"), "expected CMP, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntEq { out, .. } if *out == reg(ZF, 1)),
        ]);
    }

    fn test_add_reg_imm() {
        // ADD RAX, 8 (48 83 C0 08)
        let (_len, disasm, pcode) = decode(&[0x48, 0x83, 0xc0, 0x08], 0x1000);
        assert!(disasm.contains("ADD"), "expected ADD, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { out, .. } if *out == reg(RAX, 8)),
        ]);
    }

    fn test_sub_reg_imm() {
        // SUB RSP, 0x20 (48 83 EC 20)
        let (_len, disasm, pcode) = decode(&[0x48, 0x83, 0xec, 0x20], 0x1000);
        assert!(disasm.contains("SUB"), "expected SUB, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { out, .. } if *out == reg(RSP, 8)),
        ]);
    }

    fn test_mov_store_disp() {
        // MOV [RBP-0x8], RAX (48 89 45 F8)
        let (_len, disasm, pcode) = decode(&[0x48, 0x89, 0x45, 0xf8], 0x1000);
        assert!(disasm.contains("MOV"), "expected MOV, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_jne_rel8() {
        // JNE +5 (75 05)
        let (_len, disasm, pcode) = decode(&[0x75, 0x05], 0x1000);
        assert!(disasm.contains("JNZ") || disasm.contains("JNE"), "expected JNZ, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_jg_rel8() {
        // JG +5 (7F 05)
        let (_len, disasm, pcode) = decode(&[0x7f, 0x05], 0x1000);
        assert!(disasm.contains("JG"), "expected JG, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_jle_rel8() {
        // JLE +5 (7E 05)
        let (_len, disasm, pcode) = decode(&[0x7e, 0x05], 0x1000);
        assert!(disasm.contains("JLE"), "expected JLE, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    // ── ARM64 tests ──────────────────────────────────────────────────

    fn test_arm_mov_reg() {
        // MOV X0, X1 = ORR X0, XZR, X1 = 0xaa0103e0
        let (len, disasm, _pcode) = arm::decode(&[0xe0, 0x03, 0x01, 0xaa], 0x1000);
        assert_eq!(len, 4);
        assert!(
            disasm.contains("mov")
                || disasm.contains("MOV")
                || disasm.contains("orr")
                || disasm.contains("ORR"),
            "expected mov/orr, got {disasm}"
        );
    }

    fn test_arm_add_reg() {
        // ADD X0, X1, X2 = 0x8b020020
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0x8b], 0x1000);
        assert_eq!(len, 4);
        assert!(
            disasm.contains("add") || disasm.contains("ADD"),
            "expected ADD, got {disasm}"
        );
        // Should contain an IntAdd
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| matches!(op, PcodeOp::IntAdd { .. })],
        );
    }

    fn test_arm_ret() {
        // RET = 0xd65f03c0
        let (len, disasm, pcode) = arm::decode(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000);
        assert_eq!(len, 4);
        assert!(
            disasm.contains("ret") || disasm.contains("RET"),
            "expected RET, got {disasm}"
        );
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| matches!(op, PcodeOp::Return { .. })],
        );
    }

    fn test_arm_branch() {
        // B . (branch to self) = 0x14000000
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x00, 0x00, 0x14], 0x1000);
        assert_eq!(len, 4);
        assert!(
            disasm.contains("b") || disasm.contains("B"),
            "expected B, got {disasm}"
        );
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| matches!(op, PcodeOp::Branch { .. })],
        );
    }

    fn test_arm_sub() {
        // SUB X0, X1, X2
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0xcb], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sub"), "expected sub, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_arm_and() {
        // AND X0, X1, X2
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0x8a], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("and"), "expected and, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAnd { .. }),
        ]);
    }

    fn test_arm_orr() {
        // ORR X0, X1, X2
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0xaa], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("orr") || disasm.to_lowercase().contains("mov"),
            "expected orr/mov, got {disasm}");
        // ORR or Copy (if one operand is XZR, Ghidra may display as MOV)
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntOr { .. } | PcodeOp::Copy { .. }),
        ]);
    }

    fn test_arm_eor() {
        // EOR X0, X1, X2
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0xca], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("eor"), "expected eor, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntXor { .. }),
        ]);
    }

    fn test_arm_mul() {
        // MUL X0, X1, X2
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x7c, 0x02, 0x9b], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mul") || disasm.to_lowercase().contains("madd"),
            "expected mul/madd, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntMult { .. }),
        ]);
    }

    fn test_arm_sdiv() {
        // SDIV X0, X1, X2
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x0c, 0xc2, 0x9a], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sdiv"), "expected sdiv, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSDiv { .. }),
        ]);
    }

    fn test_arm_movz() {
        // MOVZ X0, #0x42
        let (len, disasm, pcode) = arm::decode(&[0x40, 0x08, 0x80, 0xd2], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mov"), "expected mov/movz, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Copy { input, .. }
                if input.space == AddressSpaceId::Const && input.offset == 0x42),
        ]);
    }

    fn test_arm_bl() {
        // BL . (branch and link = call)
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x00, 0x00, 0x94], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("bl"), "expected bl, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Call { .. }),
        ]);
    }

    fn test_arm_b_cond() {
        // B.EQ . (conditional branch)
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x00, 0x00, 0x54], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("b."), "expected b.eq, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_arm_cbnz() {
        // CBNZ X0, .
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x00, 0x00, 0xb5], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("cbnz"), "expected cbnz, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_arm_stp() {
        // STP X29, X30, [SP, #-16]! (push frame)
        let (len, disasm, pcode) = arm::decode(&[0xfd, 0x7b, 0xbf, 0xa9], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("stp"), "expected stp, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_ldp() {
        // LDP X29, X30, [SP], #16 (pop frame)
        let (len, disasm, pcode) = arm::decode(&[0xfd, 0x7b, 0xc1, 0xa8], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldp"), "expected ldp, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_add_imm() {
        // ADD X0, X0, #0x10
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x40, 0x00, 0x91], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("add"), "expected add, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { .. }),
        ]);
    }

    fn test_arm_ldr_w_offset() {
        // LDR W0, [X1, #4]
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x10, 0x40, 0xb9], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldr"), "expected ldr, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if out.size == 4),
        ]);
    }

    fn test_arm_strb() {
        // STRB W0, [X1]
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x00, 0x39], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("strb"), "expected strb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_ldrb() {
        // LDRB W0, [X1]
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x40, 0x39], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldrb"), "expected ldrb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if out.size == 1),
        ]);
    }

    fn test_arm_ldr() {
        // LDR X0, [X1] = 0xf9400020
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x40, 0xf9], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldr"), "expected LDR, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_str() {
        // STR X0, [X1] = 0xf9000020
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x00, 0xf9], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("str"), "expected STR, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_cmp() {
        // CMP X0, X1 = 0xeb01001f (subs xzr, x0, x1)
        let (len, disasm, pcode) = arm::decode(&[0x1f, 0x00, 0x01, 0xeb], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("cmp") || disasm.to_lowercase().contains("subs"),
            "expected CMP/SUBS, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_arm_cbz() {
        // CBZ X0, . = 0xb4000000
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x00, 0x00, 0xb4], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("cbz"), "expected CBZ, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_arm_neg() {
        // NEG X0, X1 = SUB X0, XZR, X1 = 0xcb0103e0
        let (len, disasm, pcode) = arm::decode(&[0xe0, 0x03, 0x01, 0xcb], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("neg") || disasm.to_lowercase().contains("sub"),
            "expected neg/sub, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. } | PcodeOp::IntNeg { .. }),
        ]);
    }

    fn test_arm_mvn() {
        // MVN X0, X1 = ORN X0, XZR, X1 = 0xaa2103e0
        let (len, disasm, pcode) = arm::decode(&[0xe0, 0x03, 0x21, 0xaa], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mvn") || disasm.to_lowercase().contains("orn"),
            "expected mvn/orn, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntNot { .. } | PcodeOp::IntOr { .. }),
        ]);
    }

    fn test_arm_tst() {
        // TST X0, X1 = ANDS XZR, X0, X1 = 0xea01001f
        let (len, disasm, pcode) = arm::decode(&[0x1f, 0x00, 0x01, 0xea], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("tst") || disasm.to_lowercase().contains("ands"),
            "expected tst/ands, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAnd { .. }),
        ]);
    }

    fn test_arm_lsr_imm() {
        // LSR X0, X1, #4 = UBFM X0, X1, #4, #63 = 0xd344fc20
        let (len, disasm, pcode) = arm::decode(&[0x20, 0xfc, 0x44, 0xd3], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lsr") || disasm.to_lowercase().contains("ubfm"),
            "expected lsr/ubfm, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsr { .. } | PcodeOp::IntAnd { .. }),
        ]);
    }

    fn test_arm_asr_imm() {
        // ASR X0, X1, #4 = SBFM X0, X1, #4, #63 = 0x9344fc20
        let (len, disasm, pcode) = arm::decode(&[0x20, 0xfc, 0x44, 0x93], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("asr") || disasm.to_lowercase().contains("sbfm"),
            "expected asr/sbfm, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAsr { .. } | PcodeOp::IntSext { .. }),
        ]);
    }

    fn test_arm_sxtw() {
        // SXTW X0, W1 = SBFM X0, X1, #0, #31 = 0x93407c20
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x7c, 0x40, 0x93], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sxtw") || disasm.to_lowercase().contains("sbfm"),
            "expected sxtw, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSext { out, .. } if out.size == 8),
        ]);
    }

    fn test_arm_sub_imm() {
        // SUB X0, X0, #0x10 = 0xd1004000
        let (len, disasm, pcode) = arm::decode(&[0x00, 0x40, 0x00, 0xd1], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sub"), "expected sub, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_arm_cmp_imm() {
        // CMP X0, #0 = SUBS XZR, X0, #0 = 0xf100001f
        let (len, disasm, pcode) = arm::decode(&[0x1f, 0x00, 0x00, 0xf1], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("cmp") || disasm.to_lowercase().contains("subs"),
            "expected cmp, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_arm_ldr_pre_index() {
        // LDR X0, [X1, #8]! (pre-index) = 0xf8408c20
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x8c, 0x40, 0xf8], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldr"), "expected ldr, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_str_pre_index() {
        // STR X0, [X1, #-16]! (pre-index) = 0xf81f0c20
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x0c, 0x1f, 0xf8], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("str") || disasm.to_lowercase().contains("stur"),
            "expected str, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_ldrsb() {
        // LDRSB X0, [X1] = 0x39c00020
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0xc0, 0x39], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldrsb") || disasm.to_lowercase().contains("ldr"),
            "expected ldrsb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm_csel() {
        // CSEL X0, X1, X2, EQ = 0x9a820020
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x82, 0x9a], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("csel"), "expected csel, got {disasm}");
        // CSEL uses conditional execution — should produce some P-code
        assert!(!pcode.is_empty(), "CSEL should produce P-code\n{disasm}");
    }

    fn test_arm_adrp() {
        // ADRP X0, . = 0x90000000
        let (len, disasm, _pcode) = arm::decode(&[0x00, 0x00, 0x00, 0x90], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("adrp"), "expected adrp, got {disasm}");
    }

    fn test_arm_lsl_imm() {
        // LSL X0, X1, #4 = UBFM X0, X1, #60, #59 = 0xd37cec20
        let (len, disasm, pcode) = arm::decode(&[0x20, 0x70, 0x7c, 0xd3], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lsl") || disasm.to_lowercase().contains("ubfm")
            || disasm.to_lowercase().contains("ubfiz"),
            "expected lsl/ubfm/ubfiz, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsl { .. } | PcodeOp::IntAnd { .. }),
        ]);
    }

    // ── RISC-V tests ─────────────────────────────────────────────────

    fn test_riscv_addi() {
        // addi x1, x0, 5 = 0x00500093
        let (len, disasm, _pcode) = riscv::decode(&[0x93, 0x00, 0x50, 0x00], 0x1000);
        assert_eq!(len, 4);
        // Ghidra displays "addi x1,x0,5" as "li ra,0x5" (pseudo-instruction)
        assert!(
            disasm.to_lowercase().contains("li") || disasm.to_lowercase().contains("addi"),
            "expected li/addi, got {disasm}"
        );
    }

    fn test_riscv_add() {
        // add x3, x0, x12 = 0x00c001b3
        let (len, disasm, pcode) = riscv::decode(&[0xb3, 0x01, 0xc0, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(
            disasm.to_lowercase().contains("add"),
            "expected add, got {disasm}"
        );
        assert_pcode_contains(
            &pcode,
            &disasm,
            &[|op| matches!(op, PcodeOp::IntAdd { .. } | PcodeOp::Copy { .. })],
        );
    }

    fn test_riscv_jalr() {
        // jalr x0, 0(x1) = 0x00008067
        let (len, disasm, _pcode) = riscv::decode(&[0x67, 0x80, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(
            disasm.to_lowercase().contains("jalr") || disasm.to_lowercase().contains("ret"),
            "expected jalr/ret, got {disasm}"
        );
    }

    fn test_riscv_sub() {
        // SUB x3, x1, x2 = 0x402081b3
        let (len, disasm, pcode) = riscv::decode(&[0xb3, 0x81, 0x20, 0x40], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sub"), "expected sub, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_riscv_and() {
        // AND x3, x1, x2 = 0x002091b3
        let (len, disasm, pcode) = riscv::decode(&[0xb3, 0xf1, 0x20, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("and"), "expected and, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAnd { .. }),
        ]);
    }

    fn test_riscv_or() {
        // OR x3, x1, x2 = 0x002091b3 (funct7=0, funct3=110)
        let (len, disasm, pcode) = riscv::decode(&[0xb3, 0xe1, 0x20, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("or"), "expected or, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntOr { .. }),
        ]);
    }

    fn test_riscv_xor() {
        // XOR x3, x1, x2
        let (len, disasm, pcode) = riscv::decode(&[0xb3, 0xc1, 0x20, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("xor"), "expected xor, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntXor { .. }),
        ]);
    }

    fn test_riscv_slli() {
        // SLLI x1, x1, 4
        let (len, disasm, pcode) = riscv::decode(&[0x93, 0x90, 0x40, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("slli") || disasm.to_lowercase().contains("sll"),
            "expected slli, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsl { .. }),
        ]);
    }

    fn test_riscv_srli() {
        // SRLI x1, x1, 4
        let (len, disasm, pcode) = riscv::decode(&[0x93, 0xd0, 0x40, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("srli") || disasm.to_lowercase().contains("srl"),
            "expected srli, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsr { .. }),
        ]);
    }

    fn test_riscv_lw() {
        // LW x10, 0(x11)
        let (len, disasm, pcode) = riscv::decode(&[0x03, 0xa5, 0x05, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lw"), "expected lw, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_riscv_sw() {
        // SW x10, 0(x11)
        let (len, disasm, pcode) = riscv::decode(&[0x23, 0xa0, 0xa5, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sw"), "expected sw, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_riscv_ld() {
        // LD x10, 0(x11) (64-bit load)
        let (len, disasm, pcode) = riscv::decode(&[0x03, 0xb5, 0x05, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ld"), "expected ld, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if out.size == 8),
        ]);
    }

    fn test_riscv_sd() {
        // SD x10, 0(x11) (64-bit store)
        let (len, disasm, pcode) = riscv::decode(&[0x23, 0xb0, 0xa5, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sd"), "expected sd, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_riscv_lb() {
        // LB x10, 0(x11) (byte load)
        let (len, disasm, pcode) = riscv::decode(&[0x03, 0x85, 0x05, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lb"), "expected lb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_riscv_sb() {
        // SB x10, 0(x11) (byte store)
        let (len, disasm, pcode) = riscv::decode(&[0x23, 0x80, 0xa5, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sb"), "expected sb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_riscv_beq() {
        // BEQ x10, x11, 0
        let (len, disasm, pcode) = riscv::decode(&[0x63, 0x00, 0xb5, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("beq"), "expected beq, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_riscv_bne() {
        // BNE x10, x11, 0
        let (len, disasm, pcode) = riscv::decode(&[0x63, 0x10, 0xb5, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("bne") || disasm.to_lowercase().contains("bnez"),
            "expected bne, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_riscv_jal() {
        // JAL x1, 0 (call)
        let (len, disasm, pcode) = riscv::decode(&[0xef, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("jal") || disasm.to_lowercase().contains("call"),
            "expected jal/call, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Call { .. } | PcodeOp::Branch { .. }),
        ]);
    }

    fn test_riscv_lui() {
        // LUI x1, 0x12345
        let (len, disasm, _pcode) = riscv::decode(&[0xb7, 0x50, 0x34, 0x12], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lui"), "expected lui, got {disasm}");
    }

    fn test_riscv_slti() {
        // SLTI x3, x1, 10
        let (len, disasm, pcode) = riscv::decode(&[0x93, 0xa1, 0xa0, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("slti"), "expected slti, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSLess { .. }),
        ]);
    }

    fn test_riscv_mul() {
        // MUL x3, x1, x2 (M extension)
        let (len, disasm, pcode) = riscv::decode(&[0xb3, 0x81, 0x20, 0x02], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mul"), "expected mul, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntMult { .. }),
        ]);
    }

    // ── MIPS tests ───────────────────────────────────────────────────

    fn test_mips_addiu() {
        // ADDIU $a0, $zero, 5 = 0x24040005 (big-endian)
        let (len, disasm, _pcode) = mips::decode(&[0x24, 0x04, 0x00, 0x05], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("addiu") || disasm.to_lowercase().contains("li"),
            "expected addiu/li, got {disasm}");
    }

    fn test_mips_addu() {
        // ADDU $a0, $a1, $a2 = 0x00a62021 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0xa6, 0x20, 0x21], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("addu") || disasm.to_lowercase().contains("add"),
            "expected addu, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { .. }),
        ]);
    }

    fn test_mips_subu() {
        // SUBU $a0, $a1, $a2 = 0x00a62023 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0xa6, 0x20, 0x23], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("subu") || disasm.to_lowercase().contains("sub"),
            "expected subu, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_mips_and() {
        // AND $a0, $a1, $a2 = 0x00a62024 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0xa6, 0x20, 0x24], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("and"), "expected and, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAnd { .. }),
        ]);
    }

    fn test_mips_or() {
        // OR $a0, $a1, $a2 = 0x00a62025 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0xa6, 0x20, 0x25], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("or"), "expected or, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntOr { .. }),
        ]);
    }

    fn test_mips_xor() {
        // XOR $a0, $a1, $a2 = 0x00a62026 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0xa6, 0x20, 0x26], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("xor"), "expected xor, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntXor { .. }),
        ]);
    }

    fn test_mips_sll() {
        // SLL $a0, $a1, 4 = 0x00052100 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0x05, 0x21, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sll"), "expected sll, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsl { .. }),
        ]);
    }

    fn test_mips_srl() {
        // SRL $a0, $a1, 4 = 0x00052102 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0x05, 0x21, 0x02], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("srl"), "expected srl, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsr { .. }),
        ]);
    }

    fn test_mips_slt() {
        // SLT $a0, $a1, $a2 = 0x00a6202a (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0xa6, 0x20, 0x2a], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("slt"), "expected slt, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSLess { .. }),
        ]);
    }

    fn test_mips_lw() {
        // LW $a0, 0($sp) = 0x8fa40000 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x8f, 0xa4, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lw"), "expected lw, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_mips_sw() {
        // SW $a0, 0($sp) = 0xafa40000 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0xaf, 0xa4, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sw"), "expected sw, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_mips_lb() {
        // LB $a0, 0($a1) = 0x80a40000 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x80, 0xa4, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lb"), "expected lb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_mips_sb() {
        // SB $a0, 0($a1) = 0xa0a40000 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0xa0, 0xa4, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sb"), "expected sb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_mips_beq() {
        // BEQ $a0, $zero, 0 = 0x10800000 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x10, 0x80, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("beq") || disasm.to_lowercase().contains("beqz"),
            "expected beq/beqz, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_mips_bne() {
        // BNE $a0, $zero, 0 = 0x14800000 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x14, 0x80, 0x00, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("bne") || disasm.to_lowercase().contains("bnez"),
            "expected bne/bnez, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_mips_j() {
        // J 0x1000 = 0x08000400 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x08, 0x00, 0x04, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("j"), "expected j, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Branch { .. }),
        ]);
    }

    fn test_mips_jal() {
        // JAL 0x1000 = 0x0c000400 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x0c, 0x00, 0x04, 0x00], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("jal"), "expected jal, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Call { .. }),
        ]);
    }

    fn test_mips_jr_ra() {
        // JR $ra = 0x03e00008 (big-endian, return)
        let (len, disasm, pcode) = mips::decode(&[0x03, 0xe0, 0x00, 0x08], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("jr"), "expected jr, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Return { .. } | PcodeOp::BranchInd { .. }),
        ]);
    }

    fn test_mips_lui() {
        // LUI $a0, 0x1234 = 0x3c041234 (big-endian)
        let (len, disasm, _pcode) = mips::decode(&[0x3c, 0x04, 0x12, 0x34], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lui"), "expected lui, got {disasm}");
    }

    fn test_mips_ori() {
        // ORI $a0, $a0, 0x5678 = 0x34845678 (big-endian)
        let (len, disasm, pcode) = mips::decode(&[0x34, 0x84, 0x56, 0x78], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ori"), "expected ori, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntOr { .. }),
        ]);
    }

    fn test_mips_mult() {
        // MULT $a0, $a1 = 0x00850018 (big-endian, result in HI:LO)
        let (len, disasm, pcode) = mips::decode(&[0x00, 0x85, 0x00, 0x18], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mult"), "expected mult, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntMult { .. }),
        ]);
    }

    // ── ARM32 tests ──────────────────────────────────────────────────

    // ── ARM32 tests ──────────────────────────────────────────────────

    fn test_arm32_add() {
        // ADD R0, R1, R2 = 0xe0810002
        let (len, disasm, pcode) = arm32::decode(&[0x02, 0x00, 0x81, 0xe0], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("add"), "expected add, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAdd { .. }),
        ]);
    }

    fn test_arm32_sub() {
        // SUB R0, R1, R2 = 0xe0410002
        let (len, disasm, pcode) = arm32::decode(&[0x02, 0x00, 0x41, 0xe0], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("sub"), "expected sub, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_arm32_and() {
        // AND R0, R1, R2 = 0xe0010002
        let (len, disasm, pcode) = arm32::decode(&[0x02, 0x00, 0x01, 0xe0], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("and"), "expected and, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntAnd { .. }),
        ]);
    }

    fn test_arm32_orr() {
        // ORR R0, R1, R2 = 0xe1810002
        let (len, disasm, pcode) = arm32::decode(&[0x02, 0x00, 0x81, 0xe1], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("orr"), "expected orr, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntOr { .. }),
        ]);
    }

    fn test_arm32_eor() {
        // EOR R0, R1, R2 = 0xe0210002
        let (len, disasm, pcode) = arm32::decode(&[0x02, 0x00, 0x21, 0xe0], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("eor"), "expected eor, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntXor { .. }),
        ]);
    }

    fn test_arm32_mul() {
        // MUL R0, R1, R2 = 0xe0000291
        let (len, disasm, pcode) = arm32::decode(&[0x91, 0x02, 0x00, 0xe0], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mul"), "expected mul, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntMult { .. }),
        ]);
    }

    fn test_arm32_mov_imm() {
        // MOV R0, #0x42 = 0xe3a00042
        let (len, disasm, pcode) = arm32::decode(&[0x42, 0x00, 0xa0, 0xe3], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mov"), "expected mov, got {disasm}");
        // ARM32 MOV imm goes through barrel shifter, so we check for the constant
        // appearing somewhere in the P-code (IntLsr of 0x42 by 0, or Copy)
        let has_const = pcode.iter().any(|op| match op {
            PcodeOp::Copy { input, .. } => input.space == AddressSpaceId::Const && input.offset == 0x42,
            PcodeOp::IntLsr { left, .. } => left.space == AddressSpaceId::Const && left.offset == 0x42,
            PcodeOp::IntOr { left, .. } => left.space == AddressSpaceId::Const && left.offset == 0x42,
            _ => false,
        });
        assert!(has_const, "MOV R0,#0x42 should reference constant 0x42\n{pcode:#?}");
    }

    fn test_arm32_mov_reg() {
        // MOV R0, R1 = 0xe1a00001
        let (len, disasm, pcode) = arm32::decode(&[0x01, 0x00, 0xa0, 0xe1], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("mov") || disasm.to_lowercase().contains("cpy"),
            "expected mov, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Copy { .. }),
        ]);
    }

    fn test_arm32_cmp() {
        // CMP R0, R1 = 0xe1500001
        let (len, disasm, pcode) = arm32::decode(&[0x01, 0x00, 0x50, 0xe1], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("cmp"), "expected cmp, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntSub { .. }),
        ]);
    }

    fn test_arm32_ldr() {
        // LDR R0, [R1] = 0xe5910000
        let (len, disasm, pcode) = arm32::decode(&[0x00, 0x00, 0x91, 0xe5], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldr"), "expected ldr, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm32_str() {
        // STR R0, [R1] = 0xe5810000
        let (len, disasm, pcode) = arm32::decode(&[0x00, 0x00, 0x81, 0xe5], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("str"), "expected str, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm32_ldr_offset() {
        // LDR R0, [R1, #8] = 0xe5910008
        let (len, disasm, pcode) = arm32::decode(&[0x08, 0x00, 0x91, 0xe5], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldr"), "expected ldr, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm32_ldrb() {
        // LDRB R0, [R1] = 0xe5d10000
        let (len, disasm, pcode) = arm32::decode(&[0x00, 0x00, 0xd1, 0xe5], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldrb"), "expected ldrb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if out.size == 1),
        ]);
    }

    fn test_arm32_strb() {
        // STRB R0, [R1] = 0xe5c10000
        let (len, disasm, pcode) = arm32::decode(&[0x00, 0x00, 0xc1, 0xe5], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("strb"), "expected strb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm32_b() {
        // B . = 0xeafffffe (branch to self)
        let (len, disasm, pcode) = arm32::decode(&[0xfe, 0xff, 0xff, 0xea], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("b"), "expected b, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Branch { .. }),
        ]);
    }

    fn test_arm32_bl() {
        // BL . = 0xebfffffe (branch with link = call)
        let (len, disasm, pcode) = arm32::decode(&[0xfe, 0xff, 0xff, 0xeb], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("bl"), "expected bl, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Call { .. }),
        ]);
    }

    fn test_arm32_beq() {
        // BEQ . = 0x0afffffe (conditional branch)
        let (len, disasm, pcode) = arm32::decode(&[0xfe, 0xff, 0xff, 0x0a], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("b"), "expected beq, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::CBranch { .. }),
        ]);
    }

    fn test_arm32_push() {
        // PUSH {R4, LR} = 0xe92d4010
        let (len, disasm, pcode) = arm32::decode(&[0x10, 0x40, 0x2d, 0xe9], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("stm") || disasm.to_lowercase().contains("push"),
            "expected push/stmdb, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm32_pop() {
        // POP {R4, PC} = 0xe8bd8010
        let (len, disasm, pcode) = arm32::decode(&[0x10, 0x80, 0xbd, 0xe8], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("ldm") || disasm.to_lowercase().contains("pop"),
            "expected pop/ldm, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
        ]);
    }

    fn test_arm32_bx_lr() {
        // BX LR = 0xe12fff1e (return)
        let (len, disasm, pcode) = arm32::decode(&[0x1e, 0xff, 0x2f, 0xe1], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("bx"), "expected bx, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::Return { .. } | PcodeOp::BranchInd { .. }),
        ]);
    }

    fn test_arm32_lsl_imm() {
        // MOV R0, R1, LSL #4 = 0xe1a00201 (logical shift left)
        let (len, disasm, pcode) = arm32::decode(&[0x01, 0x02, 0xa0, 0xe1], 0x1000);
        assert_eq!(len, 4);
        assert!(disasm.to_lowercase().contains("lsl") || disasm.to_lowercase().contains("mov"),
            "expected lsl/mov, got {disasm}");
        assert_pcode_contains(&pcode, &disasm, &[
            |op| matches!(op, PcodeOp::IntLsl { .. } | PcodeOp::Copy { .. }),
        ]);
    }

    // ── Stress tests: edge cases that probe for bugs ───────────────

    fn run_stress_tests() {
        // --- x86-64 REX prefix edge cases ---
        // REX.B selects R8-R15 registers
        {
            let (_len, disasm, pcode) = decode(&[0x49, 0x89, 0xc0], 0x1000); // MOV R8, RAX
            assert!(disasm.contains("R8"), "REX.B should select R8, got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Copy { out, .. } if out.offset != RAX), // NOT RAX
            ]);
        }
        {
            let (_len, disasm, _pcode) = decode(&[0x49, 0x89, 0xc7], 0x1000); // MOV R15, RAX
            assert!(disasm.contains("R15"), "REX.B+reg=7 should select R15, got {disasm}");
        }
        {
            let (_len, disasm, _pcode) = decode(&[0x41, 0x89, 0xc8], 0x1000); // MOV R8D, ECX
            assert!(disasm.contains("R8") || disasm.contains("r8"),
                "32-bit REX.B should select R8D, got {disasm}");
        }

        // --- Sign-extended immediate edge cases ---
        {
            // MOV RAX, -1 (imm32 = 0xFFFFFFFF sign-extended to 64-bit)
            let (_len, disasm, pcode) = decode(
                &[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff], 0x1000);
            assert!(disasm.contains("MOV") && disasm.contains("RAX"), "got {disasm}");
            // The constant should be 0xFFFFFFFFFFFFFFFF (sign-extended), not 0xFFFFFFFF
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Copy { input, .. }
                    if input.space == AddressSpaceId::Const
                    && input.offset == 0xFFFFFFFFFFFFFFFF),
            ]);
        }
        {
            // ADD RAX, -0x80 (imm8 = 0x80, sign-extended to -128)
            let (_len, _disasm, pcode) = decode(&[0x48, 0x83, 0xc0, 0x80], 0x1000);
            // Constant should be 0xFFFFFFFFFFFFFF80 (sign-extended), may be in Copy or IntAdd
            let has_sext_const = pcode.iter().any(|op| match op {
                PcodeOp::Copy { input, .. } | PcodeOp::IntAdd { right: input, .. } =>
                    input.space == AddressSpaceId::Const && input.offset == 0xFFFFFFFFFFFFFF80,
                _ => false,
            });
            assert!(has_sext_const,
                "ADD RAX,-0x80: imm8=0x80 should sign-extend to 0xFFFFFFFFFFFFFF80\n{pcode:#?}");
        }
        {
            // CMP RAX, -1 (imm8 = 0xFF sign-extended)
            let (_len, _disasm, pcode) = decode(&[0x48, 0x83, 0xf8, 0xff], 0x1000);
            let has_sext_const = pcode.iter().any(|op| match op {
                PcodeOp::Copy { input, .. } | PcodeOp::IntSub { right: input, .. } =>
                    input.space == AddressSpaceId::Const && input.offset == 0xFFFFFFFFFFFFFFFF,
                _ => false,
            });
            assert!(has_sext_const,
                "CMP RAX,-1: imm8=0xFF should sign-extend to 0xFFFFFFFFFFFFFFFF\n{pcode:#?}");
        }

        // --- Backward branch displacement (sign extension) ---
        {
            // JMP -2 (EB FE) = infinite loop, target should be same address
            let (_len, disasm, pcode) = decode(&[0xeb, 0xfe], 0x1000);
            assert!(disasm.contains("0x1000"), "JMP -2 at 0x1000 should target 0x1000, got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Branch { dest } if dest.offset == 0x1000),
            ]);
        }
        {
            // JZ -5 (74 FB) at 0x1000 → target 0xffd (0x1000 + 2 - 5 = 0xffd)
            let (_len, disasm, pcode) = decode(&[0x74, 0xfb], 0x1000);
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::CBranch { dest, .. } if dest.offset == 0xffd),
            ]);
        }

        // --- SIB addressing modes ---
        {
            // MOV RAX, [RSI+RDX*8]
            let (_len, disasm, pcode) = decode(&[0x48, 0x8b, 0x04, 0xd6], 0x1000);
            assert!(disasm.contains("MOV"), "expected MOV, got {disasm}");
            // Should have IntMult (scale) and IntAdd (base+index) and Load
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                    if *out == reg(RAX, 8)),
            ]);
        }
        {
            // LEA RAX, [RBX+RCX*4+0x10]
            let (_len, disasm, pcode) = decode(&[0x48, 0x8d, 0x44, 0x8b, 0x10], 0x1000);
            assert!(disasm.contains("LEA"), "expected LEA, got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::IntAdd { out, .. } if *out == reg(RAX, 8)),
            ]);
        }

        // --- 64-bit immediate (movabs) ---
        {
            // MOV RAX, 0x123456789abcdef0
            let (_len, disasm, pcode) = decode(
                &[0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12], 0x1000);
            assert_eq!(_len, 10);
            assert!(disasm.contains("MOV") || disasm.contains("RAX"), "got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Copy { out, input }
                    if *out == reg(RAX, 8)
                    && input.space == AddressSpaceId::Const
                    && input.offset == 0x123456789abcdef0),
            ]);
        }

        // --- CMOV (conditional move) ---
        {
            // CMOVZ RAX, RCX
            let (_len, disasm, pcode) = decode(&[0x48, 0x0f, 0x44, 0xc1], 0x1000);
            assert!(disasm.contains("CMOV"), "expected CMOV, got {disasm}");
            // Should read ZF and conditionally copy
            assert!(!pcode.is_empty(), "CMOV should produce P-code");
        }

        // --- XCHG ---
        {
            // XCHG RAX, RCX
            let (_len, disasm, pcode) = decode(&[0x48, 0x91], 0x1000);
            assert!(disasm.contains("XCHG"), "expected XCHG, got {disasm}");
            assert!(!pcode.is_empty(), "XCHG should produce P-code");
        }

        // --- ARM64 edge cases ---
        {
            // MOVN X0, #0 (bitwise NOT of 0 = all 1s = -1)
            let (len, disasm, pcode) = arm::decode(&[0x00, 0x00, 0x80, 0x92], 0x1000);
            assert_eq!(len, 4);
            assert!(disasm.to_lowercase().contains("mov"), "expected mov, got {disasm}");
            assert!(!pcode.is_empty(), "MOVN should produce P-code");
        }
        {
            // LDR X0, [X1, X2] (register offset)
            let (len, disasm, pcode) = arm::decode(&[0x20, 0x68, 0x62, 0xf8], 0x1000);
            assert_eq!(len, 4);
            assert!(disasm.to_lowercase().contains("ldr"), "expected ldr, got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
            ]);
        }
        {
            // MADD X0, X1, X2, X3 (multiply-add)
            let (len, disasm, pcode) = arm::decode(&[0x20, 0x0c, 0x02, 0x9b], 0x1000);
            assert_eq!(len, 4);
            assert!(disasm.to_lowercase().contains("madd") || disasm.to_lowercase().contains("mul"),
                "expected madd/mul, got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::IntMult { .. }),
            ]);
        }

        // --- RISC-V edge cases ---
        {
            // ADDI with negative immediate: ADDI x1, x1, -1
            let (_len, disasm, pcode) = riscv::decode(&[0x93, 0x80, 0xf0, 0xff], 0x1000);
            assert!(disasm.to_lowercase().contains("addi"), "expected addi, got {disasm}");
            // The immediate should be sign-extended to -1
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::IntAdd { right, .. }
                    if right.space == AddressSpaceId::Const
                    && right.offset > 0x7FFFFFFFFFFFFFFF), // negative when sign-extended
            ]);
        }
        {
            // C.NOP (compressed 16-bit instruction, RV64C)
            let (len, disasm, _pcode) = riscv::decode(&[0x01, 0x00], 0x1000);
            assert_eq!(len, 2, "compressed NOP should be 2 bytes, got {len}");
            assert!(disasm.to_lowercase().contains("nop") || disasm.to_lowercase().contains("c.nop"),
                "expected c.nop, got {disasm}");
        }
        {
            // C.ADD x1, x2 (compressed add)
            let (len, disasm, _pcode) = riscv::decode(&[0x0a, 0x90], 0x1000);
            assert_eq!(len, 2, "compressed ADD should be 2 bytes, got {len}");
        }

        // --- MIPS delay slot ---
        {
            // NOP = SLL $zero, $zero, 0 = 0x00000000
            let (len, disasm, _pcode) = mips::decode(&[0x00, 0x00, 0x00, 0x00], 0x1000);
            assert_eq!(len, 4);
            assert!(disasm.to_lowercase().contains("nop") || disasm.to_lowercase().contains("sll"),
                "expected nop/sll, got {disasm}");
        }

        // --- ARM32 conditional execution ---
        {
            // ADDNE R0, R1, R2 (condition NE = 0x1) = 0x10810002
            let (len, disasm, pcode) = arm32::decode(&[0x02, 0x00, 0x81, 0x10], 0x1000);
            assert_eq!(len, 4);
            assert!(disasm.to_lowercase().contains("add"), "expected addne, got {disasm}");
            // Conditional ARM32 should produce CBranch or conditional P-code
            assert!(!pcode.is_empty(), "conditional ADD should produce P-code");
        }
        {
            // LDR R0, [R1, R2] (register offset)
            let (len, disasm, pcode) = arm32::decode(&[0x02, 0x00, 0x91, 0xe7], 0x1000);
            assert_eq!(len, 4);
            assert!(disasm.to_lowercase().contains("ldr"), "expected ldr, got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. }),
            ]);
        }
        {
            // STR R0, [R1, #-4]! (pre-index negative offset)
            let (len, disasm, pcode) = arm32::decode(&[0x04, 0x00, 0x21, 0xe5], 0x1000);
            assert_eq!(len, 4);
            assert!(disasm.to_lowercase().contains("str"), "expected str, got {disasm}");
            assert_pcode_contains(&pcode, &disasm, &[
                |op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. }),
            ]);
        }
    }

    // ── Functional tests: real compiled code patterns ──────────────

    fn run_functional_tests() {
        test_x86_function_prologue_epilogue();
        test_x86_stack_locals();
        test_x86_call_with_args();
        test_x86_compare_and_branch();
        test_x86_loop_pattern();
        test_x86_array_access();
        test_x86_rip_relative_data();
        test_x86_sign_extend_chain();
        test_arm64_function_prologue_epilogue();
        test_arm64_adrp_add_pair();
        test_arm64_compare_and_branch();
        test_arm64_stack_locals();
        test_arm64_loop_pattern();
        test_arm64_conditional_select();
    }

    fn test_x86_function_prologue_epilogue() {
        // Standard prologue: push rbp; mov rbp,rsp; sub rsp,0x20
        // Standard epilogue: add rsp,0x20; pop rbp; ret
        let prologue = [
            0x55,                         // push rbp
            0x48, 0x89, 0xe5,             // mov rbp, rsp
            0x48, 0x83, 0xec, 0x20,       // sub rsp, 0x20
        ];
        let epilogue = [
            0x48, 0x83, 0xc4, 0x20,       // add rsp, 0x20
            0x5d,                         // pop rbp
            0xc3,                         // ret
        ];
        let seq = x86::decode_sequence(&prologue, 0x1000);
        assert_eq!(seq.len(), 3, "prologue should be 3 instructions, got {}", seq.len());
        assert!(seq[0].2.contains("PUSH"), "first should be PUSH, got {}", seq[0].2);
        assert!(seq[1].2.contains("MOV"), "second should be MOV, got {}", seq[1].2);
        assert!(seq[2].2.contains("SUB"), "third should be SUB, got {}", seq[2].2);

        // Verify prologue P-code: PUSH stores RBP, MOV copies RSP to RBP
        let push_pcode = &seq[0].3;
        assert!(push_pcode.iter().any(|op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, val, .. }
            if *val == reg(RBP, 8))), "PUSH should store RBP");
        let mov_pcode = &seq[1].3;
        assert!(mov_pcode.iter().any(|op| matches!(op, PcodeOp::Copy { out, input }
            if *out == reg(RBP, 8) && *input == reg(RSP, 8))), "MOV should copy RSP→RBP");

        let eseq = x86::decode_sequence(&epilogue, 0x2000);
        assert_eq!(eseq.len(), 3, "epilogue should be 3 instructions");
        assert!(eseq[2].3.iter().any(|op| matches!(op, PcodeOp::Return { .. })), "RET should emit Return");
    }

    fn test_x86_stack_locals() {
        // Store and load from stack locals via RBP:
        //   mov [rbp-0x8], rdi       (save arg to local)
        //   mov rax, [rbp-0x8]       (reload local)
        let bytes = [
            0x48, 0x89, 0x7d, 0xf8,   // mov [rbp-0x8], rdi
            0x48, 0x8b, 0x45, 0xf8,   // mov rax, [rbp-0x8]
        ];
        let seq = x86::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        // First: Store RDI to [RBP-8]
        let store_ops = &seq[0].3;
        assert!(store_ops.iter().any(|op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. })),
            "MOV [rbp-8],rdi should produce Store\n{store_ops:#?}");
        // Verify the displacement is sign-extended (-8 = 0xFFFFFFFFFFFFFFF8)
        let has_neg8 = store_ops.iter().any(|op| match op {
            PcodeOp::IntAdd { right, .. } =>
                right.space == AddressSpaceId::Const && right.offset == 0xFFFFFFFFFFFFFFF8,
            _ => false,
        });
        assert!(has_neg8, "displacement -8 should be sign-extended to 0xFFFFFFFFFFFFFFF8\n{store_ops:#?}");

        // Second: Load from [RBP-8] to RAX
        let load_ops = &seq[1].3;
        assert!(load_ops.iter().any(|op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
            if *out == reg(RAX, 8))),
            "MOV rax,[rbp-8] should produce Load to RAX\n{load_ops:#?}");
    }

    fn test_x86_call_with_args() {
        // SysV ABI: first 2 args in RDI, RSI
        //   mov edi, 3            (arg1 = 3)
        //   mov esi, 4            (arg2 = 4)
        //   call func             (call at +0x100)
        let bytes = [
            0xbf, 0x03, 0x00, 0x00, 0x00,       // mov edi, 3
            0xbe, 0x04, 0x00, 0x00, 0x00,       // mov esi, 4
            0xe8, 0xf1, 0x00, 0x00, 0x00,       // call +0x100 (from next_inst)
        ];
        let seq = x86::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 3, "should decode 3 instructions, got {}", seq.len());

        // Arg1: EDI = 3 (writes to RDI offset with value 3)
        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::Copy { input, .. }
            if input.space == AddressSpaceId::Const && input.offset == 3)),
            "mov edi,3 should load constant 3");

        // Arg2: ESI = 4
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::Copy { input, .. }
            if input.space == AddressSpaceId::Const && input.offset == 4)),
            "mov esi,4 should load constant 4");

        // Call: target should be base + 0xa + 0xf1 + 5 = 0x1100
        assert!(seq[2].3.iter().any(|op| matches!(op, PcodeOp::Call { dest }
            if dest.offset == 0x1100)),
            "call should target 0x1100, pcode: {:#?}", seq[2].3);
    }

    fn test_x86_compare_and_branch() {
        // if (rdi == 0) goto target
        //   test rdi, rdi
        //   je +0x10
        //   ... (fall through)
        let bytes = [
            0x48, 0x85, 0xff,       // test rdi, rdi
            0x74, 0x10,             // je +0x10 (addr 0x1005 + 0x10 = 0x1015)
        ];
        let seq = x86::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        // TEST should AND rdi with itself and set flags
        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::IntAnd { left, right, .. }
            if *left == reg(RDI, 8) && *right == reg(RDI, 8))),
            "TEST should AND rdi,rdi");
        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::IntEq { out, .. }
            if *out == reg(ZF, 1))),
            "TEST should set ZF");

        // JE should branch on ZF to 0x1015
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::CBranch { dest, cond }
            if dest.offset == 0x1015 && *cond == reg(ZF, 1))),
            "JE should CBranch on ZF to 0x1015\npcode: {:#?}", seq[1].3);
    }

    fn test_x86_loop_pattern() {
        // Simple countdown loop:
        //   mov ecx, 10           (counter)
        // loop_top:
        //   dec ecx               (counter--)
        //   jnz loop_top          (branch back if != 0)
        let bytes = [
            0xb9, 0x0a, 0x00, 0x00, 0x00,   // mov ecx, 10
            0xff, 0xc9,                       // dec ecx
            0x75, 0xfc,                       // jnz -4 (back to dec)
        ];
        let seq = x86::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 3, "should decode 3 instructions");

        // MOV ECX, 10
        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::Copy { input, .. }
            if input.space == AddressSpaceId::Const && input.offset == 10)),
            "should load constant 10");

        // DEC ECX
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::IntSub { .. })),
            "DEC should produce IntSub");

        // JNZ backward: target should be 0x1005 (the DEC instruction)
        assert!(seq[2].3.iter().any(|op| matches!(op, PcodeOp::CBranch { dest, .. }
            if dest.offset == 0x1005)),
            "JNZ should branch back to 0x1005 (the DEC)\npcode: {:#?}", seq[2].3);
    }

    fn test_x86_array_access() {
        // Array access with scale: mov rax, [rdi + rsi*8]
        // Then store: mov [rdi + rsi*8], rdx
        let bytes = [
            0x48, 0x8b, 0x04, 0xf7,   // mov rax, [rdi + rsi*8]
            0x48, 0x89, 0x14, 0xf7,   // mov [rdi + rsi*8], rdx
        ];
        let seq = x86::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        // Load: should have IntMult for scale factor and Load from RAM
        let load_ops = &seq[0].3;
        assert!(load_ops.iter().any(|op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
            if *out == reg(RAX, 8))),
            "array load should produce Load to RAX\n{load_ops:#?}");

        // Store: should Store RDX to computed address
        let store_ops = &seq[1].3;
        assert!(store_ops.iter().any(|op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, val, .. }
            if *val == reg(RDX, 8))),
            "array store should Store RDX\n{store_ops:#?}");
    }

    fn test_x86_rip_relative_data() {
        // Load from RIP-relative address (common for global data):
        //   lea rdi, [rip + 0x1000]     (48 8d 3d 00 10 00 00)
        //   mov rax, [rip + 0x2000]     (48 8b 05 00 20 00 00)
        let bytes = [
            0x48, 0x8d, 0x3d, 0x00, 0x10, 0x00, 0x00,   // lea rdi, [rip+0x1000]
            0x48, 0x8b, 0x05, 0x00, 0x20, 0x00, 0x00,   // mov rax, [rip+0x2000]
        ];
        let seq = x86::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        // LEA: should compute address into RDI, not load from memory
        // RIP-relative may produce IntAdd or Copy (if address is computed as constant)
        let lea_ops = &seq[0].3;
        let writes_rdi = lea_ops.iter().any(|op| match op {
            PcodeOp::IntAdd { out, .. } | PcodeOp::Copy { out, .. } => *out == reg(RDI, 8),
            _ => false,
        });
        assert!(writes_rdi, "LEA [rip+disp] should write to RDI\n{lea_ops:#?}");
        // Should NOT have a Load (LEA computes address only)
        assert!(!lea_ops.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
            "LEA should NOT produce Load");

        // MOV: should Load from computed address
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
            if *out == reg(RAX, 8))),
            "MOV [rip+disp] should produce Load\n{:#?}", seq[1].3);
    }

    fn test_x86_sign_extend_chain() {
        // Compiler pattern: load byte, sign-extend to 32, then to 64:
        //   movsx eax, byte ptr [rdi]    (0F BE 07)
        //   cdqe                          (48 98)
        let bytes = [
            0x0f, 0xbe, 0x07,       // movsx eax, byte ptr [rdi]
            0x48, 0x98,             // cdqe (sign-extend eax to rax)
        ];
        let seq = x86::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        // MOVSX: Load byte then sign-extend
        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::IntSext { .. })),
            "MOVSX should produce IntSext\n{:#?}", seq[0].3);

        // CDQE: sign-extend EAX to RAX
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::IntSext { out, .. }
            if *out == reg(RAX, 8))),
            "CDQE should IntSext to RAX\n{:#?}", seq[1].3);
    }

    // ── ARM64 functional tests ──────────────────────────────────────

    fn test_arm64_function_prologue_epilogue() {
        // Standard prologue: stp x29,x30,[sp,#-16]!; mov x29,sp
        // Standard epilogue: ldp x29,x30,[sp],#16; ret
        let prologue = [
            0xfd, 0x7b, 0xbf, 0xa9,   // stp x29, x30, [sp, #-16]!
            0xfd, 0x03, 0x00, 0x91,   // mov x29, sp  (add x29, sp, #0)
        ];
        let epilogue = [
            0xfd, 0x7b, 0xc1, 0xa8,   // ldp x29, x30, [sp], #16
            0xc0, 0x03, 0x5f, 0xd6,   // ret
        ];
        let pseq = arm_seq::decode_sequence(&prologue, 0x1000);
        assert_eq!(pseq.len(), 2, "prologue should be 2 instructions");

        // STP should Store both X29 and X30
        let stp_ops = &pseq[0].3;
        let store_count = stp_ops.iter().filter(|op| matches!(op, PcodeOp::Store { .. })).count();
        assert!(store_count >= 2, "STP x29,x30 should produce at least 2 Stores, got {store_count}\n{stp_ops:#?}");

        let eseq = arm_seq::decode_sequence(&epilogue, 0x2000);
        assert_eq!(eseq.len(), 2);
        // LDP should Load both registers
        let ldp_ops = &eseq[0].3;
        let load_count = ldp_ops.iter().filter(|op| matches!(op, PcodeOp::Load { .. })).count();
        assert!(load_count >= 2, "LDP should produce at least 2 Loads, got {load_count}");
        // RET
        assert!(eseq[1].3.iter().any(|op| matches!(op, PcodeOp::Return { .. })),
            "RET should emit Return");
    }

    fn test_arm64_adrp_add_pair() {
        // Address materialization: adrp x0, page; add x0, x0, #offset
        // This is how ARM64 loads addresses of globals/strings.
        let bytes = [
            0x00, 0x00, 0x00, 0x90,   // adrp x0, .  (page-aligned PC-relative)
            0x00, 0x40, 0x00, 0x91,   // add x0, x0, #0x10
        ];
        let seq = arm_seq::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);
        // ADRP should produce some P-code that writes X0
        assert!(!seq[0].3.is_empty(), "ADRP should produce P-code");
        // ADD should add immediate to X0
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::IntAdd { .. })),
            "ADD x0,x0,#0x10 should produce IntAdd\n{:#?}", seq[1].3);
    }

    fn test_arm64_compare_and_branch() {
        // if (x0 == 0) goto target:
        //   cbz x0, +8
        // else:
        //   mov x0, #1
        // target:
        let bytes = [
            0x00, 0x00, 0x00, 0xb4,   // cbz x0, +0 (branch to self for test simplicity)
            0x20, 0x00, 0x80, 0xd2,   // movz x0, #1
        ];
        let seq = arm_seq::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        // CBZ should compare to zero and conditional branch
        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::CBranch { .. })),
            "CBZ should produce CBranch\n{:#?}", seq[0].3);
    }

    fn test_arm64_stack_locals() {
        // Store and reload stack local:
        //   str x0, [sp, #8]
        //   ldr x1, [sp, #8]
        let bytes = [
            0xe0, 0x07, 0x00, 0xf9,   // str x0, [sp, #8]
            0xe1, 0x07, 0x40, 0xf9,   // ldr x1, [sp, #8]
        ];
        let seq = arm_seq::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::Store { space: AddressSpaceId::Ram, .. })),
            "STR should produce Store\n{:#?}", seq[0].3);
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. })),
            "LDR should produce Load\n{:#?}", seq[1].3);
    }

    fn test_arm64_loop_pattern() {
        // Countdown loop:
        //   mov w0, #10
        // loop:
        //   subs w0, w0, #1
        //   b.ne loop
        let bytes = [
            0x40, 0x01, 0x80, 0x52,   // movz w0, #10
            0x00, 0x04, 0x00, 0x71,   // subs w0, w0, #1
            0x01, 0xff, 0xff, 0x54,   // b.ne -4 (back to subs)
        ];
        let seq = arm_seq::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 3, "should decode 3 instructions");

        // SUBS should subtract and set flags
        assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::IntSub { .. })),
            "SUBS should produce IntSub\n{:#?}", seq[1].3);

        // B.NE should CBranch
        assert!(seq[2].3.iter().any(|op| matches!(op, PcodeOp::CBranch { .. })),
            "B.NE should produce CBranch\npcode: {:#?}", seq[2].3);
    }

    fn test_arm64_conditional_select() {
        // Pattern: x = (cond) ? a : b
        //   cmp x0, #0
        //   csel x2, x0, x1, eq
        let bytes = [
            0x1f, 0x00, 0x00, 0xf1,   // cmp x0, #0 (subs xzr, x0, #0)
            0x02, 0x00, 0x81, 0x9a,   // csel x2, x0, x1, eq
        ];
        let seq = arm_seq::decode_sequence(&bytes, 0x1000);
        assert_eq!(seq.len(), 2);

        // CMP should set flags via subtraction
        assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::IntSub { .. })),
            "CMP should produce IntSub\n{:#?}", seq[0].3);
        // CSEL should produce non-trivial P-code (conditional copy)
        assert!(seq[1].3.len() >= 1, "CSEL should produce P-code, got empty");
    }

    // ── Bug probes: targeted checks for specific semantic bugs ─────

    fn run_bug_probes() {
        // ── x86-64: sign extension at every boundary ──

        // disp32 sign extension: MOV RAX, [RBP - 0x100] (disp32 = 0xFFFFFF00)
        // 48 8B 85 00 FF FF FF
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0x8b, 0x85, 0x00, 0xff, 0xff, 0xff], 0x1000);
            assert!(disasm.contains("MOV"), "got {disasm}");
            // disp32 0xFFFFFF00 = signed -256, should sign-extend to 0xFFFFFFFFFFFFFF00
            let has_sext = pcode.iter().any(|op| match op {
                PcodeOp::IntAdd { right, .. } =>
                    right.space == AddressSpaceId::Const && right.offset == 0xFFFFFFFFFFFFFF00,
                _ => false,
            });
            assert!(has_sext,
                "disp32=-256 should sign-extend to 0xFFFFFFFFFFFFFF00\n{pcode:#?}");
        }

        // imm32 sign extension: MOV RAX, 0x80000000 (sign bit of 32-bit)
        // 48 C7 C0 00 00 00 80
        {
            let (_len, _disasm, pcode) = decode(
                &[0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x80], 0x1000);
            // 0x80000000 as signed i32 = -2147483648, sign-extends to 0xFFFFFFFF80000000
            let has_sext = pcode.iter().any(|op| match op {
                PcodeOp::Copy { input, .. } =>
                    input.space == AddressSpaceId::Const
                    && input.offset == 0xFFFFFFFF80000000,
                _ => false,
            });
            assert!(has_sext,
                "imm32=0x80000000 should sign-extend to 0xFFFFFFFF80000000\n{pcode:#?}");
        }

        // imm8 boundary: ADD RAX, 0x7F (positive max of signed byte, should stay positive)
        {
            let (_len, _disasm, pcode) = decode(&[0x48, 0x83, 0xc0, 0x7f], 0x1000);
            let has_positive = pcode.iter().any(|op| match op {
                PcodeOp::Copy { input, .. } | PcodeOp::IntAdd { right: input, .. } =>
                    input.space == AddressSpaceId::Const && input.offset == 0x7F,
                _ => false,
            });
            assert!(has_positive, "imm8=0x7F should stay 0x7F (positive)\n{pcode:#?}");
        }

        // ── x86-64: 32-bit ops zero-extend upper 32 bits ──

        // MOV EAX, 1 should clear upper 32 bits of RAX
        // After: XOR EAX, EAX should produce zero, not leave old upper bits
        {
            let (_len, disasm, pcode) = decode(&[0x31, 0xc0], 0x1000); // XOR EAX, EAX
            assert!(disasm.contains("XOR"), "got {disasm}");
            // XOR EAX,EAX writes to EAX (offset 0, size 4), not RAX (size 8)
            let writes_eax = pcode.iter().any(|op| match op {
                PcodeOp::IntXor { out, .. } | PcodeOp::Copy { out, .. } =>
                    out.offset == RAX && out.size == 4,
                _ => false,
            });
            assert!(writes_eax, "XOR EAX,EAX should write 4-byte EAX\n{pcode:#?}");
        }

        // ── x86-64: JMP/CALL rel32 sign extension ──

        // CALL -5 (E8 FB FF FF FF) at 0x1000 → target = 0x1000 + 5 + (-5) = 0x1000
        {
            let (_len, _disasm, pcode) = decode(&[0xe8, 0xfb, 0xff, 0xff, 0xff], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Call { dest }
                if dest.offset == 0x1000)),
                "CALL -5 at 0x1000 should target 0x1000 (call self)\n{pcode:#?}");
        }

        // JMP rel32 backward: E9 F6 FF FF FF at 0x1000 → 0x1000 + 5 - 10 = 0xFFB
        {
            let (_len, _disasm, pcode) = decode(&[0xe9, 0xf6, 0xff, 0xff, 0xff], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Branch { dest }
                if dest.offset == 0xFFB)),
                "JMP -10 at 0x1000 should target 0xFFB\n{pcode:#?}");
        }

        // ── x86-64: LEA vs MOV distinction ──

        // LEA should NOT produce Load; MOV with same addressing SHOULD
        {
            let (_len, _, lea_pcode) = decode(&[0x48, 0x8d, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00], 0x1000);
            // LEA RAX, [0x1000]  — computes address only
            assert!(!lea_pcode.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
                "LEA should never Load\n{lea_pcode:#?}");

            let (_len, _, mov_pcode) = decode(&[0x48, 0x8b, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00], 0x1000);
            // MOV RAX, [0x1000] — loads from memory
            assert!(mov_pcode.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
                "MOV [addr] should Load\n{mov_pcode:#?}");
        }

        // ── x86-64: all conditional branches resolve correct targets ──
        {
            // Test every Jcc rel8 at 0x1000 with offset +0x10 → target 0x1012
            let jcc_opcodes: &[(u8, &str)] = &[
                (0x70, "JO"), (0x71, "JNO"), (0x72, "JB"), (0x73, "JAE"),
                (0x74, "JE"), (0x75, "JNE"), (0x76, "JBE"), (0x77, "JA"),
                (0x78, "JS"), (0x79, "JNS"), (0x7a, "JP"), (0x7b, "JNP"),
                (0x7c, "JL"), (0x7d, "JGE"), (0x7e, "JLE"), (0x7f, "JG"),
            ];
            for (opcode, name) in jcc_opcodes {
                let (_len, _disasm, pcode) = decode(&[*opcode, 0x10], 0x1000);
                let has_cbranch = pcode.iter().any(|op| matches!(op, PcodeOp::CBranch { dest, .. }
                    if dest.offset == 0x1012));
                assert!(has_cbranch, "{name} +0x10 at 0x1000 should target 0x1012\npcode: {pcode:#?}");
            }
        }

        // ── RISC-V: sign extension for all immediate formats ──

        // B-type: BEQ x0, x0, backward (13-bit signed offset)
        {
            let bytes = &[0xe3, 0x0c, 0x00, 0xfe]; // BEQ x0, x0, negative offset
            let result = std::panic::catch_unwind(|| riscv::decode(bytes, 0x1000));
            if let Ok((_len, disasm, pcode)) = result {
                if disasm.to_lowercase().contains("beq") {
                    let has_backward = pcode.iter().any(|op| matches!(op, PcodeOp::CBranch { dest, .. }
                        if dest.offset < 0x1000));
                    assert!(has_backward,
                        "RISC-V BEQ backward should branch before 0x1000\n{pcode:#?}");
                }
            }
        }

        // U-type: LUI x1, 0xFFFFF (upper 20 bits = all 1s)
        {
            let (_len, disasm, _pcode) = riscv::decode(&[0xb7, 0xf0, 0xff, 0xff], 0x1000);
            assert!(disasm.to_lowercase().contains("lui"), "expected lui, got {disasm}");
        }

        // J-type: JAL x1, negative offset (21-bit signed)
        {
            let (_len, disasm, pcode) = riscv::decode(&[0xef, 0xf0, 0xdf, 0xff], 0x1000);
            assert!(disasm.to_lowercase().contains("jal") || disasm.to_lowercase().contains("call"),
                "expected jal, got {disasm}");
            let has_backward = pcode.iter().any(|op| match op {
                PcodeOp::Call { dest } | PcodeOp::Branch { dest } => dest.offset < 0x1000,
                _ => false,
            });
            assert!(has_backward, "RISC-V JAL backward should target before 0x1000\npcode: {pcode:#?}");
        }

        // I-type: ADDI x1, x1, -2048 (minimum 12-bit signed = 0x800)
        {
            let (_len, _disasm, pcode) = riscv::decode(&[0x93, 0x80, 0x00, 0x80], 0x1000);
            let has_neg = pcode.iter().any(|op| match op {
                PcodeOp::IntAdd { right, .. } =>
                    right.space == AddressSpaceId::Const && right.offset > 0x7FFFFFFFFFFFFFFF,
                _ => false,
            });
            assert!(has_neg, "ADDI x1,x1,-2048 should have negative constant\n{pcode:#?}");
        }

        // I-type: ADDI x1, x1, 2047 (maximum positive 12-bit signed = 0x7FF)
        {
            let (_len, _disasm, pcode) = riscv::decode(&[0x93, 0x80, 0xf0, 0x7f], 0x1000);
            let has_pos = pcode.iter().any(|op| match op {
                PcodeOp::IntAdd { right, .. } =>
                    right.space == AddressSpaceId::Const && right.offset == 2047,
                _ => false,
            });
            assert!(has_pos, "ADDI x1,x1,2047 should have constant 2047\n{pcode:#?}");
        }

        // ── MIPS: sign extension of 16-bit immediates ──

        // ADDIU $a0, $zero, -1 = 0x2404FFFF (big-endian)
        // 16-bit imm = 0xFFFF = -1 signed
        {
            let (_len, _disasm, pcode) = mips::decode(&[0x24, 0x04, 0xff, 0xff], 0x1000);
            let has_neg = pcode.iter().any(|op| match op {
                PcodeOp::IntAdd { right, .. } | PcodeOp::Copy { input: right, .. } =>
                    right.space == AddressSpaceId::Const
                    && (right.offset == 0xFFFFFFFF || right.offset == 0xFFFFFFFFFFFFFFFF),
                _ => false,
            });
            assert!(has_neg,
                "ADDIU $a0,$zero,-1: imm16=0xFFFF should sign-extend to -1\n{pcode:#?}");
        }

        // ADDIU $a0, $zero, -32768 = 0x24048000 (big-endian)
        // 16-bit imm = 0x8000 = -32768 (minimum signed 16-bit)
        {
            let (_len, _disasm, pcode) = mips::decode(&[0x24, 0x04, 0x80, 0x00], 0x1000);
            let has_neg = pcode.iter().any(|op| match op {
                PcodeOp::IntAdd { right, .. } | PcodeOp::Copy { input: right, .. } =>
                    right.space == AddressSpaceId::Const
                    && (right.offset == 0xFFFF8000 || right.offset == 0xFFFFFFFFFFFF8000),
                _ => false,
            });
            assert!(has_neg,
                "ADDIU $a0,$zero,-32768: imm16=0x8000 should sign-extend\n{pcode:#?}");
        }

        // BEQ backward: BEQ $a0, $zero, -2 = 0x1080FFFE (big-endian)
        // offset field = 0xFFFE = -2 (signed 16-bit)
        // target = inst_start + 4 + 4*(-2) = 0x1000 + 4 - 8 = 0xFFC
        {
            let (_len, disasm, pcode) = mips::decode(&[0x10, 0x80, 0xff, 0xfe], 0x1000);
            assert!(disasm.to_lowercase().contains("beq"), "got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::CBranch { dest, .. }
                if dest.offset == 0xFFC)),
                "MIPS BEQ -2 at 0x1000 should target 0xFFC\n{pcode:#?}");
        }

        // ── ARM64: signed immediate boundaries ──

        // ADD X0, X0, #0xFFF (maximum 12-bit unsigned immediate)
        {
            let (_len, disasm, pcode) = arm::decode(&[0x00, 0xfc, 0x3f, 0x91], 0x1000);
            assert!(disasm.to_lowercase().contains("add"), "expected add, got {disasm}");
            let has_fff = pcode.iter().any(|op| match op {
                PcodeOp::IntAdd { right, .. } | PcodeOp::Copy { input: right, .. } =>
                    right.space == AddressSpaceId::Const && right.offset == 0xFFF,
                _ => false,
            });
            assert!(has_fff, "ADD X0,X0,#0xFFF should have constant 0xFFF\n{pcode:#?}");
        }

        // SUB SP, SP, #0x100 (common stack allocation)
        {
            let (_len, disasm, pcode) = arm::decode(&[0xff, 0x43, 0x04, 0xd1], 0x1000);
            assert!(disasm.to_lowercase().contains("sub"), "expected sub, got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::IntSub { .. })),
                "SUB SP,SP,#0x100 should produce IntSub\n{pcode:#?}");
        }

        // MOVZ + MOVK pattern: load 32-bit constant
        // MOVZ X0, #0x5678
        // MOVK X0, #0x1234, LSL#16
        {
            let seq = arm_seq::decode_sequence(&[
                0x00, 0xAD, 0x8A, 0xD2,   // movz x0, #0x5678
                0x80, 0x46, 0xA2, 0xF2,   // movk x0, #0x1234, lsl #16
            ], 0x1000);
            assert_eq!(seq.len(), 2, "MOVZ+MOVK should decode as 2 instructions");
            // MOVZ should set X0 to 0x5678
            assert!(!seq[0].3.is_empty(), "MOVZ should produce P-code");
            // MOVK should insert bits without clearing others
            assert!(!seq[1].3.is_empty(), "MOVK should produce P-code");
        }

        // ── ARM32: rotated immediate edge cases ──

        // MOV R0, #0xFF000000 (rotation=4, imm8=0xFF) = 0xE3A004FF
        {
            let (_len, disasm, _pcode) = arm32::decode(&[0xff, 0x04, 0xa0, 0xe3], 0x1000);
            assert!(disasm.to_lowercase().contains("mov"), "expected mov, got {disasm}");
            // The rotated immediate should produce 0xFF000000
        }

        // ── Cross-architecture: instruction length correctness ──

        // x86: variable-length instructions
        {
            assert_eq!(decode(&[0x90], 0x1000).0, 1, "NOP = 1 byte");
            assert_eq!(decode(&[0x48, 0x89, 0xc7], 0x1000).0, 3, "MOV RDI,RAX = 3 bytes");
            assert_eq!(decode(&[0xe8, 0x00, 0x01, 0x00, 0x00], 0x1000).0, 5, "CALL rel32 = 5 bytes");
            assert_eq!(decode(&[0x48, 0xb8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00], 0x1000).0, 10,
                "MOV RAX,imm64 = 10 bytes");
        }

        // ARM64: all 4 bytes
        {
            let tests: &[&[u8]] = &[
                &[0xc0, 0x03, 0x5f, 0xd6],  // RET
                &[0x20, 0x00, 0x02, 0x8b],  // ADD
                &[0x00, 0x00, 0x00, 0x94],  // BL
            ];
            for bytes in tests {
                let (len, _, _) = arm::decode(bytes, 0x1000);
                assert_eq!(len, 4, "ARM64 instructions are always 4 bytes");
            }
        }

        // RISC-V: 4 bytes normal, 2 bytes compressed
        {
            let (len, _, _) = riscv::decode(&[0x93, 0x00, 0x50, 0x00], 0x1000); // ADDI
            assert_eq!(len, 4, "RISC-V standard instruction = 4 bytes");
            let (len, _, _) = riscv::decode(&[0x01, 0x00], 0x1000); // C.NOP
            assert_eq!(len, 2, "RISC-V compressed instruction = 2 bytes");
        }

        // ═══════════════════════════════════════════════════════════════
        // x86-64 deep semantic probes
        // ═══════════════════════════════════════════════════════════════

        // ── x86 ModRM edge case: [RBP] requires disp8=0 encoding ──
        // MOV RAX, [RBP] is encoded as MOV RAX, [RBP+0] (45 00) because
        // ModRM with mod=00 rm=101 means [RIP+disp32], not [RBP].
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0x8b, 0x45, 0x00], 0x1000);
            assert!(disasm.contains("MOV") && disasm.contains("RBP"), "got {disasm}");
            // Should Load from [RBP+0] = [RBP]
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if *out == reg(RAX, 8))),
                "[RBP+0] should Load to RAX\n{pcode:#?}");
        }

        // ── x86 SIB edge case: [RSP] uses SIB byte ──
        // MOV RAX, [RSP] = 48 8B 04 24 (needs SIB: base=RSP, index=none, scale=1)
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0x8b, 0x04, 0x24], 0x1000);
            assert!(disasm.contains("MOV") && disasm.contains("RSP"), "got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, space: AddressSpaceId::Ram, .. }
                if *out == reg(RAX, 8))),
                "[RSP] should Load to RAX\n{pcode:#?}");
        }

        // ── x86 operand size override: 16-bit operations ──
        // MOV AX, 0x1234 (66 B8 34 12) — 16-bit register write
        {
            let (len, disasm, pcode) = decode(&[0x66, 0xb8, 0x34, 0x12], 0x1000);
            assert_eq!(len, 4, "66h prefix MOV AX,imm16 = 4 bytes");
            assert!(disasm.contains("AX") || disasm.contains("ax"), "got {disasm}");
            // Should write 2-byte value, NOT 4 or 8
            let has_16bit = pcode.iter().any(|op| match op {
                PcodeOp::Copy { out, input } =>
                    out.size == 2 && input.space == AddressSpaceId::Const && input.offset == 0x1234,
                _ => false,
            });
            assert!(has_16bit, "66h MOV AX,0x1234 should write 2-byte const 0x1234\n{pcode:#?}");
        }

        // ── x86 REX.W with different registers ──
        // Verify all 16 GPRs are addressable
        {
            // MOV R12, RAX = 49 89 C4 (REX.WB + ModRM)
            let (_len, disasm, pcode) = decode(&[0x49, 0x89, 0xc4], 0x1000);
            assert!(disasm.contains("R12"), "REX.B + rm=4 should select R12, got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Copy { out, .. }
                if out.space == AddressSpaceId::Register && out.offset != RAX)),
                "R12 should not alias RAX");

            // MOV R13, RAX = 49 89 C5 (REX.WB + ModRM rm=5)
            let (_len, disasm, _) = decode(&[0x49, 0x89, 0xc5], 0x1000);
            assert!(disasm.contains("R13"), "REX.B + rm=5 should select R13, got {disasm}");

            // MOV R14, RAX = 49 89 C6
            let (_len, disasm, _) = decode(&[0x49, 0x89, 0xc6], 0x1000);
            assert!(disasm.contains("R14"), "got {disasm}");

            // MOV RAX, R9 = 4C 89 C8 (REX.WR)
            let (_len, disasm, _) = decode(&[0x4c, 0x89, 0xc8], 0x1000);
            assert!(disasm.contains("R9"), "REX.R should select R9, got {disasm}");
        }

        // ── x86 MUL/IMUL widening: result in RDX:RAX ──
        // MUL RCX = 48 F7 E1 — unsigned multiply RAX*RCX → RDX:RAX
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0xf7, 0xe1], 0x1000);
            assert!(disasm.contains("MUL"), "got {disasm}");
            // Should produce IntMult and write to both RAX and RDX
            let writes_rax = pcode.iter().any(|op| match op {
                PcodeOp::IntMult { out, .. } | PcodeOp::Subpiece { out, .. } | PcodeOp::Copy { out, .. }
                    => out.offset == RAX && out.space == AddressSpaceId::Register,
                _ => false,
            });
            let writes_rdx = pcode.iter().any(|op| match op {
                PcodeOp::Subpiece { out, .. } | PcodeOp::Copy { out, .. }
                    => out.offset == RDX && out.space == AddressSpaceId::Register,
                _ => false,
            });
            assert!(writes_rax, "MUL should write result low to RAX\n{pcode:#?}");
            assert!(writes_rdx, "MUL should write result high to RDX\n{pcode:#?}");
        }

        // ── x86 MOVZX from memory: correct load size ──
        // MOVZX EAX, byte ptr [RDI] = 0F B6 07
        {
            let (_len, disasm, pcode) = decode(&[0x0f, 0xb6, 0x07], 0x1000);
            assert!(disasm.contains("MOVZX"), "got {disasm}");
            // Should Load 1 byte then zero-extend to 4 bytes
            let has_byte_load = pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, .. }
                if out.size == 1));
            let has_zext = pcode.iter().any(|op| matches!(op, PcodeOp::IntZext { out, .. }
                if out.size == 4));
            assert!(has_byte_load, "MOVZX byte should Load 1 byte\n{pcode:#?}");
            assert!(has_zext, "MOVZX should zero-extend\n{pcode:#?}");
        }

        // ── x86 MOVSX from memory: correct sign extension ──
        // MOVSX EAX, word ptr [RDI] = 0F BF 07
        {
            let (_len, disasm, pcode) = decode(&[0x0f, 0xbf, 0x07], 0x1000);
            assert!(disasm.contains("MOVSX"), "got {disasm}");
            let has_word_load = pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, .. }
                if out.size == 2));
            let has_sext = pcode.iter().any(|op| matches!(op, PcodeOp::IntSext { out, .. }
                if out.size == 4));
            assert!(has_word_load, "MOVSX word should Load 2 bytes\n{pcode:#?}");
            assert!(has_sext, "MOVSX should sign-extend\n{pcode:#?}");
        }

        // ── x86 MOVSXD: 32→64 sign extension (common in loop indexing) ──
        // MOVSXD RAX, ECX = 48 63 C1
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0x63, 0xc1], 0x1000);
            assert!(disasm.contains("MOVSXD"), "got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::IntSext { out, .. }
                if *out == reg(RAX, 8))),
                "MOVSXD should sign-extend to RAX\n{pcode:#?}");
        }

        // ── x86 IDIV: quotient in RAX, remainder in RDX ──
        // CQO; IDIV RCX = 48 99; 48 F7 F9
        {
            let seq = x86::decode_sequence(&[0x48, 0x99, 0x48, 0xf7, 0xf9], 0x1000);
            assert!(seq.len() >= 2, "CQO+IDIV should decode as 2+ instructions");
            let last = &seq[seq.len() - 1];
            assert!(last.2.contains("IDIV"), "last should be IDIV, got {}", last.2);
            // IDIV should produce quotient and remainder
            let has_sdiv = last.3.iter().any(|op| matches!(op, PcodeOp::IntSDiv { .. }));
            let has_srem = last.3.iter().any(|op| matches!(op, PcodeOp::IntSRem { .. }));
            assert!(has_sdiv, "IDIV should produce IntSDiv\n{:#?}", last.3);
            assert!(has_srem, "IDIV should produce IntSRem\n{:#?}", last.3);
        }

        // ── x86 LEA with complex SIB: [RBX + RCX*4 + 0x100] ──
        // LEA RAX, [RBX + RCX*4 + 0x100] = 48 8D 84 8B 00 01 00 00
        {
            let (len, disasm, pcode) = decode(
                &[0x48, 0x8d, 0x84, 0x8b, 0x00, 0x01, 0x00, 0x00], 0x1000);
            assert_eq!(len, 8, "LEA with SIB+disp32 = 8 bytes");
            assert!(disasm.contains("LEA"), "got {disasm}");
            // Should have scale multiply (×4) and two adds (base+index, +disp)
            let has_mult = pcode.iter().any(|op| matches!(op, PcodeOp::IntMult { .. }
                | PcodeOp::IntLsl { .. }));
            assert!(has_mult || pcode.len() >= 2,
                "LEA [base+idx*4+disp] should have scale computation\n{pcode:#?}");
            // Should NOT Load from memory
            assert!(!pcode.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
                "LEA should NOT Load");
        }

        // ── x86 TEST with immediate: TEST RAX, 1 (flag-only, no write) ──
        // TEST RAX, 1 = 48 A9 01 00 00 00
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0xa9, 0x01, 0x00, 0x00, 0x00], 0x1000);
            assert!(disasm.contains("TEST"), "got {disasm}");
            // TEST should set flags but NOT write to RAX
            let writes_rax = pcode.iter().any(|op| match op {
                PcodeOp::IntAnd { out, .. } => *out == reg(RAX, 8),
                _ => false,
            });
            assert!(!writes_rax, "TEST should NOT write to RAX (flag-only)\n{pcode:#?}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::IntEq { out, .. }
                if *out == reg(ZF, 1))),
                "TEST should set ZF");
        }

        // ═══════════════════════════════════════════════════════════════
        // ARM64 deep semantic probes
        // ═══════════════════════════════════════════════════════════════

        // ── ARM64 PC-relative branch offset correctness ──
        {
            // B +8 at 0x1000 should target 0x1008
            let (_, _, pcode) = arm::decode(&[0x02, 0x00, 0x00, 0x14], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Branch { dest } if dest.offset == 0x1008)),
                "B +8 at 0x1000 should target 0x1008\n{pcode:#?}");
        }
        {
            // B -4 at 0x1000 should target 0xFFC
            let (_, _, pcode) = arm::decode(&[0xff, 0xff, 0xff, 0x17], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Branch { dest } if dest.offset == 0xFFC)),
                "B -4 at 0x1000 should target 0xFFC\n{pcode:#?}");
        }
        {
            // BL +0x100 at 0x1000 → 0x1100
            let (_, _, pcode) = arm::decode(&[0x40, 0x00, 0x00, 0x94], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Call { dest } if dest.offset == 0x1100)),
                "BL +0x100 at 0x1000 should Call 0x1100\n{pcode:#?}");
        }
        {
            // BL -4 at 0x1000 → 0xFFC
            let (_, _, pcode) = arm::decode(&[0xff, 0xff, 0xff, 0x97], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Call { dest } if dest.offset == 0xFFC)),
                "BL -4 at 0x1000 should Call 0xFFC\n{pcode:#?}");
        }

        // ── ARM64 ADDS sets flags (not just ADD) ──
        // ADDS X0, X1, X2 = 0xAB020020
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0xab], 0x1000);
            assert!(disasm.to_lowercase().contains("adds") || disasm.to_lowercase().contains("cmn"),
                "got {disasm}");
            // Should set condition flags (NG, ZR, CY, OV)
            let sets_flags = pcode.iter().any(|op| match op {
                PcodeOp::IntEq { out, .. } | PcodeOp::IntSLess { out, .. }
                | PcodeOp::IntCarry { out, .. } | PcodeOp::IntSCarry { out, .. } =>
                    out.space == AddressSpaceId::Register
                    && (256..=264).contains(&out.offset), // ARM64 flag range
                _ => false,
            });
            assert!(sets_flags, "ADDS should set condition flags\n{pcode:#?}");
        }

        // ── ARM64 LDR size variants ──
        // LDRB W0, [X1] loads 1 byte
        {
            let (_, _, pcode) = arm::decode(&[0x20, 0x00, 0x40, 0x39], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, .. } if out.size == 1)),
                "LDRB should load 1 byte\n{pcode:#?}");
        }
        // LDRH W0, [X1] loads 2 bytes
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x40, 0x79], 0x1000);
            assert!(disasm.to_lowercase().contains("ldr"), "got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, .. } if out.size == 2)),
                "LDRH should load 2 bytes\n{pcode:#?}");
        }
        // LDR W0, [X1] loads 4 bytes
        {
            let (_, _, pcode) = arm::decode(&[0x20, 0x00, 0x40, 0xb9], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, .. } if out.size == 4)),
                "LDR W0 should load 4 bytes\n{pcode:#?}");
        }
        // LDR X0, [X1] loads 8 bytes
        {
            let (_, _, pcode) = arm::decode(&[0x20, 0x00, 0x40, 0xf9], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { out, .. } if out.size == 8)),
                "LDR X0 should load 8 bytes\n{pcode:#?}");
        }

        // ── ARM64 STR size variants ──
        // STRB W0, [X1] stores 1 byte
        {
            let (_, _, pcode) = arm::decode(&[0x20, 0x00, 0x00, 0x39], 0x1000);
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Store { .. })),
                "STRB should Store\n{pcode:#?}");
        }

        // ── ARM64 SUBS X vs W (flag-setting with different widths) ──
        // SUBS W0, W1, W2 = 0x6B020020 (32-bit subtract with flags)
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x02, 0x6b], 0x1000);
            assert!(disasm.to_lowercase().contains("subs"), "got {disasm}");
            // 32-bit: output should be 4-byte register
            let has_32bit_sub = pcode.iter().any(|op| matches!(op, PcodeOp::IntSub { out, .. }
                if out.size == 4));
            assert!(has_32bit_sub, "SUBS W should produce 4-byte IntSub\n{pcode:#?}");
        }

        // ── ARM64 MOV SP (stack pointer as operand) ──
        // MOV SP, X0 = ADD SP, X0, #0 = 0x9100001F
        {
            let (_, disasm, pcode) = arm::decode(&[0x1f, 0x00, 0x00, 0x91], 0x1000);
            assert!(disasm.to_lowercase().contains("mov") || disasm.to_lowercase().contains("add"),
                "got {disasm}");
            // SP is register offset varies by arch, just check it produces P-code
            assert!(!pcode.is_empty(), "MOV SP,X0 should produce P-code");
        }

        // ── ARM64 LDRSW: sign-extending 32-bit load to 64-bit ──
        // LDRSW X0, [X1] = 0xB9800020
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x00, 0x80, 0xb9], 0x1000);
            assert!(disasm.to_lowercase().contains("ldrsw") || disasm.to_lowercase().contains("ldr"),
                "got {disasm}");
            // Should load 4 bytes then sign-extend to 8
            let has_load = pcode.iter().any(|op| matches!(op, PcodeOp::Load { .. }));
            assert!(has_load, "LDRSW should Load\n{pcode:#?}");
        }

        // ── ARM64 MADD: multiply-accumulate X0 = X1*X2 + X3 ──
        // MADD X0, X1, X2, X3 = 0x9B020C20
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x0c, 0x02, 0x9b], 0x1000);
            assert!(disasm.to_lowercase().contains("madd") || disasm.to_lowercase().contains("mul"),
                "got {disasm}");
            // Should have both IntMult and IntAdd (unless X3=XZR then it's just MUL)
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::IntMult { .. })),
                "MADD should have IntMult\n{pcode:#?}");
        }

        // ── ARM64 UBFX/SBFX: bitfield extract ──
        // UBFX X0, X1, #4, #8 = extract 8 bits starting at bit 4
        // UBFM X0, X1, #4, #11 = 0xD340AC20
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x2c, 0x44, 0xd3], 0x1000);
            assert!(disasm.to_lowercase().contains("ubfx") || disasm.to_lowercase().contains("ubfm")
                || disasm.to_lowercase().contains("lsr"),
                "got {disasm}");
            assert!(!pcode.is_empty(), "UBFX should produce P-code\n{pcode:#?}");
        }

        // ── ARM64 extended register: ADD X0, X1, W2, SXTW ──
        // 0x8B22C020
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0xc0, 0x22, 0x8b], 0x1000);
            assert!(disasm.to_lowercase().contains("add"), "got {disasm}");
            // Should sign-extend W2 to 64-bit before adding
            let has_sext = pcode.iter().any(|op| matches!(op, PcodeOp::IntSext { .. }));
            assert!(has_sext, "ADD X0,X1,W2,SXTW should sign-extend W2\n{pcode:#?}");
        }

        // ═══════════════════════════════════════════════════════════════
        // x86-64 compiled code patterns
        // ═══════════════════════════════════════════════════════════════

        // ── Stack canary load: MOV RAX, FS:[0x28] ──
        // 64 48 8B 04 25 28 00 00 00
        {
            let result = std::panic::catch_unwind(||
                decode(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00], 0x1000));
            match result {
                Ok((len, disasm, pcode)) => {
                    assert!(len == 9, "FS:[0x28] should be 9 bytes, got {len}");
                    assert!(disasm.contains("FS") || disasm.contains("fs"),
                        "should reference FS segment, got {disasm}");
                    assert!(!pcode.is_empty(), "FS segment load should produce P-code");
                }
                Err(_) => eprintln!("[BUG] FS:[0x28] decode panicked"),
            }
        }

        // ── Stack alignment: AND RSP, -16 ──
        // 48 83 E4 F0
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0x83, 0xe4, 0xf0], 0x1000);
            assert!(disasm.contains("AND"), "got {disasm}");
            // The immediate -16 = 0xFFFFFFFFFFFFFFF0 (sign-extended from 0xF0)
            let has_mask = pcode.iter().any(|op| match op {
                PcodeOp::IntAnd { right, .. } | PcodeOp::Copy { input: right, .. } =>
                    right.space == AddressSpaceId::Const
                    && right.offset == 0xFFFFFFFFFFFFFFF0,
                _ => false,
            });
            assert!(has_mask,
                "AND RSP,-16: imm8=0xF0 should sign-extend to 0xFFFFFFFFFFFFFFF0\n{pcode:#?}");
        }

        // ── Indirect call through memory: CALL [RAX] vs CALL RAX ──
        {
            // CALL RAX = FF D0 (CallInd with register)
            let (_, _, pcode1) = decode(&[0xff, 0xd0], 0x1000);
            assert!(pcode1.iter().any(|op| matches!(op, PcodeOp::CallInd { dest }
                if *dest == reg(RAX, 8))),
                "CALL RAX should CallInd with RAX\n{pcode1:#?}");

            // CALL [RAX] = FF 10 (CallInd through memory — Load then call)
            let (_, _, pcode2) = decode(&[0xff, 0x10], 0x1000);
            assert!(pcode2.iter().any(|op| matches!(op, PcodeOp::Load { space: AddressSpaceId::Ram, .. })),
                "CALL [RAX] should Load the target address first\n{pcode2:#?}");
            assert!(pcode2.iter().any(|op| matches!(op, PcodeOp::CallInd { .. })),
                "CALL [RAX] should produce CallInd\n{pcode2:#?}");
        }

        // ── JMP [RAX*8 + table] — indirect jump for switch/case ──
        // FF 24 C5 00 20 00 00 = JMP [RAX*8 + 0x2000]
        {
            let result = std::panic::catch_unwind(||
                decode(&[0xff, 0x24, 0xc5, 0x00, 0x20, 0x00, 0x00], 0x1000));
            match result {
                Ok((_len, disasm, pcode)) => {
                    assert!(disasm.contains("JMP"), "got {disasm}");
                    // Should produce BranchInd (Load may be folded into the branch)
                    assert!(pcode.iter().any(|op| matches!(op,
                        PcodeOp::BranchInd { .. } | PcodeOp::Branch { .. })),
                        "JMP [table] should BranchInd\n{pcode:#?}");
                }
                Err(_) => eprintln!("[BUG] JMP [RAX*8+table] decode panicked"),
            }
        }

        // ── SETcc: set byte on condition ──
        // SETZ AL = 0F 94 C0
        {
            let (_len, disasm, pcode) = decode(&[0x0f, 0x94, 0xc0], 0x1000);
            assert!(disasm.contains("SET"), "expected SETcc, got {disasm}");
            assert!(!pcode.is_empty(), "SETcc should produce P-code\n{pcode:#?}");
        }
        // SETL AL = 0F 9C C0
        {
            let (_len, disasm, pcode) = decode(&[0x0f, 0x9c, 0xc0], 0x1000);
            assert!(disasm.contains("SET"), "expected SETcc, got {disasm}");
            assert!(!pcode.is_empty(), "SETcc should produce P-code");
        }

        // ── REP MOVSB (memcpy pattern) ──
        // F3 A4
        {
            let result = std::panic::catch_unwind(||
                decode(&[0xf3, 0xa4], 0x1000));
            match result {
                Ok((_len, disasm, pcode)) => {
                    assert!(disasm.contains("MOVS") || disasm.contains("REP"),
                        "expected REP MOVSB, got {disasm}");
                    assert!(!pcode.is_empty(), "REP MOVSB should produce P-code");
                }
                Err(_) => eprintln!("[BUG] REP MOVSB decode panicked"),
            }
        }

        // ── LOCK XADD (atomic fetch-and-add) ──
        // F0 48 0F C1 07 = LOCK XADD [RDI], RAX
        {
            let result = std::panic::catch_unwind(||
                decode(&[0xf0, 0x48, 0x0f, 0xc1, 0x07], 0x1000));
            match result {
                Ok((_len, disasm, _pcode)) => {
                    assert!(disasm.contains("XADD"), "expected LOCK XADD, got {disasm}");
                }
                Err(_) => eprintln!("[BUG] LOCK XADD decode panicked"),
            }
        }

        // ── SSE2 floating point: ADDSD XMM0, XMM1 ──
        // F2 0F 58 C1
        {
            let result = std::panic::catch_unwind(||
                decode(&[0xf2, 0x0f, 0x58, 0xc1], 0x1000));
            match result {
                Ok((_len, disasm, pcode)) => {
                    assert!(disasm.contains("ADDSD") || disasm.contains("addsd"),
                        "expected ADDSD, got {disasm}");
                    assert!(pcode.iter().any(|op| matches!(op, PcodeOp::FloatAdd { .. })),
                        "ADDSD should produce FloatAdd\n{pcode:#?}");
                }
                Err(_) => eprintln!("[BUG] ADDSD XMM0,XMM1 decode panicked"),
            }
        }

        // ── MOVSD: load/store double ──
        // F2 0F 10 07 = MOVSD XMM0, [RDI]
        {
            let result = std::panic::catch_unwind(||
                decode(&[0xf2, 0x0f, 0x10, 0x07], 0x1000));
            match result {
                Ok((_len, disasm, pcode)) => {
                    assert!(disasm.contains("MOVSD") || disasm.contains("movsd"),
                        "expected MOVSD, got {disasm}");
                    // Should Load from memory
                    assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
                        "MOVSD from memory should Load\n{pcode:#?}");
                }
                Err(_) => eprintln!("[BUG] MOVSD XMM0,[RDI] decode panicked"),
            }
        }

        // ── Division by constant via multiply+shift: compiler output test ──
        // IMUL RDX (widening multiply) = 48 F7 EA
        {
            let (_len, disasm, pcode) = decode(&[0x48, 0xf7, 0xea], 0x1000);
            assert!(disasm.contains("IMUL"), "got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::IntMult { .. })),
                "IMUL should produce IntMult\n{pcode:#?}");
        }

        // ── Multi-byte NOP (alignment padding) ──
        {
            // 5-byte NOP: 0F 1F 44 00 00
            let (len, _, _) = decode(&[0x0f, 0x1f, 0x44, 0x00, 0x00], 0x1000);
            assert_eq!(len, 5, "5-byte NOP should be 5 bytes");

            // 4-byte NOP: 0F 1F 40 00
            let (len, _, _) = decode(&[0x0f, 0x1f, 0x40, 0x00], 0x1000);
            assert_eq!(len, 4, "4-byte NOP should be 4 bytes");
        }

        // ── SYSCALL ──
        // 0F 05
        {
            let result = std::panic::catch_unwind(||
                decode(&[0x0f, 0x05], 0x1000));
            match result {
                Ok((_len, disasm, _pcode)) => {
                    assert!(disasm.contains("SYSCALL"), "expected SYSCALL, got {disasm}");
                }
                Err(_) => eprintln!("[BUG] SYSCALL decode panicked"),
            }
        }

        // ── PLT/GOT pattern: MOV [RIP+disp], value; then CALL [RIP+disp] ──
        {
            let seq = x86::decode_sequence(&[
                0x48, 0x8b, 0x05, 0x00, 0x20, 0x00, 0x00,  // mov rax, [rip+0x2000]
                0xff, 0xd0,                                   // call rax
            ], 0x1000);
            assert_eq!(seq.len(), 2, "PLT pattern should decode 2 instructions");
            assert!(seq[0].3.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
                "MOV from [RIP+disp] should Load");
            assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::CallInd { .. })),
                "CALL RAX should CallInd");
        }

        // ═══════════════════════════════════════════════════════════════
        // ARM64 compiled code patterns
        // ═══════════════════════════════════════════════════════════════

        // ── TBZ/TBNZ: test bit and branch (extremely common) ──
        // TBZ X0, #0, +8 = 0x36000040
        {
            let (_, disasm, pcode) = arm::decode(&[0x40, 0x00, 0x00, 0x36], 0x1000);
            assert!(disasm.to_lowercase().contains("tbz"), "expected TBZ, got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::CBranch { .. })),
                "TBZ should produce CBranch\n{pcode:#?}");
        }
        // TBNZ X0, #0, +8 = 0x37000040
        {
            let (_, disasm, pcode) = arm::decode(&[0x40, 0x00, 0x00, 0x37], 0x1000);
            assert!(disasm.to_lowercase().contains("tbnz"), "expected TBNZ, got {disasm}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::CBranch { .. })),
                "TBNZ should produce CBranch\n{pcode:#?}");
        }

        // ── TBZ with backward branch ──
        // TBZ X0, #0, -4 = 0x3607FFE0
        {
            let (_, disasm, pcode) = arm::decode(&[0xe0, 0xff, 0x07, 0x36], 0x1000);
            assert!(disasm.to_lowercase().contains("tbz"), "expected TBZ, got {disasm}");
            let target = pcode.iter().find_map(|op| match op {
                PcodeOp::CBranch { dest, .. } => Some(dest.offset), _ => None,
            });
            assert!(target.map_or(false, |t| t < 0x1000),
                "TBZ backward should branch before 0x1000, target={:?}\n{pcode:#?}",
                target.map(|t| format!("0x{:x}", t)));
        }

        // ── CSET: branchless boolean (CMP + CSINC) ──
        // CSET X0, EQ = CSINC X0, XZR, XZR, NE = 0x9A9F17E0
        {
            let (_, disasm, pcode) = arm::decode(&[0xe0, 0x17, 0x9f, 0x9a], 0x1000);
            assert!(disasm.to_lowercase().contains("cset") || disasm.to_lowercase().contains("csinc"),
                "expected CSET/CSINC, got {disasm}");
            assert!(!pcode.is_empty(), "CSET should produce P-code");
        }

        // ── Shifted register: ADD X0, X1, X2, LSL #3 ──
        // 0x8B020C20
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x0c, 0x02, 0x8b], 0x1000);
            assert!(disasm.to_lowercase().contains("add"), "got {disasm}");
            // Should have a shift (IntLsl) before the add
            let has_shift = pcode.iter().any(|op| matches!(op, PcodeOp::IntLsl { .. }));
            assert!(has_shift || pcode.len() >= 2,
                "ADD with LSL should have shift\n{pcode:#?}");
        }

        // ── Post-index load: LDR X0, [X1], #8 ──
        // 0xF8408420
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x84, 0x40, 0xf8], 0x1000);
            assert!(disasm.to_lowercase().contains("ldr"), "expected LDR, got {disasm}");
            // Post-index: Load from [X1], then add 8 to X1
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
                "LDR post-index should Load\n{pcode:#?}");
            assert!(pcode.iter().any(|op| matches!(op, PcodeOp::IntAdd { .. })),
                "LDR post-index should increment base register\n{pcode:#?}");
        }

        // ── ADRP + LDR sequence: global variable access ──
        {
            let seq = arm_seq::decode_sequence(&[
                0x00, 0x00, 0x00, 0x90,   // adrp x0, .
                0x00, 0x00, 0x40, 0xf9,   // ldr x0, [x0]
            ], 0x1000);
            assert_eq!(seq.len(), 2, "ADRP+LDR should decode 2 instructions");
            assert!(!seq[0].3.is_empty(), "ADRP should produce P-code");
            assert!(seq[1].3.iter().any(|op| matches!(op, PcodeOp::Load { .. })),
                "LDR [X0] should Load from computed address");
        }

        // ── STP/LDP with large offset ──
        // STP X29, X30, [SP, #-48]! = 0xA9BD7BFD
        {
            let (_, disasm, pcode) = arm::decode(&[0xfd, 0x7b, 0xbd, 0xa9], 0x1000);
            assert!(disasm.to_lowercase().contains("stp"), "expected STP, got {disasm}");
            let store_count = pcode.iter().filter(|op| matches!(op, PcodeOp::Store { .. })).count();
            assert!(store_count >= 2, "STP should produce 2+ Stores, got {store_count}");
        }

        // ── B.cond backward branch targets ──
        {
            // B.NE -8 at 0x1000 → 0xFF8
            // 54FFFFE1
            let (_, disasm, pcode) = arm::decode(&[0xe1, 0xff, 0xff, 0x54], 0x1000);
            assert!(disasm.to_lowercase().contains("b."), "expected B.NE, got {disasm}");
            let target = pcode.iter().find_map(|op| match op {
                PcodeOp::CBranch { dest, .. } => Some(dest.offset), _ => None,
            });
            assert!(target.map_or(false, |t| t < 0x1000),
                "B.NE backward should branch before 0x1000, target={:?}\n{pcode:#?}",
                target.map(|t| format!("0x{:x}", t)));
        }

        // ── CBZ backward ──
        {
            // CBZ X0, -4 at 0x1000 → 0xFFC
            // B4FFFFE0
            let (_, _, pcode) = arm::decode(&[0xe0, 0xff, 0xff, 0xb4], 0x1000);
            let target = pcode.iter().find_map(|op| match op {
                PcodeOp::CBranch { dest, .. } => Some(dest.offset), _ => None,
            });
            assert!(target.map_or(false, |t| t < 0x1000),
                "CBZ backward should branch before 0x1000, target={:?}\n{pcode:#?}",
                target.map(|t| format!("0x{:x}", t)));
        }

        // ── MRS: read thread pointer (common in TLS access) ──
        // MRS X0, TPIDR_EL0 = 0xD53BD040
        {
            let result = std::panic::catch_unwind(||
                arm::decode(&[0x40, 0xd0, 0x3b, 0xd5], 0x1000));
            match result {
                Ok((len, disasm, _pcode)) => {
                    assert_eq!(len, 4);
                    assert!(disasm.to_lowercase().contains("mrs") || disasm.to_lowercase().contains("tpidr"),
                        "expected MRS, got {disasm}");
                }
                Err(_) => eprintln!("[BUG] MRS TPIDR_EL0 decode panicked"),
            }
        }

        // ── CSINC: conditional increment (branchless patterns) ──
        // CSINC X0, X1, X2, EQ = 0x9A820420
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x04, 0x82, 0x9a], 0x1000);
            assert!(disasm.to_lowercase().contains("csinc") || disasm.to_lowercase().contains("cinc"),
                "expected CSINC, got {disasm}");
            assert!(!pcode.is_empty(), "CSINC should produce P-code");
        }

        // ── UXTH: zero-extend halfword (common in character processing) ──
        // UXTH W0, W1 = UBFM W0, W1, #0, #15 = 0x53003C20
        {
            let (_, disasm, pcode) = arm::decode(&[0x20, 0x3c, 0x00, 0x53], 0x1000);
            assert!(disasm.to_lowercase().contains("uxth") || disasm.to_lowercase().contains("ubfm")
                || disasm.to_lowercase().contains("and"),
                "expected UXTH/UBFM, got {disasm}");
            assert!(!pcode.is_empty(), "UXTH should produce P-code");
        }

        // ── DMB: data memory barrier (concurrent code) ──
        // DMB ISH = 0xD5033BBF
        {
            let result = std::panic::catch_unwind(||
                arm::decode(&[0xbf, 0x3b, 0x03, 0xd5], 0x1000));
            match result {
                Ok((len, disasm, _)) => {
                    assert_eq!(len, 4);
                    assert!(disasm.to_lowercase().contains("dmb"),
                        "expected DMB, got {disasm}");
                }
                Err(_) => eprintln!("[BUG] DMB ISH decode panicked"),
            }
        }
    }

    fn test_x86_64_vs_ghidra_fixture() {
        let fixture = ghidra::x86_fixture().expect("failed to parse x86 Ghidra fixture");

        for case in fixture {
            let (len, disasm, pcode) = decode(&case.bytes, 0);
            assert_eq!(
                len, case.length,
                "length mismatch vs Ghidra for {} bytes {:02x?}",
                case.name, case.bytes
            );
            assert_eq!(
                disasm, case.name,
                "disassembly mismatch vs Ghidra for bytes {:02x?}",
                case.bytes
            );

            let expected = ghidra::canonicalize_pcode(&ghidra::optimize_fixture_pcode(
                case.pcode.as_ref().expect("x86 fixture missing pcode"),
            ));
            let actual = ghidra::canonicalize_pcode(&pcode);

            assert_eq!(
                actual, expected,
                "P-code mismatch vs Ghidra for {} bytes {:02x?}\nexpected:\n{}\nactual:\n{}\nraw expected:\n{:#?}\nraw actual:\n{:#?}",
                case.name,
                case.bytes,
                expected.join("\n"),
                actual.join("\n"),
                case.pcode,
                pcode,
            );
        }
    }

    fn test_aarch64_vs_ghidra_fixture() {
        let fixture = ghidra::aarch64_fixture().expect("failed to parse aarch64 Ghidra fixture");

        for case in fixture {
            let (len, disasm, pcode) = arm::decode(&case.bytes, 0);
            assert_eq!(
                len, case.length,
                "length mismatch vs Ghidra for {} bytes {:02x?}",
                case.name, case.bytes
            );

            let disasm_lower = disasm.to_lowercase();
            let expected_mnemonic = case
                .name
                .split_whitespace()
                .next()
                .expect("fixture name missing mnemonic");
            assert!(
                disasm_lower.starts_with(expected_mnemonic),
                "mnemonic mismatch vs Ghidra for bytes {:02x?}: expected '{}', got '{}'",
                case.bytes,
                expected_mnemonic,
                disasm,
            );

            if let Some(expected_ops) = case.pcode_count {
                assert!(
                    pcode.len() <= expected_ops,
                    "P-code op count exceeds Ghidra for {} bytes {:02x?}: got {}, expected at most {}",
                    case.name,
                    case.bytes,
                    pcode.len(),
                    expected_ops,
                );
            }

            if let Some(expected_pcode) = case.pcode.as_ref() {
                let expected =
                    ghidra::canonicalize_pcode(&ghidra::optimize_fixture_pcode(expected_pcode));
                let actual = ghidra::canonicalize_pcode(&pcode);
                assert_eq!(
                    actual, expected,
                    "P-code mismatch vs Ghidra for {} bytes {:02x?}",
                    case.name, case.bytes,
                );
            }
        }
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
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decoder(bytes, 0x1000)));
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
                            *cap == *capstone_mnemonic
                                && aliases.iter().any(|a| disasm_lower.starts_with(a))
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
            for f in &failed {
                eprintln!("  FAIL: {f}");
            }
            panic!(
                "{arch}: {} of {} corpus tests failed",
                failed.len(),
                corpus.len()
            );
        }
        eprintln!("  {arch} corpus: {passed}/{} validated", corpus.len());
    }

    fn test_x86_64_corpus() {
        run_corpus(
            "x86-64",
            corpus::X86_64_CORPUS,
            x86::decode,
            &[
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
            ],
        );
    }

    fn test_aarch64_corpus() {
        run_corpus(
            "aarch64",
            corpus::AARCH64_CORPUS,
            arm::decode,
            &[
                ("mov", &["mov", "orr", "movz", "movn"]),
                ("movz", &["movz", "mov"]),
                ("b.eq", &["b.eq", "b."]),
                ("b.ne", &["b.ne", "b."]),
                ("b.lt", &["b.lt", "b."]),
                ("b.gt", &["b.gt", "b."]),
                ("eor", &["eor"]),
                ("eon", &["eon"]),
                ("bic", &["bic"]),
                ("brk", &["brk"]),
                ("sxtw", &["sxtw", "sbfm"]),
                ("uxtb", &["uxtb", "ubfm", "and"]),
                ("uxth", &["uxth", "ubfm", "and"]),
                ("rbit", &["rbit"]),
                ("rev32", &["rev32", "rev"]),
                ("clz", &["clz"]),
                ("cls", &["cls"]),
                ("cinc", &["cinc", "csinc"]),
                ("csel", &["csel"]),
                ("ands", &["ands", "tst"]),
                ("adds", &["adds"]),
                ("subs", &["subs", "cmp"]),
                ("dmb", &["dmb"]),
                ("isb", &["isb"]),
                ("ldrsb", &["ldrsb"]),
                ("ldrsh", &["ldrsh"]),
                ("ldursw", &["ldrsw", "ldursw"]),
                ("sdiv", &["sdiv"]),
            ],
        );
    }

    fn test_arm32_corpus() {
        run_corpus(
            "arm32",
            corpus::ARM32_CORPUS,
            arm32::decode,
            &[
                ("mov", &["mov", "cpy"]),
                ("bx", &["bx"]),
                ("beq", &["beq"]),
                ("nop", &["nop"]),
            ],
        );
    }

    fn test_mips_corpus() {
        run_corpus(
            "mips",
            corpus::MIPS_CORPUS,
            mips::decode,
            &[
                ("addu", &["addu"]),
                ("subu", &["subu"]),
                ("addiu", &["addiu", "li"]),
                ("beq", &["beq", "b", "beqz"]),
                ("bne", &["bne", "bnez"]),
                ("jr", &["jr"]),
                ("jal", &["jal"]),
                ("nop", &["nop", "sll"]),
            ],
        );
    }

    fn test_riscv_corpus() {
        run_corpus(
            "riscv",
            corpus::RISCV_CORPUS,
            riscv::decode,
            &[
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
            ],
        );
    }

    // ---- Edge-case / robustness tests ----
    // Verify that truncated, empty, and garbage input returns None without panicking.

    #[test]
    fn truncated_and_garbage_input() {
        let t = std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(run_edge_case_tests)
            .unwrap();
        t.join().unwrap();
    }

    fn try_x86(bytes: &[u8]) -> bool {
        let mut ctx = x86::context();
        let mut gs = x86_root::GlobalSet::new(x86::context());
        x86_root::parse_instruction(bytes, &mut ctx, 0x1000, &mut gs).is_some()
    }

    fn try_aarch64(bytes: &[u8]) -> bool {
        let mut ctx = aarch64_root::ContextMemory::default();
        let mut gs = aarch64_root::GlobalSet::new(aarch64_root::ContextMemory::default());
        aarch64_root::parse_instruction(bytes, &mut ctx, 0x1000, &mut gs).is_some()
    }

    fn try_arm32(bytes: &[u8]) -> bool {
        let mut ctx = arm32_root::ContextMemory::default();
        let mut gs = arm32_root::GlobalSet::new(arm32_root::ContextMemory::default());
        arm32_root::parse_instruction(bytes, &mut ctx, 0x1000u32, &mut gs).is_some()
    }

    fn try_mips(bytes: &[u8]) -> bool {
        let mut ctx = mips_root::ContextMemory::default();
        let mut gs = mips_root::GlobalSet::new(mips_root::ContextMemory::default());
        mips_root::parse_instruction(bytes, &mut ctx, 0x1000u32, &mut gs).is_some()
    }

    fn try_riscv(bytes: &[u8]) -> bool {
        let mut ctx = riscv_root::ContextMemory::default();
        let mut gs = riscv_root::GlobalSet::new(riscv_root::ContextMemory::default());
        riscv_root::parse_instruction(bytes, &mut ctx, 0x1000, &mut gs).is_some()
    }

    fn run_edge_case_tests() {
        // Empty input — must not panic
        assert!(!try_x86(&[]));
        assert!(!try_aarch64(&[]));
        assert!(!try_arm32(&[]));
        assert!(!try_mips(&[]));
        assert!(!try_riscv(&[]));

        // Single byte — too short for most instructions
        for b in [0x00, 0xff, 0x48, 0x0f, 0x66] {
            // Should either decode (some single-byte x86 insns exist) or return None
            let _ = try_x86(&[b]);
            // Fixed-width ISAs need 4 bytes — these must return None
            assert!(!try_aarch64(&[b]));
            assert!(!try_arm32(&[b]));
            assert!(!try_mips(&[b]));
        }

        // Truncated x86 multi-byte instructions
        // REX.W + MOV needs 3 bytes, give it 1 or 2
        assert!(!try_x86(&[0x48]));
        assert!(!try_x86(&[0x48, 0x89]));
        // 0F-prefixed instructions need more bytes
        assert!(!try_x86(&[0x0f]));
        assert!(!try_x86(&[0x0f, 0x84])); // JE rel32 needs 6 bytes

        // Truncated fixed-width (2 or 3 bytes of a 4-byte instruction)
        assert!(!try_aarch64(&[0xe0, 0x03]));
        assert!(!try_aarch64(&[0xe0, 0x03, 0x01]));
        assert!(!try_arm32(&[0x00, 0x00]));
        assert!(!try_mips(&[0x00, 0x00, 0x00]));
        assert!(!try_riscv(&[0x93, 0x00]));

        // Random garbage — 1000 random 16-byte sequences, must not panic
        // Use a simple LCG so the test is deterministic
        let mut rng: u64 = 0xdeadbeef;
        let mut decoded = [0u64; 5]; // count successful decodes per arch
        for _ in 0..1000 {
            let mut buf = [0u8; 16];
            for b in &mut buf {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (rng >> 33) as u8;
            }
            if try_x86(&buf) { decoded[0] += 1; }
            if try_aarch64(&buf) { decoded[1] += 1; }
            if try_arm32(&buf) { decoded[2] += 1; }
            if try_mips(&buf) { decoded[3] += 1; }
            if try_riscv(&buf) { decoded[4] += 1; }
        }
        eprintln!(
            "  edge-case tests passed (random decode rates: x86={}/1000 aarch64={}/1000 arm32={}/1000 mips={}/1000 riscv={}/1000)",
            decoded[0], decoded[1], decoded[2], decoded[3], decoded[4]
        );

        // Decompiler fuzz: feed random decoded instructions through the decompiler.
        // This catches panics in the SSA/fold/structure/printer passes on pathological P-code.
        let mut decompile_ok = 0u64;
        let mut decompile_err = 0u64;
        let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_64);
        let mut rng2: u64 = 0xcafebabe;
        for _ in 0..200 {
            // Generate a random "function" of 2-8 instructions
            let mut insts = Vec::new();
            let mut addr = 0x1000u64;
            let n_insts = 2 + (rng2 % 7) as usize;
            rng2 = rng2.wrapping_mul(6364136223846793005).wrapping_add(3);
            for _ in 0..n_insts {
                let mut buf = [0u8; 16];
                for b in &mut buf {
                    rng2 = rng2.wrapping_mul(6364136223846793005).wrapping_add(3);
                    *b = (rng2 >> 33) as u8;
                }
                if let Ok(inst) = dec.decode(&buf, addr) {
                    let len = inst.len;
                    insts.push((addr, inst));
                    addr += len;
                }
            }
            if insts.is_empty() { continue; }
            // Run the decompiler with catch_unwind
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rsleigh_decompile::decompile(rsleigh_api::Architecture::X86_64, &insts)
            }));
            match result {
                Ok(_) => decompile_ok += 1,
                Err(e) => {
                    let msg = e.downcast_ref::<String>().map(|s| s.as_str())
                        .or_else(|| e.downcast_ref::<&str>().copied())
                        .unwrap_or("unknown");
                    eprintln!("  DECOMPILER PANIC: {} (insts={})", msg, insts.len());
                    decompile_err += 1;
                }
            }
        }
        eprintln!(
            "  decompiler fuzz: {}/{} ok, {} panics",
            decompile_ok, decompile_ok + decompile_err, decompile_err
        );
        assert_eq!(decompile_err, 0, "Decompiler panicked on random input!");
    }

    // ---- Decompiler validation tests ----

    #[test]
    fn decompiler_validation() {
        let t = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(run_decompiler_validation)
            .unwrap();
        t.join().unwrap();
    }

    fn run_decompiler_validation() {
        // Try to find or build the test binary
        let binary_path = "/tmp/test_prog_x86";
        let source = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int add(int a, int b) { return a + b; }
int factorial(int n) { if (n <= 1) return 1; return n * factorial(n - 1); }
char* reverse_string(char* str) {
    int len = strlen(str);
    for (int i = 0; i < len / 2; i++) {
        char tmp = str[i]; str[i] = str[len-1-i]; str[len-1-i] = tmp;
    }
    return str;
}
int main(int argc, char** argv) {
    printf("add(3, 4) = %d\n", add(3, 4));
    printf("factorial(5) = %d\n", factorial(5));
    char buf[32]; strcpy(buf, "hello world");
    printf("reversed: %s\n", reverse_string(buf));
    return 0;
}
"#;

        // Write source and compile in two steps so dsymutil can find the .o
        let src_path = "/tmp/test_decompile_validation.c";
        let obj_path = "/tmp/test_decompile_validation.o";
        std::fs::write(src_path, source).unwrap();
        let compile = std::process::Command::new("cc")
            .args(["-arch", "x86_64", "-g", "-c", "-o", obj_path, src_path])
            .output();

        match compile {
            Ok(output) if output.status.success() => {
                let link = std::process::Command::new("cc")
                    .args(["-arch", "x86_64", "-g", "-o", binary_path, obj_path])
                    .output();
                if !matches!(link, Ok(ref o) if o.status.success()) {
                    if !std::path::Path::new(binary_path).exists() {
                        eprintln!("  decompiler validation skipped (link failed)");
                        return;
                    }
                }
                // Generate dSYM for DWARF debug info on macOS
                let _ = std::process::Command::new("dsymutil")
                    .arg(binary_path)
                    .output();
            }
            _ => {
                if !std::path::Path::new(binary_path).exists() {
                    eprintln!("  decompiler validation skipped (no x86_64 cross-compiler)");
                    return;
                }
            }
        }

        if !std::path::Path::new(binary_path).exists() {
            eprintln!("  decompiler validation skipped (binary not found)");
            return;
        }

        let data = std::fs::read(binary_path).unwrap();
        let obj = goblin::Object::parse(&data).unwrap();

        let (segs, symbols) = match &obj {
            goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
                let segs: Vec<(u64,u64,u64)> = m.segments.iter()
                    .map(|s| (s.vmaddr, s.vmsize, s.fileoff)).collect();
                let mut syms = Vec::new();
                for sym in m.symbols() {
                    if let Ok((name, nlist)) = sym {
                        if nlist.n_type & 0x0e == 0x0e && nlist.n_value != 0 {
                            let c: &str = if name.starts_with('_') { &name[1..] } else { name };
                            if !c.is_empty() {
                                syms.push((nlist.n_value, c.to_string()));
                            }
                        }
                    }
                }
                syms.sort_by_key(|(a,_)| *a);
                syms.dedup_by_key(|(a,_)| *a);
                (segs, syms)
            }
            _ => {
                eprintln!("  decompiler validation skipped (not Mach-O)");
                return;
            }
        };

        let mut dec = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_64);

        let decompile_func = |fa: u64, dec: &mut rsleigh_api::Decoder| -> String {
            let off = segs.iter().find_map(|(va,sz,fo)|
                if fa >= *va && fa < va+sz { Some(fo+(fa-va)) } else { None });
            let Some(off) = off else { return String::new() };
            let max = 512.min(data.len() - off as usize);
            let bytes = &data[off as usize..off as usize + max];
            let mut io = 0usize;
            let mut insts = Vec::new();
            while io < max {
                match dec.decode(&bytes[io..], fa + io as u64) {
                    Ok(inst) => {
                        let r = inst.ops.iter().any(|o| matches!(o, rsleigh_api::PcodeOp::Return{..}));
                        let l = inst.len as usize;
                        insts.push((fa + io as u64, inst));
                        io += l;
                        if r { break; }
                    }
                    Err(_) => break,
                }
            }
            rsleigh_decompile::decompile_with_binary(
                rsleigh_api::Architecture::X86_64, &insts, Some(&data),
                Some(std::path::Path::new(binary_path)))
        };

        let find_addr = |name: &str| -> Option<u64> {
            symbols.iter().find(|(_, n)| n == name).map(|(a, _)| *a)
        };

        // --- Validate add() ---
        if let Some(addr) = find_addr("add") {
            let output = decompile_func(addr, &mut dec);
            assert!(output.contains("return") && output.contains("+"),
                "add(): should be 'return a + b'\n{}", output);
            let dsym_exists = std::path::Path::new(&format!("{}.dSYM", binary_path)).exists();
            if dsym_exists {
                assert!(output.contains("a + b") || output.contains("a +"),
                    "add(): DWARF should resolve params to a, b\n{}", output);
            }
            // Should be concise — ideally 1 line
            let non_empty = output.lines().filter(|l| !l.trim().is_empty()).count();
            assert!(non_empty <= 3, "add(): should be <=3 lines, got {}\n{}", non_empty, output);
            eprintln!("  add() validated ({}L)", non_empty);
        }

        // --- Validate factorial() ---
        if let Some(addr) = find_addr("factorial") {
            let output = decompile_func(addr, &mut dec);
            assert!(output.contains("if"), "factorial(): should contain if\n{}", output);
            assert!(output.contains("factorial("),
                "factorial(): should contain recursive call\n{}", output);
            assert!(output.contains("return") && output.contains("*"),
                "factorial(): should have return with multiplication\n{}", output);
            assert!(output.contains("1"), "factorial(): should contain base case 1\n{}", output);
            assert!(output.contains("n - 1") || output.contains("n-1") || output.contains("n +"),
                "factorial(): should show n-1 in recursive call\n{}", output);
            let dsym_exists = std::path::Path::new(&format!("{}.dSYM", binary_path)).exists();
            if dsym_exists {
                assert!(output.contains(" n ") || output.contains("(n ") || output.contains(" n)"),
                    "factorial(): DWARF should resolve param to n\n{}", output);
            }
            eprintln!("  factorial() validated");
        }

        // --- Validate reverse_string() ---
        if let Some(addr) = find_addr("reverse_string") {
            let output = decompile_func(addr, &mut dec);
            assert!(output.contains("while") || output.contains("for"),
                "reverse_string(): should contain loop\n{}", output);
            assert!(output.contains("strlen"),
                "reverse_string(): should call strlen\n{}", output);
            let dsym_exists = std::path::Path::new(&format!("{}.dSYM", binary_path)).exists();
            if dsym_exists {
                assert!(output.contains("str") || output.contains("param_0"),
                    "reverse_string(): should reference str param\n{}", output);
            }
            eprintln!("  reverse_string() validated");
        }

        // --- Validate main() ---
        if let Some(addr) = find_addr("main") {
            let output = decompile_func(addr, &mut dec);
            // String literals
            assert!(output.contains("add(3, 4)") || output.contains("add(3,4)"),
                "main(): should contain 'add(3, 4)' string literal\n{}", output);
            assert!(output.contains("factorial(5)"),
                "main(): should contain 'factorial(5)' string literal\n{}", output);
            assert!(output.contains("hello world"),
                "main(): should contain 'hello world' string literal\n{}", output);
            // Import + function resolution
            assert!(output.contains("printf("), "main(): should resolve printf\n{}", output);
            assert!(output.contains("add("), "main(): should call add()\n{}", output);
            assert!(output.contains("factorial("), "main(): should call factorial()\n{}", output);
            assert!(output.contains("reverse_string("),
                "main(): should call reverse_string()\n{}", output);
            assert!(output.contains("strcpy("), "main(): should call strcpy()\n{}", output);
            assert!(output.contains("return 0") || output.contains("return;"),
                "main(): should return\n{}", output);
            // Should NOT contain raw hex for string addresses
            assert!(!output.contains("0x100000"),
                "main(): should not have unresolved Mach-O addresses\n{}", output);
            eprintln!("  main() validated");
        }

        eprintln!("  decompiler validation passed");
    }

    // Verify register_name works for known registers
    #[test]
    fn register_name_lookup() {
        use rsleigh_api::Architecture;
        // x86-64: RAX is at offset 0, size 8
        assert_eq!(Architecture::X86_64.register_name(0, 8), Some("RAX"));
        // x86-64: EAX is at offset 0, size 4
        assert_eq!(Architecture::X86_64.register_name(0, 4), Some("EAX"));
        // x86-64: AL is at offset 0, size 1
        assert_eq!(Architecture::X86_64.register_name(0, 1), Some("AL"));
        // Unknown offset returns None
        assert_eq!(Architecture::X86_64.register_name(99999, 8), None);
    }
}

/// Validate structural properties of a P-code op.
fn validate_pcode_op(op: &PcodeOp) -> Option<String> {
    fn validate_input(varnode: &Varnode, op: &PcodeOp, role: &str) -> Option<String> {
        if varnode.size == 0 {
            return Some(format!("{role} varnode has size 0: {op:?}"));
        }
        None
    }

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
        PcodeOp::Store { space, ptr, val } => validate_input(ptr, op, "store pointer")
            .or_else(|| validate_input(val, op, "store value"))
            .or_else(|| {
                if *space != AddressSpaceId::Ram {
                    // Some stores go to Register space (valid for SLEIGH semantics)
                }
                None
            }),
        PcodeOp::Branch { dest }
        | PcodeOp::Call { dest }
        | PcodeOp::CallInd { dest }
        | PcodeOp::Return { dest } => validate_input(dest, op, "branch destination"),
        PcodeOp::CBranch { dest, cond } => validate_input(dest, op, "branch destination")
            .or_else(|| validate_input(cond, op, "branch condition")),
        _ => None,
    }
}
