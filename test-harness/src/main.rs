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
            assert!(output.contains("var_4") || output.contains("EDI") || output.contains("param_0") || output.contains(" a"),
                "add(): should reference first argument\n{}", output);
            assert!(output.contains("var_8") || output.contains("ESI") || output.contains("param_1") || output.contains(" b"),
                "add(): should reference second argument\n{}", output);
            assert!(output.contains("+"),
                "add(): should contain addition operator\n{}", output);
            assert!(output.contains("return"),
                "add(): should contain return\n{}", output);
            // Check DWARF parameter naming when dSYM is available
            let dsym_exists = std::path::Path::new(&format!("{}.dSYM", binary_path)).exists();
            if dsym_exists && (output.contains(" a") && output.contains(" b")) {
                eprintln!("  add() DWARF parameter names resolved (a, b)");
            }
            eprintln!("  add() validated");
        }

        // --- Validate factorial() ---
        if let Some(addr) = find_addr("factorial") {
            let output = decompile_func(addr, &mut dec);
            assert!(output.contains("if"),
                "factorial(): should contain if statement\n{}", output);
            assert!(output.contains("factorial") || output.contains(&format!("func_{:x}", addr)),
                "factorial(): should contain recursive call\n{}", output);
            assert!(output.contains("1"),
                "factorial(): should contain base case value 1\n{}", output);
            assert!(output.contains("*") || output.contains("IMUL"),
                "factorial(): should contain multiplication\n{}", output);
            eprintln!("  factorial() validated");
        }

        // --- Validate reverse_string() ---
        if let Some(addr) = find_addr("reverse_string") {
            let output = decompile_func(addr, &mut dec);
            assert!(output.contains("while") || output.contains("if"),
                "reverse_string(): should contain loop or conditional\n{}", output);
            assert!(output.contains("strlen") || output.contains("func_") || output.contains("len"),
                "reverse_string(): should reference strlen/len\n{}", output);
            assert!(output.contains("return"),
                "reverse_string(): should return\n{}", output);
            eprintln!("  reverse_string() validated");
        }

        // --- Validate main() ---
        if let Some(addr) = find_addr("main") {
            let output = decompile_func(addr, &mut dec);
            // String literals should resolve
            assert!(output.contains("add(3, 4)") || output.contains("add(3,4)"),
                "main(): should contain 'add(3, 4)' string literal\n{}", output);
            assert!(output.contains("factorial(5)"),
                "main(): should contain 'factorial(5)' string literal\n{}", output);
            assert!(output.contains("hello world"),
                "main(): should contain 'hello world' string literal\n{}", output);
            // Import resolution
            assert!(output.contains("printf"),
                "main(): should resolve printf import\n{}", output);
            // Function calls
            assert!(output.contains("add(") || output.contains("add ()"),
                "main(): should call add()\n{}", output);
            assert!(output.contains("factorial(") || output.contains("factorial ()"),
                "main(): should call factorial()\n{}", output);
            assert!(output.contains("reverse_string("),
                "main(): should call reverse_string()\n{}", output);
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
