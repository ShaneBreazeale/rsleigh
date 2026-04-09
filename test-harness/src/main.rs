#[allow(
    non_camel_case_types,
    non_snake_case,
    unused_variables,
    unused_mut,
    unused_parens,
    clippy::all
)]
mod x86_64 {
    include!(concat!(env!("OUT_DIR"), "/x86_64/root.rs"));
}

use x86_64::*;
use pcode_ir::{PcodeOp, Varnode, AddressSpaceId};

fn context_x86_64() -> ContextMemory {
    let mut ctx = ContextMemory::default();
    ctx.write_longMode(1);
    ctx.write_addrsize(2);
    ctx.write_opsize(1);
    ctx
}

fn decode(bytes: &[u8], addr: u64) -> (u64, String, Vec<PcodeOp>) {
    let mut ctx = context_x86_64();
    let mut gs = GlobalSet::new(context_x86_64());
    let (inst_next, display, mut pcode) =
        parse_instruction(bytes, &mut ctx, addr, &mut gs)
            .expect("failed to decode");
    pcode_ir::optimize(&mut pcode);
    let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
    (inst_next - addr, disasm.join(""), pcode)
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
    ];

    for (bytes, name) in tests {
        let (len, disasm, pcode) = decode(bytes, 0x1000);
        println!("{name}:");
        println!("  decoded: {disasm}");
        println!("  len={len}, pcode_ops={}", pcode.len());
        for op in &pcode {
            println!("    {op:?}");
        }
        println!();
    }
}

// ── Helpers for concise test assertions ──────────────────────────────

fn reg(offset: u64, size: u32) -> Varnode { Varnode::register(offset, size) }
fn con(value: u64, size: u32) -> Varnode { Varnode::constant(value, size) }

// x86-64 register offsets (from Ghidra's x86-64 register map)
const RAX: u64 = 0;
const RSP: u64 = 32;
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
        eprintln!("all 10 golden tests passed");
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
}
