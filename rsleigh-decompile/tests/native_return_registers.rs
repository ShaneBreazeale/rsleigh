use pcode_ir::{Instruction, PcodeOp, Varnode};
use rsleigh_api::Architecture;
use rsleigh_decompile::ir::{Expr, SsaTerminator};

fn snapshot(arch: Architecture, ops: Vec<PcodeOp>) -> rsleigh_decompile::ir::SsaCfg {
    let instructions: Vec<_> = ops
        .into_iter()
        .enumerate()
        .map(|(i, op)| {
            (
                0x1000 + i as u64,
                Instruction::new(1, String::new(), vec![op]),
            )
        })
        .collect();
    rsleigh_decompile::folded_ssa(arch, &instructions, None)
}
fn ret() -> PcodeOp {
    PcodeOp::Return {
        dest: Varnode::ram(0, 8),
    }
}
#[test]
fn native_return_registers_are_used_on_all_six_architectures() {
    for (arch, offset, size) in [
        (Architecture::X86_64, 0, 8),
        (Architecture::X86_32, 0, 4),
        (Architecture::AArch64, 16384, 8),
        (Architecture::ARM32, 32, 4),
        (Architecture::MIPS32, 8, 4),
        (Architecture::RiscV64, 0x2050, 8),
    ] {
        let ssa = snapshot(
            arch,
            vec![
                PcodeOp::Copy {
                    out: Varnode::register(offset, size),
                    input: Varnode::constant(42, size),
                },
                ret(),
            ],
        );
        let value = ssa
            .blocks
            .iter()
            .find_map(|b| {
                if let SsaTerminator::Return(Some(v)) = b.terminator {
                    Some(v)
                } else {
                    None
                }
            })
            .unwrap();
        assert!(
            matches!(ssa.var(value).expr, Expr::Const(42, _)),
            "{arch:?}: {:?}",
            ssa.var(value).expr
        );
    }
}
#[test]
fn unrelated_registers_do_not_become_mips_or_riscv_returns() {
    for (arch, wrong, size) in [
        (Architecture::MIPS32, 16, 4),
        (Architecture::RiscV64, 80, 8),
    ] {
        let ssa = snapshot(
            arch,
            vec![
                PcodeOp::Copy {
                    out: Varnode::register(wrong, size),
                    input: Varnode::constant(42, size),
                },
                ret(),
            ],
        );
        assert!(
            ssa.blocks
                .iter()
                .all(|b| !matches!(b.terminator, SsaTerminator::Return(Some(_)))),
            "{arch:?}"
        );
    }
}
#[test]
fn unsupported_argument_conventions_do_not_preserve_pre_call_returns() {
    for (arch, offset, size) in [
        (Architecture::MIPS32, 8, 4),
        (Architecture::RiscV64, 0x2050, 8),
    ] {
        let ssa = snapshot(
            arch,
            vec![
                PcodeOp::Copy {
                    out: Varnode::register(offset, size),
                    input: Varnode::constant(42, size),
                },
                PcodeOp::Call {
                    dest: Varnode::ram(0x2000, size),
                },
                ret(),
            ],
        );
        let value = ssa
            .blocks
            .iter()
            .find_map(|b| {
                if let SsaTerminator::Return(Some(v)) = b.terminator {
                    Some(v)
                } else {
                    None
                }
            })
            .unwrap();
        assert!(
            ssa.var(value).call_return,
            "{arch:?}: {:?}",
            ssa.var(value).expr
        );
        assert!(!matches!(ssa.var(value).expr, Expr::Const(..)));
        assert!(ssa.var(value).origins.operations.iter().any(|origin| origin.instruction_address == 0x1001));
    }
}
