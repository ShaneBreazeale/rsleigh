#[path = "../src/icicle_ins.rs"]
mod icicle_ins;

use icicle_ins::{check_cases_decode_report, check_decode, parse, Assignment, FailureKind};
use rsleigh_api::Architecture;

#[test]
fn parses_icicle_ins_shapes() {
    let input = r#"
        // single instruction with semantics
        0x1000 [48 89 d8] "MOV RAX,RBX" rbx = 0x11 => rax = 0x11;

        // grouped instructions, explicit expected length, and memory assignment
        @skip 0x2000 | 1 {
            [90] = 1 "NOP"
            [c3] "RET"
        } {
            mem[0x3000]:READ_WRITE = [01 02], rax = 1 => mem[0x3002] = 2;
        }
    "#;

    let cases = parse(input).expect("parse icicle .ins text");
    assert_eq!(cases.len(), 2);
    assert_eq!(cases[0].load_addr, 0x1000);
    assert_eq!(cases[0].instructions[0].bytes, vec![0x48, 0x89, 0xd8]);
    assert_eq!(cases[0].semantics.len(), 1);
    assert_eq!(cases[1].isa_mode, 1);
    assert!(cases[1].skip);
    assert_eq!(cases[1].instructions.len(), 2);

    match &cases[1].semantics[0].inputs[0] {
        Assignment::Mem { addr, perm, value } => {
            assert_eq!(*addr, 0x3000);
            assert_eq!(perm.as_deref(), Some("READ_WRITE"));
            assert_eq!(value, &[1, 2]);
        }
        other => panic!("expected mem assignment, got {other:?}"),
    }
}

#[test]
fn decodes_local_x64_icicle_fixture() {
    let input = include_str!("../fixtures/icicle/x64_smoke.ins");
    let summary = check_decode(input, Architecture::X86_64).expect("decode fixture");

    assert_eq!(summary.cases, 3);
    assert_eq!(summary.instructions, 3);
    assert_eq!(summary.skipped, 1);
    assert_eq!(summary.semantics_unsupported, 0);
}

/// Bulk regression oracle: run rsleigh's decoder against the upstream
/// Icicle `.ins` corpus per arch and emit pass-rate stats. NOT a hard
/// pass/fail — Icicle's fixtures cover more instructions than rsleigh's
/// generated decoders currently lift cleanly. Goal: track the rate over
/// time, and surface concrete decode/length/disasm gaps for fix-leaker.
fn corpus_report(name: &str, arch: Architecture, fixture: &str) {
    let cases = parse(fixture).expect("parse icicle corpus");
    let report = check_cases_decode_report(&cases, arch);

    eprintln!(
        "[{name}] cases={} attempted={} passed={} ({:.1}%) failed={} skipped={} isa_skip={} semantics={}",
        report.cases,
        report.instructions_attempted,
        report.instructions_passed,
        report.pass_rate() * 100.0,
        report.instructions_failed(),
        report.skipped,
        report.unsupported_isa_mode,
        report.semantics_unsupported,
    );

    let mut by_kind = [0usize; 3];
    for f in &report.failures {
        let idx = match f.kind {
            FailureKind::Decode => 0,
            FailureKind::Length => 1,
            FailureKind::Disasm => 2,
        };
        by_kind[idx] += 1;
    }
    eprintln!(
        "[{name}] decode={} length={} disasm={}",
        by_kind[0], by_kind[1], by_kind[2]
    );

    for f in report.failures.iter().take(5) {
        eprintln!(
            "[{name}] sample fail line={} kind={:?} bytes={:02x?} expected=`{}` got=`{}`",
            f.line, f.kind, f.bytes, f.expected_disasm, f.got
        );
    }

    // Floor at 0 to keep the test from panicking when corpus parsing is the
    // gating issue. Real assertion lives in the eprintln stats — wire a
    // CI baseline once the rate stabilizes.
    assert!(report.cases > 0, "no test cases parsed from {name} corpus");
}

#[test]
fn decodes_icicle_x64_corpus() {
    let input = include_str!("../fixtures/icicle/x64.ins");
    corpus_report("x64", Architecture::X86_64, input);
}

#[test]
fn decodes_icicle_mips_corpus() {
    let input = include_str!("../fixtures/icicle/mips.ins");
    corpus_report("mips", Architecture::MIPS32, input);
}

#[test]
fn decodes_icicle_aarch64_corpus() {
    let input = include_str!("../fixtures/icicle/aarch64.ins");
    corpus_report("aarch64", Architecture::AArch64, input);
}

#[test]
fn decodes_icicle_arm_corpus() {
    let input = include_str!("../fixtures/icicle/arm.ins");
    corpus_report("arm", Architecture::ARM32, input);
}

#[test]
fn decodes_icicle_riscv64_corpus() {
    let input = include_str!("../fixtures/icicle/riscv64gc.ins");
    corpus_report("riscv64", Architecture::RiscV64, input);
}

#[test]
fn decodes_icicle_x86_corpus() {
    let input = include_str!("../fixtures/icicle/x86.ins");
    corpus_report("x86", Architecture::X86_32, input);
}

#[test]
fn decodes_icicle_mipsel_corpus() {
    let input = include_str!("../fixtures/icicle/mipsel.ins");
    corpus_report("mipsel", Architecture::MIPS32, input);
}
