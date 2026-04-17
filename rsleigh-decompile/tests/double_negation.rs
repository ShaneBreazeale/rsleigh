//! Regression tests for double-negation condition simplification.
//!
//! Spec: docs/superpowers/specs/2026-04-16-double-negation-condition-design.md

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{BinOpKind, Expr};
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn decode_x64(bytes: &[u8], base: u64) -> Vec<(u64, pcode_ir::Instruction)> {
    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = base + off as u64;
        match dec.decode(&bytes[off..], addr) {
            Ok(inst) => {
                let l = inst.len as usize;
                insts.push((addr, inst));
                off += l;
            }
            Err(_) => break,
        }
    }
    insts
}

/// After fold, no VarDef should have the pattern BinOp(Eq, BinOp(Eq|NotEq, _, _), Const(0)).
/// This is the `(x == 0) == 0` / `(x != 0) == 0` pattern.
#[test]
fn double_negation_eq_zero_eliminated() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // xor rax, rax     — rax = 0
            // cmp rax, 0       — sets ZF
            // sete al          — al = (rax == 0) ? 1 : 0
            // cmp al, 0        — (al == 0) — double-negation
            // sete cl          — cl = (al == 0) ? 1 : 0
            // ret
            let bytes: &[u8] = &[
                0x48, 0x31, 0xC0,       // xor rax, rax
                0x48, 0x83, 0xF8, 0x00, // cmp rax, 0
                0x0F, 0x94, 0xC0,       // sete al
                0x80, 0xF8, 0x00,       // cmp al, 0
                0x0F, 0x94, 0xC1,       // sete cl
                0xC3,                   // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            for vdef in &ssa.vars {
                if let Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) = vdef.expr {
                    // zero_id must be Const(0)
                    if matches!(ssa.vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                        // inner must NOT itself be a comparison (Eq or NotEq)
                        let inner_expr = &ssa.vars[inner_id.0 as usize].expr;
                        assert!(
                            !matches!(inner_expr,
                                Expr::BinOp(BinOpKind::Eq, _, _)
                                | Expr::BinOp(BinOpKind::NotEq, _, _)
                            ),
                            "double-negation NOT eliminated: BinOp(Eq, {:?}, Const(0)) remains",
                            inner_expr
                        );
                    }
                }
            }
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Integration test: main (0x140001e41) must not contain `== 0) == 0` in output.
/// Skips gracefully if fixture binary is absent.
#[test]
fn main_func_no_double_negation_in_output() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping main_func_no_double_negation_in_output: fixture not found");
            return;
        }
    };

    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: PE parse error: {}", e);
            return;
        }
    };

    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001e41;
    let rva = func_va - image_base;
    let mut file_off = None;
    for s in &pe.sections {
        let s_va = s.virtual_address as u64;
        let s_sz = s.virtual_size as u64;
        if rva >= s_va && rva < s_va + s_sz {
            file_off = Some((s.pointer_to_raw_data as u64 + (rva - s_va)) as usize);
            break;
        }
    }
    let off = match file_off {
        Some(o) => o,
        None => {
            eprintln!("skipping: func VA not in any section");
            return;
        }
    };

    let func_len = 0x300_usize.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            use pcode_ir::PcodeOp;
            let mut dec = Decoder::new(Architecture::X86_64);
            let mut insts = Vec::new();
            let mut io = 0usize;
            while io < bytes.len() {
                match dec.decode(&bytes[io..], func_va + io as u64) {
                    Ok(inst) => {
                        let is_ret = inst.ops.iter().any(|op| matches!(op, PcodeOp::Return { .. }));
                        let l = inst.len as usize;
                        insts.push((func_va + io as u64, inst));
                        io += l;
                        if is_ret { break; }
                    }
                    Err(_) => break,
                }
            }

            let out = rsleigh_decompile::decompile_with_binary(
                Architecture::X86_64,
                &insts,
                Some(&data),
                Some(std::path::Path::new(path)),
            );

            assert!(
                !out.contains("== 0) == 0") && !out.contains("!= 0) == 0"),
                "double-negation still present in main output:\n{}",
                out.lines()
                    .filter(|l| l.contains("== 0"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
