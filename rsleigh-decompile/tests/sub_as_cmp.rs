//! Regression tests for subtraction-as-comparison simplification.
//!
//! Spec: docs/superpowers/specs/2026-04-16-sub-as-cmp-design.md

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{BinOpKind, Expr, SsaTerminator};
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

/// After fold, no CBranch condition should resolve to a bare BinOp(Sub, _, _).
/// Encodes: mov rax, rcx; sub rax, 1; jnz +3; xor rax, rax; ret
#[test]
fn sub_cond_becomes_comparison() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: &[u8] = &[
                0x48, 0x89, 0xC8,       // mov rax, rcx
                0x48, 0x83, 0xE8, 0x01, // sub rax, 1
                0x75, 0x03,             // jnz +3
                0x48, 0x31, 0xC0,       // xor rax, rax
                0xC3,                   // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            for block in &ssa.blocks {
                if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
                    let mut resolved = *cond;
                    for _ in 0..8 {
                        if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr {
                            resolved = next;
                        } else {
                            break;
                        }
                    }
                    let cond_expr = &ssa.vars[resolved.0 as usize].expr;
                    assert!(
                        !matches!(cond_expr, Expr::BinOp(BinOpKind::Sub, _, _)),
                        "CBranch condition is still a raw Sub: {:?}",
                        cond_expr
                    );
                }
            }
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Integration test: FUN_140001017 must not contain `if (!(iVar1 - 1))` patterns.
/// Skips gracefully if fixture binary is absent.
#[test]
fn sub_cond_gone_in_output() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping sub_cond_gone_in_output: fixture not found");
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
    let func_va: u64 = 0x140001017;
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

    let func_len = 0x400_usize.min(data.len() - off);
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

            let bad_lines: Vec<&str> = out.lines()
                .filter(|l| {
                    let trimmed = l.trim();
                    (trimmed.starts_with("if (") || trimmed.starts_with("while ("))
                        && (trimmed.contains(" - 1)") || trimmed.contains(" - 2)")
                            || trimmed.contains(" - 1))") || trimmed.contains(" - 2))"))
                })
                .collect();

            assert!(
                bad_lines.is_empty(),
                "sub-as-condition patterns still present:\n{}",
                bad_lines.join("\n")
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
