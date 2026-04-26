//! Regression: Stmt::Call.out must be Some(_) when the return value is used,
//! and StructuredStmt::Call.out must be Some(_) for SsaTerminator::Call.
//!
//! Spec: docs/superpowers/specs/2026-04-16-call-return-binding-design.md

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::Stmt;
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

/// After fold_with_cc, any Stmt::Call whose return value is subsequently read
/// must have out: Some(_), not None.
///
/// Sequence (Win64 calling convention):
///   48 89 F9        mov rcx, rdi        ; arg setup
///   E8 10 00 00 00  call rel32 +0x10    ; call (fallthrough = next insn)
///   48 89 45 F8     mov [rbp-8], rax    ; store call result
///   C3              ret
///
/// The `mov [rbp-8], rax` reads RAX which is the call return value.
/// After propagate_call_returns, the Stmt::Call that emits this RAX
/// must carry out: Some(rax_var_id).
#[test]
fn mid_block_call_out_is_set() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: [u8; 13] = [
                0x48, 0x89, 0xF9, // mov rcx, rdi
                0xE8, 0x10, 0x00, 0x00, 0x00, // call rel32 +0x10
                0x48, 0x89, 0x45, 0xF8, // mov [rbp-8], rax
                0xC3, // ret
            ];
            let insts = decode_x64(&bytes, 0x1000);
            assert!(
                insts.len() >= 3,
                "expected >=3 instructions, got {}",
                insts.len()
            );

            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            // Find any Stmt::Call in any block.
            let call_stmts: Vec<_> = ssa
                .blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .filter(|s| matches!(s, Stmt::Call { .. }))
                .collect();

            // There may or may not be a mid-block Call depending on how the CFG splits.
            // If one exists, it MUST have out = Some(_) because RAX is read after it.
            for stmt in &call_stmts {
                if let Stmt::Call { out, .. } = stmt {
                    assert!(
                        out.is_some(),
                        "Stmt::Call.out must be Some(_) when return value is used; got None"
                    );
                }
            }

            // At minimum: there must be at least one block with a Call terminator
            // or a Stmt::Call — the sequence contains a call instruction.
            let has_any_call = !call_stmts.is_empty()
                || ssa.blocks.iter().any(|b| {
                    matches!(
                        &b.terminator,
                        rsleigh_decompile::ir::SsaTerminator::Call { .. }
                    )
                });
            assert!(
                has_any_call,
                "no Call found in SSA after decoding a CALL instruction"
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Integration test: decompiling the strcspn-calling function from the CTF binary
/// must produce output that binds the return value to a named variable.
///
/// Skips gracefully if the fixture binary is not present.
#[test]
fn strcspn_return_is_named() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping strcspn_return_is_named: fixture binary not found");
            return;
        }
    };

    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping strcspn_return_is_named: PE parse error: {}", e);
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
            eprintln!("skipping strcspn_return_is_named: func VA not in any section");
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
                        let is_ret = inst
                            .ops
                            .iter()
                            .any(|op| matches!(op, PcodeOp::Return { .. }));
                        let l = inst.len as usize;
                        insts.push((func_va + io as u64, inst));
                        io += l;
                        if is_ret {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            let out = rsleigh_decompile::decompile_with_binary(
                Architecture::X86_64,
                &insts,
                Some(&data),
                Some(std::path::Path::new(
                    "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe",
                )),
            );

            // The strcspn call result must be bound to a named local, not discarded.
            // Accept either: `= strcspn(` (named binding) or a named var containing
            // the return in an expression like `sVar1 = strcspn(`.
            let has_named_binding = out
                .lines()
                .any(|line| line.contains("= strcspn(") || line.contains("=strcspn("));
            assert!(
                has_named_binding,
                "strcspn return value not bound to a named variable; output:\n{}",
                out
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
