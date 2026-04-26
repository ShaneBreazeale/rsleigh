//! Regression: after a Call terminator, caller-saved registers must be
//! invalidated so post-call reads resolve to fresh Expr::Unknown VarDefs.
//!
//! Spec: docs/superpowers/specs/2026-04-16-ssa-call-clobber-design.md

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::decompile_with_binary;
use rsleigh_decompile::fold::CallingConv;
use rsleigh_decompile::ir::Expr;
use rsleigh_decompile::ssa::build_ssa_with_cc;

/// Decode a tiny x86-64 sequence: set RAX to a LEA result, CALL an absolute
/// address, then read RAX. Post-call RAX must be a fresh Unknown, not the
/// pre-call LEA value.
fn decode(bytes: &[u8], base: u64) -> Vec<(u64, Instruction)> {
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

#[test]
fn post_call_rax_is_unknown_win64() {
    // x86-64 pattern matching requires a 32MB stack thread.
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // lea rax, [rip+0x10]       48 8D 05 10 00 00 00
            // mov rcx, rax               48 89 C1
            // call rel32 (to +0x20)      E8 13 00 00 00    (returns to insn after call)
            // mov rdx, rax               48 89 C2
            let bytes: [u8; 18] = [
                0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC1, 0xE8, 0x13, 0x00, 0x00,
                0x00, 0x48, 0x89, 0xC2,
            ];
            let insts = decode(&bytes, 0x1000);
            assert!(
                insts.len() >= 4,
                "expected >=4 instructions, got {}",
                insts.len()
            );

            let cfg = build_cfg(&insts);
            let ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);

            // The "mov rdx, rax" instruction reads RAX post-call. Its source must be
            // a VarDef whose expr is Expr::Unknown (a fresh clobber), NOT the LEA
            // expression from before the call.
            let rdx_vn = Varnode {
                space: AddressSpaceId::Register,
                offset: 16,
                size: 8,
            };
            let rdx_var = ssa
                .vars
                .iter()
                .rev()
                .find(|v| v.varnode == rdx_vn)
                .expect("no RDX assignment found");

            // RDX = Var(RAX_post_call) where RAX_post_call has Expr::Unknown.
            let rax_src_id = match rdx_var.expr {
                Expr::Var(id) => id,
                ref other => panic!("expected RDX = Var(RAX), got {:?}", other),
            };
            let rax_src = &ssa.vars[rax_src_id.0 as usize];
            assert!(
                matches!(rax_src.expr, Expr::Unknown),
                "post-call RAX must be Expr::Unknown; got {:?}",
                rax_src.expr
            );
            assert!(
                rax_src.call_return,
                "post-call RAX must be marked call_return=true"
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Regression: printer must not render a register as the parameter name
/// when the register has been clobbered by a Call. Specifically, after a
/// call-clobber, *(RCX) should NOT become *(param_C).
///
/// We test this by checking the full check2 output does not contain "*(C)".
/// If the fixture binary is missing, the test skips gracefully.
#[test]
fn check2_no_star_c_after_clobber() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping check2_no_star_c_after_clobber: fixture binary not found");
            return;
        }
    };

    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "skipping check2_no_star_c_after_clobber: PE parse error: {}",
                e
            );
            return;
        }
    };
    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001a68;
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
            eprintln!("skipping check2_no_star_c_after_clobber: func_va not in any section");
            return;
        }
    };
    let func_len = 0x200_usize.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
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

            let out = decompile_with_binary(
                Architecture::X86_64,
                &insts,
                Some(&data),
                Some(std::path::Path::new(path)),
            );
            assert!(
                !out.contains("*(C)"),
                "printer rendered *(C) after call-clobber fix; output snippet:\n{}",
                out.lines()
                    .filter(|l| l.contains("*(C)"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
