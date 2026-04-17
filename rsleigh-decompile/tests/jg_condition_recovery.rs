//! Regression tests for JG condition recovery after mba_simplify.
//!
//! Spec: docs/superpowers/specs/2026-04-17-jg-condition-recovery-design.md

use pcode_ir::AddressSpaceId;
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
            Ok(inst) => { let l = inst.len as usize; insts.push((addr, inst)); off += l; }
            Err(_) => break,
        }
    }
    insts
}

// cmp rax, rcx; jg +3; xor rax, rax; ret
const JG_BYTES: &[u8] = &[
    0x48, 0x39, 0xC8, // CMP rax, rcx  (rax - rcx; sets ZF, SF, OF, CF)
    0x7F, 0x03,       // JG +3         (jump if rax > rcx signed)
    0x48, 0x31, 0xC0, // XOR rax, rax
    0xC3,             // RET
];

/// After fold, the CBranch condition for a JG instruction must be SLess(rcx, rax),
/// meaning "rcx < rax" i.e. "rax > rcx" (signed). Exact opcode AND operand order checked.
/// This test fails before the fix because BoolNot(ZF) gets rewritten to NotEq(a,b)
/// by mba_simplify before recover_conditions runs, breaking the existing JG recognizer.
#[test]
fn jg_recovered_as_signed_greater() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let insts = decode_x64(JG_BYTES, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            // Find the CBranch condition
            let cond_id = ssa.blocks.iter()
                .find_map(|b| if let SsaTerminator::CBranch { cond, .. } = b.terminator { Some(cond) } else { None })
                .expect("no CBranch block after fold");

            // Resolve through Var chains (up to 8 hops) to get the expression
            let mut resolved = cond_id;
            for _ in 0..8 {
                if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr { resolved = next; } else { break; }
            }
            let cond_expr = &ssa.vars[resolved.0 as usize].expr;

            // Must be SLess, not BoolAnd or anything flag-involving
            let (sl, sr) = match cond_expr {
                Expr::BinOp(BinOpKind::SLess, l, r) => (*l, *r),
                other => panic!("expected SLess, got {:?}", other),
            };

            // Resolve operands through Var/Unique chains to get register vars
            let resolve = |mut id: rsleigh_decompile::ir::VarId| {
                for _ in 0..8 {
                    let v = &ssa.vars[id.0 as usize];
                    match v.expr {
                        Expr::Var(next) => id = next,
                        _ => break,
                    }
                    if v.varnode.space == AddressSpaceId::Register { break; }
                }
                id
            };
            let left_var = resolve(sl);
            let right_var = resolve(sr);
            let left_off = ssa.vars[left_var.0 as usize].varnode.offset;
            let right_off = ssa.vars[right_var.0 as usize].varnode.offset;

            // CMP rax, rcx → JG means rax > rcx → SLess(rcx, rax)
            // RAX is at register offset 0, RCX is at register offset 8
            assert_eq!(left_off, 8,  "SLess left operand must be RCX (offset 8), got offset {}", left_off);
            assert_eq!(right_off, 0, "SLess right operand must be RAX (offset 0), got offset {}", right_off);

            // Neither operand should be a flag register
            const FLAG_OFFSETS: &[u64] = &[512, 513, 514, 518, 519, 521, 523];
            assert!(!FLAG_OFFSETS.contains(&left_off),  "left operand is a flag register");
            assert!(!FLAG_OFFSETS.contains(&right_off), "right operand is a flag register");
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Validates the operand-match guard: a BoolAnd(NotEq(0,1), Eq(OF,SF)) where the NotEq
/// operands do NOT match the CMP operands must NOT be recovered as a signed comparison.
/// This proves the validation logic is actually present and working.
#[test]
fn jg_no_false_positive() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let insts = decode_x64(JG_BYTES, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);

            // Before fold: the CBranch has BoolAnd(BoolNot(ZF), Eq(OF,SF)).
            // We replace it with BoolAnd(NotEq(Const(0), Const(1)), Eq(OF,SF)) —
            // operands 0 and 1 do not match rax/rcx, so the validator must reject it.
            let cbranch_block = ssa.blocks.iter()
                .position(|b| matches!(b.terminator, SsaTerminator::CBranch { .. }))
                .expect("no CBranch");

            // Extract Eq(OF,SF) from the right side of the BoolAnd, and terminator fields
            let (eq_of_sf_id, taken, fallthrough) = {
                if let SsaTerminator::CBranch { cond, taken, fallthrough } = ssa.blocks[cbranch_block].terminator {
                    let eq_id = if let Expr::BinOp(BinOpKind::BoolAnd, _l, r) = ssa.vars[cond.0 as usize].expr {
                        r
                    } else { panic!("expected BoolAnd before fold, got {:?}", ssa.vars[cond.0 as usize].expr) };
                    (eq_id, taken, fallthrough)
                } else { panic!("expected CBranch") }
            };
            let template_varnode = ssa.vars[eq_of_sf_id.0 as usize].varnode;

            // Build NotEq(Const(0), Const(1)) — operands that will NOT match rax/rcx
            let c0 = ssa.new_var(template_varnode, Expr::Const(0, 8), 8);
            let c1 = ssa.new_var(template_varnode, Expr::Const(1, 8), 8);
            let mismatched_neq = ssa.new_var(template_varnode, Expr::BinOp(BinOpKind::NotEq, c0, c1), 1);
            let mismatched_cond = ssa.new_var(template_varnode, Expr::BinOp(BinOpKind::BoolAnd, mismatched_neq, eq_of_sf_id), 1);
            ssa.blocks[cbranch_block].terminator = SsaTerminator::CBranch { cond: mismatched_cond, taken, fallthrough };

            // Fold: the mismatched condition must NOT be recovered to SLess
            fold_with_cc(&mut ssa, CallingConv::Win64);

            if let SsaTerminator::CBranch { cond, .. } = &ssa.blocks[cbranch_block].terminator {
                let mut resolved = *cond;
                for _ in 0..8 {
                    if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr { resolved = next; } else { break; }
                }
                assert!(
                    !matches!(ssa.vars[resolved.0 as usize].expr, Expr::BinOp(BinOpKind::SLess, _, _)),
                    "false positive: NotEq(0,1) was incorrectly recovered as SLess: {:?}",
                    ssa.vars[resolved.0 as usize].expr,
                );
            }
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Integration: function 0x14000195e must not contain "OF == SF" or "SF == OF"
/// in output, and must contain " > " in at least one condition line.
/// Skips gracefully if the fixture binary is absent.
#[test]
fn jg_integration_positive() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => { eprintln!("skipping jg_integration_positive: fixture not found"); return; }
    };
    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => { eprintln!("skipping: PE parse error: {}", e); return; }
    };

    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x14000195e;
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
        None => { eprintln!("skipping: VA not in any section"); return; }
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

            // Negative: no flag register names in conditions
            assert!(
                !out.contains("OF == SF") && !out.contains("SF == OF"),
                "flag registers still leak into output:\n{}",
                out.lines().filter(|l| l.contains("OF") || l.contains("SF")).collect::<Vec<_>>().join("\n")
            );

            // Positive: a signed > comparison was emitted somewhere
            let has_gt = out.lines().any(|l| {
                let t = l.trim();
                (t.starts_with("if (") || t.starts_with("while (") || t.starts_with("} else if ("))
                    && t.contains(" > ")
            });
            assert!(has_gt, "no signed > comparison found in output:\n{}", out);
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}
