//! Probe: dump SSA for check2 (0x140001a68) in cb_baristas_secret_x64.exe.
//!
//! Goal: determine whether memory SSA is (a) failing to match the [RBP-0x8]
//! store/load pair to the same SlotKey, (b) matching but failing to forward,
//! or (c) forwarding correctly but the printer is mislabeling.
//!
//! Audit context: docs/audits/2026-04-16-x86-64-pseudocode-audit.md
//!
//! Run: cargo run -p test-harness --example probe_check2_ssa --release

use goblin::pe::PE;
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::ir::{Expr, Stmt, VarDef};
use rsleigh_decompile::ssa::build_ssa;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use pcode_ir::{AddressSpaceId, Instruction, PcodeOp};

const BIN_PATH: &str = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
// Override via env RSLEIGH_PROBE_ADDR=0xVVVVVVVV
const DEFAULT_FUNC_VA: u64 = 0x140001a68;
const FUNC_LEN: usize = 0x400; // generous; decoder will stop at RET

fn main() {
    let func_va: u64 = std::env::var("RSLEIGH_PROBE_ADDR")
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(DEFAULT_FUNC_VA);

    let data = std::fs::read(BIN_PATH).expect("read binary");
    let pe = PE::parse(&data).expect("parse PE");
    let image_base = pe.image_base as u64;
    let rva = func_va - image_base;
    println!("// probing 0x{:x}", func_va);

    // Find section containing the RVA and compute file offset.
    let mut file_off = None;
    for s in &pe.sections {
        let s_va = s.virtual_address as u64;
        let s_sz = s.virtual_size as u64;
        if rva >= s_va && rva < s_va + s_sz {
            file_off = Some((s.pointer_to_raw_data as u64 + (rva - s_va)) as usize);
            break;
        }
    }
    let file_off = file_off.expect("function addr not in any section");
    let bytes = &data[file_off..file_off + FUNC_LEN.min(data.len() - file_off)];

    // Decode instructions until RET or decode error.
    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts: Vec<(u64, Instruction)> = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = func_va + off as u64;
        match dec.decode(&bytes[off..], addr) {
            Ok(inst) => {
                let l = inst.len as usize;
                let is_ret = inst.ops.iter().any(|op| matches!(op, PcodeOp::Return { .. }));
                insts.push((addr, inst));
                off += l;
                if is_ret { break; }
            }
            Err(e) => {
                eprintln!("decode error at 0x{:x}: {:?}", addr, e);
                break;
            }
        }
    }
    println!("// decoded {} instructions for check2", insts.len());

    let cfg = build_cfg(&insts);
    println!("// CFG has {} blocks", cfg.blocks.len());

    let mut ssa = build_ssa(&cfg);
    let run_fold = std::env::var("RSLEIGH_PROBE_FOLD").ok().as_deref() == Some("1");
    if run_fold {
        println!("// running fold_with_cc(Win64)");
        fold_with_cc(&mut ssa, CallingConv::Win64);
    } else {
        println!("// fold SKIPPED (set RSLEIGH_PROBE_FOLD=1 to enable)");
    }

    // Dump every block's stmts and var defs used within.
    for (bi, b) in ssa.blocks.iter().enumerate() {
        println!("\n=== block {} (addr 0x{:x}, {} stmts) ===", bi, b.addr, b.stmts.len());
        for stmt in &b.stmts {
            dump_stmt(stmt, &ssa.vars);
        }
        println!("  terminator: {:?}", terminator_tag(&b.terminator));
    }

    // Specifically: enumerate all Load exprs and all Store stmts; highlight
    // anything that references base register RBP (offset 40) or RSP (offset 32).
    println!("\n=== Loads and Stores with stack-slot analysis ===");
    for (bi, b) in ssa.blocks.iter().enumerate() {
        for stmt in &b.stmts {
            match stmt {
                Stmt::Store { addr, val } => {
                    let slot = stack_slot_key(*addr, &ssa.vars);
                    println!(
                        "  block {} STORE addr=v{} val=v{} slot={:?}",
                        bi, addr.0, val.0, slot
                    );
                }
                Stmt::Assign(vid) => {
                    let v = &ssa.vars[vid.0 as usize];
                    if let Expr::Load(ptr) = &v.expr {
                        let slot = stack_slot_key(*ptr, &ssa.vars);
                        println!(
                            "  block {} LOAD v{} = *v{}  slot={:?}  (still-a-Load: YES)",
                            bi, vid.0, ptr.0, slot
                        );
                    }
                }
                _ => {}
            }
        }
    }

    println!("\n=== VarDefs with Expr::Var (forwarded Loads appear here) ===");
    for v in &ssa.vars {
        if let Expr::Var(target) = v.expr {
            println!(
                "  v{} (vn={:?}/{}/{}) = Var(v{})  // possibly a forwarded Load",
                v.id.0,
                v.varnode.space,
                v.varnode.offset,
                v.varnode.size,
                target.0
            );
        }
    }
}

fn dump_stmt(stmt: &Stmt, vars: &[VarDef]) {
    match stmt {
        Stmt::Assign(vid) => {
            let v = &vars[vid.0 as usize];
            println!(
                "  v{} (vn={:?}/{:x}/{}) = {}",
                v.id.0,
                v.varnode.space,
                v.varnode.offset,
                v.varnode.size,
                expr_str(&v.expr, vars)
            );
        }
        Stmt::Store { addr, val } => {
            println!("  STORE *v{} = v{}", addr.0, val.0);
        }
        Stmt::Call { target, args, out } => {
            println!(
                "  CALL {:?} args={:?} out={:?}",
                target,
                args.iter().map(|a| a.0).collect::<Vec<_>>(),
                out.map(|o| o.0)
            );
        }
    }
}

fn expr_str(e: &Expr, _vars: &[VarDef]) -> String {
    match e {
        Expr::Var(v) => format!("Var(v{})", v.0),
        Expr::Const(c, sz) => format!("Const({:#x}, {})", c, sz),
        Expr::BinOp(k, l, r) => format!("BinOp({:?}, v{}, v{})", k, l.0, r.0),
        Expr::UnaryOp(k, x) => format!("UnaryOp({:?}, v{})", k, x.0),
        Expr::Load(p) => format!("Load(v{})", p.0),
        Expr::FieldAccess(b, o) => format!("FieldAccess(v{}, {:#x})", b.0, o),
        Expr::Phi(ins) => format!("Phi({:?})", ins.iter().map(|i| i.0).collect::<Vec<_>>()),
        Expr::Ternary(c, t, e) => format!("Ternary(v{}, v{}, v{})", c.0, t.0, e.0),
        Expr::Unknown => "Unknown".to_string(),
        Expr::UserOp { func_id, inputs } => format!(
            "UserOp({}, {:?})",
            func_id,
            inputs.iter().map(|i| i.0).collect::<Vec<_>>()
        ),
    }
}

fn terminator_tag(t: &rsleigh_decompile::ir::SsaTerminator) -> String {
    use rsleigh_decompile::ir::SsaTerminator::*;
    match t {
        Fallthrough(b) => format!("Fallthrough(b{})", b.0),
        Branch(b) => format!("Branch(b{})", b.0),
        CBranch { cond, taken, fallthrough } => {
            format!("CBranch(v{} -> b{} / b{})", cond.0, taken.0, fallthrough.0)
        }
        Call { target, args, fallthrough, .. } => {
            format!(
                "Call({:?}, args={:?}, fall=b{})",
                target,
                args.iter().map(|a| a.0).collect::<Vec<_>>(),
                fallthrough.0
            )
        }
        Return(v) => format!("Return({:?})", v.map(|x| x.0)),
        Indirect(v) => format!("Indirect(v{})", v.0),
    }
}

/// Mirror of ssa.rs get_slot_key for diagnostic printing.
fn stack_slot_key(ptr: rsleigh_decompile::ir::VarId, vars: &[VarDef]) -> Option<(u64, i64, u32)> {
    let pv = &vars[ptr.0 as usize];
    match &pv.expr {
        Expr::Unknown if pv.varnode.space == AddressSpaceId::Register => {
            if [40u64, 29, 32, 256, 112].contains(&pv.varnode.offset) {
                return Some((pv.varnode.offset, 0, pv.varnode.size));
            }
        }
        Expr::BinOp(rsleigh_decompile::ir::BinOpKind::Add, l, r) => {
            let lv = &vars[l.0 as usize];
            let rv = &vars[r.0 as usize];
            if lv.varnode.space == AddressSpaceId::Register
                && [40u64, 29, 32, 256, 112].contains(&lv.varnode.offset)
            {
                if let Expr::Const(val, _) = &rv.expr {
                    return Some((lv.varnode.offset, *val as i64, pv.varnode.size));
                }
            }
            if rv.varnode.space == AddressSpaceId::Register
                && [40u64, 29, 32, 256, 112].contains(&rv.varnode.offset)
            {
                if let Expr::Const(val, _) = &lv.expr {
                    return Some((rv.varnode.offset, *val as i64, pv.varnode.size));
                }
            }
        }
        _ => {}
    }
    None
}
