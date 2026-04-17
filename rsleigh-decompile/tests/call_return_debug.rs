// Temporary debug test
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ssa::build_ssa_with_cc;
use rsleigh_decompile::structure::recover_structure;
use rsleigh_decompile::ir::{StructuredStmt, CallTarget};
use pcode_ir::PcodeOp;

#[test]
fn debug_strcspn_stmts() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) { Ok(d) => d, Err(_) => { return; } };
    let pe = goblin::pe::PE::parse(&data).unwrap();
    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001e41;
    let rva = func_va - image_base;
    let mut file_off = None;
    for s in &pe.sections {
        let s_va = s.virtual_address as u64;
        let s_sz = s.virtual_size as u64;
        if rva >= s_va && rva < s_va + s_sz {
            file_off = Some((s.pointer_to_raw_data as u64 + (rva - s_va)) as usize);
        }
    }
    let off = file_off.unwrap();
    let bytes = data[off..off + 0x300.min(data.len() - off)].to_vec();
    let handle = std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(move || {
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
        let cfg = build_cfg(&insts);
        let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
        fold_with_cc(&mut ssa, CallingConv::Win64);

        let stmts = recover_structure(&ssa, &cfg);

        // Find the then_body of the outer IfElse
        fn find_func_call(stmts: &[StructuredStmt], ssa: &rsleigh_decompile::ir::SsaCfg) {
            for stmt in stmts {
                match stmt {
                    StructuredStmt::Call { target: CallTarget::Direct(addr), args, out } => {
                        let target_addr = *addr;
                        eprintln!("Call 0x{:x} out={:?} args={:?}", target_addr, out,
                            args.iter().map(|a| {
                                let v = ssa.var(*a);
                                format!("VarId({}) off={} size={} expr={:?}", a.0, v.varnode.offset, v.varnode.size, v.expr)
                            }).collect::<Vec<_>>());
                    }
                    StructuredStmt::IfElse { then_body, else_body, .. } => {
                        find_func_call(then_body, ssa);
                        find_func_call(else_body, ssa);
                    }
                    _ => {}
                }
            }
        }
        find_func_call(&stmts, &ssa);
    }).unwrap();
    handle.join().unwrap();
}
