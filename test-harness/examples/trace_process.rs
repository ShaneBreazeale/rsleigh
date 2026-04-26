use rsleigh_api::{Architecture, Decoder};

fn main() {
    let t = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let data = std::fs::read("/tmp/quality_test").unwrap();
            let obj = goblin::Object::parse(&data).unwrap();
            let goblin::Object::Mach(goblin::mach::Mach::Binary(m)) = obj else {
                return;
            };

            let addr = m
                .symbols()
                .flatten()
                .find(|(n, _)| *n == "_process")
                .map(|(_, nl)| nl.n_value)
                .unwrap();

            let seg = m
                .segments
                .iter()
                .find(|s| addr >= s.vmaddr && addr < s.vmaddr + s.vmsize)
                .unwrap();
            let off = (seg.fileoff + (addr - seg.vmaddr)) as usize;

            let mut dec = Decoder::new(Architecture::X86_64);
            let mut insts = Vec::new();
            let mut io = 0;
            while io < 256 && off + io < data.len() {
                match dec.decode(&data[off + io..], addr + io as u64) {
                    Ok(inst) => {
                        let len = inst.len as usize;
                        if len == 0 {
                            break;
                        }
                        let is_ret = inst.disassembly.starts_with("RET");
                        insts.push((addr + io as u64, inst));
                        io += len;
                        if is_ret {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            let cfg = rsleigh_decompile::cfg::build_cfg(&insts);
            println!("CFG: {} blocks", cfg.blocks.len());
            for block in &cfg.blocks {
                let succs: Vec<_> = cfg.successors(block.id).iter().map(|s| s.0).collect();
                println!(
                    "  Block {} (0x{:x}): {} ops → {:?}",
                    block.id.0,
                    block.addr,
                    block.ops.len(),
                    succs
                );
            }

            let ssa = rsleigh_decompile::ssa::build_ssa(&cfg);

            println!("\nRDI (offset 56) VarIds:");
            for (i, v) in ssa.vars.iter().enumerate() {
                if v.varnode.space == pcode_ir::AddressSpaceId::Register && v.varnode.offset == 56 {
                    let expr_str = match &v.expr {
                        rsleigh_decompile::ir::Expr::Unknown => "Unknown".into(),
                        rsleigh_decompile::ir::Expr::Const(val, _) => format!("Const(0x{:x})", val),
                        rsleigh_decompile::ir::Expr::Var(id) => format!("Var({})", id.0),
                        rsleigh_decompile::ir::Expr::Load(id) => format!("Load({})", id.0),
                        rsleigh_decompile::ir::Expr::Phi(inputs) => {
                            format!("Phi({:?})", inputs.iter().map(|i| i.0).collect::<Vec<_>>())
                        }
                        rsleigh_decompile::ir::Expr::BinOp(k, l, r) => {
                            format!("{:?}({}, {})", k, l.0, r.0)
                        }
                        rsleigh_decompile::ir::Expr::UnaryOp(k, i) => format!("{:?}({})", k, i.0),
                        _ => format!("{:?}", v.expr),
                    };
                    println!(
                        "  VarId({:3}) size={} param={:?} expr={}",
                        i, v.varnode.size, v.param_name, expr_str
                    );
                }
            }

            println!("\nCall stmts:");
            for (bi, block) in ssa.blocks.iter().enumerate() {
                for stmt in &block.stmts {
                    if let rsleigh_decompile::ir::Stmt::Call { target, args, .. } = stmt {
                        let tgt = match target {
                            rsleigh_decompile::ir::CallTarget::Direct(a) => format!("0x{:x}", a),
                            rsleigh_decompile::ir::CallTarget::Indirect(v) => {
                                format!("ind({:?})", v)
                            }
                        };
                        let a: Vec<String> = args
                            .iter()
                            .map(|a| {
                                let v = &ssa.vars[a.0 as usize];
                                format!(
                                    "{}:off={},expr={:?}",
                                    a.0,
                                    v.varnode.offset,
                                    match &v.expr {
                                        rsleigh_decompile::ir::Expr::Const(val, _) =>
                                            format!("0x{:x}", val),
                                        rsleigh_decompile::ir::Expr::Load(id) =>
                                            format!("Load({})", id.0),
                                        rsleigh_decompile::ir::Expr::Var(id) =>
                                            format!("Var({})", id.0),
                                        rsleigh_decompile::ir::Expr::Unknown => "Unk".into(),
                                        _ => "..".into(),
                                    }
                                )
                            })
                            .collect();
                        println!("  B{}: {} args=[{}]", bi, tgt, a.join(", "));
                    }
                }
                if let rsleigh_decompile::ir::SsaTerminator::Call { target, args, .. } =
                    &block.terminator
                {
                    let tgt = match target {
                        rsleigh_decompile::ir::CallTarget::Direct(a) => format!("0x{:x}", a),
                        _ => "?".into(),
                    };
                    let a: Vec<String> = args
                        .iter()
                        .map(|a| format!("{}:off={}", a.0, ssa.vars[a.0 as usize].varnode.offset))
                        .collect();
                    println!("  B{}: TERM {} args=[{}]", bi, tgt, a.join(", "));
                }
            }
        })
        .unwrap();
    t.join().unwrap();
}
