use rsleigh_api::{Architecture, Decoder};
fn main() {
    let t = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let data = std::fs::read("/tmp/test_swift_arm64").unwrap();
            let obj = goblin::Object::parse(&data).unwrap();
            let goblin::Object::Mach(goblin::mach::Mach::Binary(m)) = obj else {
                return;
            };
            let addr = m
                .symbols()
                .flatten()
                .find(|(n, _)| *n == "_$s16test_swift_arm649fibonacciyS2iF")
                .map(|(_, nl)| nl.n_value)
                .unwrap();
            let seg = m
                .segments
                .iter()
                .find(|s| addr >= s.vmaddr && addr < s.vmaddr + s.vmsize)
                .unwrap();
            let off = (seg.fileoff + (addr - seg.vmaddr)) as usize;
            let mut dec = Decoder::new(Architecture::AArch64);
            let mut insts = Vec::new();
            let mut io = 0;
            while io < 128 && off + io < data.len() {
                match dec.decode(&data[off + io..], addr + io as u64) {
                    Ok(inst) => {
                        let len = inst.len as usize;
                        if len == 0 {
                            break;
                        }
                        let is_ret =
                            inst.disassembly.contains("ret") || inst.disassembly.contains("RET");
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
            let ssa = rsleigh_decompile::ssa::build_ssa(&cfg);
            println!(
                "fibonacci: {} blocks, {} vars",
                ssa.blocks.len(),
                ssa.vars.len()
            );
            for (bi, block) in ssa.blocks.iter().enumerate() {
                let term = match &block.terminator {
                    rsleigh_decompile::ir::SsaTerminator::Return(None) => {
                        "Return(None)".to_string()
                    }
                    rsleigh_decompile::ir::SsaTerminator::Return(Some(v)) => {
                        let vd = &ssa.vars[v.0 as usize];
                        format!(
                            "Return(VarId({}) off={} expr={:?})",
                            v.0,
                            vd.varnode.offset,
                            match &vd.expr {
                                rsleigh_decompile::ir::Expr::Unknown => "Unk",
                                _ => "other",
                            }
                        )
                    }
                    rsleigh_decompile::ir::SsaTerminator::Branch(t) => format!("Branch({})", t.0),
                    rsleigh_decompile::ir::SsaTerminator::CBranch {
                        taken, fallthrough, ..
                    } => format!("CBranch({}/{})", taken.0, fallthrough.0),
                    _ => "?".to_string(),
                };
                println!("  Block {}: {}", bi, term);
            }
        })
        .unwrap();
    t.join().unwrap();
}
