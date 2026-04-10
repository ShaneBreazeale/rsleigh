use pcode_ir::AddressSpaceId;
use crate::ir::*;

/// x86 flag register offsets (Ghidra register space).
const FLAG_OFFSETS: &[u64] = &[
    512, // CF
    513, // F1
    514, // PF
    518, // ZF
    519, // SF
    521, // DF
    523, // OF
];

/// Fold expressions: inline single-use temps, eliminate dead code and flags.
pub fn fold(ssa: &mut SsaCfg) {
    for _round in 0..4 {
        let before = ssa.vars.len();
        fold_once(ssa);
        // Recount uses after each round
        recount_uses(ssa);
        if ssa.vars.len() == before {
            break;
        }
    }
}

fn fold_once(ssa: &mut SsaCfg) {
    // Pass 1: Collapse trivial Phis
    for v in 0..ssa.vars.len() {
        if let Expr::Phi(inputs) = &ssa.vars[v].expr {
            if inputs.is_empty() {
                continue;
            }
            let first = inputs[0];
            if inputs.iter().all(|i| *i == first) {
                ssa.vars[v].expr = Expr::Var(first);
            }
        }
    }

    // Pass 2: Inline single-use Unique/flag temporaries
    // We do this by replacing Var(id) references with the inlined expr
    for v in 0..ssa.vars.len() {
        let vdef = &ssa.vars[v];
        if vdef.use_count != 1 {
            continue;
        }
        if vdef.varnode.space != AddressSpaceId::Unique {
            continue;
        }
        // This var is a single-use unique — mark it for inlining
        // (The actual inlining happens when the printer resolves expressions)
    }

    // Pass 3: Mark dead flag writes for elimination
    for block in &mut ssa.blocks {
        block.stmts.retain(|stmt| {
            match stmt {
                Stmt::Assign(var_id) => {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    // Remove if: writes to a flag register with zero uses
                    if vdef.varnode.space == AddressSpaceId::Register
                        && FLAG_OFFSETS.contains(&vdef.varnode.offset)
                        && vdef.use_count == 0
                    {
                        return false;
                    }
                    // Remove if: writes to Unique with zero uses and pure expression
                    if vdef.varnode.space == AddressSpaceId::Unique && vdef.use_count == 0 {
                        return false;
                    }
                    true
                }
                _ => true, // Keep stores and calls
            }
        });
    }
}

fn recount_uses(ssa: &mut SsaCfg) {
    let mut use_counts = vec![0u32; ssa.vars.len()];

    for v in 0..ssa.vars.len() {
        match &ssa.vars[v].expr {
            Expr::Var(id) => use_counts[id.0 as usize] += 1,
            Expr::BinOp(_, l, r) => {
                use_counts[l.0 as usize] += 1;
                use_counts[r.0 as usize] += 1;
            }
            Expr::UnaryOp(_, i) | Expr::Load(i) => use_counts[i.0 as usize] += 1,
            Expr::Phi(inputs) => {
                for i in inputs { use_counts[i.0 as usize] += 1; }
            }
            Expr::Const(_, _) | Expr::Unknown => {}
        }
    }
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, val } => {
                    use_counts[addr.0 as usize] += 1;
                    use_counts[val.0 as usize] += 1;
                }
                Stmt::Call { args, .. } => {
                    for a in args { use_counts[a.0 as usize] += 1; }
                }
                _ => {}
            }
        }
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => use_counts[cond.0 as usize] += 1,
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => use_counts[v.0 as usize] += 1,
            _ => {}
        }
    }

    for (i, count) in use_counts.into_iter().enumerate() {
        ssa.vars[i].use_count = count;
    }
}
