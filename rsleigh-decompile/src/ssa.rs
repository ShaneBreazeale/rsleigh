use std::collections::HashMap;
use pcode_ir::{PcodeOp, Varnode, AddressSpaceId, get_output};
use crate::ir::*;

/// Convert a CFG into SSA form.
pub fn build_ssa(cfg: &Cfg) -> SsaCfg {
    let mut ssa = SsaCfg {
        blocks: Vec::new(),
        vars: Vec::new(),
        entry: cfg.entry,
    };

    let preds = cfg.predecessors();

    // Per-block: map from varnode -> VarId at block exit
    let mut block_exit_vars: Vec<HashMap<Varnode, VarId>> = vec![HashMap::new(); cfg.blocks.len()];

    // First pass: local numbering within each block
    for block in &cfg.blocks {
        let mut current: HashMap<Varnode, VarId> = HashMap::new();

        // Inherit from single predecessor if it exists
        let block_preds = &preds[block.id.0];
        if block_preds.len() == 1 {
            current = block_exit_vars[block_preds[0].0].clone();
        }

        let mut stmts = Vec::new();

        for (_addr, op) in &block.ops {
            match op.clone() {
                PcodeOp::Store { ptr, val, .. } => {
                    let addr_var = resolve_input(&mut ssa, &mut current, &ptr);
                    let val_var = resolve_input(&mut ssa, &mut current, &val);
                    stmts.push(Stmt::Store { addr: addr_var, val: val_var });
                }
                ref op => {
                    if let Some(out_vn) = get_output(op) {
                        let expr = build_expr(&mut ssa, &mut current, op);
                        let var_id = ssa.new_var(out_vn, expr, out_vn.size);
                        current.insert(out_vn, var_id);
                        stmts.push(Stmt::Assign(var_id));
                    }
                    // Ops with no output and not Store (e.g., Branch handled as terminator)
                }
            }
        }

        let terminator = convert_terminator(&mut ssa, &mut current, &block.terminator);

        block_exit_vars[block.id.0] = current;

        ssa.blocks.push(SsaBlock {
            id: block.id,
            addr: block.addr,
            stmts,
            terminator,
        });
    }

    // Second pass: insert Phi nodes at join points
    for bid in 0..cfg.blocks.len() {
        let block_preds = &preds[bid];
        if block_preds.len() <= 1 {
            continue;
        }

        // Find varnodes that differ across predecessors
        let mut all_varnodes: HashMap<Varnode, Vec<(BlockId, VarId)>> = HashMap::new();
        for &pred_id in block_preds {
            for (vn, &var_id) in &block_exit_vars[pred_id.0] {
                // Skip flag registers and tiny temporaries for cleaner output
                if vn.space == AddressSpaceId::Unique {
                    continue;
                }
                all_varnodes.entry(*vn).or_default().push((pred_id, var_id));
            }
        }

        let mut phi_stmts = Vec::new();
        for (vn, entries) in &all_varnodes {
            if entries.len() < 2 {
                continue;
            }
            // Check if all predecessors agree
            let first_var = entries[0].1;
            if entries.iter().all(|(_, v)| *v == first_var) {
                continue;
            }
            // Insert Phi
            let phi_inputs: Vec<VarId> = entries.iter().map(|(_, v)| *v).collect();
            let phi_var = ssa.new_var(*vn, Expr::Phi(phi_inputs.clone()), vn.size);
            phi_stmts.push(Stmt::Assign(phi_var));
        }

        // Prepend phis to block
        if !phi_stmts.is_empty() {
            let block = &mut ssa.blocks[bid];
            let mut new_stmts = phi_stmts;
            new_stmts.append(&mut block.stmts);
            block.stmts = new_stmts;
        }
    }

    // Count uses
    count_uses(&mut ssa);

    ssa
}

fn resolve_input(ssa: &mut SsaCfg, current: &mut HashMap<Varnode, VarId>, vn: &Varnode) -> VarId {
    if vn.space == AddressSpaceId::Const {
        return ssa.new_var(*vn, Expr::Const(vn.offset, vn.size), vn.size);
    }
    if let Some(&var_id) = current.get(vn) {
        return var_id;
    }
    // Unknown — function parameter or uninitialized
    let var_id = ssa.new_var(*vn, Expr::Unknown, vn.size);
    current.insert(*vn, var_id);
    var_id
}

fn build_expr(ssa: &mut SsaCfg, current: &mut HashMap<Varnode, VarId>, op: &PcodeOp) -> Expr {
    macro_rules! bin {
        ($kind:ident, $left:expr, $right:expr) => {{
            let l = resolve_input(ssa, current, $left);
            let r = resolve_input(ssa, current, $right);
            Expr::BinOp(BinOpKind::$kind, l, r)
        }};
    }
    macro_rules! unary {
        ($kind:ident, $input:expr) => {{
            let i = resolve_input(ssa, current, $input);
            Expr::UnaryOp(UnaryOpKind::$kind, i)
        }};
    }

    match op {
        PcodeOp::Copy { input, .. } => {
            let v = resolve_input(ssa, current, input);
            Expr::Var(v)
        }
        PcodeOp::Load { ptr, .. } => {
            let p = resolve_input(ssa, current, ptr);
            Expr::Load(p)
        }
        PcodeOp::IntAdd { left, right, .. } => bin!(Add, left, right),
        PcodeOp::IntSub { left, right, .. } => bin!(Sub, left, right),
        PcodeOp::IntMult { left, right, .. } => bin!(Mult, left, right),
        PcodeOp::IntDiv { left, right, .. } => bin!(Div, left, right),
        PcodeOp::IntSDiv { left, right, .. } => bin!(SDiv, left, right),
        PcodeOp::IntRem { left, right, .. } => bin!(Rem, left, right),
        PcodeOp::IntSRem { left, right, .. } => bin!(SRem, left, right),
        PcodeOp::IntAnd { left, right, .. } => bin!(And, left, right),
        PcodeOp::IntOr { left, right, .. } => bin!(Or, left, right),
        PcodeOp::IntXor { left, right, .. } => bin!(Xor, left, right),
        PcodeOp::IntLsl { left, right, .. } => bin!(Lsl, left, right),
        PcodeOp::IntLsr { left, right, .. } => bin!(Lsr, left, right),
        PcodeOp::IntAsr { left, right, .. } => bin!(Asr, left, right),
        PcodeOp::IntEq { left, right, .. } => bin!(Eq, left, right),
        PcodeOp::IntNotEq { left, right, .. } => bin!(NotEq, left, right),
        PcodeOp::IntLess { left, right, .. } => bin!(Less, left, right),
        PcodeOp::IntLessEq { left, right, .. } => bin!(LessEq, left, right),
        PcodeOp::IntSLess { left, right, .. } => bin!(SLess, left, right),
        PcodeOp::IntSLessEq { left, right, .. } => bin!(SLessEq, left, right),
        PcodeOp::IntCarry { left, right, .. } => bin!(Carry, left, right),
        PcodeOp::IntSCarry { left, right, .. } => bin!(SCarry, left, right),
        PcodeOp::IntSBorrow { left, right, .. } => bin!(SBorrow, left, right),
        PcodeOp::IntNeg { input, .. } => unary!(Neg, input),
        PcodeOp::IntNot { input, .. } => unary!(Not, input),
        PcodeOp::IntZext { input, .. } => unary!(Zext, input),
        PcodeOp::IntSext { input, .. } => unary!(Sext, input),
        PcodeOp::BoolAnd { left, right, .. } => bin!(BoolAnd, left, right),
        PcodeOp::BoolOr { left, right, .. } => bin!(BoolOr, left, right),
        PcodeOp::BoolXor { left, right, .. } => bin!(BoolXor, left, right),
        PcodeOp::BoolNot { input, .. } => unary!(BoolNot, input),
        PcodeOp::FloatAdd { left, right, .. } => bin!(FloatAdd, left, right),
        PcodeOp::FloatSub { left, right, .. } => bin!(FloatSub, left, right),
        PcodeOp::FloatMult { left, right, .. } => bin!(FloatMult, left, right),
        PcodeOp::FloatDiv { left, right, .. } => bin!(FloatDiv, left, right),
        PcodeOp::FloatEq { left, right, .. } => bin!(FloatEq, left, right),
        PcodeOp::FloatNotEq { left, right, .. } => bin!(FloatNotEq, left, right),
        PcodeOp::FloatLess { left, right, .. } => bin!(FloatLess, left, right),
        PcodeOp::FloatLessEq { left, right, .. } => bin!(FloatLessEq, left, right),
        PcodeOp::FloatNeg { input, .. } => unary!(FloatNeg, input),
        PcodeOp::FloatAbs { input, .. } => unary!(FloatAbs, input),
        PcodeOp::FloatSqrt { input, .. } => unary!(FloatSqrt, input),
        PcodeOp::FloatNan { input, .. } => unary!(FloatNan, input),
        PcodeOp::Int2Float { input, .. } => unary!(Int2Float, input),
        PcodeOp::Float2Float { input, .. } => unary!(Float2Float, input),
        PcodeOp::Trunc { input, .. } => unary!(Trunc, input),
        PcodeOp::FloatCeil { input, .. } => unary!(FloatCeil, input),
        PcodeOp::FloatFloor { input, .. } => unary!(FloatFloor, input),
        PcodeOp::FloatRound { input, .. } => unary!(FloatRound, input),
        PcodeOp::Popcount { input, .. } => unary!(Popcount, input),
        PcodeOp::Lzcount { input, .. } => unary!(Lzcount, input),
        PcodeOp::Subpiece { input, lsb, out } => {
            let i = resolve_input(ssa, current, input);
            if *lsb == 0 {
                // Truncation — just treat as a variable reference
                Expr::Var(i)
            } else {
                let shift_amt = ssa.new_var(
                    Varnode::constant((*lsb as u64) * 8, 4),
                    Expr::Const((*lsb as u64) * 8, 4),
                    4,
                );
                Expr::BinOp(BinOpKind::Lsr, i, shift_amt)
            }
        }
        _ => Expr::Unknown,
    }
}

fn convert_terminator(
    ssa: &mut SsaCfg,
    current: &mut HashMap<Varnode, VarId>,
    term: &Terminator,
) -> SsaTerminator {
    match term {
        Terminator::Fallthrough(b) => SsaTerminator::Fallthrough(*b),
        Terminator::Branch(b) => SsaTerminator::Branch(*b),
        Terminator::CBranch { cond, taken, fallthrough } => {
            let cond_var = resolve_input(ssa, current, cond);
            SsaTerminator::CBranch { cond: cond_var, taken: *taken, fallthrough: *fallthrough }
        }
        Terminator::Call { target, fallthrough } => {
            SsaTerminator::Call { target: target.clone(), args: vec![], fallthrough: *fallthrough }
        }
        Terminator::Return => {
            // Try to find RAX/X0 as return value (common convention)
            SsaTerminator::Return(None)
        }
        Terminator::Indirect(vn) => {
            let v = resolve_input(ssa, current, vn);
            SsaTerminator::Indirect(v)
        }
    }
}

fn count_uses(ssa: &mut SsaCfg) {
    // Collect all referenced VarIds first, then update counts
    let mut use_counts = vec![0u32; ssa.vars.len()];

    for v in 0..ssa.vars.len() {
        let refs = collect_expr_refs(&ssa.vars[v].expr);
        for id in refs {
            use_counts[id.0 as usize] += 1;
        }
    }

    for block in &ssa.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, val } => {
                    use_counts[addr.0 as usize] += 1;
                    use_counts[val.0 as usize] += 1;
                }
                Stmt::Call { args, out: _, .. } => {
                    for a in args {
                        use_counts[a.0 as usize] += 1;
                    }
                }
                _ => {}
            }
        }
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => {
                use_counts[cond.0 as usize] += 1;
            }
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => {
                use_counts[v.0 as usize] += 1;
            }
            _ => {}
        }
    }

    for (i, count) in use_counts.into_iter().enumerate() {
        ssa.vars[i].use_count = count;
    }
}

fn collect_expr_refs(expr: &Expr) -> Vec<VarId> {
    match expr {
        Expr::Var(id) => vec![*id],
        Expr::BinOp(_, l, r) => vec![*l, *r],
        Expr::UnaryOp(_, i) | Expr::Load(i) => vec![*i],
        Expr::Phi(inputs) => inputs.clone(),
        Expr::Const(_, _) | Expr::Unknown => vec![],
    }
}
