use std::collections::{HashMap, HashSet, VecDeque};
use pcode_ir::{PcodeOp, Varnode, AddressSpaceId, get_output};
use crate::ir::*;

/// Stack slot key: identifies a unique stack memory location.
/// Keyed by (base register offset, displacement, access size) to prevent
/// conflating different-sized accesses at the same offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SlotKey {
    base_reg: u64,  // Frame register offset (RBP=40, x29=29, RSP=32, SP=256, GP=112)
    disp: i64,      // Displacement from base
    size: u32,      // Access size in bytes
}

type StackMap = HashMap<SlotKey, VarId>;

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

    // Per-block: stack slot values at block exit (Phase 1 collection).
    let mut block_exit_stack: Vec<StackMap> = vec![HashMap::new(); cfg.blocks.len()];
    // Track which blocks have STORES (not inherited) for each slot key.
    let mut slot_store_blocks: HashMap<SlotKey, Vec<usize>> = HashMap::new();

    // Iterative dataflow: re-process blocks until exit vars stabilize (max 4 passes)
    for iteration in 0..4u32 {
        let prev_exit_vars: Vec<HashMap<Varnode, VarId>> = block_exit_vars.clone();
        let mut changed = false;

        for (block_idx, block) in cfg.blocks.iter().enumerate() {
            let block_preds = &preds[block.id.0];

            // On iteration > 0, skip blocks whose predecessors haven't changed.
            // Also always skip the entry block — it has no predecessors, so its
            // register state (function parameters) should never be modified by
            // loop convergence iterations.
            if iteration > 0 {
                if block_preds.is_empty() {
                    continue; // Entry block — never re-process
                }
                let any_pred_changed = block_preds.iter().any(|pred| {
                    prev_exit_vars[pred.0] != block_exit_vars[pred.0]
                });
                // Also check if any predecessor has new keys not in our current entry state
                let any_new_keys = block_preds.iter().any(|pred| {
                    block_exit_vars[pred.0].keys().any(|k| {
                        !prev_exit_vars[pred.0].contains_key(k)
                    })
                });
                if !any_pred_changed && !any_new_keys {
                    continue;
                }
            }

            let mut current: HashMap<Varnode, VarId> = HashMap::new();
            // Phase 1 stack tracking: INTRA-BLOCK only during SSA construction.
            // Cross-block resolution happens in Phase 2 after Phi insertion.
            let mut local_stack: StackMap = HashMap::new();

            // Inherit from the first already-processed FORWARD predecessor.
            // A forward predecessor has a lower block ID (comes before in CFG order).
            // Back-edge predecessors (higher block ID, from loop back-edges) are excluded
            // to prevent loop-contaminated register values from leaking into the loop
            // header's initial state. Back-edge values are properly merged via Phi nodes.
            if !block_preds.is_empty() {
                // First try forward predecessors only
                for pred in block_preds {
                    if pred.0 < block.id.0 && !block_exit_vars[pred.0].is_empty() {
                        current = block_exit_vars[pred.0].clone();
                        break;
                    }
                }
                // Fallback: if no forward predecessor has data (entry block or unreachable),
                // use any predecessor
                if current.is_empty() {
                    for pred in block_preds {
                        if !block_exit_vars[pred.0].is_empty() {
                            current = block_exit_vars[pred.0].clone();
                            break;
                        }
                    }
                }
            }

            let mut stmts = Vec::new();

            // Group P-code ops by instruction address for correct intra-instruction
            // register handling. x86-64 generates IntZext(EAX→RAX) before address
            // calculations that read RAX — the Zext must be deferred until after all
            // reads from the same instruction are resolved.
            let mut ops_iter = block.ops.iter().peekable();
            while ops_iter.peek().is_some() {
                // Collect all ops from the same instruction (same address)
                let inst_addr = ops_iter.peek().unwrap().0;
                let mut inst_ops: Vec<&PcodeOp> = Vec::new();
                while ops_iter.peek().map_or(false, |(a, _)| *a == inst_addr) {
                    inst_ops.push(&ops_iter.next().unwrap().1);
                }

                // Check for the sub-register Zext clobber pattern:
                // IntZext{out=(R,off,big), input=(R,off,small)} appears before
                // other ops that read (R,off,big).
                // If found, snapshot the pre-Zext value and defer the Zext write.
                let mut deferred_zext: Vec<(Varnode, VarId)> = Vec::new();

                // Find Zext ops that write to a register that is also read by later ops
                for (i, op) in inst_ops.iter().enumerate() {
                    if let PcodeOp::IntZext { out, input } = op {
                        if out.space == AddressSpaceId::Register
                            && input.space == AddressSpaceId::Register
                            && out.offset == input.offset
                            && out.size > input.size
                        {
                            // Check if any later op in this instruction reads the output register
                            let reads_later = inst_ops[i+1..].iter().any(|later_op| {
                                pcode_ir::reads_varnode(later_op, out)
                            });
                            if reads_later {
                                // Snapshot the current value of the super-register
                                // Process the Zext to get its VarId, but don't update current yet
                                let input_var = resolve_input(&mut ssa, &mut current, input);
                                let expr = Expr::UnaryOp(UnaryOpKind::Zext, input_var);
                                let var_id = ssa.new_var(*out, expr, out.size);
                                stmts.push(Stmt::Assign(var_id));
                                deferred_zext.push((*out, var_id));
                                continue;
                            }
                        }
                    }
                }

                // Process remaining ops normally
                for op in &inst_ops {
                    // Skip ops we already handled as deferred Zext
                    if let PcodeOp::IntZext { out, input } = op {
                        if deferred_zext.iter().any(|(vn, _)| vn == out) {
                            continue;
                        }
                    }

                    match (*op).clone() {
                        PcodeOp::Store { ptr, val, .. } => {
                            let addr_var = resolve_input(&mut ssa, &mut current, &ptr);
                            let val_var = resolve_input(&mut ssa, &mut current, &val);
                            // Track stack stores for intra-block forwarding
                            let val_size = ssa.vars[val_var.0 as usize].size;
                            let key = get_slot_key(addr_var, val_size, &ssa);
                            if let Some(key) = key {
                                local_stack.insert(key, val_var);
                                slot_store_blocks.entry(key).or_default().push(block.id.0);
                            }
                            stmts.push(Stmt::Store { addr: addr_var, val: val_var });
                        }
                        ref op => {
                            if let Some(out_vn) = get_output(op) {
                                // For Loads: only resolve from INTRA-BLOCK stores (Phase 1).
                                // Cross-block resolution happens in Phase 2.
                                let expr = if let PcodeOp::Load { ptr, .. } = op {
                                    let p = resolve_input(&mut ssa, &mut current, ptr);
                                    let key = get_slot_key(p, out_vn.size, &ssa);
                                    if let Some(key) = key {
                                        if let Some(&stored_var) = local_stack.get(&key) {
                                            Expr::Var(stored_var)
                                        } else {
                                            Expr::Load(p) // Leave opaque for Phase 2
                                        }
                                    } else {
                                        Expr::Load(p)
                                    }
                                } else {
                                    build_expr(&mut ssa, &mut current, op)
                                };
                                let var_id = ssa.new_var(out_vn, expr, out_vn.size);
                                current.insert(out_vn, var_id);
                                stmts.push(Stmt::Assign(var_id));
                            }
                        }
                    }
                }

                // Now apply deferred Zext writes
                for (vn, var_id) in deferred_zext {
                    current.insert(vn, var_id);
                }
            }

            let terminator = convert_terminator(&mut ssa, &mut current, &block.terminator);

            // Build exit stack: inherit from forward predecessor + local stores
            let mut exit_stack: StackMap = if !block_preds.is_empty() {
                block_preds.iter()
                    .find(|p| p.0 < block.id.0)
                    .map(|p| block_exit_stack[p.0].clone())
                    .unwrap_or_default()
            } else {
                HashMap::new()
            };
            for (key, var_id) in &local_stack {
                exit_stack.insert(*key, *var_id);
            }

            if block_exit_vars[block.id.0] != current || block_exit_stack[block.id.0] != exit_stack {
                changed = true;
            }
            block_exit_vars[block.id.0] = current;
            block_exit_stack[block.id.0] = exit_stack;

            // On first iteration, push new blocks; on subsequent iterations, replace
            if iteration == 0 {
                ssa.blocks.push(SsaBlock {
                    id: block.id,
                    addr: block.addr,
                    stmts,
                    terminator,
                });
            } else {
                ssa.blocks[block_idx].stmts = stmts;
                ssa.blocks[block_idx].terminator = terminator;
            }
        }

        if iteration > 0 && !changed {
            break;
        }
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

    // ====================================================================
    // Phase 2: Memory SSA — resolve cross-block stack Loads via Phi nodes
    // ====================================================================
    //
    // Phase 2a: Compute block_entry_stack to fixed point via worklist.
    //           Insert memory Phis at join points where predecessors disagree.
    // Phase 2b: Walk all Loads and replace opaque Expr::Load(ptr) with
    //           Expr::Var(resolved_value) when the stack slot is known.
    {
        let mut block_entry_stack: Vec<StackMap> = vec![HashMap::new(); cfg.blocks.len()];
        // Effective exit stacks for Phase 2 (entry values + Phase 1 stores)
        let mut effective_exit: Vec<StackMap> = vec![HashMap::new(); cfg.blocks.len()];
        // Memory Phis created: (block_id, slot_key) → phi VarId
        let mut mem_phis: HashMap<(usize, SlotKey), VarId> = HashMap::new();

        // Phase 2a: Fixed-point computation of entry stack state
        let mut worklist: VecDeque<usize> = (0..cfg.blocks.len()).collect();
        let mut visited = vec![false; cfg.blocks.len()];
        let max_iterations = cfg.blocks.len() * 4; // safety cap
        let mut iter_count = 0;

        while let Some(bid) = worklist.pop_front() {
            iter_count += 1;
            if iter_count > max_iterations { break; }

            let block_preds_list = &preds[bid];
            let mut new_entry: StackMap = HashMap::new();

            if block_preds_list.is_empty() {
                // Entry block: no predecessors, entry stack is empty
            } else if block_preds_list.len() == 1 {
                // Single predecessor: inherit from effective exit
                new_entry = effective_exit[block_preds_list[0].0].clone();
            } else {
                // Multiple predecessors: merge with Phi insertion
                let mut all_keys: HashSet<SlotKey> = HashSet::new();
                for &pred_id in block_preds_list {
                    for key in effective_exit[pred_id.0].keys() {
                        all_keys.insert(*key);
                    }
                }

                for key in &all_keys {
                    let pred_values: Vec<Option<VarId>> = block_preds_list.iter()
                        .map(|pred| effective_exit[pred.0].get(key).copied())
                        .collect();

                    // If ANY predecessor is missing this slot, don't forward (fail closed)
                    if pred_values.iter().any(|v| v.is_none()) {
                        continue;
                    }

                    let values: Vec<VarId> = pred_values.into_iter().map(|v| v.unwrap()).collect();

                    // If all predecessors agree, no Phi needed
                    if values.iter().all(|v| *v == values[0]) {
                        new_entry.insert(*key, values[0]);
                    } else {
                        // Create or reuse a memory Phi
                        let phi_key = (bid, *key);
                        let phi_var = if let Some(&existing) = mem_phis.get(&phi_key) {
                            // Update existing Phi's inputs
                            ssa.vars[existing.0 as usize].expr = Expr::Phi(values.clone());
                            existing
                        } else {
                            let slot_vn = Varnode {
                                space: AddressSpaceId::Unique,
                                offset: 0xF000_0000_u64.wrapping_add(key.disp as u64)
                                    .wrapping_add(key.base_reg << 32),
                                size: key.size,
                            };
                            let phi_var = ssa.new_var(slot_vn, Expr::Phi(values), key.size);
                            // Prepend Phi stmt to block
                            ssa.blocks[bid].stmts.insert(0, Stmt::Assign(phi_var));
                            mem_phis.insert(phi_key, phi_var);
                            phi_var
                        };
                        new_entry.insert(*key, phi_var);
                    }
                }
            }

            // Check for convergence
            if visited[bid] && new_entry == block_entry_stack[bid] {
                continue; // No change — don't re-process successors
            }
            visited[bid] = true;
            block_entry_stack[bid] = new_entry.clone();

            // Compute effective exit: entry values + Phase 1 local stores.
            let mut new_effective_exit = new_entry.clone();
            for (key, var_id) in &block_exit_stack[bid] {
                // Phase 1 local stores override inherited values
                new_effective_exit.insert(*key, *var_id);
            }

            if effective_exit[bid] != new_effective_exit {
                effective_exit[bid] = new_effective_exit;
                // Schedule successors for re-processing
                for succ in cfg.successors(BlockId(bid)) {
                    if !worklist.contains(&succ.0) {
                        worklist.push_back(succ.0);
                    }
                }
            }
        }

        // Phase 2b: Resolve cross-block Loads using computed entry stack
        for bid in 0..ssa.blocks.len() {
            let mut running_stack = block_entry_stack[bid].clone();
            let mut local_stack_keys: HashSet<SlotKey> = HashSet::new();

            for stmt in &ssa.blocks[bid].stmts {
                match stmt {
                    Stmt::Store { addr, val } => {
                        let val_size = ssa.vars[val.0 as usize].size;
                        if let Some(key) = get_slot_key(*addr, val_size, &ssa) {
                            running_stack.insert(key, *val);
                            local_stack_keys.insert(key);
                        }
                    }
                    Stmt::Assign(var_id) => {
                        let vdef = &ssa.vars[var_id.0 as usize];
                        if let Expr::Load(ptr) = &vdef.expr {
                            let load_size = vdef.size;
                            if let Some(key) = get_slot_key(*ptr, load_size, &ssa) {
                                if let Some(&stored_var) = running_stack.get(&key) {
                                    // Only resolve when safe:
                                    // - Phi: properly merged value at join point
                                    // - Local: same-block store→load (always safe)
                                    // - Readonly: slot only written in entry block (never changes)
                                    let is_phi = matches!(&ssa.vars[stored_var.0 as usize].expr, Expr::Phi(_));
                                    let is_local = local_stack_keys.contains(&key);
                                    // Check if this slot is only stored in the entry block
                                    let is_readonly = slot_store_blocks.get(&key)
                                        .map_or(false, |blocks| blocks.iter().all(|b| *b == 0));
                                    if is_phi || is_local || is_readonly {
                                        ssa.vars[var_id.0 as usize].expr = Expr::Var(stored_var);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Count uses (after Phase 2 may have changed expressions)
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

/// Frame base register offsets recognized for stack slot tracking.
const FRAME_REGS: [u64; 5] = [40, 29, 32, 256, 112]; // RBP, x29, RSP, SP, GP

/// Extract a stack slot key from a pointer VarId.
/// Recognizes: FRAME_REG + const, FRAME_REG - const (via large unsigned const).
fn get_slot_key(ptr_var: VarId, size: u32, ssa: &SsaCfg) -> Option<SlotKey> {
    let vdef = &ssa.vars[ptr_var.0 as usize];
    match &vdef.expr {
        Expr::Unknown if vdef.varnode.space == AddressSpaceId::Register => {
            if FRAME_REGS.contains(&vdef.varnode.offset) {
                Some(SlotKey { base_reg: vdef.varnode.offset, disp: 0, size })
            } else { None }
        }
        Expr::BinOp(BinOpKind::Add, left, right) => {
            let lv = &ssa.vars[left.0 as usize];
            let rv = &ssa.vars[right.0 as usize];
            if lv.varnode.space == AddressSpaceId::Register
                && FRAME_REGS.contains(&lv.varnode.offset)
            {
                if let Expr::Const(val, _) = &rv.expr {
                    return Some(SlotKey { base_reg: lv.varnode.offset, disp: *val as i64, size });
                }
            }
            if rv.varnode.space == AddressSpaceId::Register
                && FRAME_REGS.contains(&rv.varnode.offset)
            {
                if let Expr::Const(val, _) = &lv.expr {
                    return Some(SlotKey { base_reg: rv.varnode.offset, disp: *val as i64, size });
                }
            }
            None
        }
        _ => None,
    }
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
        PcodeOp::Subpiece { input, lsb, out: _ } => {
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
            // Try to find RAX/EAX/x0/r0/v0 (return value register) in current state.
            // These are the conventional return value registers for each architecture:
            // x86-64/x86-32: RAX/EAX at register offset 0
            // AArch64: x0 at register offset 0 (per AAPCS64)
            // ARM32: r0 at register offset 0
            // MIPS32: v0 at register offset 16
            // RISC-V: a0 at register offset 80
            // Prefer the smaller (more specific) register first: EAX before RAX,
            // w0 before x0. This gets the correct return type (int vs long).
            // Only use the register if it has a real expression (not Unknown),
            // to avoid false return values from void functions that happen to
            // leave x0/EAX as the entry parameter value.
            let ret_val = [
                Varnode { space: AddressSpaceId::Register, offset: 0, size: 4 }, // EAX / w0 / r0
                Varnode { space: AddressSpaceId::Register, offset: 0, size: 8 }, // RAX / x0
                Varnode { space: AddressSpaceId::Register, offset: 16, size: 4 }, // MIPS v0
                Varnode { space: AddressSpaceId::Register, offset: 80, size: 8 }, // RISC-V a0
            ].iter().find_map(|vn| {
                let var_id = current.get(vn).copied()?;
                let vdef = &ssa.vars[var_id.0 as usize];
                // Skip if this is just the entry parameter value (Unknown or Phi)
                // — the function didn't explicitly set a return value
                if matches!(&vdef.expr, Expr::Unknown) && vdef.param_name.is_some() {
                    return None;
                }
                Some(var_id)
            });
            SsaTerminator::Return(ret_val)
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
        Expr::UnaryOp(_, i) | Expr::Load(i) | Expr::FieldAccess(i, _) => vec![*i],
        Expr::Phi(inputs) => inputs.clone(),
        Expr::Const(_, _) | Expr::Unknown => vec![],
    }
}
