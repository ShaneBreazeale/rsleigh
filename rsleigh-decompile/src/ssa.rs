use std::collections::{HashMap, HashSet, VecDeque};
use pcode_ir::{PcodeOp, Varnode, AddressSpaceId, get_output};
use crate::ir::*;
use crate::fold::CallingConv;

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

/// Convert a CFG into SSA form (SysV calling convention).
pub fn build_ssa(cfg: &Cfg) -> SsaCfg {
    build_ssa_with_cc(cfg, CallingConv::SysV)
}

/// Convert a CFG into SSA form with a specific calling convention.
/// The `cc` parameter controls which registers are invalidated after Call sites.
pub fn build_ssa_with_cc(cfg: &Cfg, cc: CallingConv) -> SsaCfg {
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
                // Self-loop blocks (block is its own predecessor) must be re-processed
                // on iteration 1 so that early Phi nodes can be created for loop accumulators.
                // Without this, the skip condition prevents the block from ever seeing its
                // own back-edge exit vars.
                let is_self_loop = block_preds.iter().any(|pred| pred.0 == block.id.0);
                let has_back_edge = block_preds.iter().any(|pred| pred.0 >= block.id.0);
                if !any_pred_changed && !any_new_keys && !(has_back_edge && iteration == 1) {
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

            // Note: Phi nodes for loop-carried variables are created in the late Phi
            // pass (after all iterations) and then re-linked into loop body expressions.

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

                // Detect MOVSD zero-clobber pattern:
                // Load { out: XMM(off>=4608, sz:16) } followed by
                // Copy { out: same_XMM, input: Const(0) }
                // The Copy zeros upper bytes — drop it to preserve the Load result.
                let mut skip_zero_copy: HashSet<usize> = HashSet::new();
                for (i, op) in inst_ops.iter().enumerate() {
                    if let PcodeOp::Load { out, .. } = op {
                        if out.space == AddressSpaceId::Register
                            && out.offset >= 4608
                            && out.size == 16
                        {
                            if i + 1 < inst_ops.len() {
                                if let PcodeOp::Copy { out: copy_out, input } = inst_ops[i + 1] {
                                    if copy_out.space == out.space
                                        && copy_out.offset == out.offset
                                        && input.space == AddressSpaceId::Const
                                        && input.offset == 0
                                    {
                                        skip_zero_copy.insert(i + 1);
                                    }
                                }
                            }
                        }
                    }
                }

                // Detect intra-instruction CBranch (AArch64 CSEL/CSINC/CNEG pattern)
                // Pattern: [pre-ops..., CBranch{Const,cond}, else-ops..., post-op]
                // CBranch condition TRUE → skip else → use "then" value (from pre-ops)
                // CBranch condition FALSE → execute else → use "else" value
                let cbranch_idx = inst_ops.iter().position(|op| {
                    matches!(op, PcodeOp::CBranch { dest, .. } if dest.space == AddressSpaceId::Const)
                });

                if let Some(cb_idx) = cbranch_idx {
                    // Get the CBranch condition varnode
                    let cond_vn = if let PcodeOp::CBranch { cond, .. } = inst_ops[cb_idx] {
                        *cond
                    } else { unreachable!() };

                    // Process pre-CBranch ops normally (condition setup + then-value copies)
                    for (op_idx, op) in inst_ops[..cb_idx].iter().enumerate() {
                        if skip_zero_copy.contains(&op_idx) { continue; }
                        if let PcodeOp::IntZext { out, .. } = op {
                            if deferred_zext.iter().any(|(vn, _)| vn == out) { continue; }
                        }
                        process_op(&mut ssa, &mut current, &mut local_stack, &mut slot_store_blocks, block.id.0, &mut stmts, op, cc);
                    }

                    let cond_var = resolve_input(&mut ssa, &mut current, &cond_vn);

                    // Snapshot current state — Unique varnodes hold "then" values
                    let then_state: HashMap<Varnode, VarId> = current.iter()
                        .filter(|(vn, _)| vn.space == AddressSpaceId::Unique)
                        .map(|(vn, vid)| (*vn, *vid))
                        .collect();

                    // Process else-path ops (between CBranch and last op)
                    let last_idx = inst_ops.len() - 1;
                    for op in &inst_ops[cb_idx+1..last_idx] {
                        process_op(&mut ssa, &mut current, &mut local_stack, &mut slot_store_blocks, block.id.0, &mut stmts, op, cc);
                    }

                    // For each Unique varnode written in both then and else paths,
                    // create a Ternary expression
                    for (vn, then_var) in &then_state {
                        if let Some(&else_var) = current.get(vn) {
                            if else_var != *then_var {
                                let ternary_expr = Expr::Ternary(cond_var, *then_var, else_var);
                                let ternary_id = ssa.new_var(*vn, ternary_expr, vn.size);
                                current.insert(*vn, ternary_id);
                                stmts.push(Stmt::Assign(ternary_id));
                            }
                        }
                    }

                    // Process post-label ops (final assignment like IntZext)
                    if last_idx < inst_ops.len() {
                        process_op(&mut ssa, &mut current, &mut local_stack, &mut slot_store_blocks, block.id.0, &mut stmts, inst_ops[last_idx], cc);
                    }
                } else {
                // Process remaining ops normally
                for (op_idx, op) in inst_ops.iter().enumerate() {
                    // Skip MOVSD zero-clobber copies
                    if skip_zero_copy.contains(&op_idx) {
                        continue;
                    }
                    // Skip ops we already handled as deferred Zext
                    if let PcodeOp::IntZext { out, input } = op {
                        if deferred_zext.iter().any(|(vn, _)| vn == out) {
                            continue;
                        }
                    }

                    process_op(&mut ssa, &mut current, &mut local_stack, &mut slot_store_blocks, block.id.0, &mut stmts, op, cc);
                }
                }

                // Now apply deferred Zext writes
                for (vn, var_id) in deferred_zext {
                    current.insert(vn, var_id);
                }
            }

            let terminator = convert_terminator(&mut ssa, &mut current, &block.terminator, cc, &mut stmts);

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

        // Prepend phis to block and re-link loop body expressions
        if !phi_stmts.is_empty() {
            // Build a replacement map: for each Phi, map the forward-predecessor's
            // VarId to the Phi VarId. This allows re-linking loop body expressions
            // so they read the Phi output instead of the stale pre-loop value.
            let mut relink: HashMap<VarId, VarId> = HashMap::new();
            for stmt in &phi_stmts {
                if let Stmt::Assign(phi_vid) = stmt {
                    if let Expr::Phi(inputs) = &ssa.vars[phi_vid.0 as usize].expr {
                        // The first input is typically the forward-predecessor value.
                        // Find which inputs come from forward preds (pred.0 < bid).
                        let phi_vn = ssa.vars[phi_vid.0 as usize].varnode;
                        for &pred_id in block_preds {
                            if pred_id.0 < bid {
                                if let Some(&fwd_var) = block_exit_vars[pred_id.0].get(&phi_vn) {
                                    relink.insert(fwd_var, *phi_vid);
                                }
                            }
                        }
                    }
                }
            }

            // Also build back-edge relink: map back-edge VarIds to Phi VarIds.
            // This ensures post-loop blocks reference the Phi (loop variable)
            // instead of the raw loop body result.
            let mut back_relink: HashMap<VarId, VarId> = HashMap::new();
            for stmt in &phi_stmts {
                if let Stmt::Assign(phi_vid) = stmt {
                    if let Expr::Phi(inputs) = &ssa.vars[phi_vid.0 as usize].expr {
                        let phi_vn = ssa.vars[phi_vid.0 as usize].varnode;
                        for &pred_id in block_preds {
                            if pred_id.0 >= bid {
                                if let Some(&back_var) = block_exit_vars[pred_id.0].get(&phi_vn) {
                                    back_relink.insert(back_var, *phi_vid);
                                }
                            }
                        }
                    }
                }
            }

            // Re-link: replace stale forward-pred references with Phi VarIds
            // in all expressions within this block.
            if !relink.is_empty() {
                let block = &mut ssa.blocks[bid];
                for stmt in &block.stmts {
                    if let Stmt::Assign(vid) = stmt {
                        let vi = vid.0 as usize;
                        ssa.vars[vi].expr = relink_expr(&ssa.vars[vi].expr, &relink);
                    }
                }
                // Also re-link the terminator condition
                if let SsaTerminator::CBranch { cond, taken, fallthrough } = &block.terminator {
                    if let Some(&new_cond) = relink.get(cond) {
                        let t = *taken;
                        let f = *fallthrough;
                        ssa.blocks[bid].terminator = SsaTerminator::CBranch {
                            cond: new_cond, taken: t, fallthrough: f,
                        };
                    }
                }
            }

            // Re-link successor blocks: replace back-edge VarIds with Phi VarIds.
            // This ensures post-loop returns reference the Phi (the loop variable)
            // instead of the raw ADD result from the last iteration.
            if !back_relink.is_empty() {
                // Find successor blocks (exit targets from this loop header)
                let successors: Vec<usize> = match &ssa.blocks[bid].terminator {
                    SsaTerminator::CBranch { taken, fallthrough, .. } => {
                        let mut s = Vec::new();
                        if taken.0 != bid { s.push(taken.0); }
                        if fallthrough.0 != bid { s.push(fallthrough.0); }
                        s
                    }
                    SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) => {
                        if b.0 != bid { vec![b.0] } else { vec![] }
                    }
                    _ => vec![],
                };
                for succ_bid in successors {
                    if succ_bid >= ssa.blocks.len() { continue; }
                    for stmt in &ssa.blocks[succ_bid].stmts {
                        if let Stmt::Assign(vid) = stmt {
                            let vi = vid.0 as usize;
                            ssa.vars[vi].expr = relink_expr(&ssa.vars[vi].expr, &back_relink);
                        }
                    }
                    // Re-link return value
                    if let SsaTerminator::Return(Some(ret_var)) = &ssa.blocks[succ_bid].terminator {
                        if let Some(&phi_var) = back_relink.get(ret_var) {
                            ssa.blocks[succ_bid].terminator = SsaTerminator::Return(Some(phi_var));
                        } else {
                            // Also check: the return might reference a Var/Zext chain
                            // that wraps a back-edge VarId. Follow one level.
                            let rv = &ssa.vars[ret_var.0 as usize];
                            let inner = match &rv.expr {
                                Expr::Var(v) => Some(*v),
                                Expr::UnaryOp(UnaryOpKind::Zext, v) => Some(*v),
                                _ => None,
                            };
                            if let Some(inner_id) = inner {
                                if let Some(&phi_var) = back_relink.get(&inner_id) {
                                    ssa.blocks[succ_bid].terminator = SsaTerminator::Return(Some(phi_var));
                                }
                            }
                        }
                    }
                }
            }

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
                                        // If the stored VarId has a param_name but its expression
                                        // was contaminated by SSA convergence (Const/Phi instead of
                                        // Unknown), the param's original value is lost. In that case,
                                        // keep the Load as-is — the printer will handle it.
                                        // Only forward if the expression is still usable.
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

/// Process a single P-code op: resolve inputs, build SSA expression, update current map.
/// Extracted to avoid duplication between normal path and CSEL path.
fn process_op(
    ssa: &mut SsaCfg,
    current: &mut HashMap<Varnode, VarId>,
    local_stack: &mut StackMap,
    slot_store_blocks: &mut HashMap<SlotKey, Vec<usize>>,
    block_id: usize,
    stmts: &mut Vec<Stmt>,
    op: &PcodeOp,
    _cc: CallingConv,
) {
    match op.clone() {
        PcodeOp::Store { ptr, val, .. } => {
            let addr_var = resolve_input(ssa, current, &ptr);
            let val_var = resolve_input(ssa, current, &val);
            let val_size = ssa.vars[val_var.0 as usize].size;
            let key = get_slot_key(addr_var, val_size, ssa);
            if let Some(key) = key {
                local_stack.insert(key, val_var);
                slot_store_blocks.entry(key).or_default().push(block_id);
            }
            stmts.push(Stmt::Store { addr: addr_var, val: val_var });
        }
        PcodeOp::CallOther { func_id, inputs, out: None } => {
            // Void user-pcodeop (e.g. `software_interrupt(0x71)` on ARM swi).
            // Emit as a statement even though there's no output varnode — the
            // side effect itself is meaningful (it changes machine state the
            // decompiler cannot model, so surfacing the call keeps the
            // analyst informed).
            let resolved: Vec<VarId> = inputs.iter()
                .map(|vn| resolve_input(ssa, current, vn))
                .collect();
            // Allocate a synthetic var to hold the UserOp expr so the printer
            // can process it through the usual Stmt::Assign path.
            let placeholder_vn = Varnode {
                space: AddressSpaceId::Unique,
                offset: u64::MAX - func_id,
                size: 0,
            };
            let var_id = ssa.new_var(
                placeholder_vn,
                Expr::UserOp { func_id, inputs: resolved },
                0,
            );
            stmts.push(Stmt::Assign(var_id));
        }
        ref op => {
            if let Some(out_vn) = get_output(op) {
                let expr = if let PcodeOp::Load { ptr, .. } = op {
                    let p = resolve_input(ssa, current, ptr);
                    let key = get_slot_key(p, out_vn.size, ssa);
                    if let Some(key) = key {
                        if let Some(&stored_var) = local_stack.get(&key) {
                            Expr::Var(stored_var)
                        } else {
                            Expr::Load(p)
                        }
                    } else {
                        Expr::Load(p)
                    }
                } else {
                    build_expr(ssa, current, op)
                };
                let effective_size = float_semantic_size(&expr, &ssa.vars)
                    .unwrap_or(out_vn.size);
                let var_id = ssa.new_var(out_vn, expr, effective_size);
                current.insert(out_vn, var_id);
                // Sub-register propagation: when writing to a larger register (e.g., RAX 8-byte),
                // also update the smaller sub-register at the same offset (e.g., EAX 4-byte).
                // This ensures that return value detection finds the correct value when the
                // function uses 64-bit ops (LEA/INC on RAX) but the return checks EAX first.
                if out_vn.space == AddressSpaceId::Register && out_vn.size == 8 {
                    let sub_vn = Varnode { space: out_vn.space, offset: out_vn.offset, size: 4 };
                    current.insert(sub_vn, var_id);
                }
                stmts.push(Stmt::Assign(var_id));
            }
        }
    }
}

fn resolve_input(ssa: &mut SsaCfg, current: &mut HashMap<Varnode, VarId>, vn: &Varnode) -> VarId {
    if vn.space == AddressSpaceId::Const {
        return ssa.new_var(*vn, Expr::Const(vn.offset, vn.size), vn.size);
    }
    if let Some(&var_id) = current.get(vn) {
        return var_id;
    }
    // Sub-register aliasing at the same offset:
    // Case 1: Reading smaller (w8) when larger (x8) was written → reuse directly
    //   Common on AArch64 where CSETM writes x8 and CSINC reads w8.
    // Case 2: Reading larger (RDX) when smaller (EDX) was written → zero-extend
    //   Common on x86-64 where 32-bit ops implicitly zero-extend to 64-bit.
    if vn.space == AddressSpaceId::Register {
        for (&existing_vn, &existing_var) in current.iter() {
            if existing_vn.space == AddressSpaceId::Register
                && existing_vn.offset == vn.offset
                && existing_vn.size != vn.size
            {
                if existing_vn.size > vn.size {
                    // Case 1: read smaller from larger — reuse directly
                    return existing_var;
                } else {
                    // Case 2: read larger from smaller — zero-extend
                    let expr = Expr::UnaryOp(UnaryOpKind::Zext, existing_var);
                    let var_id = ssa.new_var(*vn, expr, vn.size);
                    current.insert(*vn, var_id);
                    return var_id;
                }
            }
        }
    }
    // Unknown — function parameter or uninitialized
    let var_id = ssa.new_var(*vn, Expr::Unknown, vn.size);
    current.insert(*vn, var_id);
    var_id
}

/// Replace VarId references in an expression according to a replacement map.
/// Used to re-link loop body expressions to read from Phi nodes instead of
/// stale pre-loop values.
fn relink_expr(expr: &Expr, relink: &HashMap<VarId, VarId>) -> Expr {
    match expr {
        Expr::Var(id) => Expr::Var(*relink.get(id).unwrap_or(id)),
        Expr::BinOp(k, l, r) => {
            Expr::BinOp(*k, *relink.get(l).unwrap_or(l), *relink.get(r).unwrap_or(r))
        }
        Expr::UnaryOp(k, i) => {
            Expr::UnaryOp(*k, *relink.get(i).unwrap_or(i))
        }
        Expr::Load(p) => Expr::Load(*relink.get(p).unwrap_or(p)),
        Expr::Ternary(c, t, e) => {
            Expr::Ternary(
                *relink.get(c).unwrap_or(c),
                *relink.get(t).unwrap_or(t),
                *relink.get(e).unwrap_or(e),
            )
        }
        Expr::Phi(inputs) => {
            Expr::Phi(inputs.iter().map(|i| *relink.get(i).unwrap_or(i)).collect())
        }
        Expr::UserOp { func_id, inputs } => {
            Expr::UserOp {
                func_id: *func_id,
                inputs: inputs.iter().map(|i| *relink.get(i).unwrap_or(i)).collect(),
            }
        }
        _ => expr.clone(),
    }
}

/// Frame base register offsets recognized for stack slot tracking.
const FRAME_REGS: [u64; 5] = [40, 29, 32, 256, 112]; // RBP, x29, RSP, SP, GP

/// Caller-saved (volatile) integer register offsets per ABI.
/// These registers must be invalidated in the SSA `current` map after any Call.
///
/// x86-64 offsets: RAX=0, RCX=8, RDX=16, RSI=48, RDI=56, R8=128, R9=136, R10=144, R11=152
/// AArch64: x0=16384 stride 8, x0..x18 are caller-saved
/// ARM32/x86-32: r0/EAX=0, r1/ECX=8, r2/EDX=16, r3=44(ARM) or nothing extra
/// MIPS/RISC-V: covered by SysV default as fallback
const WIN64_CALLER_SAVED: &[u64] = &[
    0,   // RAX
    8,   // RCX
    16,  // RDX
    128, // R8
    136, // R9
    144, // R10
    152, // R11
];

const SYSV64_CALLER_SAVED: &[u64] = &[
    0,   // RAX
    8,   // RCX
    16,  // RDX
    48,  // RSI
    56,  // RDI
    128, // R8
    136, // R9
    144, // R10
    152, // R11
];

/// AArch64 AAPCS64 caller-saved: x0..x18 at stride 8 starting at 16384.
const AARCH64_CALLER_SAVED: &[u64] = &[
    16384, 16392, 16400, 16408, 16416, 16424, 16432, 16440, // x0..x7
    16448, 16456, 16464, 16472, 16480, 16488, 16496, 16504, // x8..x15
    16512, 16520, 16528,                                    // x16..x18
];

/// x86-32 cdecl caller-saved: EAX, ECX, EDX. Offsets same as x86-64 lower regs.
const X86_32_CALLER_SAVED: &[u64] = &[
    0,  // EAX
    8,  // ECX
    16, // EDX
];

/// ARM32 AAPCS caller-saved: r0-r3 (args), r12 (IP scratch), r14 (LR).
const ARM32_CALLER_SAVED: &[u64] = &[
    32, 36, 40, 44, // r0..r3
    80,             // r12 (offset 0x20 + 12*4 = 0x50 = 80)
    88,             // r14 / lr (0x20 + 14*4 = 0x58 = 88)
];

/// Register offset of the return register per calling convention.
fn return_reg_offset(cc: CallingConv) -> u64 {
    match cc {
        CallingConv::SysV | CallingConv::Win64 | CallingConv::Cdecl32
        | CallingConv::GoAmd64 => 0, // RAX/EAX
        CallingConv::AArch64 => 16384, // x0
        CallingConv::Arm32 => 32,      // r0
    }
}

/// Size in bytes of the return register per calling convention.
fn return_reg_size(cc: CallingConv) -> u32 {
    match cc {
        CallingConv::SysV | CallingConv::Win64 | CallingConv::GoAmd64 => 8,
        CallingConv::Cdecl32 => 4,
        CallingConv::AArch64 => 8,
        CallingConv::Arm32 => 4,
    }
}

fn caller_saved_offsets(cc: CallingConv) -> &'static [u64] {
    match cc {
        CallingConv::Win64 => WIN64_CALLER_SAVED,
        CallingConv::SysV | CallingConv::GoAmd64 => SYSV64_CALLER_SAVED,
        CallingConv::AArch64 => AARCH64_CALLER_SAVED,
        CallingConv::Cdecl32 => X86_32_CALLER_SAVED,
        CallingConv::Arm32 => ARM32_CALLER_SAVED,
    }
}

/// Invalidate caller-saved registers in `current` after a Call.
/// Emits one `Stmt::Assign(ret_var)` for the return register with `call_return=true`.
/// Other caller-saved registers are removed from `current`; if read later,
/// `resolve_input` will create fresh Unknown VarDefs for them.
fn clobber_caller_saved(
    ssa: &mut SsaCfg,
    current: &mut HashMap<Varnode, VarId>,
    cc: CallingConv,
    stmts: &mut Vec<Stmt>,
) {
    let offsets = caller_saved_offsets(cc);
    let ret_off = return_reg_offset(cc);
    let ret_size = return_reg_size(cc);

    // Drop every current entry at any caller-saved offset, regardless of size.
    current.retain(|vn, _| {
        !(vn.space == AddressSpaceId::Register && offsets.contains(&vn.offset))
    });

    // Create a fresh return-register clobber with call_return=true.
    let ret_vn = Varnode {
        space: AddressSpaceId::Register,
        offset: ret_off,
        size: ret_size,
    };
    let ret_var = ssa.new_var(ret_vn, Expr::Unknown, ret_size);
    ssa.vars[ret_var.0 as usize].call_return = true;
    current.insert(ret_vn, ret_var);

    // Seed size-4 sub-register too (so `mov eax, ...` reads see the same VarId).
    if ret_size == 8 {
        let sub_vn = Varnode {
            space: AddressSpaceId::Register,
            offset: ret_off,
            size: 4,
        };
        current.insert(sub_vn, ret_var);
    }

    stmts.push(Stmt::Assign(ret_var));
}

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
        PcodeOp::IntXor { left, right, out, .. } => {
            // XOR reg, reg → 0 (common zero-init: XORPS/XORPD/XOR EAX,EAX)
            if left.space == right.space
                && left.offset == right.offset
                && left.size == right.size
                && left.space == AddressSpaceId::Register
            {
                Expr::Const(0, out.size)
            } else {
                bin!(Xor, left, right)
            }
        }
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
        PcodeOp::CallOther { func_id, inputs, .. } => {
            let resolved: Vec<VarId> = inputs.iter()
                .map(|vn| resolve_input(ssa, current, vn))
                .collect();
            Expr::UserOp { func_id: *func_id, inputs: resolved }
        }
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

/// For float ops, return the semantic operand size (4=float, 8=double).
/// SSE scalar instructions write to full 16-byte XMM registers but the
/// meaningful result is only the low 4 or 8 bytes.
fn float_semantic_size(expr: &Expr, vars: &[VarDef]) -> Option<u32> {
    match expr {
        Expr::BinOp(kind, left, right) => {
            use BinOpKind::*;
            match kind {
                FloatAdd | FloatSub | FloatMult | FloatDiv => {
                    let ls = vars[left.0 as usize].size;
                    let rs = vars[right.0 as usize].size;
                    Some(ls.min(rs))
                }
                _ => None,
            }
        }
        Expr::UnaryOp(kind, input) => {
            use UnaryOpKind::*;
            match kind {
                FloatNeg | FloatAbs | FloatSqrt | FloatCeil
                | FloatFloor | FloatRound => {
                    Some(vars[input.0 as usize].size)
                }
                Int2Float => {
                    let is = vars[input.0 as usize].size;
                    Some(if is >= 8 { 8 } else { 4 })
                }
                Float2Float => None,
                _ => None,
            }
        }
        _ => None,
    }
}

fn convert_terminator(
    ssa: &mut SsaCfg,
    current: &mut HashMap<Varnode, VarId>,
    term: &Terminator,
    cc: CallingConv,
    stmts: &mut Vec<Stmt>,
) -> SsaTerminator {
    match term {
        Terminator::Fallthrough(b) => SsaTerminator::Fallthrough(*b),
        Terminator::Branch(b) => SsaTerminator::Branch(*b),
        Terminator::CBranch { cond, taken, fallthrough } => {
            let cond_var = resolve_input(ssa, current, cond);
            SsaTerminator::CBranch { cond: cond_var, taken: *taken, fallthrough: *fallthrough }
        }
        Terminator::Call { target, fallthrough } => {
            clobber_caller_saved(ssa, current, cc, stmts);
            SsaTerminator::Call { target: target.clone(), args: vec![], out: None, fallthrough: *fallthrough }
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
            // AArch64 x0 checked first: on AArch64, offset 0 is PC (set by RET),
            // not the return value register. Checking 16384 first prevents false matches.
            // Check smaller register first (EAX before RAX) for correct return types.
            // BUT: if EAX has a stale value (Const(0) from XOR self-zeroing) and
            // RAX has a real value, prefer RAX. This handles loop counters where
            // XOR EAX,EAX inits the counter but LEA/INC on RAX is the loop result.
            let ret_val = [
                Varnode { space: AddressSpaceId::Register, offset: 16384, size: 4 }, // AArch64 w0
                Varnode { space: AddressSpaceId::Register, offset: 16384, size: 8 }, // AArch64 x0
                Varnode { space: AddressSpaceId::Register, offset: 0, size: 4 }, // EAX / r0
                Varnode { space: AddressSpaceId::Register, offset: 0, size: 8 }, // RAX
                Varnode { space: AddressSpaceId::Register, offset: 16, size: 4 }, // MIPS v0
                Varnode { space: AddressSpaceId::Register, offset: 80, size: 8 }, // RISC-V a0
            ].iter().find_map(|vn| {
                let var_id = current.get(vn).copied()?;
                let vdef = &ssa.vars[var_id.0 as usize];
                // Skip if this is just the entry parameter value (Unknown)
                // — the function didn't explicitly set a return value.
                // Also skip bare Unknown without param_name (uninitialized reads).
                if matches!(&vdef.expr, Expr::Unknown) {
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
        Expr::Ternary(c, t, e) => vec![*c, *t, *e],
        Expr::UserOp { inputs, .. } => inputs.clone(),
        Expr::Const(_, _) | Expr::Unknown => vec![],
    }
}
