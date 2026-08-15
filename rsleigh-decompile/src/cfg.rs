use crate::ir::*;
use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use std::collections::HashMap;

/// Build a control flow graph from decoded instructions.
pub fn build_cfg(instructions: &[(u64, Instruction)]) -> Cfg {
    if instructions.is_empty() {
        return Cfg {
            blocks: vec![],
            entry: BlockId(0),
            diagnostics: vec![],
        };
    }
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    // Flatten into (addr, op) pairs, grouped by instruction address
    let mut inst_ops: Vec<(u64, Vec<PcodeOp>)> = Vec::new();
    for (addr, inst) in instructions {
        inst_ops.push((*addr, inst.ops.clone()));
    }

    // Find block leaders: first instruction, branch targets, instruction after branch/call/return
    let mut leaders: Vec<u64> = vec![instructions[0].0];
    let _addr_set: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, (addr, _))| (*addr, i))
        .collect();

    for (addr, inst) in instructions {
        let next_addr = addr + inst.len;
        for op in &inst.ops {
            match op {
                PcodeOp::Branch { dest } if dest.space == AddressSpaceId::Ram => {
                    leaders.push(dest.offset);
                    leaders.push(next_addr); // instruction after unconditional branch
                }
                PcodeOp::CBranch { dest, .. } if dest.space == AddressSpaceId::Ram => {
                    leaders.push(dest.offset);
                    leaders.push(next_addr);
                }
                PcodeOp::Branch { .. } => {
                    leaders.push(next_addr);
                }
                PcodeOp::Call { dest } if dest.space == AddressSpaceId::Ram => {
                    leaders.push(next_addr);
                }
                PcodeOp::CallInd { .. } | PcodeOp::Call { .. } => {
                    leaders.push(next_addr);
                }
                PcodeOp::Return { .. } => {
                    leaders.push(next_addr);
                }
                _ => {}
            }
        }
    }

    leaders.sort_unstable();
    leaders.dedup();

    let inst_addrs: Vec<u64> = instructions.iter().map(|(a, _)| *a).collect();
    // Filter leaders to only include addresses that correspond to instructions
    let valid_addrs: std::collections::HashSet<u64> = inst_addrs.iter().copied().collect();
    leaders.retain(|a| valid_addrs.contains(a));

    // Map leader address -> block id
    let mut leader_to_block: HashMap<u64, BlockId> = HashMap::new();
    for (i, &addr) in leaders.iter().enumerate() {
        leader_to_block.insert(addr, BlockId(i));
    }

    // Build blocks
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let func_end = instructions.last().map(|(a, i)| a + i.len).unwrap_or(0);

    for (block_idx, &leader_addr) in leaders.iter().enumerate() {
        // Find the range of instructions in this block
        let next_leader = leaders.get(block_idx + 1).copied().unwrap_or(func_end);

        let mut ops: Vec<(u64, PcodeOp)> = Vec::new();
        let mut last_inst_addr = leader_addr;
        let mut last_inst_len = 0u64;

        for (addr, inst) in instructions {
            if *addr >= leader_addr && *addr < next_leader {
                for op in &inst.ops {
                    ops.push((*addr, op.clone()));
                }
                last_inst_addr = *addr;
                last_inst_len = inst.len;
            }
        }

        let next_inst_addr = last_inst_addr + last_inst_len;

        // Determine terminator from the last op
        let terminator = if let Some((_, last_op)) = ops.last().cloned() {
            match last_op {
                PcodeOp::Return { .. } => {
                    ops.pop();
                    // Strip x86-32 return boilerplate (Load ret_addr from [ESP]; IntAdd ESP, 4)
                    strip_return_pop_ops(&mut ops);
                    Terminator::Return
                }
                PcodeOp::Branch { dest } if dest.space == AddressSpaceId::Ram => {
                    let target = dest.offset;
                    ops.pop();
                    if let Some(&bid) = leader_to_block.get(&target) {
                        Terminator::Branch(bid)
                    } else {
                        diagnostics.push(Diagnostic {
                            severity: Severity::Warn,
                            kind: DiagKind::UnresolvedBranchTarget,
                            addr: Some(last_inst_addr),
                            detail: format!("Branch target {:#x} not in instruction set", target),
                        });
                        Terminator::Indirect(dest)
                    }
                }
                PcodeOp::CBranch { dest, cond } if dest.space == AddressSpaceId::Ram => {
                    let target = dest.offset;
                    ops.pop();
                    let taken = leader_to_block.get(&target).copied();
                    let fallthrough = leader_to_block.get(&next_inst_addr).copied();
                    match (taken, fallthrough) {
                        (Some(taken), Some(fallthrough)) => Terminator::CBranch {
                            cond,
                            taken,
                            fallthrough,
                        },
                        (taken, fallthrough) => {
                            diagnostics.push(Diagnostic {
                                severity: Severity::Warn,
                                kind: DiagKind::UnresolvedBranchTarget,
                                addr: Some(last_inst_addr),
                                detail: format!(
                                    "CBranch target {:#x} or fallthrough {:#x} not in instruction set",
                                    target, next_inst_addr
                                ),
                            });
                            // A caller may provide a bounded instruction window
                            // that excludes one edge (for example, a stack-canary
                            // failure block just past the function's RET). Keep
                            // traversing the edge that is present so an in-range
                            // return or body is not discarded with the missing
                            // edge. The diagnostic above preserves the loss of
                            // control-flow information for consumers.
                            match (taken, fallthrough) {
                                (Some(taken), None) => Terminator::Branch(taken),
                                (None, Some(fallthrough)) => Terminator::Fallthrough(fallthrough),
                                (None, None) => Terminator::Indirect(dest),
                                (Some(_), Some(_)) => unreachable!(),
                            }
                        }
                    }
                }
                PcodeOp::BranchInd { dest } => {
                    let dest_vn = dest;
                    ops.pop();
                    // ARM32: POP {PC} generates BranchInd where dest is loaded from stack.
                    // Detect this as a Return: if the dest was loaded from SP-relative address
                    // (the preceding ops include a Load from mult_addr/sp), treat as Return.
                    let is_stack_return = ops.iter().rev().take(10).any(|(_, op)| {
                        match op {
                            PcodeOp::Load { out, .. } => {
                                // Load dest matches the BranchInd target (POP {PC} pattern)
                                out.offset == dest_vn.offset && out.space == dest_vn.space
                            }
                            _ => false,
                        }
                    });
                    // Also detect BX LR pattern: BranchInd where dest is the LR register
                    // ARM32 LR = register offset 0x58=88 (r14), AArch64 x30 = 0xF0=240
                    let is_bx_lr = dest_vn.space == AddressSpaceId::Register
                        && matches!(dest_vn.offset, 88 | 240);
                    if is_stack_return || is_bx_lr {
                        Terminator::Return
                    } else {
                        Terminator::Indirect(dest_vn)
                    }
                }
                PcodeOp::Call { dest } => {
                    let target = if dest.space == AddressSpaceId::Ram {
                        // ARM32-generated Pcode emits Call dest varnodes
                        // with an extra 0x04000000 set in the offset (the
                        // codegen-side bug puts a 1 into bit 26 of every
                        // ram-space address). Disasm rendering happens to
                        // strip it; the SSA Call target keeps it, so the
                        // imports-map lookup fails on every PLT call. Mask
                        // to 28 bits — a no-op for legitimate <28-bit code
                        // addresses, recovers the right target for the
                        // ARM32 case. Filed for proper codegen-layer fix.
                        // ARM32 generated codegen ORs a spurious 0x04000000
                        // (bit 26) into every Ram-space Call dest offset.
                        // Disasm rendering happens to strip it; SSA keeps
                        // it, so the imports-map lookup misses every PLT
                        // call and downstream --search/--xrefs/--smt-
                        // explore can't recognise libc sources or sinks.
                        // Strip the tag only when the resulting address
                        // would still fit in a realistic text segment
                        // (raw < 0x10000000) — leaves legitimate >64MB
                        // text addresses untouched.
                        let raw = dest.offset;
                        let masked = if raw & 0x0400_0000 != 0 && raw & 0xF000_0000 == 0 {
                            raw & !0x0400_0000
                        } else {
                            raw
                        };
                        CallTarget::Direct(masked)
                    } else {
                        CallTarget::Indirect(dest)
                    };
                    ops.pop();
                    // Strip x86-32 return address push (IntSub ESP + Store [ESP])
                    strip_call_push_ops(&mut ops);
                    let fallthrough = leader_to_block
                        .get(&next_inst_addr)
                        .copied()
                        .unwrap_or(BlockId(block_idx));
                    Terminator::Call {
                        target,
                        fallthrough,
                    }
                }
                PcodeOp::CallInd { dest } => {
                    // Try to resolve indirect calls through constant Load
                    // (e.g., CALL dword ptr [IAT_addr] → Load tmp, [const]; CallInd tmp)
                    // For MIPS PIC: pass all function ops to resolve GP-relative calls
                    let func_addr = instructions[0].0;
                    let all_ops: Vec<(u64, PcodeOp)> = instructions
                        .iter()
                        .flat_map(|(addr, inst)| inst.ops.iter().map(move |op| (*addr, op.clone())))
                        .collect();
                    let target = resolve_callind_target(&ops, &dest, func_addr, &all_ops);
                    if matches!(target, CallTarget::Indirect(_)) {
                        diagnostics.push(Diagnostic {
                            severity: Severity::Info,
                            kind: DiagKind::UnresolvedIndirectCall,
                            addr: Some(last_inst_addr),
                            detail: format!(
                                "CallInd via {:?} not resolved through Load chain or GP-relative trace",
                                dest
                            ),
                        });
                    }
                    ops.pop();
                    // Strip x86-32 return address push (IntSub ESP + Store [ESP])
                    strip_call_push_ops(&mut ops);
                    let fallthrough = leader_to_block
                        .get(&next_inst_addr)
                        .copied()
                        .unwrap_or(BlockId(block_idx));
                    Terminator::Call {
                        target,
                        fallthrough,
                    }
                }
                _ => {
                    // Fallthrough to next block
                    if let Some(&next_bid) = leader_to_block.get(&next_inst_addr) {
                        Terminator::Fallthrough(next_bid)
                    } else {
                        Terminator::Return // end of function
                    }
                }
            }
        } else {
            Terminator::Return
        };

        blocks.push(BasicBlock {
            id: BlockId(block_idx),
            addr: leader_addr,
            ops,
            terminator,
        });
    }

    Cfg {
        entry: BlockId(0),
        blocks,
        diagnostics,
    }
}

/// x86-32 ESP register: offset 16, size 4.
const ESP_OFFSET_32: u64 = 16;
const ESP_SIZE_32: u32 = 4;

/// Check if a varnode is the x86-32 ESP register.
fn is_esp(vn: &Varnode) -> bool {
    vn.space == AddressSpaceId::Register && vn.offset == ESP_OFFSET_32 && vn.size == ESP_SIZE_32
}

/// Strip x86-32 CALL return address push from the end of a block's ops.
///
/// x86-32 CALL generates: Subpiece, IntSub ESP, Store [ESP] ret_addr, CallInd
/// After popping the CallInd, strip the preceding Store+IntSub+Subpiece.
fn strip_call_push_ops(ops: &mut Vec<(u64, PcodeOp)>) {
    // Pattern (from end): Store { ptr: ESP-derived, val: ret_addr }, IntSub ESP
    // The Store writes the return address to [ESP], preceded by IntSub ESP, 4
    // There may also be a Subpiece extracting the return address constant.

    // Strip Store [ESP-like], val — the return address push
    if let Some((_, PcodeOp::Store { ptr, .. })) = ops.last() {
        if is_esp(ptr) || ptr.space == AddressSpaceId::Unique {
            ops.pop();
        }
    }
    // Strip IntSub ESP, ESP, 4 — the stack pointer decrement
    if let Some((_, PcodeOp::IntSub { out, .. })) = ops.last() {
        if is_esp(out) {
            ops.pop();
        }
    }
    // Strip Subpiece for return address constant extraction
    if let Some((_, PcodeOp::Subpiece { .. })) = ops.last() {
        ops.pop();
    }
}

/// Strip x86-32 RET boilerplate ops from the end of a block's ops.
///
/// x86-32 RET generates: Load ret_addr from [ESP], IntAdd ESP 4, Return
/// After popping Return, strip the Load and IntAdd.
fn strip_return_pop_ops(ops: &mut Vec<(u64, PcodeOp)>) {
    // Strip IntAdd ESP, ESP, 4 — stack pointer increment
    if let Some((_, PcodeOp::IntAdd { out, .. })) = ops.last() {
        if is_esp(out) {
            ops.pop();
        }
    }
    // Strip Load ret_addr from [ESP]
    if let Some((_, PcodeOp::Load { out, .. })) = ops.last() {
        // The loaded value is the return address (EIP)
        if out.space == AddressSpaceId::Register && out.offset == 256 {
            // 256 = EIP offset in x86-32 register space
            ops.pop();
        }
    }
}

/// Resolve a CallInd target by scanning backwards for the Load that produced the
/// dest varnode. If the Load reads from a constant address (e.g., IAT entry in PE),
/// return CallTarget::Direct(addr) so the import map can resolve it.
///
/// Also handles MIPS PIC: `lw t9, -OFFSET(gp); jalr t9` → resolve GP+offset to GOT
/// entry by tracing the GP register value from the function prologue.
fn resolve_callind_target(
    ops: &[(u64, PcodeOp)],
    dest: &pcode_ir::Varnode,
    func_addr: u64,
    all_ops: &[(u64, PcodeOp)],
) -> CallTarget {
    // Trace backwards from the CallInd dest through IntAnd/IntSext/IntAdd/Copy chains
    // to find the Load that produced the function address.
    // Accumulate constant adjustments (e.g., addiu t9, t9, -0x68c0).
    let mut target_vn = *dest;
    let mut adjustment: i64 = 0;
    for _depth in 0..8 {
        let mut found_producer = false;
        for (_addr, op) in ops.iter().rev() {
            if let Some(out) = pcode_ir::get_output(op) {
                if out.space == target_vn.space && out.offset == target_vn.offset {
                    match op {
                        // Load from memory — this is the function address source
                        PcodeOp::Load { ptr, .. } => {
                            if ptr.space == AddressSpaceId::Const {
                                let addr = (ptr.offset as i64 + adjustment) as u64;
                                return CallTarget::Direct(addr);
                            }
                            // MIPS PIC: ptr is GP + offset (Unique from IntAdd)
                            if ptr.space == AddressSpaceId::Unique {
                                if let Some(got_addr) =
                                    resolve_gp_relative_addr(ops, ptr, func_addr, all_ops)
                                {
                                    let addr = (got_addr as i64 + adjustment) as u64;
                                    return CallTarget::Direct(addr);
                                }
                            }
                            return CallTarget::Indirect(*dest);
                        }
                        // IntAnd (MIPS ISA mode bit masking) — follow through
                        PcodeOp::IntAnd { left, right, .. } => {
                            target_vn = if right.space == AddressSpaceId::Const {
                                *left
                            } else {
                                *right
                            };
                            found_producer = true;
                            break;
                        }
                        // IntAdd with constant: t9 = t9 + offset (addiu adjustment)
                        // Accumulate the adjustment and continue tracing the register operand
                        PcodeOp::IntAdd { left, right, .. } => {
                            if right.space == AddressSpaceId::Const {
                                adjustment += right.offset as i64;
                                target_vn = *left;
                                found_producer = true;
                                break;
                            } else if left.space == AddressSpaceId::Const {
                                adjustment += left.offset as i64;
                                target_vn = *right;
                                found_producer = true;
                                break;
                            }
                            return CallTarget::Indirect(*dest);
                        }
                        // IntSext/IntZext — follow through
                        PcodeOp::IntSext { input, .. } | PcodeOp::IntZext { input, .. } => {
                            target_vn = *input;
                            found_producer = true;
                            break;
                        }
                        // Copy — follow through
                        PcodeOp::Copy { input, .. } => {
                            if input.space == AddressSpaceId::Const {
                                let addr = (input.offset as i64 + adjustment) as u64;
                                return CallTarget::Direct(addr);
                            }
                            target_vn = *input;
                            found_producer = true;
                            break;
                        }
                        _ => {
                            return CallTarget::Indirect(*dest);
                        }
                    }
                }
            }
        }
        if !found_producer {
            // Block-local trace exhausted — fall back to function-wide
            // scan for the IAT-into-reg loaded-in-earlier-block pattern.
            return resolve_callind_via_all_ops(all_ops, dest, target_vn, adjustment);
        }
    }
    CallTarget::Indirect(*dest)
}

/// Function-wide fallback for `resolve_callind_target` when the block-local
/// trace exhausts. Scans `all_ops` in reverse from the (last) CallInd site,
/// chasing the same Load/Copy/IntAdd/IntZext/IntSext chain. Bails as soon as
/// any `Call` or `CallInd` op is crossed — those clobber caller-saved regs,
/// so any reg-def reaching past them is unsafe to follow.
fn resolve_callind_via_all_ops(
    all_ops: &[(u64, PcodeOp)],
    dest: &pcode_ir::Varnode,
    initial_target: pcode_ir::Varnode,
    initial_adjustment: i64,
) -> CallTarget {
    // Locate the CallInd we're resolving. It's the last CallInd in all_ops
    // (resolver runs at terminator construction, which is the last block op).
    let call_idx = match all_ops
        .iter()
        .rposition(|(_, op)| matches!(op, PcodeOp::CallInd { dest: d } if d == dest))
    {
        Some(i) => i,
        None => return CallTarget::Indirect(*dest),
    };

    let mut target_vn = initial_target;
    let mut adjustment = initial_adjustment;
    for _depth in 0..8 {
        let mut found_producer = false;
        // Walk backward from just before the call site.
        for i in (0..call_idx).rev() {
            let op = &all_ops[i].1;
            // Any intervening call clobbers caller-saved regs.
            if matches!(op, PcodeOp::Call { .. } | PcodeOp::CallInd { .. }) {
                return CallTarget::Indirect(*dest);
            }
            if let Some(out) = pcode_ir::get_output(op) {
                if out.space == target_vn.space && out.offset == target_vn.offset {
                    match op {
                        PcodeOp::Load { ptr, .. } => {
                            if ptr.space == AddressSpaceId::Const {
                                let addr = (ptr.offset as i64 + adjustment) as u64;
                                return CallTarget::Direct(addr);
                            }
                            return CallTarget::Indirect(*dest);
                        }
                        PcodeOp::IntAnd { left, right, .. } => {
                            target_vn = if right.space == AddressSpaceId::Const {
                                *left
                            } else {
                                *right
                            };
                            found_producer = true;
                            break;
                        }
                        PcodeOp::IntAdd { left, right, .. } => {
                            if right.space == AddressSpaceId::Const {
                                adjustment += right.offset as i64;
                                target_vn = *left;
                                found_producer = true;
                                break;
                            } else if left.space == AddressSpaceId::Const {
                                adjustment += left.offset as i64;
                                target_vn = *right;
                                found_producer = true;
                                break;
                            }
                            return CallTarget::Indirect(*dest);
                        }
                        PcodeOp::IntSext { input, .. } | PcodeOp::IntZext { input, .. } => {
                            target_vn = *input;
                            found_producer = true;
                            break;
                        }
                        PcodeOp::Copy { input, .. } => {
                            if input.space == AddressSpaceId::Const {
                                let addr = (input.offset as i64 + adjustment) as u64;
                                return CallTarget::Direct(addr);
                            }
                            target_vn = *input;
                            found_producer = true;
                            break;
                        }
                        _ => return CallTarget::Indirect(*dest),
                    }
                }
            }
        }
        if !found_producer {
            break;
        }
    }
    CallTarget::Indirect(*dest)
}

/// Resolve a GP-relative address for MIPS PIC calls.
/// Scans backwards for IntAdd(GP_reg, const_offset) that produced the given Unique varnode,
/// then traces GP to find its constant value from the function prologue.
fn resolve_gp_relative_addr(
    ops: &[(u64, PcodeOp)],
    ptr: &pcode_ir::Varnode,
    func_addr: u64,
    all_ops: &[(u64, PcodeOp)],
) -> Option<u64> {
    // Find the IntAdd that produced this Unique varnode
    for (_addr, op) in ops.iter().rev() {
        if let PcodeOp::IntAdd { out, left, right } = op {
            if out.space == ptr.space && out.offset == ptr.offset && out.size == ptr.size {
                // One operand should be GP (a register), the other a constant offset
                let (reg, offset) = if right.space == AddressSpaceId::Const {
                    (left, right.offset as i64)
                } else if left.space == AddressSpaceId::Const {
                    (right, left.offset as i64)
                } else {
                    return None;
                };

                // The register should be GP — trace its value.
                // Try all_ops first (function-wide GP setup from prologue).
                // GP is function-invariant in MIPS PIC: set once, restored after calls.
                if reg.space == AddressSpaceId::Register {
                    if let Some(gp_val) = trace_register_value(all_ops, reg, func_addr) {
                        // Handle negative offsets (sign-extend 32-bit)
                        let got_addr = if offset > 0x7FFFFFFF {
                            gp_val.wrapping_add(offset as u64 | 0xFFFFFFFF00000000)
                        } else {
                            (gp_val as i64 + offset) as u64
                        };
                        return Some(got_addr);
                    }
                }
                return None;
            }
        }
    }
    None
}

/// Trace a register's constant value by scanning backwards through P-code ops.
/// Handles MIPS GP setup patterns like: Copy(GP, const) or IntAdd(GP, GP, const).
fn trace_register_value(
    ops: &[(u64, PcodeOp)],
    reg: &pcode_ir::Varnode,
    func_addr: u64,
) -> Option<u64> {
    let mut value: Option<u64> = None;

    // Scan FORWARD to build up the register value (handles multi-instruction setup)
    for (_addr, op) in ops.iter() {
        match op {
            // Copy from constant: reg = const (lui produces this)
            PcodeOp::Copy { out, input }
                if out.offset == reg.offset
                    && out.space == reg.space
                    && input.space == AddressSpaceId::Const =>
            {
                value = Some(input.offset);
            }
            // IntAdd with constant: reg = reg + const (addiu reg, reg, lo)
            PcodeOp::IntAdd { out, left, right }
                if out.offset == reg.offset
                    && out.space == reg.space
                    && left.offset == reg.offset
                    && left.space == reg.space
                    && right.space == AddressSpaceId::Const =>
            {
                if let Some(prev) = value {
                    value = Some((prev as i64 + right.offset as i64) as u64);
                }
            }
            // IntAdd with another register: reg = reg + other_reg (addu gp, gp, t9)
            // In MIPS PIC, t9 holds the function address at entry.
            PcodeOp::IntAdd { out, left, right }
                if out.offset == reg.offset
                    && out.space == reg.space
                    && left.offset == reg.offset
                    && left.space == reg.space
                    && right.space == AddressSpaceId::Register =>
            {
                if let Some(prev) = value {
                    // The other register is likely t9 (func entry address)
                    // Use func_addr as the value of t9 at function entry
                    value = Some(prev.wrapping_add(func_addr));
                }
            }
            // Also: reg = other_reg + reg (commuted form)
            PcodeOp::IntAdd { out, left, right }
                if out.offset == reg.offset
                    && out.space == reg.space
                    && right.offset == reg.offset
                    && right.space == reg.space
                    && left.space == AddressSpaceId::Register =>
            {
                if let Some(prev) = value {
                    value = Some(prev.wrapping_add(func_addr));
                }
            }
            // IntAdd where result is in a DIFFERENT output but same logical register
            // (handles t9 = gp + offset patterns where t9 is the output)
            PcodeOp::IntAdd { out, left, right }
                if out.offset == reg.offset
                    && out.space == reg.space
                    && right.space == AddressSpaceId::Const =>
            {
                // left must be a register we can resolve
                if left.space == AddressSpaceId::Register {
                    let left_val = trace_register_value_simple(ops, left);
                    if let Some(lv) = left_val {
                        value = Some((lv as i64 + right.offset as i64) as u64);
                    }
                }
            }
            // IntSext from a Unique — trace through to find the Unique's value
            // This handles MIPS lui: IntLsl(const, 16) → Unique → IntSext → GP
            PcodeOp::IntSext { out, input }
                if out.offset == reg.offset && out.space == reg.space =>
            {
                // Try to resolve the Unique input to a constant
                if input.space == AddressSpaceId::Unique {
                    // Scan backward for the op that produced this Unique
                    for (_a2, op2) in ops.iter().rev() {
                        if let Some(out2) = pcode_ir::get_output(op2) {
                            if out2.space == input.space && out2.offset == input.offset {
                                if let PcodeOp::IntLsl { left, right, .. } = op2 {
                                    if left.space == AddressSpaceId::Const
                                        && right.space == AddressSpaceId::Const
                                    {
                                        value = Some(left.offset << right.offset);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            // GP register restores: in MIPS PIC, lw gp, N(sp) restores the prologue
            // GP value after a call. The P-code chain is Load→IntSext→GP.
            // Don't clear tracking — GP is function-invariant.
            PcodeOp::Load { out, .. }
                if out.offset == reg.offset && out.space == reg.space && reg.offset == 112 =>
            {
                // GP restore from stack — keep the prologue value
            }
            PcodeOp::IntSext { out, .. }
                if out.offset == reg.offset && out.space == reg.space && reg.offset == 112 =>
            {
                // GP restore via sign extension — keep the prologue value
            }
            PcodeOp::Copy { out, .. }
                if out.offset == reg.offset && out.space == reg.space && reg.offset == 112 =>
            {
                // GP copy — keep the prologue value
            }
            // Any other write to this register clears our tracking
            _ => {
                if let Some(out) = pcode_ir::get_output(op) {
                    if out.offset == reg.offset && out.space == reg.space {
                        value = None;
                    }
                }
            }
        }
    }
    value
}

/// Simple constant trace for a register — just find the most recent Copy(reg, const).
fn trace_register_value_simple(ops: &[(u64, PcodeOp)], reg: &pcode_ir::Varnode) -> Option<u64> {
    for (_addr, op) in ops.iter().rev() {
        if let PcodeOp::Copy { out, input } = op {
            if out.offset == reg.offset
                && out.space == reg.space
                && input.space == AddressSpaceId::Const
            {
                return Some(input.offset);
            }
        }
        // IntAdd self: reg = reg + const
        if let PcodeOp::IntAdd { out, left, right } = op {
            if out.offset == reg.offset
                && out.space == reg.space
                && left.offset == reg.offset
                && left.space == reg.space
                && right.space == AddressSpaceId::Const
            {
                // Need previous value — scan further back
                if let Some(prev) = trace_register_value_simple(
                    &ops[..ops
                        .iter()
                        .rposition(|(_, o)| std::ptr::eq(o, op))
                        .unwrap_or(0)],
                    reg,
                ) {
                    return Some((prev as i64 + right.offset as i64) as u64);
                }
            }
        }
    }
    None
}

impl Cfg {
    pub fn successors(&self, block: BlockId) -> Vec<BlockId> {
        match &self.blocks[block.0].terminator {
            Terminator::Fallthrough(b) | Terminator::Branch(b) => vec![*b],
            Terminator::CBranch {
                taken, fallthrough, ..
            } => vec![*taken, *fallthrough],
            Terminator::Call { fallthrough, .. } => vec![*fallthrough],
            Terminator::Return | Terminator::Indirect(_) => vec![],
        }
    }

    pub fn predecessors(&self) -> Vec<Vec<BlockId>> {
        let mut preds = vec![vec![]; self.blocks.len()];
        for block in &self.blocks {
            for succ in self.successors(block.id) {
                if succ.0 < preds.len() {
                    preds[succ.0].push(block.id);
                }
            }
        }
        preds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(len: u64, ops: Vec<PcodeOp>) -> Instruction {
        Instruction {
            len,
            disassembly: String::new(),
            ops,
            constructor: None,
        }
    }

    #[test]
    fn direct_branch_to_non_instruction_target_is_indirect() {
        let cfg = build_cfg(&[
            (
                0x1000,
                inst(
                    4,
                    vec![PcodeOp::Branch {
                        dest: Varnode::ram(0x1006, 8),
                    }],
                ),
            ),
            (0x1004, inst(4, vec![])),
            (0x1008, inst(4, vec![])),
        ]);

        assert!(matches!(
            cfg.blocks[0].terminator,
            Terminator::Indirect(v) if v == Varnode::ram(0x1006, 8)
        ));
    }

    #[test]
    fn conditional_branch_preserves_in_range_fallthrough() {
        let cfg = build_cfg(&[
            (
                0x1000,
                inst(
                    4,
                    vec![PcodeOp::CBranch {
                        dest: Varnode::ram(0x1006, 8),
                        cond: Varnode::register(0, 1),
                    }],
                ),
            ),
            (0x1004, inst(4, vec![])),
            (0x1008, inst(4, vec![])),
        ]);

        assert!(matches!(
            cfg.blocks[0].terminator,
            Terminator::Fallthrough(BlockId(1))
        ));
        assert!(cfg
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagKind::UnresolvedBranchTarget));
    }
}
