use std::collections::HashMap;
use pcode_ir::{PcodeOp, AddressSpaceId, Instruction, Varnode};
use crate::ir::*;

/// Build a control flow graph from decoded instructions.
pub fn build_cfg(instructions: &[(u64, Instruction)]) -> Cfg {
    if instructions.is_empty() {
        return Cfg { blocks: vec![], entry: BlockId(0) };
    }

    // Flatten into (addr, op) pairs, grouped by instruction address
    let mut inst_ops: Vec<(u64, Vec<PcodeOp>)> = Vec::new();
    for (addr, inst) in instructions {
        inst_ops.push((*addr, inst.ops.clone()));
    }

    // Find block leaders: first instruction, branch targets, instruction after branch/call/return
    let mut leaders: Vec<u64> = vec![instructions[0].0];
    let _addr_set: HashMap<u64, usize> = instructions.iter()
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

    // Snap branch targets to the nearest valid instruction address.
    // Works around rsleigh branch target computation bugs where relative offsets
    // may be off by a constant (known issue with subtable inst_next).
    let inst_addrs: Vec<u64> = instructions.iter().map(|(a, _)| *a).collect();
    let snap_to_inst = |addr: u64| -> u64 {
        if inst_addrs.contains(&addr) { return addr; }
        // Find nearest instruction address (within 256 bytes)
        inst_addrs.iter().copied()
            .filter(|a| (*a as i64 - addr as i64).unsigned_abs() <= 256)
            .min_by_key(|a| (*a as i64 - addr as i64).unsigned_abs())
            .unwrap_or(addr)
    };
    leaders = leaders.into_iter().map(|a| snap_to_inst(a)).collect();
    leaders.sort_unstable();
    leaders.dedup();

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
    let func_end = instructions.last()
        .map(|(a, i)| a + i.len)
        .unwrap_or(0);

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
        let terminator = if let Some((_, last_op)) = ops.last() {
            match last_op {
                PcodeOp::Return { .. } => {
                    ops.pop();
                    // Strip x86-32 return boilerplate (Load ret_addr from [ESP]; IntAdd ESP, 4)
                    strip_return_pop_ops(&mut ops);
                    Terminator::Return
                }
                PcodeOp::Branch { dest } if dest.space == AddressSpaceId::Ram => {
                    let target = snap_to_inst(dest.offset);
                    ops.pop();
                    if let Some(&bid) = leader_to_block.get(&target) {
                        Terminator::Branch(bid)
                    } else {
                        Terminator::Branch(BlockId(block_idx)) // self-loop fallback
                    }
                }
                PcodeOp::CBranch { dest, cond } if dest.space == AddressSpaceId::Ram => {
                    let target = snap_to_inst(dest.offset);
                    let cond = *cond;
                    ops.pop();
                    let taken = leader_to_block.get(&target)
                        .copied()
                        .unwrap_or(BlockId(block_idx));
                    let fallthrough = leader_to_block.get(&next_inst_addr)
                        .copied()
                        .unwrap_or(BlockId(block_idx));
                    Terminator::CBranch { cond, taken, fallthrough }
                }
                PcodeOp::BranchInd { dest } => {
                    let dest = *dest;
                    ops.pop();
                    Terminator::Indirect(dest)
                }
                PcodeOp::Call { dest } => {
                    let target = if dest.space == AddressSpaceId::Ram {
                        CallTarget::Direct(dest.offset)
                    } else {
                        CallTarget::Indirect(*dest)
                    };
                    ops.pop();
                    // Strip x86-32 return address push (IntSub ESP + Store [ESP])
                    strip_call_push_ops(&mut ops);
                    let fallthrough = leader_to_block.get(&next_inst_addr)
                        .copied()
                        .unwrap_or(BlockId(block_idx));
                    Terminator::Call { target, fallthrough }
                }
                PcodeOp::CallInd { dest } => {
                    // Try to resolve indirect calls through constant Load
                    // (e.g., CALL dword ptr [IAT_addr] → Load tmp, [const]; CallInd tmp)
                    let target = resolve_callind_target(&ops, dest);
                    ops.pop();
                    // Strip x86-32 return address push (IntSub ESP + Store [ESP])
                    strip_call_push_ops(&mut ops);
                    let fallthrough = leader_to_block.get(&next_inst_addr)
                        .copied()
                        .unwrap_or(BlockId(block_idx));
                    Terminator::Call { target, fallthrough }
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
fn resolve_callind_target(ops: &[(u64, PcodeOp)], dest: &pcode_ir::Varnode) -> CallTarget {
    // Scan backwards for a Load whose output matches the CallInd dest varnode
    for (_addr, op) in ops.iter().rev() {
        if let PcodeOp::Load { out, ptr, .. } = op {
            if out.space == dest.space && out.offset == dest.offset && out.size == dest.size {
                // Found the Load — check if the pointer is a constant (IAT-style)
                if ptr.space == AddressSpaceId::Const {
                    return CallTarget::Direct(ptr.offset);
                }
                break;
            }
        }
    }
    CallTarget::Indirect(*dest)
}

impl Cfg {
    pub fn successors(&self, block: BlockId) -> Vec<BlockId> {
        match &self.blocks[block.0].terminator {
            Terminator::Fallthrough(b) | Terminator::Branch(b) => vec![*b],
            Terminator::CBranch { taken, fallthrough, .. } => vec![*taken, *fallthrough],
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
