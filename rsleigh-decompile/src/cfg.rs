use std::collections::HashMap;
use pcode_ir::{PcodeOp, AddressSpaceId, Instruction};
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
    let addr_set: HashMap<u64, usize> = instructions.iter()
        .enumerate()
        .map(|(i, (addr, _))| (*addr, i))
        .collect();

    for (addr, inst) in instructions {
        let next_addr = addr + inst.len;
        for op in &inst.ops {
            match op {
                PcodeOp::Branch { dest } | PcodeOp::CBranch { dest, .. }
                    if dest.space == AddressSpaceId::Ram =>
                {
                    leaders.push(dest.offset);
                    if matches!(op, PcodeOp::CBranch { .. }) {
                        leaders.push(next_addr);
                    }
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
                    Terminator::Return
                }
                PcodeOp::Branch { dest } if dest.space == AddressSpaceId::Ram => {
                    let target = dest.offset;
                    ops.pop();
                    if let Some(&bid) = leader_to_block.get(&target) {
                        Terminator::Branch(bid)
                    } else {
                        Terminator::Branch(BlockId(block_idx)) // self-loop fallback
                    }
                }
                PcodeOp::CBranch { dest, cond } if dest.space == AddressSpaceId::Ram => {
                    let target = dest.offset;
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
                    let fallthrough = leader_to_block.get(&next_inst_addr)
                        .copied()
                        .unwrap_or(BlockId(block_idx));
                    Terminator::Call { target, fallthrough }
                }
                PcodeOp::CallInd { dest } => {
                    let target = CallTarget::Indirect(*dest);
                    ops.pop();
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
