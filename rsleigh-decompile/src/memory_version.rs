//! Conservative region-aware reaching memory definitions.
//!
//! The analysis is observational: it does not replace the existing exact-slot
//! SSA or authorize a fold.  Stores kill only definitions proven MustAlias;
//! MayAlias definitions and unknown calls remain in every relevant load's
//! reaching set.

use std::collections::{BTreeSet, VecDeque};

use crate::ir::{BlockId, Expr, SsaCfg, SsaTerminator, Stmt, VarId};
use crate::memory_effect::{query_alias, AliasClass, MemoryAccess};
use crate::region::RegionMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryVersionTerminal {
    Converged,
    Exhausted,
    InvalidCfg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryDefinitionKind {
    Store,
    UnknownCall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryDefinition {
    pub id: usize,
    pub block: BlockId,
    /// Statement ordinal, or `block.stmts.len()` for a call terminator.
    pub statement_index: usize,
    pub kind: MemoryDefinitionKind,
    pub access: Option<MemoryAccess>,
    pub value: Option<VarId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachingLoad {
    pub block: BlockId,
    pub statement_index: usize,
    pub output: VarId,
    pub access: MemoryAccess,
    pub reaching_definitions: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryVersionAnalysis {
    pub terminal: MemoryVersionTerminal,
    pub rounds: usize,
    pub definitions: Vec<MemoryDefinition>,
    pub loads: Vec<ReachingLoad>,
}

/// Build deterministic reaching-definition observations under an explicit
/// round budget.  Exhaustion returns the best conservative state reached so
/// far and is never reported as convergence.
pub fn analyze_memory_versions(
    ssa: &SsaCfg,
    regions: &RegionMap,
    max_rounds: usize,
) -> MemoryVersionAnalysis {
    let Some(blocks_by_id) = validate_cfg(ssa) else {
        return MemoryVersionAnalysis {
            terminal: MemoryVersionTerminal::InvalidCfg,
            rounds: 0,
            definitions: Vec::new(),
            loads: Vec::new(),
        };
    };

    let (definitions, events) = collect_definitions(ssa, &blocks_by_id);
    let predecessors = predecessors(ssa, &blocks_by_id);
    let reachable = reachable_blocks(ssa, &blocks_by_id);
    let mut in_states = vec![BTreeSet::new(); ssa.blocks.len()];
    let mut out_states = vec![BTreeSet::new(); ssa.blocks.len()];
    let mut rounds = 0;
    let mut terminal = MemoryVersionTerminal::Exhausted;

    for round in 0..max_rounds {
        let previous_out = out_states.clone();
        let mut changed = false;
        for block_id in 0..ssa.blocks.len() {
            if !reachable[block_id] {
                continue;
            }
            let mut next_in = BTreeSet::new();
            for predecessor in &predecessors[block_id] {
                next_in.extend(previous_out[predecessor.0].iter().copied());
            }
            let next_out = transfer_block(ssa, regions, &definitions, &events[block_id], &next_in);
            if next_in != in_states[block_id] || next_out != out_states[block_id] {
                changed = true;
            }
            in_states[block_id] = next_in;
            out_states[block_id] = next_out;
        }
        rounds = round + 1;
        if !changed {
            terminal = MemoryVersionTerminal::Converged;
            break;
        }
    }

    let loads = collect_loads(
        ssa,
        regions,
        &definitions,
        &events,
        &in_states,
        &blocks_by_id,
        &reachable,
        terminal,
    );
    MemoryVersionAnalysis {
        terminal,
        rounds,
        definitions,
        loads,
    }
}

fn validate_cfg(ssa: &SsaCfg) -> Option<Vec<usize>> {
    if ssa.blocks.is_empty() || ssa.entry.0 >= ssa.blocks.len() {
        return None;
    }
    let mut blocks_by_id = vec![usize::MAX; ssa.blocks.len()];
    for (index, block) in ssa.blocks.iter().enumerate() {
        if block.id.0 >= ssa.blocks.len() || blocks_by_id[block.id.0] != usize::MAX {
            return None;
        }
        blocks_by_id[block.id.0] = index;
        for successor in successors(&block.terminator) {
            if successor.0 >= ssa.blocks.len() {
                return None;
            }
        }
    }
    if blocks_by_id.iter().any(|index| *index == usize::MAX) {
        return None;
    }
    Some(blocks_by_id)
}

fn collect_definitions(
    ssa: &SsaCfg,
    blocks_by_id: &[usize],
) -> (Vec<MemoryDefinition>, Vec<Vec<Vec<usize>>>) {
    let mut definitions = Vec::new();
    let mut events = vec![Vec::new(); ssa.blocks.len()];
    for block_id in 0..ssa.blocks.len() {
        let block = &ssa.blocks[blocks_by_id[block_id]];
        let mut block_events = vec![Vec::new(); block.stmts.len() + 1];
        for (statement_index, statement) in block.stmts.iter().enumerate() {
            let definition = match statement {
                Stmt::Store { addr, val } => Some(MemoryDefinition {
                    id: definitions.len(),
                    block: block.id,
                    statement_index,
                    kind: MemoryDefinitionKind::Store,
                    access: Some(MemoryAccess {
                        address: *addr,
                        displacement: 0,
                        width: var_width(ssa, *val),
                    }),
                    value: Some(*val),
                }),
                Stmt::Call { .. } => Some(MemoryDefinition {
                    id: definitions.len(),
                    block: block.id,
                    statement_index,
                    kind: MemoryDefinitionKind::UnknownCall,
                    access: None,
                    value: None,
                }),
                Stmt::Assign(_) => None,
            };
            if let Some(definition) = definition {
                let id = definition.id;
                definitions.push(definition);
                block_events[statement_index].push(id);
            }
        }
        if matches!(block.terminator, SsaTerminator::Call { .. }) {
            let definition = MemoryDefinition {
                id: definitions.len(),
                block: block.id,
                statement_index: block.stmts.len(),
                kind: MemoryDefinitionKind::UnknownCall,
                access: None,
                value: None,
            };
            let id = definition.id;
            definitions.push(definition);
            block_events[block.stmts.len()].push(id);
        }
        events[block_id] = block_events;
    }
    (definitions, events)
}

fn predecessors(ssa: &SsaCfg, blocks_by_id: &[usize]) -> Vec<Vec<BlockId>> {
    let mut predecessors = vec![Vec::new(); ssa.blocks.len()];
    for block_id in 0..ssa.blocks.len() {
        let block = &ssa.blocks[blocks_by_id[block_id]];
        for successor in successors(&block.terminator) {
            predecessors[successor.0].push(block.id);
        }
    }
    for values in &mut predecessors {
        values.sort_by_key(|block| block.0);
        values.dedup();
    }
    predecessors
}

fn reachable_blocks(ssa: &SsaCfg, blocks_by_id: &[usize]) -> Vec<bool> {
    let mut reachable = vec![false; ssa.blocks.len()];
    let mut queue = VecDeque::from([ssa.entry]);
    while let Some(block_id) = queue.pop_front() {
        if reachable[block_id.0] {
            continue;
        }
        reachable[block_id.0] = true;
        let block = &ssa.blocks[blocks_by_id[block_id.0]];
        queue.extend(successors(&block.terminator));
    }
    reachable
}

fn successors(terminator: &SsaTerminator) -> Vec<BlockId> {
    let mut values = match terminator {
        SsaTerminator::Fallthrough(target) | SsaTerminator::Branch(target) => vec![*target],
        SsaTerminator::CBranch {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        SsaTerminator::Call { fallthrough, .. } => vec![*fallthrough],
        SsaTerminator::Return(_) | SsaTerminator::Indirect(_) => Vec::new(),
    };
    values.sort_by_key(|block| block.0);
    values.dedup();
    values
}

fn transfer_block(
    ssa: &SsaCfg,
    regions: &RegionMap,
    definitions: &[MemoryDefinition],
    events: &[Vec<usize>],
    input: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let mut state = input.clone();
    for statement_events in events {
        for definition_id in statement_events {
            apply_definition(ssa, regions, definitions, &mut state, *definition_id);
        }
    }
    state
}

fn apply_definition(
    ssa: &SsaCfg,
    regions: &RegionMap,
    definitions: &[MemoryDefinition],
    state: &mut BTreeSet<usize>,
    definition_id: usize,
) {
    let definition = &definitions[definition_id];
    if let Some(new_access) = definition.access {
        state.retain(|old_id| {
            let Some(old_access) = definitions[*old_id].access else {
                return true;
            };
            query_alias(ssa, regions, new_access, old_access).class != AliasClass::MustAlias
        });
    }
    state.insert(definition_id);
}

fn collect_loads(
    ssa: &SsaCfg,
    regions: &RegionMap,
    definitions: &[MemoryDefinition],
    events: &[Vec<Vec<usize>>],
    in_states: &[BTreeSet<usize>],
    blocks_by_id: &[usize],
    reachable: &[bool],
    terminal: MemoryVersionTerminal,
) -> Vec<ReachingLoad> {
    let mut loads = Vec::new();
    for block_id in 0..ssa.blocks.len() {
        if !reachable[block_id] {
            continue;
        }
        let block = &ssa.blocks[blocks_by_id[block_id]];
        // A budget exit cannot publish the partially propagated state as a
        // reaching-definition result.  Widen to every definition and retain
        // only alias-compatible facts at each load.  This admits false
        // positives (including later stores) but cannot omit a real may-def.
        let exhausted = terminal == MemoryVersionTerminal::Exhausted;
        let mut state = if exhausted {
            (0..definitions.len()).collect()
        } else {
            in_states[block_id].clone()
        };
        for (statement_index, statement) in block.stmts.iter().enumerate() {
            if let Stmt::Assign(output) = statement {
                if let Some(access) = load_access(ssa, *output) {
                    let reaching_definitions = state
                        .iter()
                        .copied()
                        .filter(|definition_id| {
                            let definition = &definitions[*definition_id];
                            definition.access.map_or(true, |definition_access| {
                                query_alias(ssa, regions, access, definition_access).class
                                    != AliasClass::NoAlias
                            })
                        })
                        .collect();
                    loads.push(ReachingLoad {
                        block: block.id,
                        statement_index,
                        output: *output,
                        access,
                        reaching_definitions,
                    });
                }
            }
            if !exhausted {
                for definition_id in &events[block_id][statement_index] {
                    apply_definition(ssa, regions, definitions, &mut state, *definition_id);
                }
            }
        }
    }
    loads
}

fn load_access(ssa: &SsaCfg, output: VarId) -> Option<MemoryAccess> {
    let definition = ssa.vars.get(output.0 as usize)?;
    match definition.expr {
        Expr::Load(address) => Some(MemoryAccess {
            address,
            displacement: 0,
            width: u64::from(definition.size),
        }),
        Expr::FieldAccess(base, displacement) => Some(MemoryAccess {
            address: base,
            displacement: i128::from(displacement),
            width: u64::from(definition.size),
        }),
        _ => None,
    }
}

fn var_width(ssa: &SsaCfg, value: VarId) -> u64 {
    ssa.vars
        .get(value.0 as usize)
        .map(|definition| u64::from(definition.size))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CallTarget, InferredType, SsaBlock, VarDef};
    use crate::region::infer_regions;
    use pcode_ir::Varnode;

    fn var(id: u32, expr: Expr, size: u32, param: Option<&str>) -> VarDef {
        VarDef {
            id: VarId(id),
            varnode: Varnode::register(u64::from(id) * 8, size),
            expr,
            size,
            use_count: 0,
            param_name: param.map(str::to_owned),
            call_return: false,
            inferred_type: InferredType::Unknown,
            display_type: None,
        }
    }

    fn block(id: usize, stmts: Vec<Stmt>, terminator: SsaTerminator) -> SsaBlock {
        SsaBlock {
            id: BlockId(id),
            addr: 0x1000 + id as u64 * 0x10,
            stmts,
            terminator,
        }
    }

    fn analysis(ssa: &SsaCfg, rounds: usize) -> MemoryVersionAnalysis {
        let regions = infer_regions(ssa);
        analyze_memory_versions(ssa, &regions, rounds)
    }

    #[test]
    fn diamond_load_keeps_both_reaching_branch_stores() {
        let ssa = SsaCfg {
            blocks: vec![
                block(
                    0,
                    vec![],
                    SsaTerminator::CBranch {
                        cond: VarId(5),
                        taken: BlockId(1),
                        fallthrough: BlockId(2),
                    },
                ),
                block(
                    1,
                    vec![Stmt::Store {
                        addr: VarId(0),
                        val: VarId(1),
                    }],
                    SsaTerminator::Branch(BlockId(3)),
                ),
                block(
                    2,
                    vec![Stmt::Store {
                        addr: VarId(0),
                        val: VarId(2),
                    }],
                    SsaTerminator::Branch(BlockId(3)),
                ),
                block(3, vec![Stmt::Assign(VarId(4))], SsaTerminator::Return(None)),
            ],
            vars: vec![
                var(0, Expr::Unknown, 8, Some("param_0")),
                var(1, Expr::Const(1, 8), 8, None),
                var(2, Expr::Const(2, 8), 8, None),
                var(3, Expr::Const(3, 8), 8, None),
                var(4, Expr::Load(VarId(0)), 8, None),
                var(5, Expr::Const(1, 1), 1, None),
            ],
            entry: BlockId(0),
            diagnostics: Vec::new(),
        };
        let result = analysis(&ssa, 8);
        assert_eq!(result.terminal, MemoryVersionTerminal::Converged);
        assert_eq!(result.loads.len(), 1);
        assert_eq!(result.loads[0].reaching_definitions, vec![0, 1]);
    }

    #[test]
    fn must_alias_store_kills_old_definition_but_partial_store_does_not() {
        let ssa = SsaCfg {
            blocks: vec![block(
                0,
                vec![
                    Stmt::Store {
                        addr: VarId(0),
                        val: VarId(1),
                    },
                    Stmt::Store {
                        addr: VarId(0),
                        val: VarId(2),
                    },
                    Stmt::Assign(VarId(3)),
                ],
                SsaTerminator::Return(None),
            )],
            vars: vec![
                var(0, Expr::Unknown, 8, Some("param_0")),
                var(1, Expr::Const(1, 8), 8, None),
                var(2, Expr::Const(2, 8), 8, None),
                var(3, Expr::Load(VarId(0)), 8, None),
            ],
            entry: BlockId(0),
            diagnostics: Vec::new(),
        };
        let result = analysis(&ssa, 4);
        assert_eq!(result.loads[0].reaching_definitions, vec![1]);

        let partial_ssa = SsaCfg {
            blocks: ssa.blocks,
            vars: vec![
                var(0, Expr::Unknown, 8, Some("param_0")),
                var(1, Expr::Const(1, 8), 8, None),
                var(2, Expr::Const(2, 4), 4, None),
                var(3, Expr::Load(VarId(0)), 8, None),
            ],
            entry: BlockId(0),
            diagnostics: Vec::new(),
        };
        let partial = analysis(&partial_ssa, 4);
        assert_eq!(partial.loads[0].reaching_definitions, vec![0, 1]);
    }

    #[test]
    fn may_alias_parameter_store_and_unknown_call_are_retained() {
        let ssa = SsaCfg {
            blocks: vec![block(
                0,
                vec![
                    Stmt::Store {
                        addr: VarId(0),
                        val: VarId(2),
                    },
                    Stmt::Store {
                        addr: VarId(1),
                        val: VarId(3),
                    },
                    Stmt::Call {
                        target: CallTarget::Direct(0x4000),
                        args: vec![],
                        out: None,
                    },
                    Stmt::Assign(VarId(4)),
                ],
                SsaTerminator::Return(None),
            )],
            vars: vec![
                var(0, Expr::Unknown, 8, Some("param_0")),
                var(1, Expr::Unknown, 8, Some("param_1")),
                var(2, Expr::Const(1, 8), 8, None),
                var(3, Expr::Const(2, 8), 8, None),
                var(4, Expr::Load(VarId(0)), 8, None),
            ],
            entry: BlockId(0),
            diagnostics: Vec::new(),
        };
        let result = analysis(&ssa, 4);
        assert_eq!(result.loads[0].reaching_definitions, vec![0, 1, 2]);
        assert_eq!(
            result.definitions[2].kind,
            MemoryDefinitionKind::UnknownCall
        );
    }

    #[test]
    fn field_displacement_selects_only_overlapping_definition() {
        let ssa = SsaCfg {
            blocks: vec![block(
                0,
                vec![
                    Stmt::Store {
                        addr: VarId(2),
                        val: VarId(3),
                    },
                    Stmt::Assign(VarId(4)),
                ],
                SsaTerminator::Return(None),
            )],
            vars: vec![
                var(0, Expr::Unknown, 8, Some("param_0")),
                var(1, Expr::Const(8, 8), 8, None),
                var(
                    2,
                    Expr::BinOp(crate::ir::BinOpKind::Add, VarId(0), VarId(1)),
                    8,
                    None,
                ),
                var(3, Expr::Const(0xaa, 4), 4, None),
                var(4, Expr::FieldAccess(VarId(0), 8), 4, None),
            ],
            entry: BlockId(0),
            diagnostics: Vec::new(),
        };
        let result = analysis(&ssa, 4);
        assert_eq!(result.loads[0].access.displacement, 8);
        assert_eq!(result.loads[0].reaching_definitions, vec![0]);
    }

    #[test]
    fn budget_exhaustion_and_invalid_cfg_are_typed() {
        let ssa = SsaCfg {
            blocks: vec![block(
                0,
                vec![
                    Stmt::Store {
                        addr: VarId(0),
                        val: VarId(1),
                    },
                    Stmt::Assign(VarId(2)),
                ],
                SsaTerminator::Return(None),
            )],
            vars: vec![
                var(0, Expr::Unknown, 8, Some("param_0")),
                var(1, Expr::Const(1, 8), 8, None),
                var(2, Expr::Load(VarId(0)), 8, None),
            ],
            entry: BlockId(0),
            diagnostics: Vec::new(),
        };
        let exhausted = analysis(&ssa, 0);
        assert_eq!(exhausted.terminal, MemoryVersionTerminal::Exhausted);
        assert_eq!(exhausted.loads[0].reaching_definitions, vec![0]);

        let invalid = SsaCfg {
            blocks: vec![block(1, vec![], SsaTerminator::Return(None))],
            vars: vec![],
            entry: BlockId(0),
            diagnostics: Vec::new(),
        };
        assert_eq!(
            analysis(&invalid, 4).terminal,
            MemoryVersionTerminal::InvalidCfg
        );
    }
}
