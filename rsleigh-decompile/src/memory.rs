//! Conservative, bounded reaching-store analysis over the completed register SSA.
use crate::{
    fold::CallingConv,
    ir::*,
    region::{exact_location, ExactLocation},
};
use pcode_ir::{AddressSpaceId, Varnode};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_LOCATIONS: usize = 1024;
const MAX_STORES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    UnmodeledMemory,
    AmbiguousAlias,
    OverlappingStore,
    UnsupportedSideEffects,
    UnsupportedAddressSpace,
    MemoryStateLimit,
    MemoryTraversalLimit,
}
impl Boundary {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnmodeledMemory => "unmodeled_memory",
            Self::AmbiguousAlias => "ambiguous_alias",
            Self::OverlappingStore => "overlapping_store",
            Self::UnsupportedSideEffects => "unsupported_side_effects",
            Self::UnsupportedAddressSpace => "unsupported_address_space",
            Self::MemoryStateLimit => "memory_state_limit",
            Self::MemoryTraversalLimit => "memory_traversal_limit",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Access {
    Store {
        space: AddressSpaceId,
    },
    Load {
        space: AddressSpaceId,
        stores: Vec<VarId>,
        boundary: Option<Boundary>,
    },
}

#[derive(Clone, PartialEq, Eq)]
struct State {
    values: BTreeMap<ExactLocation, BTreeSet<u32>>,
    boundary: Boundary,
}
impl State {
    fn empty(boundary: Boundary) -> Self {
        Self {
            values: BTreeMap::new(),
            boundary,
        }
    }
    fn invalidate(&mut self, boundary: Boundary) {
        self.values.clear();
        self.boundary = boundary;
    }
    fn store(&mut self, ssa: &SsaCfg, addr: VarId, val: VarId, cc: CallingConv) {
        if matches!(ssa.var(val).memory, Some(Access::Store { space }) if space != AddressSpaceId::Ram)
        {
            self.invalidate(Boundary::UnsupportedAddressSpace);
            return;
        }
        let Some(location) = exact_location(ssa, addr, ssa.var(val).size, cc) else {
            self.invalidate(Boundary::AmbiguousAlias);
            return;
        };
        self.values.retain(|key, _| {
            crate::budget::work("memory", 1);
            if key.may_overlap(location) {
                if *key != location {
                    self.boundary = Boundary::OverlappingStore;
                }
                false
            } else {
                true
            }
        });
        if self.values.len() >= MAX_LOCATIONS {
            self.invalidate(Boundary::MemoryStateLimit);
        }
        self.values.insert(location, BTreeSet::from([val.0]));
    }
    fn step(&mut self, ssa: &SsaCfg, stmt: &Stmt, cc: CallingConv) {
        crate::budget::work("memory", 1);
        match stmt {
            Stmt::Store { addr, val } => self.store(ssa, *addr, *val, cc),
            Stmt::Call { .. } => self.invalidate(Boundary::UnsupportedSideEffects),
            Stmt::Assign(id) if matches!(ssa.var(*id).expr, Expr::UserOp { .. }) => {
                self.invalidate(Boundary::UnsupportedSideEffects)
            }
            _ => {}
        }
    }
}

fn merge(preds: &[BlockId], exits: &[State]) -> State {
    let Some(first) = preds.first() else {
        return State::empty(Boundary::UnmodeledMemory);
    };
    let mut result = exits[first.0].clone();
    for pred in &preds[1..] {
        let other = &exits[pred.0];
        result.values.retain(|key, values| {
            crate::budget::work("memory", 1);
            if let Some(inputs) = other.values.get(key) {
                values.extend(inputs);
                if values.len() <= MAX_STORES {
                    return true;
                }
                result.boundary = Boundary::MemoryStateLimit;
            } else {
                result.boundary = other.boundary;
            }
            false
        });
    }
    result
}

pub(crate) fn forward(ssa: &mut SsaCfg, cfg: &Cfg, cc: CallingConv) {
    let preds = cfg.predecessors();
    let mut exits = vec![State::empty(Boundary::UnmodeledMemory); cfg.blocks.len()];
    let mut entries = exits.clone();
    let mut queue: VecDeque<_> = (0..cfg.blocks.len()).collect();
    let mut queued = vec![true; cfg.blocks.len()];
    let limit = cfg.blocks.len().saturating_mul(64);
    let mut work = 0;
    while let Some(bid) = queue.pop_front() {
        crate::budget::work("memory", 1);
        if work >= limit {
            queue.push_front(bid);
            break;
        }
        work += 1;
        queued[bid] = false;
        let mut state = if bid == cfg.entry.0 {
            State::empty(Boundary::UnmodeledMemory)
        } else {
            merge(&preds[bid], &exits)
        };
        entries[bid] = state.clone();
        for stmt in &ssa.blocks[bid].stmts {
            state.step(ssa, stmt, cc);
        }
        if matches!(ssa.blocks[bid].terminator, SsaTerminator::Call { .. }) {
            state.invalidate(Boundary::UnsupportedSideEffects);
        }
        if exits[bid] != state {
            exits[bid] = state;
            for succ in cfg.successors(BlockId(bid)) {
                if !queued[succ.0] {
                    queue.push_back(succ.0);
                    queued[succ.0] = true;
                }
            }
        }
    }
    if !queue.is_empty() {
        entries.fill(State::empty(Boundary::MemoryTraversalLimit));
        ssa.diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            kind: DiagKind::StackAliasingUnknown,
            addr: None,
            detail: "memory reaching-store iteration limit; only same-block stores are followed"
                .into(),
        });
    }
    // Apply only after reaching-store sets stabilize. Creating a Phi during
    // propagation would conflate intermediate states with final evidence.
    for (bid, mut state) in entries.into_iter().enumerate() {
        let stmts = ssa.blocks[bid].stmts.clone();
        for stmt in &stmts {
            if let Stmt::Assign(id) = stmt {
                if let Expr::Load(ptr) = ssa.var(*id).expr {
                    let space = match ssa.var(*id).memory {
                        Some(Access::Load { space, .. }) => space,
                        _ => AddressSpaceId::Ram,
                    };
                    let location = exact_location(ssa, ptr, ssa.var(*id).size, cc);
                    let (stores, boundary) = if space != AddressSpaceId::Ram {
                        (vec![], Some(Boundary::UnsupportedAddressSpace))
                    } else if let Some(location) = location {
                        match state.values.get(&location) {
                            Some(values) => {
                                (values.iter().copied().map(VarId).collect::<Vec<_>>(), None)
                            }
                            None => (vec![], Some(state.boundary)),
                        }
                    } else {
                        (
                            vec![],
                            Some(if state.values.is_empty() {
                                state.boundary
                            } else {
                                Boundary::AmbiguousAlias
                            }),
                        )
                    };
                    ssa.var_mut(*id).memory = Some(Access::Load {
                        space,
                        stores: stores.clone(),
                        boundary,
                    });
                    if !stores.is_empty() {
                        let value = if stores.len() == 1 {
                            stores[0]
                        } else {
                            let size = location.unwrap().size();
                            ssa.new_var(
                                Varnode::unique(0xF000_0000 + ssa.vars.len() as u64, size),
                                Expr::Phi(stores),
                                size,
                            )
                        };
                        crate::provenance::rewrite(&mut ssa.vars, id.0 as usize, Expr::Var(value));
                    }
                }
            }
            state.step(ssa, stmt, cc);
        }
    }
}
