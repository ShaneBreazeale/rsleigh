//! Bounded instruction evidence retained across SSA transformations.
//!
//! Addresses and raw, zero-based P-code indices are local to one analysis
//! snapshot. Origins describe contributing evidence, not execution proofs.
use crate::ir::{Expr, VarDef};
use std::cell::Cell;
use std::collections::VecDeque;

pub const MAX_ORIGINS: usize = 32;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct OperationOrigin {
    pub instruction_address: u64,
    pub operation_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Origins {
    pub operations: Vec<OperationOrigin>,
    pub truncated: bool,
    /// This definition was introduced by analysis rather than direct lowering.
    pub synthetic: bool,
}

impl Default for Origins {
    fn default() -> Self {
        Self {
            operations: Vec::new(),
            truncated: false,
            synthetic: true,
        }
    }
}

impl Origins {
    pub fn insert(&mut self, origin: OperationOrigin) {
        if let Err(index) = self.operations.binary_search(&origin) {
            if index < MAX_ORIGINS {
                self.operations.insert(index, origin);
                if self.operations.len() > MAX_ORIGINS {
                    self.operations.pop();
                    self.truncated = true;
                }
            } else {
                self.truncated = true;
            }
        }
    }

    pub(crate) fn merge(&mut self, other: &Self) {
        for &origin in &other.operations {
            self.insert(origin);
        }
        self.truncated |= other.truncated;
    }

    pub(crate) fn definition(expr: &Expr, vars: &[VarDef]) -> Self {
        let origin = SOURCE.with(Cell::get);
        let mut result = Self {
            synthetic: origin.is_none(),
            ..Self::default()
        };
        // Reading an incoming or otherwise unknown value does not define it.
        if !matches!(expr, Expr::Unknown) {
            if let Some(origin) = origin {
                result.insert(origin);
            }
        }
        result.merge_inputs(expr, vars);
        result
    }

    fn merge_inputs(&mut self, expr: &Expr, vars: &[VarDef]) {
        for id in crate::ssa::collect_expr_refs(expr) {
            crate::budget::work("provenance", 1);
            if let Some(var) = vars.get(id.0 as usize) {
                self.merge(&var.origins);
            }
        }
    }

    pub(crate) fn attach_source(&mut self) {
        if let Some(origin) = SOURCE.with(Cell::get) {
            self.insert(origin);
            self.synthetic = false;
        }
    }
}

thread_local! {
    static SOURCE: Cell<Option<OperationOrigin>> = const { Cell::new(None) };
}

/// Restores the previous source even when an analysis budget unwinds.
pub(crate) struct SourceScope(Option<OperationOrigin>);
impl SourceScope {
    pub(crate) fn enter(origin: Option<OperationOrigin>) -> Self {
        Self(SOURCE.with(|source| source.replace(origin)))
    }
}
impl Drop for SourceScope {
    fn drop(&mut self) {
        SOURCE.with(|source| source.set(self.0));
    }
}

/// Preserve removed inputs as evidence before replacing an expression.
pub(crate) fn rewrite(vars: &mut [VarDef], index: usize, expr: Expr) {
    // A store proxy carries the write's metadata. Keep the separate source
    // node when inlining would hide a read/call boundary behind that write.
    let expr = if matches!(
        vars[index].memory,
        Some(crate::memory::Access::Store { .. })
    ) && matches!(vars[index].expr, Expr::Var(_))
        && matches!(
            expr,
            Expr::Load(_) | Expr::FieldAccess(..) | Expr::Unknown | Expr::UserOp { .. }
        ) {
        vars[index].expr.clone()
    } else {
        expr
    };
    let mut origins = vars[index].origins.clone();
    origins.merge_inputs(&vars[index].expr, vars);
    origins.merge_inputs(&expr, vars);
    // Copy propagation may inline a Load into a variable that was originally
    // just a Copy. Keep its memory boundary/store evidence as well as origins.
    if vars[index].memory.is_none() {
        let source = match (&vars[index].expr, &expr) {
            (Expr::Var(source), _) | (_, Expr::Var(source)) => Some(*source),
            _ => None,
        };
        if let Some(mut source) = source {
            for _ in 0..32 {
                let Some(var) = vars.get(source.0 as usize) else {
                    break;
                };
                if matches!(var.memory, Some(crate::memory::Access::Load { .. })) {
                    vars[index].memory = var.memory.clone();
                    break;
                }
                if let Expr::Var(next) = var.expr {
                    source = next;
                } else {
                    break;
                }
            }
        }
    }
    vars[index].origins = origins;
    vars[index].expr = expr;
}

/// Resolve forward references and cycles with a bounded monotone worklist.
/// If the local work ceiling is reached, remaining nodes and their consumers
/// are explicitly marked truncated. The shared execution budget also applies.
pub(crate) fn propagate(vars: &mut [VarDef]) {
    let mut consumers = vec![Vec::new(); vars.len()];
    for (index, var) in vars.iter().enumerate() {
        crate::budget::work("provenance", 1);
        for input in crate::ssa::collect_expr_refs(&var.expr) {
            crate::budget::work("provenance", 1);
            if let Some(users) = consumers.get_mut(input.0 as usize) {
                users.push(index);
            }
        }
    }
    let mut queue: VecDeque<_> = (0..vars.len()).collect();
    let mut queued = vec![true; vars.len()];
    let limit = vars.len().saturating_mul(MAX_ORIGINS + 2);
    let mut work = 0;
    while let Some(index) = queue.pop_front() {
        if work >= limit {
            queue.push_front(index);
            break;
        }
        work += 1;
        crate::budget::work("provenance", 1);
        queued[index] = false;
        let mut origins = vars[index].origins.clone();
        origins.merge_inputs(&vars[index].expr, vars);
        if origins != vars[index].origins {
            vars[index].origins = origins;
            for &user in &consumers[index] {
                if !queued[user] {
                    queued[user] = true;
                    queue.push_back(user);
                }
            }
        }
    }
    // Bound this closure walk to one visit per variable even for cyclic SSA.
    let mut marked = vec![false; vars.len()];
    while let Some(index) = queue.pop_front() {
        crate::budget::work("provenance", 1);
        if marked[index] {
            continue;
        }
        marked[index] = true;
        vars[index].origins.truncated = true;
        queue.extend(consumers[index].iter().copied().filter(|&i| !marked[i]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BlockId, SsaCfg, VarId};
    use pcode_ir::Varnode;

    fn empty() -> SsaCfg {
        SsaCfg {
            blocks: vec![],
            vars: vec![],
            entry: BlockId(0),
            diagnostics: vec![],
        }
    }

    fn source(ssa: &mut SsaCfg, address: u64) -> VarId {
        let _scope = SourceScope::enter(Some(OperationOrigin {
            instruction_address: address,
            operation_index: 0,
        }));
        ssa.new_var(Varnode::unique(address, 4), Expr::Const(address, 4), 4)
    }

    #[test]
    fn cycles_and_removed_dependencies_retain_bounded_origins() {
        let mut ssa = empty();
        let a = source(&mut ssa, 0x1000);
        let phi = ssa.new_var(Varnode::unique(1, 4), Expr::Phi(vec![a, VarId(2)]), 4);
        let tail = ssa.new_var(Varnode::unique(2, 4), Expr::Var(phi), 4);
        ssa.vars[tail.0 as usize].origins.insert(OperationOrigin {
            instruction_address: 0x2000,
            operation_index: 1,
        });
        propagate(&mut ssa.vars);
        assert_eq!(ssa.var(phi).origins.operations.len(), 2);
        assert!(ssa.var(phi).origins.synthetic);
        rewrite(&mut ssa.vars, phi.0 as usize, Expr::Const(7, 4));
        assert_eq!(ssa.var(phi).origins.operations.len(), 2);
        let mut last = phi;
        for address in 0x3000..0x3060 {
            let input = source(&mut ssa, address);
            last = ssa.new_var(Varnode::unique(address, 4), Expr::Phi(vec![last, input]), 4);
        }
        propagate(&mut ssa.vars);
        let origins = &ssa.var(last).origins;
        assert_eq!(origins.operations.len(), MAX_ORIGINS);
        assert!(origins.truncated);
        assert!(origins.operations.windows(2).all(|w| w[0] < w[1]));
        let bytes = serde_json::to_vec(&ssa).unwrap();
        let restored: SsaCfg = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.var(last).origins, *origins);
    }

    #[test]
    fn incoming_values_do_not_claim_the_read_instruction_as_a_definition() {
        let mut ssa = empty();
        {
            let _scope = SourceScope::enter(Some(OperationOrigin {
                instruction_address: 0x1000,
                operation_index: 2,
            }));
            let incoming = ssa.new_var(Varnode::register(0, 4), Expr::Unknown, 4);
            assert!(ssa.var(incoming).origins.operations.is_empty());
            let copy = ssa.new_var(Varnode::unique(0, 4), Expr::Var(incoming), 4);
            assert_eq!(ssa.var(copy).origins.operations[0].operation_index, 2);
            assert!(!ssa.var(copy).origins.synthetic);
        }
        let synthetic = ssa.new_var(Varnode::unique(1, 4), Expr::Const(0, 4), 4);
        assert!(ssa.var(synthetic).origins.synthetic);
        assert!(ssa.var(synthetic).origins.operations.is_empty());
    }
}
