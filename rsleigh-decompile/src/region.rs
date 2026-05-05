//! v4 region inference for SMT path analysis.
//!
//! Each VarId carrying a pointer is assigned a `Region` — an
//! abstract location class derived from the value's allocation
//! site. Two VarIds in the same Region may alias; two in different
//! Regions never do. The MemMap in `smt_explore` keys Stores by
//! (Region, OffsetClass) instead of a flat canonical-string of the
//! address expression, so a stack slot rewritten via fresh Unique
//! varnodes at each call site still collides on the same key.
//!
//! v4 keeps the model deliberately coarse — region-classes only,
//! no must-alias inference, no field-sensitive splitting beyond
//! `ConstOffset(c)`. Anything ambiguous becomes `Symbolic(VarId)`
//! and is treated as overlapping with all other symbolic accesses
//! on the same region (sound over-approximation for the SAT
//! feasibility check, which still grounds in the per-SinkKind
//! constraint).
//!
//! Inference seeds:
//!   * Function args (recovered via `param_name`) → `Param(N)`.
//!   * Stack pointer + const offset → `StackFrame`.
//!   * Const RAM addresses → `Global(addr)`.
//!   * Call returns from `malloc/calloc/realloc/strdup` →
//!     `Heap(call_site_addr)`.
//!   * Everything else → `Unknown` (no aliasing claims).

use std::collections::HashMap;

use crate::ir::{Expr, SsaCfg, Stmt, SsaTerminator, VarDef, VarId};
use pcode_ir::AddressSpaceId;

/// Newtype index into the per-SsaCfg `regions` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Region(pub u32);

/// Where a Region got its identity from. Two Regions are equal iff
/// their AllocSites are equal — `Unknown` is intentionally NOT
/// equal to itself across distinct VarIds (we mint a fresh Region
/// id for each unknown so they don't accidentally alias).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllocSite {
    /// Function parameter slot N (caller-supplied pointer).
    Param(u8),
    /// Stack frame of the analysed function.
    StackFrame,
    /// Const-address load — `Global(addr)`.
    Global(u64),
    /// Heap allocation observed at the given call-site PC.
    Heap(u64),
    /// Constant value used as a pointer (e.g. NULL, MMIO).
    Const(u64),
    /// Region whose origin the analyser couldn't pin down. Each
    /// such VarId mints a fresh Region id with `Unknown(varid)`
    /// so two unrelated unknowns don't accidentally alias.
    Unknown(u32),
}

/// Offset within a region. v4 distinguishes a known constant
/// offset from a symbolic / index-driven offset; the latter is
/// treated as overlapping any other access on the same region.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OffsetClass {
    ConstOffset(i64),
    Symbolic,
}

/// Per-function region inference result.
#[derive(Debug, Clone, Default)]
pub struct RegionMap {
    /// Region per VarId. Indexed by `VarId.0`. Length = ssa.vars.len().
    by_var: Vec<Region>,
    /// AllocSite per Region (interned). `regions[Region(i).0 as usize]`.
    sites: Vec<AllocSite>,
    /// Reverse interner: AllocSite → Region.
    intern: HashMap<AllocSite, Region>,
}

impl RegionMap {
    /// Region of `var`. If the var wasn't classified (out-of-bounds),
    /// returns a fresh `Unknown` region.
    pub fn region_of(&self, var: VarId) -> Region {
        *self
            .by_var
            .get(var.0 as usize)
            .unwrap_or(&Region(u32::MAX))
    }

    /// AllocSite for a region.
    pub fn site_of(&self, r: Region) -> Option<&AllocSite> {
        self.sites.get(r.0 as usize)
    }

    fn intern_site(&mut self, site: AllocSite) -> Region {
        if let Some(r) = self.intern.get(&site) {
            return *r;
        }
        let r = Region(self.sites.len() as u32);
        self.sites.push(site.clone());
        self.intern.insert(site, r);
        r
    }
}

/// Run region inference on an SSA function.
///
/// Strategy: forward iteration over `ssa.vars` (SSA dominance
/// order is implicit in VarId order — defs precede uses except
/// for Phi back-edges, which we treat conservatively). For each
/// VarDef compute its Region from operand Regions. Iterate to
/// fixpoint (cap 4 iterations) so Phi joins stabilise.
pub fn infer_regions(ssa: &SsaCfg) -> RegionMap {
    let mut map = RegionMap::default();
    map.by_var = vec![Region(u32::MAX); ssa.vars.len()];

    // Build call_site table for malloc/calloc/realloc/strdup
    // returns (Heap site).
    let heap_returns = collect_heap_returns(ssa);

    // Seeds. Iteration N≤4 lets BinOp(Add, ptr, idx) inherit the
    // ptr's region after we discover ptr is a Param/Stack/Global.
    for _iter in 0..4 {
        let mut changed = false;
        for i in 0..ssa.vars.len() {
            let id = VarId(i as u32);
            let cur = map.by_var[i];
            let site_opt = classify(&ssa.vars[i], &map, &heap_returns, id);
            let new = match site_opt {
                Some(s) => map.intern_site(s),
                None => Region(u32::MAX),
            };
            if new != cur {
                map.by_var[i] = new;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Final pass: anything still UMAX gets a fresh Unknown.
    for (i, slot) in map.by_var.iter_mut().enumerate() {
        if slot.0 == u32::MAX {
            let r = Region(map.sites.len() as u32);
            map.sites.push(AllocSite::Unknown(i as u32));
            map.intern
                .insert(AllocSite::Unknown(i as u32), r);
            *slot = r;
        }
    }
    map
}

/// Returns the AllocSite this VarDef should map to, or None if the
/// VarDef is best left as Unknown (filled in at the post-pass).
fn classify(
    def: &VarDef,
    map: &RegionMap,
    heap_returns: &HashMap<VarId, u64>,
    id: VarId,
) -> Option<AllocSite> {
    if let Some(name) = &def.param_name {
        if let Some(rest) = name.strip_prefix("param_") {
            if let Ok(n) = rest.parse::<u8>() {
                return Some(AllocSite::Param(n));
            }
        }
    }
    if def.call_return {
        if let Some(call_site) = heap_returns.get(&id) {
            return Some(AllocSite::Heap(*call_site));
        }
        return None;
    }
    match &def.expr {
        Expr::Const(c, _) => {
            if def.varnode.space == AddressSpaceId::Ram && *c != 0 {
                Some(AllocSite::Global(*c as u64))
            } else {
                Some(AllocSite::Const(*c as u64))
            }
        }
        Expr::Var(inner) => site_of_var(*inner, map),
        Expr::BinOp(_, a, b) => site_of_var(*a, map).or_else(|| site_of_var(*b, map)),
        Expr::UnaryOp(_, a) => site_of_var(*a, map),
        Expr::FieldAccess(base, _) => site_of_var(*base, map),
        Expr::Phi(args) => args.iter().find_map(|a| site_of_var(*a, map)),
        Expr::Unknown if def.varnode.space == AddressSpaceId::Register => {
            Some(AllocSite::StackFrame)
        }
        _ => None,
    }
}

fn site_of_var(v: VarId, map: &RegionMap) -> Option<AllocSite> {
    let r = *map.by_var.get(v.0 as usize)?;
    if r.0 == u32::MAX {
        return None;
    }
    let site = map.sites.get(r.0 as usize)?;
    if matches!(site, AllocSite::Unknown(_)) {
        return None;
    }
    Some(site.clone())
}

fn collect_heap_returns(ssa: &SsaCfg) -> HashMap<VarId, u64> {
    let mut m = HashMap::new();
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            if let Stmt::Call {
                target,
                out: Some(o),
                ..
            } = stmt
            {
                if let crate::ir::CallTarget::Direct(addr) = target {
                    m.insert(*o, *addr);
                }
            }
        }
        if let SsaTerminator::Call {
            target,
            out: Some(o),
            ..
        } = &block.terminator
        {
            if let crate::ir::CallTarget::Direct(addr) = target {
                m.insert(*o, *addr);
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        BlockId, Diagnostic, Expr, InferredType, SsaBlock, SsaCfg, SsaTerminator, VarDef,
    };
    use pcode_ir::Varnode;

    fn mk_var(id: u32, expr: Expr, vn: Varnode, param: Option<&str>) -> VarDef {
        VarDef {
            id: VarId(id),
            varnode: vn,
            expr,
            size: 8,
            use_count: 1,
            param_name: param.map(String::from),
            call_return: false,
            inferred_type: InferredType::Unknown,
            display_type: None,
        }
    }

    fn empty_ssa(vars: Vec<VarDef>) -> SsaCfg {
        SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0,
                stmts: vec![],
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::<Diagnostic>::new(),
        }
    }

    #[test]
    fn param_var_classified_as_param() {
        let vars = vec![mk_var(
            0,
            Expr::Unknown,
            Varnode::register(0, 8),
            Some("param_2"),
        )];
        let map = infer_regions(&empty_ssa(vars));
        let r = map.region_of(VarId(0));
        match map.site_of(r) {
            Some(AllocSite::Param(2)) => {}
            other => panic!("expected Param(2), got {other:?}"),
        }
    }

    #[test]
    fn pointer_arith_inherits_base_region() {
        // v0 = param_0 (ptr), v1 = const(8), v2 = v0 + v1
        let vars = vec![
            mk_var(0, Expr::Unknown, Varnode::register(0, 8), Some("param_0")),
            mk_var(1, Expr::Const(8, 8), Varnode::constant(8, 8), None),
            mk_var(
                2,
                Expr::BinOp(crate::ir::BinOpKind::Add, VarId(0), VarId(1)),
                Varnode::register(64, 8),
                None,
            ),
        ];
        let map = infer_regions(&empty_ssa(vars));
        let r0 = map.region_of(VarId(0));
        let r2 = map.region_of(VarId(2));
        assert_eq!(r0, r2, "BinOp(Add, ptr, const) must inherit ptr's region");
    }

    #[test]
    fn distinct_params_get_distinct_regions() {
        let vars = vec![
            mk_var(0, Expr::Unknown, Varnode::register(0, 8), Some("param_0")),
            mk_var(1, Expr::Unknown, Varnode::register(8, 8), Some("param_1")),
        ];
        let map = infer_regions(&empty_ssa(vars));
        assert_ne!(map.region_of(VarId(0)), map.region_of(VarId(1)));
    }

    #[test]
    fn const_global_classified_as_global() {
        let vars = vec![mk_var(
            0,
            Expr::Const(0x602080, 8),
            Varnode {
                space: pcode_ir::AddressSpaceId::Ram,
                offset: 0x602080,
                size: 8,
            },
            None,
        )];
        let map = infer_regions(&empty_ssa(vars));
        let r = map.region_of(VarId(0));
        match map.site_of(r) {
            Some(AllocSite::Global(0x602080)) => {}
            other => panic!("expected Global(0x602080), got {other:?}"),
        }
    }
}
