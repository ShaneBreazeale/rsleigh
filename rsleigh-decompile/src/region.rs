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

use crate::ir::{Expr, SsaCfg, SsaTerminator, Stmt, VarDef, VarId};
use pcode_ir::AddressSpaceId;

/// An exact address suitable for store/load dependency forwarding. A stack
/// base is an incoming SSA value, never just a physical register number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ExactLocation {
    Global {
        address: u64,
        size: u32,
    },
    Stack {
        base: u32,
        displacement: i64,
        size: u32,
    },
}

impl ExactLocation {
    pub(crate) fn size(self) -> u32 {
        match self {
            Self::Global { size, .. } | Self::Stack { size, .. } => size,
        }
    }

    /// Different bases are not assumed disjoint: an unknown pointer or an
    /// independently read frame register may alias the stored location.
    pub(crate) fn may_overlap(self, other: Self) -> bool {
        let overlaps = |a: i128, a_size: u32, b: i128, b_size: u32| {
            a < b + b_size as i128 && b < a + a_size as i128
        };
        match (self, other) {
            (
                Self::Global {
                    address: a,
                    size: sa,
                },
                Self::Global {
                    address: b,
                    size: sb,
                },
            ) => overlaps(a as i128, sa, b as i128, sb),
            (
                Self::Stack {
                    base: a,
                    displacement: da,
                    size: sa,
                },
                Self::Stack {
                    base: b,
                    displacement: db,
                    size: sb,
                },
            ) if a == b => overlaps(da as i128, sa, db as i128, sb),
            _ => true,
        }
    }
}

/// Resolve only bounded copy/add/sub address expressions with constant
/// displacements. Symbolic indices, phi addresses, and wrapped ranges remain
/// unknown. This is stricter than the coarse region classifier used for taint.
pub(crate) fn exact_location(
    ssa: &SsaCfg,
    ptr: VarId,
    size: u32,
    cc: crate::fold::CallingConv,
) -> Option<ExactLocation> {
    use crate::{fold::CallingConv, ir::BinOpKind};
    fn resolve(
        ssa: &SsaCfg,
        ptr: VarId,
        size: u32,
        frames: &[u64],
        depth: usize,
    ) -> Option<ExactLocation> {
        crate::budget::work("memory", 1);
        if depth >= 64 || size == 0 {
            return None;
        }
        let var = ssa.vars.get(ptr.0 as usize)?;
        let offset = |value: u64, width: u32| -> Option<i64> {
            if !(1..=8).contains(&width) {
                return None;
            }
            let shift = 64 - width * 8;
            Some(((value << shift) as i64) >> shift)
        };
        fn constant_bits(ssa: &SsaCfg, id: VarId, depth: usize, fuel: &mut usize) -> Option<u64> {
            crate::budget::work("memory", 1);
            if depth >= 64 || *fuel == 0 {
                return None;
            }
            *fuel -= 1;
            let var = ssa.vars.get(id.0 as usize)?;
            if !(1..=8).contains(&var.size) {
                return None;
            }
            let mask = u64::MAX >> (64 - var.size * 8);
            let value = match var.expr {
                Expr::Const(value, _) => value,
                Expr::Var(inner) => constant_bits(ssa, inner, depth + 1, fuel)?,
                Expr::UnaryOp(crate::ir::UnaryOpKind::Zext, inner) => {
                    constant_bits(ssa, inner, depth + 1, fuel)?
                }
                Expr::UnaryOp(crate::ir::UnaryOpKind::Sext, inner) => {
                    let value = constant_bits(ssa, inner, depth + 1, fuel)?;
                    let width = ssa.vars.get(inner.0 as usize)?.size;
                    if !(1..=8).contains(&width) || width > var.size {
                        return None;
                    }
                    let shift = 64 - width * 8;
                    (((value << shift) as i64) >> shift) as u64
                }
                Expr::BinOp(BinOpKind::Add, a, b) => constant_bits(ssa, a, depth + 1, fuel)?
                    .wrapping_add(constant_bits(ssa, b, depth + 1, fuel)?),
                Expr::BinOp(BinOpKind::Sub, a, b) => constant_bits(ssa, a, depth + 1, fuel)?
                    .wrapping_sub(constant_bits(ssa, b, depth + 1, fuel)?),
                _ => return None,
            };
            Some(value & mask)
        }
        let constant = |id: VarId| {
            offset(
                constant_bits(ssa, id, 0, &mut 64)?,
                ssa.vars.get(id.0 as usize)?.size,
            )
        };
        let adjust = |location: ExactLocation, displacement: i64| -> Option<ExactLocation> {
            match location {
                ExactLocation::Global { address, size } => {
                    let address = address.checked_add_signed(displacement)?;
                    if var.size < 8 && address >= 1u64.checked_shl(var.size * 8)? {
                        return None;
                    }
                    address.checked_add(size as u64)?;
                    Some(ExactLocation::Global { address, size })
                }
                ExactLocation::Stack {
                    base,
                    displacement: prior,
                    size,
                } => Some(ExactLocation::Stack {
                    base,
                    displacement: prior.checked_add(displacement)?,
                    size,
                }),
            }
        };
        match var.expr {
            Expr::Const(address, _) if address.checked_add(size as u64).is_some() => {
                Some(ExactLocation::Global { address, size })
            }
            Expr::Unknown
                if var.varnode.space == AddressSpaceId::Register
                    && frames.contains(&var.varnode.offset)
                    && !var.call_return =>
            {
                Some(ExactLocation::Stack {
                    base: ptr.0,
                    displacement: 0,
                    size,
                })
            }
            Expr::Var(inner) => resolve(ssa, inner, size, frames, depth + 1),
            Expr::BinOp(BinOpKind::Add, a, b) => {
                if let Some(displacement) = constant(b) {
                    adjust(resolve(ssa, a, size, frames, depth + 1)?, displacement)
                } else {
                    adjust(resolve(ssa, b, size, frames, depth + 1)?, constant(a)?)
                }
            }
            Expr::BinOp(BinOpKind::Sub, a, b) => adjust(
                resolve(ssa, a, size, frames, depth + 1)?,
                constant(b)?.checked_neg()?,
            ),
            _ => None,
        }
    }
    let frames: &[u64] = match cc {
        CallingConv::SysV | CallingConv::Win64 | CallingConv::GoAmd64 => &[32, 40],
        CallingConv::Cdecl32
        | CallingConv::Stdcall32
        | CallingConv::Thiscall32
        | CallingConv::Fastcall32 => &[16, 20],
        CallingConv::AArch64 => &[8, 16616], // SP, x29 in the native register space
        CallingConv::Arm32 => &[84, 76],     // SP, r11
    };
    resolve(ssa, ptr, size, frames, 0)
}

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
        *self.by_var.get(var.0 as usize).unwrap_or(&Region(u32::MAX))
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

    // v14: spill-map. Stack slots that received a Param value via
    // a Store get an entry mapping the slot's canon-key to the
    // stored VarId. classify_load_via_spill consults this so
    // `Load(stack_spill_addr)` inherits the SPILLED value's region
    // (typically Param(N)) instead of blindly taking the stack
    // frame's region.
    let spill_map = build_spill_map(ssa);

    // Seeds. Iteration N≤4 lets BinOp(Add, ptr, idx) inherit the
    // ptr's region after we discover ptr is a Param/Stack/Global.
    for _iter in 0..4 {
        let mut changed = false;
        for i in 0..ssa.vars.len() {
            let id = VarId(i as u32);
            let cur = map.by_var[i];
            let site_opt = classify(&ssa.vars[i], &map, &heap_returns, id, ssa, &spill_map);
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
            map.intern.insert(AllocSite::Unknown(i as u32), r);
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
    ssa: &SsaCfg,
    spill_map: &SpillMap,
) -> Option<AllocSite> {
    let _ = id;
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
        Expr::FieldAccess(base, off) => {
            // v14: FieldAccess(base, off) is folded Load(base+off).
            // Check spill_map for synthetic BAdd canon-key.
            let key = format!(
                "BAdd({},C{}.8)",
                addr_canon_local(*base, &ssa.vars).unwrap_or_else(|| "?".to_string()),
                off
            );
            if let Some(stored) = spill_map.by_canon.get(&key) {
                if let Some(site) = site_of_var(*stored, map) {
                    return Some(site);
                }
            }
            site_of_var(*base, map)
        }
        // v14: if Load addr matches a spill slot whose stored
        // value has a known region (typically Param), inherit
        // that region — this bridges the spill-reload of param
        // pointers (`mov [sp+N], param0` then `ldr xK, [sp+N]`)
        // so the reloaded varid keeps the Param identity.
        // Falls back to v4's "same region as addr" approximation
        // when the spill map has no matching entry.
        Expr::Load(addr) => {
            if let Some(stored) = spill_map.lookup(*addr, &ssa.vars) {
                if let Some(site) = site_of_var(stored, map) {
                    return Some(site);
                }
            }
            site_of_var(*addr, map)
        }
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

/// v14: per-function spill map. Walks every Stmt::Store and indexes
/// the address by a canonical-form string AND by raw varnode
/// identity. Canonical-form catches the common -O0 stack-frame
/// spill pattern (BAdd(sp,N) varying across SSA versions). Raw
/// varnode catches the v15 case where the addr's expr is a bare
/// register read (`Unknown` for a register varnode whose previous
/// Store's addr happens to share the same varnode identity).
struct SpillMap {
    by_canon: HashMap<String, VarId>,
    by_varnode: HashMap<pcode_ir::Varnode, VarId>,
}

fn build_spill_map(ssa: &SsaCfg) -> SpillMap {
    use crate::ir::Stmt;
    let mut by_canon: HashMap<String, VarId> = HashMap::new();
    let mut by_varnode: HashMap<pcode_ir::Varnode, VarId> = HashMap::new();
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            if let Stmt::Store { addr, val } = stmt {
                if let Some(key) = addr_canon_local(*addr, &ssa.vars) {
                    by_canon.insert(key, *val);
                }
                if let Some(addr_def) = ssa.vars.get(addr.0 as usize) {
                    by_varnode.insert(addr_def.varnode, *val);
                }
            }
        }
    }
    SpillMap {
        by_canon,
        by_varnode,
    }
}

impl SpillMap {
    fn lookup(&self, addr: VarId, vars: &[VarDef]) -> Option<VarId> {
        if let Some(key) = addr_canon_local(addr, vars) {
            if let Some(v) = self.by_canon.get(&key) {
                return Some(*v);
            }
        }
        if let Some(d) = vars.get(addr.0 as usize) {
            if let Some(v) = self.by_varnode.get(&d.varnode) {
                return Some(*v);
            }
        }
        None
    }
}

/// Recursive canonical-form key for an address expression. Mirrors
/// `function_summary::addr_canon` so the spill-map and the lineage
/// walker's mem-map produce compatible keys for the same logical
/// stack slot. Bounded depth.
fn addr_canon_local(var: VarId, vars: &[VarDef]) -> Option<String> {
    fn rec(var: VarId, vars: &[VarDef], depth: u32) -> Option<String> {
        if depth > 16 {
            return None;
        }
        let def = vars.get(var.0 as usize)?;
        Some(match &def.expr {
            Expr::Var(inner) => rec(*inner, vars, depth + 1)?,
            Expr::Const(c, sz) => format!("C{}.{}", c, sz),
            Expr::BinOp(op, a, b) => {
                let ka = rec(*a, vars, depth + 1).unwrap_or_else(|| "?".to_string());
                let kb = rec(*b, vars, depth + 1).unwrap_or_else(|| "?".to_string());
                format!("B{:?}({},{})", op, ka, kb)
            }
            Expr::UnaryOp(op, a) => {
                let ka = rec(*a, vars, depth + 1).unwrap_or_else(|| "?".to_string());
                format!("U{:?}({})", op, ka)
            }
            _ => format!(
                "V{:?}/{}/{}",
                def.varnode.space, def.varnode.offset, def.varnode.size
            ),
        })
    }
    rec(var, vars, 0)
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
            memory: None,
            origins: Default::default(),
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
