//! Conservative typed alias and memory-effect observations.
//!
//! This module is analysis-only.  It exposes the existing region inference as
//! a public query seam without changing SSA construction, folding, or rewrite
//! decisions.  A query returns `MayAlias` whenever the available evidence does
//! not prove either identity over the represented bytes or disjointness.

use crate::ir::{BinOpKind, Expr, SsaCfg, VarDef, VarId};
use crate::region::{AllocSite, OffsetClass, Region, RegionMap};

/// The three-point alias lattice.  `MayAlias` is the conservative top value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasClass {
    NoAlias,
    MayAlias,
    MustAlias,
}

/// Machine-checkable explanation for an alias result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasReason {
    SameAddressValue,
    SameSingletonBytes,
    DisjointSingletonRanges,
    DisjointStorageClasses,
    PartialOverlap,
    SymbolicOffset,
    UnknownRegion,
    PotentialParameterAlias,
    NonSingletonRegion,
    InvalidWidth,
    MissingAddress,
    InsufficientEvidence,
}

/// One memory range submitted to the alias query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    pub address: VarId,
    /// Signed byte displacement from `address` (for folded field accesses).
    pub displacement: i128,
    /// Number of represented bytes.  Zero is invalid and degrades to MayAlias.
    pub width: u64,
}

/// Evidence retained for either side of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEvidence {
    pub address: VarId,
    pub displacement: i128,
    pub width: u64,
    pub region: Region,
    pub site: Option<AllocSite>,
    /// Root SSA value after stripping copies and constant byte offsets.
    /// This prevents a coarse shared region from fabricating base identity.
    pub base: Option<VarId>,
    pub offset: OffsetClass,
}

/// Complete typed result.  Consumers can inspect provenance without rerunning
/// region inference or converting an unknown result into disjointness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasResult {
    pub class: AliasClass,
    pub reason: AliasReason,
    pub left: AddressEvidence,
    pub right: AddressEvidence,
}

/// Memory behavior category.  `Call` does not imply a proven summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryEffectKind {
    Read,
    Write,
    ReadWrite,
    Allocate,
    Free,
    Call,
    Fence,
    Unknown,
}

/// Ordering class carried independently from read/write behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOrdering {
    Ordinary,
    Volatile,
    Atomic,
    Mmio,
}

/// Provenance for an effect observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectSource {
    LiftedOperation,
    ProvenCallSummary,
    UnknownCall,
    AnalystAnnotation,
}

/// Typed effect observation.  An absent access means that the touched range is
/// not known; it never means that the effect touches no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryEffect {
    pub kind: MemoryEffectKind,
    pub ordering: MemoryOrdering,
    pub access: Option<MemoryAccess>,
    pub source: EffectSource,
}

impl MemoryEffect {
    /// Conservative representation for a call without a proven summary.
    pub fn unknown_call() -> Self {
        Self {
            kind: MemoryEffectKind::Call,
            ordering: MemoryOrdering::Ordinary,
            access: None,
            source: EffectSource::UnknownCall,
        }
    }

    /// Whether optimizers must retain relative memory ordering.
    pub fn preserves_order(self) -> bool {
        self.kind == MemoryEffectKind::Fence
            || matches!(
                self.ordering,
                MemoryOrdering::Volatile | MemoryOrdering::Atomic | MemoryOrdering::Mmio
            )
    }

    /// Whether the observation may read memory.  Unknown calls and unknown
    /// effects remain read/write conservative.
    pub fn may_read(self) -> bool {
        matches!(
            self.kind,
            MemoryEffectKind::Read
                | MemoryEffectKind::ReadWrite
                | MemoryEffectKind::Call
                | MemoryEffectKind::Unknown
        )
    }

    /// Whether the observation may write memory.  Unknown calls and unknown
    /// effects remain read/write conservative.
    pub fn may_write(self) -> bool {
        matches!(
            self.kind,
            MemoryEffectKind::Write
                | MemoryEffectKind::ReadWrite
                | MemoryEffectKind::Allocate
                | MemoryEffectKind::Free
                | MemoryEffectKind::Call
                | MemoryEffectKind::Unknown
        )
    }
}

/// Query two byte ranges using a caller-supplied region epoch.
pub fn query_alias(
    ssa: &SsaCfg,
    regions: &RegionMap,
    left: MemoryAccess,
    right: MemoryAccess,
) -> AliasResult {
    query_alias_vars(&ssa.vars, regions, left, right)
}

/// Query two byte ranges when the caller already owns the SSA definition
/// vector.  This is the migration seam for existing path-local consumers.
pub fn query_alias_vars(
    vars: &[VarDef],
    regions: &RegionMap,
    left: MemoryAccess,
    right: MemoryAccess,
) -> AliasResult {
    let left_evidence = evidence(vars, regions, left);
    let right_evidence = evidence(vars, regions, right);
    let (class, reason) = classify_alias(&left_evidence, &right_evidence);
    AliasResult {
        class,
        reason,
        left: left_evidence,
        right: right_evidence,
    }
}

fn evidence(vars: &[VarDef], regions: &RegionMap, access: MemoryAccess) -> AddressEvidence {
    let region = regions.region_of(access.address);
    AddressEvidence {
        address: access.address,
        displacement: access.displacement,
        width: access.width,
        region,
        site: regions.site_of(region).cloned(),
        base: expression_base(access.address, vars),
        offset: exact_offset(access.address, vars)
            .map(i128::from)
            .and_then(|offset| offset.checked_add(access.displacement))
            .and_then(|offset| i64::try_from(offset).ok())
            .map(OffsetClass::ConstOffset)
            .unwrap_or(OffsetClass::Symbolic),
    }
}

fn classify_alias(left: &AddressEvidence, right: &AddressEvidence) -> (AliasClass, AliasReason) {
    if left.width == 0 || right.width == 0 {
        return (AliasClass::MayAlias, AliasReason::InvalidWidth);
    }
    if left.site.is_none() || right.site.is_none() {
        return (AliasClass::MayAlias, AliasReason::MissingAddress);
    }
    if left.address == right.address
        && left.displacement == right.displacement
        && left.width == right.width
    {
        return (AliasClass::MustAlias, AliasReason::SameAddressValue);
    }

    let (left_offset, right_offset) = match (&left.offset, &right.offset) {
        (OffsetClass::ConstOffset(a), OffsetClass::ConstOffset(b)) => (*a, *b),
        _ => return (AliasClass::MayAlias, AliasReason::SymbolicOffset),
    };

    if is_unknown(left.site.as_ref()) || is_unknown(right.site.as_ref()) {
        return (AliasClass::MayAlias, AliasReason::UnknownRegion);
    }

    if left.region == right.region {
        let site = left.site.as_ref().expect("site checked");
        if requires_same_base(site) && (left.base.is_none() || left.base != right.base) {
            return (AliasClass::MayAlias, AliasReason::NonSingletonRegion);
        }
        if left_offset == right_offset && left.width == right.width {
            return (AliasClass::MustAlias, AliasReason::SameSingletonBytes);
        }
        return if ranges_disjoint(left_offset, left.width, right_offset, right.width) {
            (AliasClass::NoAlias, AliasReason::DisjointSingletonRanges)
        } else {
            (AliasClass::MayAlias, AliasReason::PartialOverlap)
        };
    }

    let left_site = left.site.as_ref().expect("site checked");
    let right_site = right.site.as_ref().expect("site checked");
    if matches!(left_site, AllocSite::Param(_)) || matches!(right_site, AllocSite::Param(_)) {
        return (AliasClass::MayAlias, AliasReason::PotentialParameterAlias);
    }

    if let (Some(left_absolute), Some(right_absolute)) = (
        absolute_range(left_site, left_offset, left.width),
        absolute_range(right_site, right_offset, right.width),
    ) {
        return if left_absolute == right_absolute {
            (AliasClass::MustAlias, AliasReason::SameSingletonBytes)
        } else if left_absolute.1 <= right_absolute.0 || right_absolute.1 <= left_absolute.0 {
            (AliasClass::NoAlias, AliasReason::DisjointSingletonRanges)
        } else {
            (AliasClass::MayAlias, AliasReason::PartialOverlap)
        };
    }

    if storage_classes_disjoint(left_site, right_site) {
        return (AliasClass::NoAlias, AliasReason::DisjointStorageClasses);
    }

    (AliasClass::MayAlias, AliasReason::InsufficientEvidence)
}

fn is_unknown(site: Option<&AllocSite>) -> bool {
    matches!(site, Some(AllocSite::Unknown(_)) | None)
}

fn requires_same_base(site: &AllocSite) -> bool {
    // StackFrame is intentionally coarse in the inherited RegionMap: any
    // otherwise-unknown register can receive that site. Heap identity is also
    // allocation-routine keyed rather than allocation-instance keyed.
    matches!(site, AllocSite::StackFrame | AllocSite::Heap(_))
}

fn storage_classes_disjoint(left: &AllocSite, right: &AllocSite) -> bool {
    // RegionMap currently uses StackFrame as the fallback for any otherwise
    // unknown register value, not only a proven SP/FP derivation.  It is
    // therefore unsafe to use StackFrame as a storage-class disjointness
    // proof here.  Global-vs-allocator-return remains the one admitted
    // cross-region class proof.
    use AllocSite::{Global, Heap};
    matches!((left, right), (Global(_), Heap(_)) | (Heap(_), Global(_)))
}

fn ranges_disjoint(left: i64, left_width: u64, right: i64, right_width: u64) -> bool {
    let left_start = i128::from(left);
    let right_start = i128::from(right);
    let left_end = left_start + i128::from(left_width);
    let right_end = right_start + i128::from(right_width);
    left_end <= right_start || right_end <= left_start
}

fn absolute_range(site: &AllocSite, offset: i64, width: u64) -> Option<(i128, i128)> {
    let base = match site {
        AllocSite::Global(base) | AllocSite::Const(base) => i128::from(*base),
        _ => return None,
    };
    let start = base + i128::from(offset);
    Some((start, start + i128::from(width)))
}

/// Recover a constant byte offset relative to the inferred region base.
fn exact_offset(start: VarId, vars: &[VarDef]) -> Option<i64> {
    fn constant_value(start: VarId, vars: &[VarDef], depth: usize) -> Option<i64> {
        if depth >= 32 {
            return None;
        }
        match &vars.get(start.0 as usize)?.expr {
            Expr::Const(value, _) => i64::try_from(*value).ok(),
            Expr::Var(inner) => constant_value(*inner, vars, depth + 1),
            _ => None,
        }
    }

    fn walk(start: VarId, vars: &[VarDef], depth: usize) -> Option<i64> {
        if depth >= 32 {
            return None;
        }
        match &vars.get(start.0 as usize)?.expr {
            // A constant pointer is the region base, not an offset from itself.
            Expr::Const(_, _) | Expr::Unknown => Some(0),
            Expr::Var(inner) => walk(*inner, vars, depth + 1),
            Expr::FieldAccess(base, offset) => {
                let offset = i64::try_from(*offset).ok()?;
                walk(*base, vars, depth + 1)?.checked_add(offset)
            }
            Expr::BinOp(BinOpKind::Add, left, right) => {
                if let Some(value) = constant_value(*left, vars, depth + 1) {
                    return walk(*right, vars, depth + 1)?.checked_add(value);
                }
                if let Some(value) = constant_value(*right, vars, depth + 1) {
                    return walk(*left, vars, depth + 1)?.checked_add(value);
                }
                None
            }
            Expr::BinOp(BinOpKind::Sub, left, right) => {
                let value = constant_value(*right, vars, depth + 1)?;
                walk(*left, vars, depth + 1)?.checked_sub(value)
            }
            _ => None,
        }
    }

    walk(start, vars, 0)
}

fn expression_base(start: VarId, vars: &[VarDef]) -> Option<VarId> {
    fn walk(start: VarId, vars: &[VarDef], depth: usize) -> Option<VarId> {
        if depth >= 32 {
            return None;
        }
        match &vars.get(start.0 as usize)?.expr {
            Expr::Var(inner) => walk(*inner, vars, depth + 1),
            Expr::FieldAccess(base, _) => walk(*base, vars, depth + 1),
            Expr::BinOp(BinOpKind::Add, left, right) => {
                let left_constant = matches!(vars.get(left.0 as usize)?.expr, Expr::Const(_, _));
                let right_constant = matches!(vars.get(right.0 as usize)?.expr, Expr::Const(_, _));
                match (left_constant, right_constant) {
                    (true, false) => walk(*right, vars, depth + 1),
                    (false, true) => walk(*left, vars, depth + 1),
                    _ => None,
                }
            }
            Expr::BinOp(BinOpKind::Sub, left, right)
                if matches!(vars.get(right.0 as usize)?.expr, Expr::Const(_, _)) =>
            {
                walk(*left, vars, depth + 1)
            }
            Expr::Const(_, _) | Expr::Unknown => Some(start),
            _ => None,
        }
    }

    walk(start, vars, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BlockId, InferredType, SsaBlock, SsaTerminator, VarDef};
    use crate::region::infer_regions;
    use pcode_ir::Varnode;

    fn var(id: u32, expr: Expr, varnode: Varnode, param_name: Option<&str>) -> VarDef {
        VarDef {
            id: VarId(id),
            varnode,
            expr,
            size: 8,
            use_count: 0,
            param_name: param_name.map(str::to_owned),
            call_return: false,
            inferred_type: InferredType::Pointer,
            display_type: None,
        }
    }

    fn fixture(vars: Vec<VarDef>) -> SsaCfg {
        SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: Vec::new(),
                terminator: SsaTerminator::Return(None),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn same_stack_bytes_must_alias_and_disjoint_slots_do_not() {
        let ssa = fixture(vec![
            var(0, Expr::Unknown, Varnode::register(0, 8), None),
            var(1, Expr::Const(8, 8), Varnode::constant(8, 8), None),
            var(2, Expr::Const(32, 8), Varnode::constant(32, 8), None),
            var(
                3,
                Expr::BinOp(BinOpKind::Add, VarId(0), VarId(1)),
                Varnode::unique(0x10, 8),
                None,
            ),
            var(
                4,
                Expr::BinOp(BinOpKind::Add, VarId(0), VarId(1)),
                Varnode::unique(0x20, 8),
                None,
            ),
            var(
                5,
                Expr::BinOp(BinOpKind::Add, VarId(0), VarId(2)),
                Varnode::unique(0x30, 8),
                None,
            ),
        ]);
        let regions = infer_regions(&ssa);
        let same = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(3),
                displacement: 0,
                width: 8,
            },
            MemoryAccess {
                address: VarId(4),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(same.class, AliasClass::MustAlias);
        assert_eq!(same.reason, AliasReason::SameSingletonBytes);

        let disjoint = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(3),
                displacement: 0,
                width: 8,
            },
            MemoryAccess {
                address: VarId(5),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(disjoint.class, AliasClass::NoAlias);
        assert_eq!(disjoint.reason, AliasReason::DisjointSingletonRanges);
    }

    #[test]
    fn overlaps_and_unknowns_remain_may_alias() {
        let ssa = fixture(vec![
            var(0, Expr::Unknown, Varnode::register(0, 8), None),
            var(1, Expr::Const(4, 8), Varnode::constant(4, 8), None),
            var(
                2,
                Expr::BinOp(BinOpKind::Add, VarId(0), VarId(1)),
                Varnode::unique(0x10, 8),
                None,
            ),
            var(3, Expr::Unknown, Varnode::unique(0x20, 8), None),
        ]);
        let regions = infer_regions(&ssa);
        let overlap = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 8,
            },
            MemoryAccess {
                address: VarId(2),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(overlap.class, AliasClass::MayAlias);
        assert_eq!(overlap.reason, AliasReason::PartialOverlap);

        let unknown = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(3),
                displacement: 0,
                width: 8,
            },
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(unknown.class, AliasClass::MayAlias);
        assert_eq!(unknown.reason, AliasReason::UnknownRegion);
    }

    #[test]
    fn coarse_stack_region_does_not_fabricate_base_identity() {
        let ssa = fixture(vec![
            var(0, Expr::Unknown, Varnode::register(0, 8), None),
            var(1, Expr::Unknown, Varnode::register(8, 8), None),
        ]);
        let regions = infer_regions(&ssa);
        assert_eq!(regions.region_of(VarId(0)), regions.region_of(VarId(1)));

        let result = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 8,
            },
            MemoryAccess {
                address: VarId(1),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(result.class, AliasClass::MayAlias);
        assert_eq!(result.reason, AliasReason::NonSingletonRegion);
    }

    #[test]
    fn coarse_stack_label_does_not_prove_disjoint_from_global() {
        let ssa = fixture(vec![
            var(0, Expr::Unknown, Varnode::register(0, 8), None),
            var(1, Expr::Const(0x4000, 8), Varnode::ram(0x4000, 8), None),
        ]);
        let regions = infer_regions(&ssa);
        let result = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 8,
            },
            MemoryAccess {
                address: VarId(1),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(result.class, AliasClass::MayAlias);
        assert_eq!(result.reason, AliasReason::InsufficientEvidence);
    }

    #[test]
    fn distinct_parameters_are_not_assumed_disjoint() {
        let ssa = fixture(vec![
            var(0, Expr::Unknown, Varnode::register(0, 8), Some("param_0")),
            var(1, Expr::Unknown, Varnode::register(8, 8), Some("param_1")),
        ]);
        let regions = infer_regions(&ssa);
        let result = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 8,
            },
            MemoryAccess {
                address: VarId(1),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(result.class, AliasClass::MayAlias);
        assert_eq!(result.reason, AliasReason::PotentialParameterAlias);
    }

    #[test]
    fn exact_globals_are_disjoint_and_width_zero_is_invalid() {
        let ssa = fixture(vec![
            var(0, Expr::Const(0x1000, 8), Varnode::ram(0x1000, 8), None),
            var(1, Expr::Const(0x2000, 8), Varnode::ram(0x2000, 8), None),
        ]);
        let regions = infer_regions(&ssa);
        let disjoint = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 16,
            },
            MemoryAccess {
                address: VarId(1),
                displacement: 0,
                width: 16,
            },
        );
        assert_eq!(disjoint.class, AliasClass::NoAlias);

        let invalid = query_alias(
            &ssa,
            &regions,
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 0,
            },
            MemoryAccess {
                address: VarId(0),
                displacement: 0,
                width: 8,
            },
        );
        assert_eq!(invalid.class, AliasClass::MayAlias);
        assert_eq!(invalid.reason, AliasReason::InvalidWidth);
    }

    #[test]
    fn effect_types_preserve_unknown_call_and_ordering() {
        let call = MemoryEffect::unknown_call();
        assert!(call.may_read());
        assert!(call.may_write());
        assert!(!call.preserves_order());

        let mmio_write = MemoryEffect {
            kind: MemoryEffectKind::Write,
            ordering: MemoryOrdering::Mmio,
            access: Some(MemoryAccess {
                address: VarId(7),
                displacement: 0,
                width: 4,
            }),
            source: EffectSource::AnalystAnnotation,
        };
        assert!(!mmio_write.may_read());
        assert!(mmio_write.may_write());
        assert!(mmio_write.preserves_order());

        let fence = MemoryEffect {
            kind: MemoryEffectKind::Fence,
            ordering: MemoryOrdering::Atomic,
            access: None,
            source: EffectSource::LiftedOperation,
        };
        assert!(fence.preserves_order());
    }
}
