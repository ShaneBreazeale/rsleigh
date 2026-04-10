//! P-code intermediate representation types.
//!
//! Zero-dependency crate defining [`PcodeOp`] and [`Varnode`] — the types
//! emitted by SLEIGH-generated instruction decoders.

#![no_std]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Identifies an address space in the P-code model.
///
/// `Ord` is derived for use as `BTreeMap` keys in the peephole optimizer (no_std
/// precludes `HashMap`). The derived ordering is arbitrary and should not be relied
/// upon for semantic comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressSpaceId {
    /// CPU registers (offset = Ghidra register offset).
    Register,
    /// Main memory / RAM.
    Ram,
    /// Temporary storage (unique per instruction lift).
    Unique,
    /// Constants (offset = the constant value itself).
    Const,
}

/// A triple (space, offset, size) identifying a storage location or constant.
///
/// `Ord` is derived for use as `BTreeMap` keys in the peephole optimizer.
/// The derived lexicographic ordering is not semantically meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Varnode {
    pub space: AddressSpaceId,
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl Varnode {
    /// A CPU register at the given Ghidra offset.
    #[inline]
    pub fn register(offset: u64, size: u32) -> Self {
        Self {
            space: AddressSpaceId::Register,
            offset,
            size,
        }
    }

    /// A unique (temporary) varnode.
    #[inline]
    pub fn unique(offset: u64, size: u32) -> Self {
        Self {
            space: AddressSpaceId::Unique,
            offset,
            size,
        }
    }

    /// A RAM location.
    #[inline]
    pub fn ram(offset: u64, size: u32) -> Self {
        Self {
            space: AddressSpaceId::Ram,
            offset,
            size,
        }
    }

    /// A constant value encoded as a varnode.
    #[inline]
    pub fn constant(value: u64, size: u32) -> Self {
        Self {
            space: AddressSpaceId::Const,
            offset: value,
            size,
        }
    }
}

/// A decoded and lifted instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Number of bytes consumed by this instruction.
    pub len: u64,
    /// Human-readable disassembly (e.g. "MOV RAX,RBX").
    pub disassembly: String,
    /// P-code operations (peephole-optimized).
    pub ops: Vec<PcodeOp>,
}

/// Decode error returned when an instruction cannot be parsed.
#[derive(Debug, Clone)]
pub enum DecodeError {
    /// The byte sequence does not match any known instruction encoding.
    UnknownInstruction,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::UnknownInstruction => write!(f, "unknown instruction encoding"),
        }
    }
}

/// Offset all Unique-space varnode offsets in an op by the given amount.
/// Used to avoid unique offset collisions when combining P-code from multiple subtables.
pub fn offset_unique_varnodes(op: &mut PcodeOp, offset: u64) {
    // Offset outputs
    if let Some(out) = get_output_mut(op) {
        if out.space == AddressSpaceId::Unique {
            out.offset += offset;
        }
    }
    // Offset inputs
    visit_reads_mut(op, &mut |v| {
        if v.space == AddressSpaceId::Unique {
            v.offset += offset;
        }
    });
}

/// Peephole-optimize a P-code op sequence:
/// - Remove identity `Subpiece { lsb: 0 }` where input.size == out.size
/// - Forward-substitute `Copy` chains (A=B, C=A → C=B) when the
///   intermediate is a unique varnode used only once after its definition
pub fn optimize(ops: &mut Vec<PcodeOp>) {
    // Run passes until fixpoint (later passes create opportunities for earlier ones)
    for _round in 0..4 {
        let before = ops.len();
        optimize_once(ops);
        if ops.len() == before {
            break;
        }
    }
}

fn optimize_once(ops: &mut Vec<PcodeOp>) {
    // Pass 0: constant folding — IntZext/IntSext of constants
    for op in ops.iter_mut() {
        match op {
            PcodeOp::IntZext { out, input } if input.space == AddressSpaceId::Const => {
                *op = PcodeOp::Copy {
                    out: *out,
                    input: Varnode::constant(input.offset, out.size),
                };
            }
            PcodeOp::IntSext { out, input } if input.space == AddressSpaceId::Const => {
                // Sign-extend: if the high bit of input is set, fill upper bits
                let val = input.offset;
                let in_bits = (input.size as u64) * 8;
                let extended = if in_bits < 64 && (val >> (in_bits - 1)) & 1 != 0 {
                    val | (!0u64 << in_bits)
                } else {
                    val
                };
                *op = PcodeOp::Copy {
                    out: *out,
                    input: Varnode::constant(extended, out.size),
                };
            }
            // Shift by zero → Copy
            PcodeOp::IntLsr { out, left, right }
            | PcodeOp::IntLsl { out, left, right }
            | PcodeOp::IntAsr { out, left, right }
                if right.space == AddressSpaceId::Const && right.offset == 0 =>
            {
                *op = PcodeOp::Copy {
                    out: *out,
                    input: *left,
                };
            }
            // OR with zero → Copy
            PcodeOp::IntOr { out, left, right }
                if right.space == AddressSpaceId::Const && right.offset == 0 =>
            {
                *op = PcodeOp::Copy {
                    out: *out,
                    input: *left,
                };
            }
            PcodeOp::IntOr { out, left, right }
                if left.space == AddressSpaceId::Const && left.offset == 0 =>
            {
                *op = PcodeOp::Copy {
                    out: *out,
                    input: *right,
                };
            }
            // AND with all-ones (for the size) → Copy
            PcodeOp::IntAnd { out, left, right }
                if right.space == AddressSpaceId::Const
                    && right.offset == u64::MAX >> (64 - out.size as u64 * 8) =>
            {
                *op = PcodeOp::Copy {
                    out: *out,
                    input: *left,
                };
            }
            _ => {}
        }
    }

    // Pass 1: eliminate identity Subpiece
    for op in ops.iter_mut() {
        if let PcodeOp::Subpiece { out, input, lsb: 0 } = op {
            if out.size == input.size {
                *op = PcodeOp::Copy {
                    out: *out,
                    input: *input,
                };
            }
        }
    }

    // Compute unique-varnode analysis once. Passes below share and recompute only
    // after structural mutations (removals). Indices in NextAccess::Read are
    // invalidated by any removal, so we must recompute after each ops.remove().
    let mut analysis = analyze_unique_outputs(ops);

    // Pass 1a: redundant IntAnd — if IntAnd{out1, x, mask} followed by IntAnd{out2, out1, mask}
    // with same mask and out1 used only once, remove the second
    let mut i = 0;
    while i + 1 < ops.len() {
        let collapse = if let PcodeOp::IntAnd {
            out: out1,
            left: _,
            right: mask1,
        } = &ops[i]
        {
            if out1.space == AddressSpaceId::Unique && mask1.space == AddressSpaceId::Const {
                if let PcodeOp::IntAnd {
                    out: out2,
                    left: in2,
                    right: mask2,
                } = &ops[i + 1]
                {
                    if *in2 == *out1 && *mask2 == *mask1 {
                        // out1 is Unique (checked above), so analysis[i] is always Some.
                        // Use pattern match to be explicit rather than unwrap_or which
                        // would silently treat non-Unique outputs as zero reads.
                        let total_reads = match analysis.get(i) {
                            Some(Some(info)) => info.future_reads,
                            _ => usize::MAX, // conservative: don't collapse if unknown
                        };
                        if total_reads == 1 {
                            Some(*out2)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(new_out) = collapse {
            if let PcodeOp::IntAnd { out, .. } = &mut ops[i] {
                *out = new_out;
            }
            ops.remove(i + 1);
            analysis = analyze_unique_outputs(ops);
            continue;
        }
        i += 1;
    }

    // Pass 2: forward-substitute single-use Copy chains.
    // If ops[i] is Copy { out: A, input: B } and A is Unique,
    // and exactly one later op reads A, replace that read with B.
    // Analysis is still valid from pass 1a (no in-place mutations between).
    let mut i = 0;
    while i < ops.len() {
        if let PcodeOp::Copy { out, input } = &ops[i] {
            if out.space == AddressSpaceId::Unique {
                let target = *out;
                let replacement = *input;
                let entry = analysis.get(i).and_then(|entry| entry.as_ref());
                if let Some(UniqueOutputInfo {
                    future_reads: 1,
                    next_access: Some(NextAccess::Read(read_idx)),
                }) = entry
                {
                    replace_reads(&mut ops[*read_idx], &target, &replacement);
                    ops.remove(i);
                    analysis = analyze_unique_outputs(ops);
                    continue;
                }
            }
        }
        i += 1;
    }

    // Pass 2b + 3: overwrite elimination and dead code elimination.
    // Remove ops that write to Unique varnodes that are either overwritten before
    // any read (2b) or never read at all (3). These removals are independent —
    // removing a dead/overwritten op cannot make another op live — so we collect
    // all indices in one scan and batch-remove in reverse order.
    // Analysis is still valid from pass 2 (no in-place mutations between).
    {
        let mut to_remove = Vec::new();
        for (i, entry) in analysis.iter().enumerate() {
            if let Some(info) = entry {
                if info.future_reads == 0
                    || matches!(info.next_access, Some(NextAccess::Write))
                {
                    to_remove.push(i);
                }
            }
        }
        for &idx in to_remove.iter().rev() {
            ops.remove(idx);
        }
    }

    // Pass 4: sink unique outputs into subsequent Copy destinations.
    // If ops[i] writes to Unique(X) and some later ops[j] is Copy { out: dest, input: Unique(X) },
    // and Unique(X) is read exactly once (by that Copy), and dest is not written or read between
    // i and j, rewrite ops[i] to output directly to dest and remove the Copy.
    // Must recompute — batch removal above invalidated indices.
    analysis = analyze_unique_outputs(ops);
    let mut i = 0;
    while i < ops.len() {
        let should_sink = match (
            get_output(&ops[i]),
            analysis.get(i).and_then(|entry| entry.as_ref()),
        ) {
            (
                Some(out),
                Some(UniqueOutputInfo {
                    future_reads: 1,
                    next_access: Some(NextAccess::Read(copy_idx)),
                }),
            ) if out.space == AddressSpaceId::Unique => {
                if let PcodeOp::Copy {
                    out: copy_dest,
                    input: copy_src,
                } = &ops[*copy_idx]
                {
                    if *copy_src == out {
                        let d = *copy_dest;
                        let safe = (i + 1..*copy_idx)
                            .all(|k| count_reads(&ops[k], &d) == 0 && !writes_to(&ops[k], &d));
                        if safe {
                            Some((*copy_idx, d))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some((copy_idx, new_dest)) = should_sink {
            if let Some(out) = get_output_mut(&mut ops[i]) {
                *out = new_dest;
            }
            ops.remove(copy_idx);
            analysis = analyze_unique_outputs(ops);
            continue;
        }
        i += 1;
    }
}

#[derive(Clone, Copy)]
struct UniqueOutputInfo {
    future_reads: usize,
    next_access: Option<NextAccess>,
}

#[derive(Clone, Copy)]
enum NextAccess {
    Read(usize),
    Write,
}

fn analyze_unique_outputs(ops: &[PcodeOp]) -> Vec<Option<UniqueOutputInfo>> {
    let mut future_reads = BTreeMap::<Varnode, usize>::new();
    let mut next_access = BTreeMap::<Varnode, NextAccess>::new();
    let mut result = vec![None; ops.len()];

    for (idx, op) in ops.iter().enumerate().rev() {
        if let Some(out) = get_output(op).filter(|out| out.space == AddressSpaceId::Unique) {
            result[idx] = Some(UniqueOutputInfo {
                future_reads: future_reads.get(&out).copied().unwrap_or(0),
                next_access: next_access.get(&out).copied(),
            });
            future_reads.remove(&out);
            next_access.insert(out, NextAccess::Write);
        }

        visit_reads(op, &mut |v| {
            if v.space == AddressSpaceId::Unique {
                *future_reads.entry(*v).or_insert(0) += 1;
                next_access.insert(*v, NextAccess::Read(idx));
            }
        });
    }

    result
}

pub fn get_output(op: &PcodeOp) -> Option<Varnode> {
    match op {
        PcodeOp::Copy { out, .. }
        | PcodeOp::Load { out, .. }
        | PcodeOp::Subpiece { out, .. }
        | PcodeOp::IntNeg { out, .. }
        | PcodeOp::IntNot { out, .. }
        | PcodeOp::IntZext { out, .. }
        | PcodeOp::IntSext { out, .. }
        | PcodeOp::BoolNot { out, .. }
        | PcodeOp::FloatNeg { out, .. }
        | PcodeOp::FloatAbs { out, .. }
        | PcodeOp::FloatSqrt { out, .. }
        | PcodeOp::FloatNan { out, .. }
        | PcodeOp::Int2Float { out, .. }
        | PcodeOp::Float2Float { out, .. }
        | PcodeOp::Trunc { out, .. }
        | PcodeOp::FloatCeil { out, .. }
        | PcodeOp::FloatFloor { out, .. }
        | PcodeOp::FloatRound { out, .. }
        | PcodeOp::Popcount { out, .. }
        | PcodeOp::Lzcount { out, .. }
        | PcodeOp::IntAdd { out, .. }
        | PcodeOp::IntSub { out, .. }
        | PcodeOp::IntMult { out, .. }
        | PcodeOp::IntDiv { out, .. }
        | PcodeOp::IntSDiv { out, .. }
        | PcodeOp::IntRem { out, .. }
        | PcodeOp::IntSRem { out, .. }
        | PcodeOp::IntEq { out, .. }
        | PcodeOp::IntNotEq { out, .. }
        | PcodeOp::IntLess { out, .. }
        | PcodeOp::IntLessEq { out, .. }
        | PcodeOp::IntSLess { out, .. }
        | PcodeOp::IntSLessEq { out, .. }
        | PcodeOp::IntAnd { out, .. }
        | PcodeOp::IntOr { out, .. }
        | PcodeOp::IntXor { out, .. }
        | PcodeOp::IntLsl { out, .. }
        | PcodeOp::IntLsr { out, .. }
        | PcodeOp::IntAsr { out, .. }
        | PcodeOp::IntCarry { out, .. }
        | PcodeOp::IntSCarry { out, .. }
        | PcodeOp::IntSBorrow { out, .. }
        | PcodeOp::BoolAnd { out, .. }
        | PcodeOp::BoolOr { out, .. }
        | PcodeOp::BoolXor { out, .. }
        | PcodeOp::FloatAdd { out, .. }
        | PcodeOp::FloatSub { out, .. }
        | PcodeOp::FloatMult { out, .. }
        | PcodeOp::FloatDiv { out, .. }
        | PcodeOp::FloatEq { out, .. }
        | PcodeOp::FloatNotEq { out, .. }
        | PcodeOp::FloatLess { out, .. }
        | PcodeOp::FloatLessEq { out, .. } => Some(*out),
        _ => None,
    }
}

fn get_output_mut(op: &mut PcodeOp) -> Option<&mut Varnode> {
    match op {
        PcodeOp::Copy { out, .. }
        | PcodeOp::Load { out, .. }
        | PcodeOp::Subpiece { out, .. }
        | PcodeOp::IntNeg { out, .. }
        | PcodeOp::IntNot { out, .. }
        | PcodeOp::IntZext { out, .. }
        | PcodeOp::IntSext { out, .. }
        | PcodeOp::BoolNot { out, .. }
        | PcodeOp::FloatNeg { out, .. }
        | PcodeOp::FloatAbs { out, .. }
        | PcodeOp::FloatSqrt { out, .. }
        | PcodeOp::FloatNan { out, .. }
        | PcodeOp::Int2Float { out, .. }
        | PcodeOp::Float2Float { out, .. }
        | PcodeOp::Trunc { out, .. }
        | PcodeOp::FloatCeil { out, .. }
        | PcodeOp::FloatFloor { out, .. }
        | PcodeOp::FloatRound { out, .. }
        | PcodeOp::Popcount { out, .. }
        | PcodeOp::Lzcount { out, .. }
        | PcodeOp::IntAdd { out, .. }
        | PcodeOp::IntSub { out, .. }
        | PcodeOp::IntMult { out, .. }
        | PcodeOp::IntDiv { out, .. }
        | PcodeOp::IntSDiv { out, .. }
        | PcodeOp::IntRem { out, .. }
        | PcodeOp::IntSRem { out, .. }
        | PcodeOp::IntEq { out, .. }
        | PcodeOp::IntNotEq { out, .. }
        | PcodeOp::IntLess { out, .. }
        | PcodeOp::IntLessEq { out, .. }
        | PcodeOp::IntSLess { out, .. }
        | PcodeOp::IntSLessEq { out, .. }
        | PcodeOp::IntAnd { out, .. }
        | PcodeOp::IntOr { out, .. }
        | PcodeOp::IntXor { out, .. }
        | PcodeOp::IntLsl { out, .. }
        | PcodeOp::IntLsr { out, .. }
        | PcodeOp::IntAsr { out, .. }
        | PcodeOp::IntCarry { out, .. }
        | PcodeOp::IntSCarry { out, .. }
        | PcodeOp::IntSBorrow { out, .. }
        | PcodeOp::BoolAnd { out, .. }
        | PcodeOp::BoolOr { out, .. }
        | PcodeOp::BoolXor { out, .. }
        | PcodeOp::FloatAdd { out, .. }
        | PcodeOp::FloatSub { out, .. }
        | PcodeOp::FloatMult { out, .. }
        | PcodeOp::FloatDiv { out, .. }
        | PcodeOp::FloatEq { out, .. }
        | PcodeOp::FloatNotEq { out, .. }
        | PcodeOp::FloatLess { out, .. }
        | PcodeOp::FloatLessEq { out, .. } => Some(out),
        _ => None,
    }
}

pub fn writes_to(op: &PcodeOp, target: &Varnode) -> bool {
    match op {
        PcodeOp::Copy { out, .. }
        | PcodeOp::Load { out, .. }
        | PcodeOp::Subpiece { out, .. }
        | PcodeOp::IntNeg { out, .. }
        | PcodeOp::IntNot { out, .. }
        | PcodeOp::IntZext { out, .. }
        | PcodeOp::IntSext { out, .. }
        | PcodeOp::BoolNot { out, .. }
        | PcodeOp::FloatNeg { out, .. }
        | PcodeOp::FloatAbs { out, .. }
        | PcodeOp::FloatSqrt { out, .. }
        | PcodeOp::FloatNan { out, .. }
        | PcodeOp::Int2Float { out, .. }
        | PcodeOp::Float2Float { out, .. }
        | PcodeOp::Trunc { out, .. }
        | PcodeOp::FloatCeil { out, .. }
        | PcodeOp::FloatFloor { out, .. }
        | PcodeOp::FloatRound { out, .. }
        | PcodeOp::Popcount { out, .. }
        | PcodeOp::Lzcount { out, .. }
        | PcodeOp::IntAdd { out, .. }
        | PcodeOp::IntSub { out, .. }
        | PcodeOp::IntMult { out, .. }
        | PcodeOp::IntDiv { out, .. }
        | PcodeOp::IntSDiv { out, .. }
        | PcodeOp::IntRem { out, .. }
        | PcodeOp::IntSRem { out, .. }
        | PcodeOp::IntEq { out, .. }
        | PcodeOp::IntNotEq { out, .. }
        | PcodeOp::IntLess { out, .. }
        | PcodeOp::IntLessEq { out, .. }
        | PcodeOp::IntSLess { out, .. }
        | PcodeOp::IntSLessEq { out, .. }
        | PcodeOp::IntAnd { out, .. }
        | PcodeOp::IntOr { out, .. }
        | PcodeOp::IntXor { out, .. }
        | PcodeOp::IntLsl { out, .. }
        | PcodeOp::IntLsr { out, .. }
        | PcodeOp::IntAsr { out, .. }
        | PcodeOp::IntCarry { out, .. }
        | PcodeOp::IntSCarry { out, .. }
        | PcodeOp::IntSBorrow { out, .. }
        | PcodeOp::BoolAnd { out, .. }
        | PcodeOp::BoolOr { out, .. }
        | PcodeOp::BoolXor { out, .. }
        | PcodeOp::FloatAdd { out, .. }
        | PcodeOp::FloatSub { out, .. }
        | PcodeOp::FloatMult { out, .. }
        | PcodeOp::FloatDiv { out, .. }
        | PcodeOp::FloatEq { out, .. }
        | PcodeOp::FloatNotEq { out, .. }
        | PcodeOp::FloatLess { out, .. }
        | PcodeOp::FloatLessEq { out, .. } => out == target,
        PcodeOp::CallOther { out: Some(out), .. } => out == target,
        _ => false,
    }
}

pub fn count_reads(op: &PcodeOp, target: &Varnode) -> usize {
    let mut n = 0;
    visit_reads(op, &mut |v| {
        if v == target {
            n += 1
        }
    });
    n
}

fn replace_reads(op: &mut PcodeOp, target: &Varnode, replacement: &Varnode) -> bool {
    let mut found = false;
    visit_reads_mut(op, &mut |v| {
        if v == target {
            *v = *replacement;
            found = true;
        }
    });
    found
}

pub fn visit_reads(op: &PcodeOp, f: &mut impl FnMut(&Varnode)) {
    match op {
        PcodeOp::Copy { input, .. } => f(input),
        PcodeOp::Load { ptr, .. } => f(ptr),
        PcodeOp::Store { ptr, val, .. } => {
            f(ptr);
            f(val);
        }
        PcodeOp::Branch { dest }
        | PcodeOp::BranchInd { dest }
        | PcodeOp::Call { dest }
        | PcodeOp::CallInd { dest }
        | PcodeOp::Return { dest } => f(dest),
        PcodeOp::CBranch { dest, cond } => {
            f(dest);
            f(cond);
        }
        PcodeOp::Subpiece { input, .. } => f(input),
        PcodeOp::IntNeg { input, .. }
        | PcodeOp::IntNot { input, .. }
        | PcodeOp::IntZext { input, .. }
        | PcodeOp::IntSext { input, .. }
        | PcodeOp::BoolNot { input, .. }
        | PcodeOp::FloatNeg { input, .. }
        | PcodeOp::FloatAbs { input, .. }
        | PcodeOp::FloatSqrt { input, .. }
        | PcodeOp::FloatNan { input, .. }
        | PcodeOp::Int2Float { input, .. }
        | PcodeOp::Float2Float { input, .. }
        | PcodeOp::Trunc { input, .. }
        | PcodeOp::FloatCeil { input, .. }
        | PcodeOp::FloatFloor { input, .. }
        | PcodeOp::FloatRound { input, .. }
        | PcodeOp::Popcount { input, .. }
        | PcodeOp::Lzcount { input, .. } => f(input),
        PcodeOp::IntAdd { left, right, .. }
        | PcodeOp::IntSub { left, right, .. }
        | PcodeOp::IntMult { left, right, .. }
        | PcodeOp::IntDiv { left, right, .. }
        | PcodeOp::IntSDiv { left, right, .. }
        | PcodeOp::IntRem { left, right, .. }
        | PcodeOp::IntSRem { left, right, .. }
        | PcodeOp::IntEq { left, right, .. }
        | PcodeOp::IntNotEq { left, right, .. }
        | PcodeOp::IntLess { left, right, .. }
        | PcodeOp::IntLessEq { left, right, .. }
        | PcodeOp::IntSLess { left, right, .. }
        | PcodeOp::IntSLessEq { left, right, .. }
        | PcodeOp::IntAnd { left, right, .. }
        | PcodeOp::IntOr { left, right, .. }
        | PcodeOp::IntXor { left, right, .. }
        | PcodeOp::IntLsl { left, right, .. }
        | PcodeOp::IntLsr { left, right, .. }
        | PcodeOp::IntAsr { left, right, .. }
        | PcodeOp::IntCarry { left, right, .. }
        | PcodeOp::IntSCarry { left, right, .. }
        | PcodeOp::IntSBorrow { left, right, .. }
        | PcodeOp::BoolAnd { left, right, .. }
        | PcodeOp::BoolOr { left, right, .. }
        | PcodeOp::BoolXor { left, right, .. }
        | PcodeOp::FloatAdd { left, right, .. }
        | PcodeOp::FloatSub { left, right, .. }
        | PcodeOp::FloatMult { left, right, .. }
        | PcodeOp::FloatDiv { left, right, .. }
        | PcodeOp::FloatEq { left, right, .. }
        | PcodeOp::FloatNotEq { left, right, .. }
        | PcodeOp::FloatLess { left, right, .. }
        | PcodeOp::FloatLessEq { left, right, .. } => {
            f(left);
            f(right);
        }
        PcodeOp::CallOther { inputs, .. } => {
            for v in inputs {
                f(v);
            }
        }
    }
}

fn visit_reads_mut(op: &mut PcodeOp, f: &mut impl FnMut(&mut Varnode)) {
    match op {
        PcodeOp::Copy { input, .. } => f(input),
        PcodeOp::Load { ptr, .. } => f(ptr),
        PcodeOp::Store { ptr, val, .. } => {
            f(ptr);
            f(val);
        }
        PcodeOp::Branch { dest }
        | PcodeOp::BranchInd { dest }
        | PcodeOp::Call { dest }
        | PcodeOp::CallInd { dest }
        | PcodeOp::Return { dest } => f(dest),
        PcodeOp::CBranch { dest, cond } => {
            f(dest);
            f(cond);
        }
        PcodeOp::Subpiece { input, .. } => f(input),
        PcodeOp::IntNeg { input, .. }
        | PcodeOp::IntNot { input, .. }
        | PcodeOp::IntZext { input, .. }
        | PcodeOp::IntSext { input, .. }
        | PcodeOp::BoolNot { input, .. }
        | PcodeOp::FloatNeg { input, .. }
        | PcodeOp::FloatAbs { input, .. }
        | PcodeOp::FloatSqrt { input, .. }
        | PcodeOp::FloatNan { input, .. }
        | PcodeOp::Int2Float { input, .. }
        | PcodeOp::Float2Float { input, .. }
        | PcodeOp::Trunc { input, .. }
        | PcodeOp::FloatCeil { input, .. }
        | PcodeOp::FloatFloor { input, .. }
        | PcodeOp::FloatRound { input, .. }
        | PcodeOp::Popcount { input, .. }
        | PcodeOp::Lzcount { input, .. } => f(input),
        PcodeOp::IntAdd { left, right, .. }
        | PcodeOp::IntSub { left, right, .. }
        | PcodeOp::IntMult { left, right, .. }
        | PcodeOp::IntDiv { left, right, .. }
        | PcodeOp::IntSDiv { left, right, .. }
        | PcodeOp::IntRem { left, right, .. }
        | PcodeOp::IntSRem { left, right, .. }
        | PcodeOp::IntEq { left, right, .. }
        | PcodeOp::IntNotEq { left, right, .. }
        | PcodeOp::IntLess { left, right, .. }
        | PcodeOp::IntLessEq { left, right, .. }
        | PcodeOp::IntSLess { left, right, .. }
        | PcodeOp::IntSLessEq { left, right, .. }
        | PcodeOp::IntAnd { left, right, .. }
        | PcodeOp::IntOr { left, right, .. }
        | PcodeOp::IntXor { left, right, .. }
        | PcodeOp::IntLsl { left, right, .. }
        | PcodeOp::IntLsr { left, right, .. }
        | PcodeOp::IntAsr { left, right, .. }
        | PcodeOp::IntCarry { left, right, .. }
        | PcodeOp::IntSCarry { left, right, .. }
        | PcodeOp::IntSBorrow { left, right, .. }
        | PcodeOp::BoolAnd { left, right, .. }
        | PcodeOp::BoolOr { left, right, .. }
        | PcodeOp::BoolXor { left, right, .. }
        | PcodeOp::FloatAdd { left, right, .. }
        | PcodeOp::FloatSub { left, right, .. }
        | PcodeOp::FloatMult { left, right, .. }
        | PcodeOp::FloatDiv { left, right, .. }
        | PcodeOp::FloatEq { left, right, .. }
        | PcodeOp::FloatNotEq { left, right, .. }
        | PcodeOp::FloatLess { left, right, .. }
        | PcodeOp::FloatLessEq { left, right, .. } => {
            f(left);
            f(right);
        }
        PcodeOp::CallOther { inputs, .. } => {
            for v in inputs {
                f(v);
            }
        }
    }
}

/// A single P-code operation.
///
/// Variant naming follows Ghidra's P-code reference.
/// See: <https://ghidra.re/courses/languages/html/pcoderef.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcodeOp {
    // ── Data Movement ──────────────────────────────────────────────
    Copy {
        out: Varnode,
        input: Varnode,
    },
    Load {
        out: Varnode,
        space: AddressSpaceId,
        ptr: Varnode,
    },
    Store {
        space: AddressSpaceId,
        ptr: Varnode,
        val: Varnode,
    },

    // ── Branching ──────────────────────────────────────────────────
    Branch {
        dest: Varnode,
    },
    CBranch {
        dest: Varnode,
        cond: Varnode,
    },
    BranchInd {
        dest: Varnode,
    },
    Call {
        dest: Varnode,
    },
    CallInd {
        dest: Varnode,
    },
    Return {
        dest: Varnode,
    },

    // ── Integer Arithmetic ─────────────────────────────────────────
    IntAdd {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSub {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntMult {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntDiv {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSDiv {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntRem {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSRem {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntNeg {
        out: Varnode,
        input: Varnode,
    },

    // ── Integer Comparison ─────────────────────────────────────────
    IntEq {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntNotEq {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntLess {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntLessEq {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSLess {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSLessEq {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },

    // ── Integer Logical / Bitwise ──────────────────────────────────
    IntAnd {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntOr {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntXor {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntNot {
        out: Varnode,
        input: Varnode,
    },

    // ── Shift ──────────────────────────────────────────────────────
    IntLsl {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntLsr {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntAsr {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },

    // ── Extension / Truncation ─────────────────────────────────────
    IntZext {
        out: Varnode,
        input: Varnode,
    },
    IntSext {
        out: Varnode,
        input: Varnode,
    },
    Subpiece {
        out: Varnode,
        input: Varnode,
        lsb: u32,
    },

    // ── Carry / Borrow ─────────────────────────────────────────────
    IntCarry {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSCarry {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSBorrow {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },

    // ── Boolean ────────────────────────────────────────────────────
    BoolAnd {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    BoolOr {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    BoolXor {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    BoolNot {
        out: Varnode,
        input: Varnode,
    },

    // ── Floating Point Arithmetic ──────────────────────────────────
    FloatAdd {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatSub {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatMult {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatDiv {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatNeg {
        out: Varnode,
        input: Varnode,
    },
    FloatAbs {
        out: Varnode,
        input: Varnode,
    },
    FloatSqrt {
        out: Varnode,
        input: Varnode,
    },

    // ── Floating Point Comparison ──────────────────────────────────
    FloatEq {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatNotEq {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatLess {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatLessEq {
        out: Varnode,
        left: Varnode,
        right: Varnode,
    },
    FloatNan {
        out: Varnode,
        input: Varnode,
    },

    // ── Floating Point Conversion ──────────────────────────────────
    Int2Float {
        out: Varnode,
        input: Varnode,
    },
    Float2Float {
        out: Varnode,
        input: Varnode,
    },
    Trunc {
        out: Varnode,
        input: Varnode,
    },
    FloatCeil {
        out: Varnode,
        input: Varnode,
    },
    FloatFloor {
        out: Varnode,
        input: Varnode,
    },
    FloatRound {
        out: Varnode,
        input: Varnode,
    },

    // ── Bit Manipulation ───────────────────────────────────────────
    Popcount {
        out: Varnode,
        input: Varnode,
    },
    Lzcount {
        out: Varnode,
        input: Varnode,
    },

    // ── Miscellaneous ──────────────────────────────────────────────
    /// User-defined or architecture-specific operation.
    CallOther {
        out: Option<Varnode>,
        func_id: u64,
        inputs: Vec<Varnode>,
    },
}
