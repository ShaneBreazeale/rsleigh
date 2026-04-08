//! P-code intermediate representation types.
//!
//! Zero-dependency crate defining [`PcodeOp`] and [`Varnode`] — the types
//! emitted by SLEIGH-generated instruction decoders.

#![no_std]

extern crate alloc;
use alloc::vec::Vec;

/// Identifies an address space in the P-code model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        Self { space: AddressSpaceId::Register, offset, size }
    }

    /// A unique (temporary) varnode.
    #[inline]
    pub fn unique(offset: u64, size: u32) -> Self {
        Self { space: AddressSpaceId::Unique, offset, size }
    }

    /// A RAM location.
    #[inline]
    pub fn ram(offset: u64, size: u32) -> Self {
        Self { space: AddressSpaceId::Ram, offset, size }
    }

    /// A constant value encoded as a varnode.
    #[inline]
    pub fn constant(value: u64, size: u32) -> Self {
        Self { space: AddressSpaceId::Const, offset: value, size }
    }
}

/// A single P-code operation.
///
/// Variant naming follows Ghidra's P-code reference.
/// See: <https://ghidra.re/courses/languages/html/pcoderef.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcodeOp {
    // ── Data Movement ──────────────────────────────────────────────
    Copy { out: Varnode, input: Varnode },
    Load { out: Varnode, space: AddressSpaceId, ptr: Varnode },
    Store { space: AddressSpaceId, ptr: Varnode, val: Varnode },

    // ── Branching ──────────────────────────────────────────────────
    Branch { dest: Varnode },
    CBranch { dest: Varnode, cond: Varnode },
    BranchInd { dest: Varnode },
    Call { dest: Varnode },
    CallInd { dest: Varnode },
    Return { dest: Varnode },

    // ── Integer Arithmetic ─────────────────────────────────────────
    IntAdd { out: Varnode, left: Varnode, right: Varnode },
    IntSub { out: Varnode, left: Varnode, right: Varnode },
    IntMult { out: Varnode, left: Varnode, right: Varnode },
    IntDiv { out: Varnode, left: Varnode, right: Varnode },
    IntSDiv { out: Varnode, left: Varnode, right: Varnode },
    IntRem { out: Varnode, left: Varnode, right: Varnode },
    IntSRem { out: Varnode, left: Varnode, right: Varnode },
    IntNeg { out: Varnode, input: Varnode },

    // ── Integer Comparison ─────────────────────────────────────────
    IntEq { out: Varnode, left: Varnode, right: Varnode },
    IntNotEq { out: Varnode, left: Varnode, right: Varnode },
    IntLess { out: Varnode, left: Varnode, right: Varnode },
    IntLessEq { out: Varnode, left: Varnode, right: Varnode },
    IntSLess { out: Varnode, left: Varnode, right: Varnode },
    IntSLessEq { out: Varnode, left: Varnode, right: Varnode },

    // ── Integer Logical / Bitwise ──────────────────────────────────
    IntAnd { out: Varnode, left: Varnode, right: Varnode },
    IntOr { out: Varnode, left: Varnode, right: Varnode },
    IntXor { out: Varnode, left: Varnode, right: Varnode },
    IntNot { out: Varnode, input: Varnode },

    // ── Shift ──────────────────────────────────────────────────────
    IntLsl { out: Varnode, left: Varnode, right: Varnode },
    IntLsr { out: Varnode, left: Varnode, right: Varnode },
    IntAsr { out: Varnode, left: Varnode, right: Varnode },

    // ── Extension / Truncation ─────────────────────────────────────
    IntZext { out: Varnode, input: Varnode },
    IntSext { out: Varnode, input: Varnode },
    Subpiece { out: Varnode, input: Varnode, lsb: u32 },

    // ── Carry / Borrow ─────────────────────────────────────────────
    IntCarry { out: Varnode, left: Varnode, right: Varnode },
    IntSCarry { out: Varnode, left: Varnode, right: Varnode },
    IntSBorrow { out: Varnode, left: Varnode, right: Varnode },

    // ── Boolean ────────────────────────────────────────────────────
    BoolAnd { out: Varnode, left: Varnode, right: Varnode },
    BoolOr { out: Varnode, left: Varnode, right: Varnode },
    BoolXor { out: Varnode, left: Varnode, right: Varnode },
    BoolNot { out: Varnode, input: Varnode },

    // ── Floating Point Arithmetic ──────────────────────────────────
    FloatAdd { out: Varnode, left: Varnode, right: Varnode },
    FloatSub { out: Varnode, left: Varnode, right: Varnode },
    FloatMult { out: Varnode, left: Varnode, right: Varnode },
    FloatDiv { out: Varnode, left: Varnode, right: Varnode },
    FloatNeg { out: Varnode, input: Varnode },
    FloatAbs { out: Varnode, input: Varnode },
    FloatSqrt { out: Varnode, input: Varnode },

    // ── Floating Point Comparison ──────────────────────────────────
    FloatEq { out: Varnode, left: Varnode, right: Varnode },
    FloatNotEq { out: Varnode, left: Varnode, right: Varnode },
    FloatLess { out: Varnode, left: Varnode, right: Varnode },
    FloatLessEq { out: Varnode, left: Varnode, right: Varnode },
    FloatNan { out: Varnode, input: Varnode },

    // ── Floating Point Conversion ──────────────────────────────────
    Int2Float { out: Varnode, input: Varnode },
    Float2Float { out: Varnode, input: Varnode },
    Trunc { out: Varnode, input: Varnode },
    FloatCeil { out: Varnode, input: Varnode },
    FloatFloor { out: Varnode, input: Varnode },
    FloatRound { out: Varnode, input: Varnode },

    // ── Bit Manipulation ───────────────────────────────────────────
    Popcount { out: Varnode, input: Varnode },
    Lzcount { out: Varnode, input: Varnode },

    // ── Miscellaneous ──────────────────────────────────────────────
    /// User-defined or architecture-specific operation.
    CallOther { out: Option<Varnode>, func_id: u64, inputs: Vec<Varnode> },
}
