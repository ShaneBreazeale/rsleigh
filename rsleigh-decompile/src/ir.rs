use pcode_ir::{PcodeOp, Varnode};

// ---- Identifiers ----

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockId(pub usize);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VarId(pub u32);

// ---- CFG types ----

pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub entry: BlockId,
}

pub struct BasicBlock {
    pub id: BlockId,
    pub addr: u64,
    /// (instruction address, pcode op)
    pub ops: Vec<(u64, PcodeOp)>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone)]
pub enum Terminator {
    Fallthrough(BlockId),
    Branch(BlockId),
    CBranch { cond: Varnode, taken: BlockId, fallthrough: BlockId },
    Call { target: CallTarget, fallthrough: BlockId },
    Return,
    Indirect(Varnode),
}

#[derive(Debug, Clone)]
pub enum CallTarget {
    Direct(u64),
    Indirect(Varnode),
}

// ---- SSA types ----

pub struct SsaCfg {
    pub blocks: Vec<SsaBlock>,
    pub vars: Vec<VarDef>,
    pub entry: BlockId,
}

pub struct SsaBlock {
    pub id: BlockId,
    pub addr: u64,
    pub stmts: Vec<Stmt>,
    pub terminator: SsaTerminator,
}

#[derive(Debug, Clone)]
pub enum SsaTerminator {
    Fallthrough(BlockId),
    Branch(BlockId),
    CBranch { cond: VarId, taken: BlockId, fallthrough: BlockId },
    Call { target: CallTarget, args: Vec<VarId>, fallthrough: BlockId },
    Return(Option<VarId>),
    Indirect(VarId),
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Assign(VarId),
    Store { addr: VarId, val: VarId },
    Call { target: CallTarget, args: Vec<VarId>, out: Option<VarId> },
}

/// Inferred type for a variable, propagated by the type inference pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferredType {
    /// No type inferred yet — prints as uintN_t based on size
    Unknown,
    /// Explicitly unsigned (from unsigned ops like IntDiv, IntLess, IntZext)
    Unsigned,
    /// Signed integer (from IntSDiv, IntSLess, IntSext, IntSRight, IntNeg)
    Signed,
    /// IEEE 754 float (from FloatAdd, FloatMult, Int2Float, etc.)
    Float,
    /// Pointer (used as Load/Store address)
    Pointer,
    /// Boolean (comparison result, flag register, BoolAnd/BoolOr operand)
    Bool,
}

impl InferredType {
    /// Merge two types: if they agree, keep it; if they conflict, prefer the more specific.
    pub fn merge(self, other: InferredType) -> InferredType {
        if self == other { return self; }
        match (self, other) {
            (InferredType::Unknown, t) | (t, InferredType::Unknown) => t,
            // Signed wins over Unsigned (common in mixed contexts)
            (InferredType::Signed, InferredType::Unsigned)
            | (InferredType::Unsigned, InferredType::Signed) => InferredType::Signed,
            // Everything else: keep the first (don't corrupt)
            _ => self,
        }
    }
}

pub struct VarDef {
    pub id: VarId,
    pub varnode: Varnode,
    pub expr: Expr,
    pub size: u32,
    pub use_count: u32,
    /// If this var is a function parameter, its name (e.g. "param_0")
    pub param_name: Option<String>,
    /// If this var holds a call return value, the call's VarId
    pub call_return: bool,
    /// Inferred type from dataflow analysis
    pub inferred_type: InferredType,
    /// Display type name from signature database (e.g. "HANDLE", "DWORD", "LPCWSTR").
    /// When set, the printer uses this instead of mapping InferredType to a generic C type.
    /// Propagates through Var/Copy chains alongside InferredType.
    pub display_type: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Var(VarId),
    Const(u64, u32),
    BinOp(BinOpKind, VarId, VarId),
    UnaryOp(UnaryOpKind, VarId),
    Load(VarId),
    /// Struct field access: base pointer + byte offset.
    /// Recognized from Load(Add(base, Const(offset))) patterns.
    FieldAccess(VarId, u64),
    Phi(Vec<VarId>),
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum BinOpKind {
    Add, Sub, Mult, Div, SDiv, Rem, SRem,
    And, Or, Xor,
    Lsl, Lsr, Asr,
    Eq, NotEq, Less, LessEq, SLess, SLessEq,
    Carry, SCarry, SBorrow,
    BoolAnd, BoolOr, BoolXor,
    FloatAdd, FloatSub, FloatMult, FloatDiv,
    FloatEq, FloatNotEq, FloatLess, FloatLessEq,
}

#[derive(Debug, Clone, Copy)]
pub enum UnaryOpKind {
    Neg, Not, Zext, Sext,
    BoolNot,
    FloatNeg, FloatAbs, FloatSqrt, FloatNan,
    Int2Float, Float2Float, Trunc,
    FloatCeil, FloatFloor, FloatRound,
    Popcount, Lzcount,
}

// ---- Structured output types ----

#[derive(Debug, Clone)]
pub enum StructuredStmt {
    Assign { lhs: VarId, rhs: VarId },
    Store { addr: VarId, val: VarId },
    Call { target: CallTarget, args: Vec<VarId>, out: Option<VarId> },
    Return(Option<VarId>),
    IfElse {
        cond: VarId,
        then_body: Vec<StructuredStmt>,
        else_body: Vec<StructuredStmt>,
    },
    While {
        cond: VarId,
        negate: bool,
        body: Vec<StructuredStmt>,
    },
    /// Post-tested loop: do { body } while (cond)
    DoWhile {
        cond: VarId,
        negate: bool,
        body: Vec<StructuredStmt>,
    },
    /// Switch/case recovered from if-else chains or jump tables.
    Switch {
        expr: VarId,
        cases: Vec<(Vec<i64>, Vec<StructuredStmt>)>,  // (case values, body)
        default: Vec<StructuredStmt>,
    },
    Break,
    Continue,
    Goto(u64),
    Label(u64),
}

/// Sentinel VarDef returned for out-of-bounds VarId lookups.
/// Prevents panics on malformed/adversarial input.
/// Safe VarDef lookup from a slice — returns sentinel for OOB access.
pub fn safe_var(vars: &[VarDef], id: VarId) -> &VarDef {
    vars.get(id.0 as usize).unwrap_or(&SENTINEL_VARDEF)
}

static SENTINEL_VARDEF: std::sync::LazyLock<VarDef> = std::sync::LazyLock::new(|| VarDef {
    id: VarId(u32::MAX),
    varnode: Varnode { space: pcode_ir::AddressSpaceId::Const, offset: 0, size: 0 },
    expr: Expr::Unknown,
    size: 0,
    use_count: 0,
    param_name: None,
    call_return: false,
    inferred_type: InferredType::Unknown,
    display_type: None,
});

impl SsaCfg {
    /// Safe variable lookup — returns a sentinel for out-of-bounds VarId
    /// instead of panicking. This is critical for handling malformed binaries
    /// that produce pathological P-code with invalid varnode references.
    pub fn var(&self, id: VarId) -> &VarDef {
        self.vars.get(id.0 as usize).unwrap_or(&SENTINEL_VARDEF)
    }

    pub fn var_mut(&mut self, id: VarId) -> &mut VarDef {
        let idx = id.0 as usize;
        if idx >= self.vars.len() {
            // Extend with sentinel entries to accommodate the index
            // This shouldn't happen in normal operation but prevents panic
            while self.vars.len() <= idx {
                self.vars.push(VarDef {
                    id: VarId(self.vars.len() as u32),
                    varnode: Varnode { space: pcode_ir::AddressSpaceId::Const, offset: 0, size: 0 },
                    expr: Expr::Unknown,
                    size: 0,
                    use_count: 0,
                    param_name: None,
                    call_return: false,
                    inferred_type: InferredType::Unknown,
                    display_type: None,
                });
            }
        }
        &mut self.vars[idx]
    }

    pub fn new_var(&mut self, varnode: Varnode, expr: Expr, size: u32) -> VarId {
        let id = VarId(self.vars.len() as u32);
        self.vars.push(VarDef {
            id,
            varnode,
            expr,
            size,
            use_count: 0,
            param_name: None,
            call_return: false,
            inferred_type: InferredType::Unknown,
            display_type: None,
        });
        id
    }
}
