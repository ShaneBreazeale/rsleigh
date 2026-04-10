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

pub struct VarDef {
    pub id: VarId,
    pub varnode: Varnode,
    pub expr: Expr,
    pub size: u32,
    pub use_count: u32,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Var(VarId),
    Const(u64, u32),
    BinOp(BinOpKind, VarId, VarId),
    UnaryOp(UnaryOpKind, VarId),
    Load(VarId),
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
        body: Vec<StructuredStmt>,
    },
    Goto(u64),
    Label(u64),
}

impl SsaCfg {
    pub fn var(&self, id: VarId) -> &VarDef {
        &self.vars[id.0 as usize]
    }

    pub fn var_mut(&mut self, id: VarId) -> &mut VarDef {
        &mut self.vars[id.0 as usize]
    }

    pub fn new_var(&mut self, varnode: Varnode, expr: Expr, size: u32) -> VarId {
        let id = VarId(self.vars.len() as u32);
        self.vars.push(VarDef {
            id,
            varnode,
            expr,
            size,
            use_count: 0,
        });
        id
    }
}
