# CLAUDE.md — sleigh-rust

## What This Is

A fork of `sleigh-rs` (SLEIGH spec parser) and `sleigh2rust` (Rust code generator)
with a new companion crate `pcode-ir`, extended to emit **P-code operations** from
Ghidra's `.slaspec` architecture specification files.

Goal: pure Rust, zero C++ deps, generate `Vec<PcodeOp>` for any instruction from any
architecture Ghidra supports, using the same `.slaspec` files Ghidra ships (Apache 2.0).

This feeds into Spectra's native analysis backend as a drop-in replacement for the
Ghidra JVM daemon.

---

## Workspace Structure

```
sleigh-rust/
├── Cargo.toml              ← workspace members
├── CLAUDE.md               ← this file
├── PLAN.md                 ← phased implementation plan
├── sleigh-rs/              ← forked parser (rbran/sleigh-rs)
├── sleigh2rust/            ← forked codegen (rbran/sleigh2rust)
├── pcode-ir/               ← new: PcodeOp / Varnode types (tiny, no deps)
├── test-vectors/
│   ├── x86_64/             ← golden P-code output from Ghidra
│   └── aarch64/
└── slaspec/
    ├── x86-64.slaspec      ← from Ghidra repo (Apache 2.0)
    └── AARCH64.slaspec
```

---

## Critical Architecture: How the Pipeline Works

```
.slaspec file
    ↓
file_to_sleigh(path) → Sleigh struct          [sleigh-rs entry point]
    ↓
Disassembler::new(sleigh, debug)              [sleigh2rust]
    ↓  for each Table → for each Constructor:
    ├─ ConstructorStruct::new()
    ├─ gen_pattern()    → parse() fn          [already implemented]
    ├─ gen_display()    → display_extend() fn [already implemented]
    └─ gen_execution()  → lift() fn           [TO IMPLEMENT]
    ↓
TokenStream (Rust source code)
    ↓
Generated crate compiled into Spectra
```

The key insight: `Constructor.execution: Option<Execution>` is **fully populated** by
sleigh-rs. sleigh2rust currently ignores it. We add `gen_execution()`.

---

## sleigh-rs: Key Types

### Entry Point

```rust
// sleigh-rs/src/lib.rs
pub fn file_to_sleigh(filename: &Path) -> Result<Sleigh, Box<SleighError>>
```

### Sleigh struct — `sleigh-rs/src/semantic/mod.rs`

```rust
pub struct Sleigh {
    endian: Endian,
    alignment: u8,
    default_space: SpaceId,
    instruction_table: TableId,        // always TableId(0)
    spaces: Box<[Space]>,
    varnodes: Box<[Varnode]>,          // registers
    contexts: Box<[Context]>,
    tokens: Box<[Token]>,
    token_fields: Box<[TokenField]>,
    user_functions: Box<[UserFunction]>,
    tables: Box<[Table]>,
    attach_varnodes: Box<[AttachVarnode]>,
    attach_literals: Box<[AttachLiteral]>,
    attach_numbers: Box<[AttachNumber]>,
    // ...
}

// Key accessors:
sleigh.table(id: TableId) -> &Table
sleigh.varnode(id: VarnodeId) -> &Varnode
sleigh.space(id: SpaceId) -> &Space
sleigh.user_functions() -> &[UserFunction]
```

### Constructor — `sleigh-rs/src/semantic/table.rs`

```rust
pub struct Table {
    pub name: Box<str>,
    pub is_root: bool,
    pub constructors: Box<[Constructor]>,
    pub matcher_order: Box<[Matcher]>,
    pub export: Option<ExportLen>,
    pub pattern_len: PatternLen,
}

pub struct Constructor {
    pub pattern: Pattern,
    pub display: Display,
    pub execution: Option<Execution>,   // ← THIS IS WHAT WE EMIT P-CODE FROM
    pub location: Span,
    pub variants_bits: Box<[...]>,
}
```

### Execution — `sleigh-rs/src/semantic/execution.rs`

```rust
pub struct Execution {
    pub(crate) variables: Box<[Variable]>,
    pub(crate) blocks: Box<[Block]>,
    pub(crate) export: Option<ExportLen>,
    pub entry_block: BlockId,
}

pub struct Block {
    pub name: Option<Box<str>>,          // label for LocalGoto targets
    pub next: Option<BlockId>,           // fall-through
    pub statements: Box<[Statement]>,
}

pub struct Variable {
    pub(crate) name: Box<str>,
    pub len_bits: NumberNonZeroUnsigned,
    pub location: Option<Span>,
}

pub enum Statement {
    Delayslot(NumberUnsigned),
    Export(Export),
    CpuBranch(CpuBranch),
    LocalGoto(LocalGoto),
    UserCall(UserCall),
    Build(Build),
    Declare(VariableId),
    Assignment(Assignment),
}
```

### Expressions — `sleigh-rs/src/semantic/execution.rs`

```rust
pub enum Expr {
    Value(ExprElement),
    Op(ExprBinaryOp),
}

pub enum ExprElement {
    Value { location: Span, value: ExprValue },
    UserCall(UserCall),
    Reference(Reference),
    Op(ExprUnaryOp),
    New(ExprNew),         // unimplemented in sleigh-rs — stub OK
    CPool(ExprCPool),     // unimplemented in sleigh-rs — stub OK
}

pub enum ExprValue {
    Int(ExprNumber),                    // constant integer
    IntDynamic(ExprDynamicInt),         // attachment lookup
    InstStart(InstStart),               // instruction address
    InstNext(InstNext),                 // next instruction address
    TokenField(ExprTokenField),         // field from instruction encoding
    Context(ExprContext),               // context variable
    Varnode(VarnodeId),                 // register/named varnode
    VarnodeDynamic(ExprVarnodeDynamic), // dynamic register lookup
    Bitrange(ExprBitrange),             // bitfield
    Table(TableId),                     // subtable export value
    DisVar(ExprDisVar),                 // disassembly variable
    ExeVar(VariableId),                 // local execution variable
}

pub struct ExprBinaryOp {
    pub location: Span,
    pub len_bits: NumberNonZeroUnsigned,   // result size — always known
    pub op: Binary,
    pub left: Box<Expr>,
    pub right: Box<Expr>,
}

pub struct ExprUnaryOp {
    pub location: Span,
    pub op: Unary,
    pub input: Box<Expr>,
}
```

### Binary ops → P-code mapping — `sleigh-rs/src/semantic/execution.rs`

```
sleigh-rs Binary::*      →  pcode-ir PcodeOp::*
──────────────────────────────────────────────────
Add                      →  IntAdd
Sub                      →  IntSub
Mult                     →  IntMult
Div                      →  IntDiv
SigDiv                   →  IntSDiv
Rem                      →  IntRem
SigRem                   →  IntSRem
FloatAdd                 →  FloatAdd
FloatSub                 →  FloatSub
FloatMult                →  FloatMult
FloatDiv                 →  FloatDiv
Lsl                      →  IntLsl
Lsr                      →  IntLsr
Asr                      →  IntAsr
BitAnd                   →  IntAnd
BitOr                    →  IntOr
BitXor                   →  IntXor
And                      →  IntAnd (bool)
Or                       →  IntOr  (bool)
Xor                      →  IntXor (bool)
Eq                       →  IntEq
Ne                       →  IntNotEq
Less                     →  IntLess
Greater                  →  IntLess (swapped operands)
LessEq                   →  IntLessEq
GreaterEq                →  IntLessEq (swapped)
SigLess                  →  IntSLess
SigGreater               →  IntSLess (swapped)
SigLessEq                →  IntSLessEq
SigGreaterEq             →  IntSLessEq (swapped)
FloatEq                  →  FloatEq
FloatNe                  →  FloatNotEq
FloatLess                →  FloatLess
FloatLessEq              →  FloatLessEq
Carry                    →  IntCarry
SCarry                   →  IntSCarry
SBorrow                  →  IntSBorrow
```

### Unary ops → P-code mapping

```
sleigh-rs Unary::*       →  PcodeOp::*
──────────────────────────────────────
Zext(bits)               →  IntZext
Sext(bits)               →  IntSext
Dereference(mem)         →  Load { space, ptr }
TakeLsb(n)               →  Subpiece { lsb: 0, size: n }
TrunkLsb { trunk, bits } →  Subpiece { lsb: trunk }
BitRange { range, bits } →  shift + Subpiece
Popcount(bits)           →  Popcount
Lzcount(bits)            →  Lzcount
Negation                 →  IntNot (boolean)
BitNegation              →  IntNot (bitwise)
Negative                 →  IntNeg
FloatNegative            →  FloatNeg
FloatAbs                 →  FloatAbs
FloatSqrt                →  FloatSqrt
FloatNan                 →  FloatNan
Int2Float                →  Int2Float
Float2Float              →  Float2Float
SignTrunc                →  Trunc
FloatCeil                →  FloatCeil
FloatFloor               →  FloatFloor
FloatRound               →  FloatRound
```

### Control flow statements

```rust
pub struct CpuBranch {
    pub cond: Option<Expr>,     // None = unconditional
    pub call: BranchCall,       // Goto | Call | Return
    pub direct: bool,
    pub dst: Expr,
}

pub enum BranchCall { Goto, Call, Return }
// Goto   → Branch / CBranch
// Call   → Call / CallInd
// Return → Return

pub struct LocalGoto {
    pub cond: Option<Expr>,
    pub dst: BlockId,           // target block index
}
// → emit unconditional/conditional Branch to label
```

### Assignment targets

```rust
pub enum AssignmentWrite {
    Variable {
        value: AssignmentWriteVariable,
        op: Option<AssignmentOp>,   // None=assign, Some(Add)=+=, etc.
    },
    Memory { mem: MemoryLocation, addr: Expr },    // → Store op
    TableExport { table_id, op, size },
}

pub enum AssignmentWriteVariable {
    Varnode(VarnodeId),             // register write → Copy op
    Bitrange(BitrangeId),           // bitfield write → shift + mask + Or
    DynVarnode { value_id, attach_id }, // dynamic register → runtime lookup
    Variable(VariableId),           // local temp → Copy to unique space
}
```

---

## sleigh2rust: Key Types

### Disassembler — `sleigh2rust/src/builder/disassembler/mod.rs`

```rust
pub struct Disassembler {
    pub debug: bool,
    pub registers: RegistersEnum,
    pub meanings: Meanings,
    pub display: DisplayElement,
    pub tables: Vec<TableEnum>,
    pub token_field_functions: TokenFieldFunctions,
    pub addr_type: Ident,
    pub inst_work_type: WorkType,
    pub context: ContextMemory,
    pub sleigh: sleigh_rs::Sleigh,
}
```

`to_tokens()` generates everything: types, register enum, display, context, tables,
and the top-level `parse_instruction()` function.

### ConstructorStruct — `sleigh2rust/src/builder/disassembler/constructor/mod.rs`

```rust
pub struct ConstructorStruct {
    pub constructor_id: sleigh_rs::table::ConstructorId,
    pub table_id: sleigh_rs::TableId,
    pub struct_name: Ident,         // e.g. "add_Instruction0"
    pub enum_name: Ident,
    pub display_fun: Ident,         // "display_extend"
    pub disassembly_fun: Ident,     // "disassembly"
    pub parser_fun: Ident,          // "parse"
    pub table_fields: IndexMap<sleigh_rs::TableId, Ident>,
    pub ass_fields: IndexMap<sleigh_rs::TokenFieldId, Ident>,
}
```

**`to_tokens()` generates:**
1. Struct definition with token field and sub-table fields
2. `parse()` — pattern matching
3. `display_extend()` — formatting
4. (TO ADD) `lift()` — P-code emission

**`gen_display()`** in `mod.rs:150` returns a `TokenStream`. Follow this exact
pattern for `gen_execution()`.

### DisassemblyDisplay — `sleigh2rust/src/builder/disassembler/constructor/disassembly.rs`

**Model this for `ExecutionGenerator`:**

```rust
pub struct DisassemblyDisplay<'a> {
    pub disassembler: &'a Disassembler,
    pub constructor: &'a ConstructorStruct,
    pub display_param: &'a Ident,
    pub context_param: &'a Ident,
    pub inst_start: &'a Ident,
    pub inst_next: &'a Ident,
    pub global_set_param: &'a Ident,
    pub vars: RefCell<IndexMap<VariableId, Ident>>,
}
```

`ExecutionGenerator` will be the same shape with `ops_param: &'a Ident` instead of
`display_param`.

---

## pcode-ir: What to Build

New crate at `pcode-ir/`. No deps. Defines the types emitted by generated code.

```rust
// pcode-ir/src/lib.rs

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Varnode {
    pub space: AddressSpaceId,
    pub offset: u64,
    pub size: u32,              // in bytes
}

impl Varnode {
    pub fn register(offset: u64, size: u32) -> Self
    pub fn unique(offset: u64, size: u32) -> Self
    pub fn ram(offset: u64, size: u32) -> Self
    pub fn constant(value: u64, size: u32) -> Self
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceId {
    Register,
    Ram,
    Unique,
    Const,
}

// ~60 variants — see PLAN.md for full list
pub enum PcodeOp {
    Copy     { out: Varnode, input: Varnode },
    Load     { out: Varnode, space: AddressSpaceId, ptr: Varnode },
    Store    { space: AddressSpaceId, ptr: Varnode, val: Varnode },
    Branch   { dest: Varnode },
    CBranch  { dest: Varnode, cond: Varnode },
    // ... (full list in PLAN.md)
}
```

---

## Implementation: Where to Add Code

### Step 1 — Fix sleigh-rs gaps (touch sleigh-rs only)

All gaps are in `sleigh-rs/src/semantic/execution.rs`:

```rust
// Line 125: UserCall len_bits
// Fix: look up return type from sleigh.user_functions[id].return_size

// Line 114: ExprNew — stub returning len_bits=64, warn
// Line 115: ExprCPool — stub returning CallOther variant

// sleigh-rs/src/semantic/inner/execution/op.rs line 80:
// Carry/SCarry/SBorrow — implement bit-width propagation:
// result is always 1-bit (boolean), inputs are any width
```

### Step 2 — New file: `sleigh2rust/src/builder/disassembler/constructor/execution.rs`

```rust
pub struct ExecutionGenerator<'a> {
    pub disassembler: &'a Disassembler,
    pub constructor: &'a ConstructorStruct,
    pub addr_param: &'a Ident,
    pub inst_next_param: &'a Ident,
    pub ops_param: &'a Ident,              // `ops: &mut Vec<PcodeOp>`
    pub unique_counter: Cell<u64>,         // for allocating unique space varnodes
    pub vars: RefCell<IndexMap<VariableId, Ident>>,
}

impl<'a> ExecutionGenerator<'a> {
    // Top-level: walk all blocks starting from entry_block
    pub fn gen_lift(&self, execution: &Execution) -> TokenStream

    // Walk one block, emit statements
    fn gen_block(&self, block: &Block, execution: &Execution) -> TokenStream

    // Statement dispatch
    fn gen_statement(&self, stmt: &Statement) -> TokenStream
    fn gen_assignment(&self, a: &Assignment) -> TokenStream
    fn gen_branch(&self, b: &CpuBranch) -> TokenStream
    fn gen_local_goto(&self, g: &LocalGoto) -> TokenStream
    fn gen_build(&self, b: &Build) -> TokenStream
    fn gen_user_call(&self, c: &UserCall) -> TokenStream
    fn gen_export(&self, e: &Export) -> TokenStream

    // Expression lowering — allocates unique varnode, emits op, returns varnode ident
    fn lower_expr(&self, expr: &Expr) -> TokenStream   // returns (varnode, stmts)
    fn lower_binary(&self, op: &ExprBinaryOp) -> TokenStream
    fn lower_unary(&self, op: &ExprUnaryOp) -> TokenStream
    fn lower_value(&self, v: &ExprValue) -> TokenStream

    // Unique space varnode allocation
    fn fresh_unique(&self, size_bits: u64) -> Ident
}
```

**Generated `lift()` signature:**
```rust
fn lift(
    &self,
    inst_start: AddrType,
    inst_next: AddrType,
) -> Vec<pcode_ir::PcodeOp>
```

### Step 3 — Wire into `ConstructorStruct::to_tokens()`

In `sleigh2rust/src/builder/disassembler/constructor/mod.rs`:

```rust
// After gen_display(), add:
let exec = disassembler.sleigh
    .table(self.table_id)
    .constructor(self.constructor_id);

if let Some(execution) = &exec.execution {
    let gen = ExecutionGenerator::new(disassembler, self, ...);
    tokens.extend(gen.gen_lift(execution));
}
```

### Step 4 — Expose from top-level `parse_instruction()`

Update generated `parse_instruction()` signature to return P-code:

```rust
pub fn parse_instruction(
    tokens: &[u8],
    context: &mut ContextMemory,
    inst_start: AddrType,
    global_set: &mut GlobalSet,
) -> Option<(InstWorkType, Vec<DisplayElement>, Vec<pcode_ir::PcodeOp>)>
//                                              ↑ NEW
```

---

## Testing Approach

### Golden output tests

For each instruction in `test-vectors/x86_64/`, compare our P-code against Ghidra's.
Use Ghidra headless or libsla to generate the golden corpus.

Target instructions for initial test suite:
- `48 89 c7` — MOV rdi, rax
- `48 01 c7` — ADD rdi, rax
- `ff d0`    — CALL rax
- `c3`       — RET
- `74 05`    — JE rel8
- `50`       — PUSH rax
- `58`       — POP rax
- `48 8b 07` — MOV rax, [rdi]
- `48 89 07` — MOV [rdi], rax
- `48 39 c7` — CMP rdi, rax

Expected P-code for MOV rdi, rax (Ghidra output):
```
(register, 0x38, 8) COPY (register, 0x0, 8)
```

Our output should be:
```rust
PcodeOp::Copy {
    out:   Varnode { space: Register, offset: 0x38, size: 8 },
    input: Varnode { space: Register, offset: 0x0,  size: 8 },
}
```

### Test harness

```rust
// tests/x86_64_golden.rs
#[test]
fn test_mov_rdi_rax() {
    let bytes = &[0x48u8, 0x89, 0xc7];
    let (len, _display, ops) = parse_instruction(bytes, &mut ctx, 0x1000, &mut gs)
        .expect("should decode");
    assert_eq!(len, 3);
    assert_eq!(ops, vec![
        PcodeOp::Copy {
            out:   Varnode::register(0x38, 8),
            input: Varnode::register(0x0, 8),
        }
    ]);
}
```

---

## Known Gaps in sleigh-rs (do not panic on these — stub or warn)

| Location | What's missing | Stubbing strategy |
|----------|---------------|-------------------|
| `execution.rs:125` | `UserCall` len_bits | Return `user_function.return_len` from Sleigh |
| `execution.rs:114` | `ExprNew` | Emit `CallOther { func_id: NEW_OPCODE }`, warn |
| `execution.rs:115` | `ExprCPool` | Emit `CallOther { func_id: CPOOL_OPCODE }`, warn |
| `op.rs:80` | Carry/SCarry/SBorrow bit-width | Result is always 1 bit |
| `lib.rs` TODO | `inst_next2` | Return `inst_next + instr_len`, warn |

`ExprNew` and `ExprCPool` only appear in JVM bytecode and WASM specs — not in x86-64
or ARM64. Safe to stub for Phase 1-3.

---

## Dependency Notes

- `sleigh-rs` uses: `nom`, `thiserror`, `tracing`
- `sleigh2rust` uses: `quote`, `proc-macro2`, `indexmap`, `ethnum`, `bitvec`
- `pcode-ir` uses: nothing — zero deps by design
- `ethnum` provides `u256`/`i256` for wide integer operations (SIMD, large immediates)

Do not add runtime deps to `pcode-ir`. The generated code should only depend on
`pcode-ir` — not on any sleigh crate.

---

## What We Are NOT Building (scope boundary)

- **SSA construction** — out of scope here, done in Spectra's analysis layer
- **Structure recovery** (if/else, loops) — out of scope
- **Type inference** — out of scope
- **Pseudocode generation** — out of scope; P-code is the output, LLM does the rest
- **An interpreter** — we generate code, we don't interpret at runtime
- **Full 50+ architecture support** in Phase 1-3 — x86-64 and ARM64 first
