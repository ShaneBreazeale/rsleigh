# sleigh-rust — Execution Plan

> Technical reference (types, file locations, op mappings): see CLAUDE.md  
> This document is the *what to do and in what order* — task lists, milestones, risks.

---

## Goal

Add P-code emission to sleigh2rust so that Ghidra's `.slaspec` architecture files
can generate pure Rust code that returns `Vec<PcodeOp>` per instruction.

Feeds into Spectra's native analysis backend as a drop-in for the Ghidra JVM daemon.

---

## Phase 0 — Workspace Setup
**Status: Complete**

- [x] Clone sleigh-rs → `sleigh-rust/sleigh-rs`
- [x] Clone sleigh2rust → `sleigh-rust/sleigh2rust`
- [x] Create workspace `Cargo.toml`
- [x] Create `pcode-ir/` crate (see CLAUDE.md for full `PcodeOp` enum)
- [x] Download Ghidra's x86-64 and ARM64 `.slaspec` files into `slaspec/`
  - Source: `github.com/NationalSecurityAgency/ghidra` → `Ghidra/Processors/`
  - Files: `slaspec/x86/x86-64.slaspec`, `slaspec/AARCH64/AARCH64.slaspec`
  - License: Apache 2.0 — fine to bundle at build time
- [x] Smoke test: `cargo run --example smoke_test -- slaspec/x86/x86-64.slaspec` parses without panic
- [x] Constructor count: 4576 instruction constructors, 5708 total (more than estimated ~1500)
- [x] Fixed sleigh2rust ↔ sleigh-rs API compatibility (Expr tree, ExportLen, private fields)

**Done:** workspace builds, x86-64.slaspec parses cleanly, ARM64 fails on NEON (Phase 3).

---

## Phase 1 — Fix sleigh-rs Gaps
**Status: Complete**

Five known `unimplemented!()` sites block x86-64. All are in `sleigh-rs/src/`.
See CLAUDE.md "Known Gaps" table for exact file locations.

### 1a — Carry/borrow bit-width (`op.rs:80`)
- `IntCarry`, `IntSCarry`, `IntSBorrow` always produce a 1-bit result
- Used heavily by x86 flag computation — **blocks most ALU instructions**
- Fix: return `FieldSize::new_unsized().possible_min(1)` as result size

### 1b — `UserCall` len_bits (`execution.rs:125`)
- Look up `sleigh.user_functions[id]` return size
- If no declared return size, default to `addr_bytes * 8`

### 1c — `ExprCPool` stub (`execution.rs:115`)
- Only appears in JVM bytecode and WASM specs — not x86-64 or ARM64
- Stub: emit a zero-size warning, return `len_bits = 0`

### 1d — `inst_next2` stub (`lib.rs` TODO)
- Appears in delay-slot architectures (MIPS, SPARC) — not x86-64 or ARM64
- Stub: return `inst_next + instruction_len`

### 1e — `ExprNew` stub (`execution.rs:114`)
- Extremely rare
- Stub: `unimplemented!` replaced with `todo!("ExprNew not yet supported")`

**Test milestone:** Parse x86-64.slaspec, iterate all constructors, assert
`constructor.execution.is_some()` for all non-prefix constructors. Zero panics.

---

## Phase 2 — P-code Codegen in sleigh2rust
**Target: Weeks 2–3**

All new code lives in `sleigh2rust/src/`. See CLAUDE.md for exact type names and
the complete Binary/Unary → PcodeOp mapping tables.

### 2a — New crate dependency
Add `pcode-ir` to `sleigh2rust/Cargo.toml`. The generated code emits `pcode_ir::PcodeOp`.

### 2b — New file: `builder/disassembler/constructor/execution.rs`
Model it on `disassembly.rs`. Implement `ExecutionGenerator` struct (see CLAUDE.md for
full struct definition) with these methods:

```
gen_lift(execution: &Execution) -> TokenStream   ← top-level, walk blocks
gen_block(block: &Block) -> TokenStream
gen_statement(stmt: &Statement) -> TokenStream
gen_assignment(a: &Assignment) -> TokenStream
gen_branch(b: &CpuBranch) -> TokenStream
gen_local_goto(g: &LocalGoto) -> TokenStream
gen_build(b: &Build) -> TokenStream
lower_expr(expr: &Expr) -> TokenStream           ← alloc unique, emit op, return varnode
```

**Order to implement (easiest first):**
1. `ExprValue::Int` → `Varnode::constant()`
2. `ExprValue::Varnode` → `Varnode::register()`
3. `Statement::Assignment` with `AssignmentWrite::Variable` → `PcodeOp::Copy`
4. `Binary::Add/Sub/And/Or/Xor` → corresponding `IntAdd/IntSub/IntAnd...`
5. `Unary::Zext/Sext` → `IntZext/IntSext`
6. `Unary::Dereference` → `PcodeOp::Load`
7. `AssignmentWrite::Memory` → `PcodeOp::Store`
8. `CpuBranch` → `Branch/CBranch/Call/Return`
9. `Statement::Build` → recursive sub-table emission
10. Remaining binary/unary ops (full mapping in CLAUDE.md)
11. `LocalGoto` → `loop {}` + `break 'label` pattern

### 2c — Wire into `ConstructorStruct::to_tokens()`
In `mod.rs`, after the existing `gen_display()` call:

```rust
if let Some(execution) = &constructor.execution {
    let gen = ExecutionGenerator::new(disassembler, self, ...);
    tokens.extend(gen.gen_lift(execution));
}
```

The generated `lift()` method signature:
```rust
fn lift(&self, inst_start: AddrType, inst_next: AddrType) -> Vec<pcode_ir::PcodeOp>
```

### 2d — Update `parse_instruction()` return type
Add `Vec<pcode_ir::PcodeOp>` as third element of the returned tuple.

**Test milestone — golden output for 10 instructions:**

| Bytes | Instruction | Key P-code ops expected |
|-------|------------|------------------------|
| `48 89 c7` | MOV rdi, rax | `Copy(reg:0x38, reg:0x0)` |
| `48 01 c7` | ADD rdi, rax | `IntAdd`, `IntCarry` (CF), `IntSCarry` (OF) |
| `48 39 c7` | CMP rdi, rax | `IntSub` + 6 flag ops |
| `74 05`    | JE rel8 | `CBranch` on ZF |
| `eb 0a`    | JMP rel8 | `Branch` |
| `ff d0`    | CALL rax | `Copy(SP-8), Store, Call` |
| `c3`       | RET | `Load(SP), Return` |
| `50`       | PUSH rax | `IntSub(SP,8), Store` |
| `58`       | POP rax | `Load, IntAdd(SP,8)` |
| `48 8b 07` | MOV rax,[rdi] | `Load` |

Compare against Ghidra headless output. Exact match on op type and varnode offsets/sizes.

---

## Phase 3 — ARM64
**Target: Week 4**

Run the same pipeline against `AARCH64.slaspec`. Most codegen is architecture-agnostic
— expected fixes are edge cases in sleigh-rs's semantic parser for:
- Condition code computation (NZCV flags)
- Shifted/extended register operands
- Load/store pair instructions

**Test milestone — golden output for ARM64:**

| Bytes | Instruction |
|-------|------------|
| `E0 03 01 AA` | MOV x0, x1 |
| `00 00 01 8B` | ADD x0, x0, x1 |
| `C0 03 5F D6` | RET |
| `00 00 00 94` | BL #0 |
| `40 00 00 B4` | CBZ x0, #8 |
| `00 00 40 F9` | LDR x0, [x0] |
| `00 00 00 F9` | STR x0, [x0] |

---

## Phase 4 — Spectra Integration
**Target: Week 5**

### 4a — `AnalysisBackend` trait in Spectra

New file `src-tauri/src/analysis/backend.rs`:

```rust
pub trait AnalysisBackend: Send + Sync {
    fn list_functions(&mut self) -> Result<Vec<FunctionEntry>>;
    fn decompile(&mut self, addr: u64) -> Result<DecompileResult>;
    fn get_cfg(&mut self, addr: u64) -> Result<CfgResult>;
    fn get_xrefs(&mut self, addr: u64) -> Result<Vec<XrefEntry>>;
    fn get_disasm(&mut self, addr: u64) -> Result<Vec<Instruction>>;
    fn get_strings(&mut self) -> Result<Vec<StringEntry>>;
    fn get_imports(&mut self) -> Result<Vec<ImportEntry>>;
    fn name(&self) -> &'static str;
}
```

### 4b — `GhidraBackend` wraps existing `GhidraBridge`
Pure refactor — no behavior change. All existing commands route through the trait.

### 4c — `NativeBackend` uses generated decoders
- `list_functions`: goblin symbols + recursive descent from entry points
- `get_disasm`: generated decoder from Phase 2/3
- `get_cfg`: petgraph CFG from branch analysis
- `get_xrefs`: call/jump targets from disassembly
- `get_strings`, `get_imports`: goblin (already in Spectra)
- `decompile`: `Vec<PcodeOp>` formatted as text → LLM refine pipeline

### 4d — Settings toggle
Add `analysis_backend: "ghidra" | "native"` to `Settings`. Wire into project open.
Settings UI: dropdown in the Analysis section.

**Done when:** Spectra can open an x86-64 binary with `native` backend, show functions,
disassembly, CFG, and xrefs without Ghidra running.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| sleigh-rs has hidden semantic bugs for x86-64 | Medium | High | Golden tests in Phase 2 catch early |
| `Build` recursion causes infinite loops | Low | High | Depth limit + cycle detection |
| Unique varnode naming collisions | Low | Medium | `addr:seq` counter per instruction |
| Generated x86-64 module too large to compile | Low | Medium | Split by instruction group |
| ARM64 SIMD/SVE too complex for Phase 3 | Medium | Low | Stub SIMD, ship scalar first |
| Ghidra register offsets differ from what we assume | Medium | High | Validate against `.pspec` file |

---

## Out of Scope

- SSA construction (done in Spectra's analysis layer)
- Structure recovery / if-else / loop detection  
- Type inference
- Pseudocode generation (LLM handles this from P-code text)
- Architectures beyond x86-64 and ARM64 in Phases 1–4
- An interpreter or emulator (we generate code, not evaluate it)

---

## Reference

- `CLAUDE.md` — complete type reference, file locations, op mapping tables
- `libsla` (github.com/mnemonikr/libsla) — C++ runtime doing same thing we code-generate
- Ghidra P-code docs — `github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/languages`
- Ghidra `.slaspec` files — `github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors`
