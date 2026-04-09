# CLAUDE.md — rsleigh

## What This Is

A unified Rust crate (merged from `sleigh-rs` + `sleigh2rust`) that parses Ghidra's
`.slaspec` architecture definitions and generates Rust code that decodes instructions
and emits P-code IR.

**Goal:** Pure Rust, zero C++ deps, generate `Vec<PcodeOp>` for any instruction from
any architecture Ghidra supports, using the same `.slaspec` files Ghidra ships (Apache 2.0).

This feeds into Spectra's native analysis backend as a drop-in replacement for the
Ghidra JVM daemon.

---

## Current Status

**Working end-to-end for 3 architectures:**

| Architecture | Constructors | Extensions | Generated | Build time |
|---|---|---|---|---|
| x86-64 | 5700+ | full | 33 MB | ~3.5 min |
| AARCH64 | 3500+ | NEON + SVE | 34 MB | ~11 sec |
| RISC-V (RV64) | 500+ | F/D/B/K/P/Q/V/C | 5 MB | ~2.6 sec |

**223 validated instructions** (23 golden with exact P-code assertions + 200 corpus
cross-referenced against capstone for decode/length/mnemonic/P-code structure).

---

## Workspace Structure

```
rsleigh/
├── Cargo.toml                  ← workspace root (rsleigh lib + members)
├── CLAUDE.md                   ← this file
├── Makefile                    ← make generate / make test / make run
├── src/                        ← rsleigh parser + codegen library
│   ├── codegen/                ← Rust code generation from SLEIGH
│   │   └── builder/disassembler/constructor/
│   │       ├── execution.rs    ← P-code emission (ExecutionGenerator)
│   │       ├── pattern.rs      ← instruction pattern matching codegen
│   │       ├── disassembly.rs  ← disassembly variable codegen
│   │       └── mod.rs          ← ConstructorStruct, gen_display, gen_execution
│   └── semantic/               ← SLEIGH semantic analysis (forked sleigh-rs)
├── pcode-ir/                   ← P-code types + peephole optimizer (no_std, zero deps)
├── rsleigh-generate/           ← Pre-build binary: parses slaspecs, writes generated code
├── generated/                  ← Generated crate source (gitignored /out/ dirs)
│   ├── x86-shared/             ← shared types, registers, context (108 KB)
│   ├── x86-subtables/          ← 236 subtable enums + constructors (3.5 MB)
│   ├── x86-instr-00..07/       ← 8 instruction constructor batches (3-5 MB each)
│   ├── x86-root/               ← instruction enum + parse_instruction()
│   ├── aarch64-*/              ← same pattern, 4 batches
│   └── riscv-*/                ← same pattern, 2 batches
├── test-harness/               ← golden tests + corpus validation
├── slaspec/
│   ├── x86/                    ← Ghidra x86-64 slaspec (Apache 2.0)
│   ├── AARCH64/                ← Ghidra AARCH64 slaspec
│   └── RISCV/                  ← Ghidra RISC-V slaspec
└── .gitignore
```

---

## Build Workflow

```bash
make test                           # generate + build + test (recommended)

# Or manually:
cargo run -p rsleigh-generate       # parse slaspecs, write generated code (~30s)
cargo test -p test-harness          # parallel compile + run 223 tests

# Single architecture:
cargo run -p rsleigh-generate -- x86-64
cargo run -p rsleigh-generate -- aarch64
cargo run -p rsleigh-generate -- riscv
```

---

## Pipeline Architecture

```
.slaspec file
    ↓
file_to_sleigh(path) → Sleigh struct              [parser]
    ↓
generate_split_disassembler() → GeneratedModule[]  [codegen]
    ↓
rsleigh-generate distributes across crates         [multi-crate splitter]
    ↓
Generated crates compile in parallel               [cargo]
    ↓
parse_instruction(bytes, ctx, addr, gs)
  → (inst_next, Vec<DisplayElement>, Vec<PcodeOp>)
    ↓
pcode_ir::optimize(&mut ops)                       [peephole optimizer]
```

### Crate dependency graph (x86-64 shown):

```
pcode-ir → x86-shared → x86-subtables → x86-instr-00 ─┐
                                         x86-instr-01 ─┤
                                         ...           ├→ x86-root → test-harness
                                         x86-instr-07 ─┘
```

The 8 instruction batch crates compile in parallel (~500% CPU on M4).

---

## Key Implementation Details

### ExecutionGenerator (`src/codegen/builder/disassembler/constructor/execution.rs`)

Generates the `lift()` function for each constructor. Key design:

- **Subtable cache:** Each subtable's lift() is called exactly once at the top of
  the function. Results cached in `{field}_ops/{field}_exp/{field}_ref` variables.
  All consumers (expressions, assignments, branches, exports) use the cache.

- **Export propagation:** lift() returns `(Vec<PcodeOp>, Option<Varnode>, Option<RefInfo>)`.
  The second element is the export value, the third is reference info (space + address)
  for memory-reference exports.

- **Reference vs value exports:** Register-space references (e.g. `export ZF`) produce
  direct Register varnodes. RAM-space references (e.g. `export *[ram]:8 addr`) produce
  address info — consumers emit Load for value reads, Store for writes, or use the
  address directly for branches.

- **Disassembly variables:** Stored as `i128` struct fields (e.g. `calc_reloc`).
  Computed during parse(), recomputed in lift() with correct `inst_next` from the
  parent instruction.

- **Dynamic lookups:** `VarnodeDynamic`, `IntDynamic`, `DynVarnode` all use
  `dynamic_value_expr()` + `dynamic_varnode_expr()`/`dynamic_int_expr()` helpers
  to generate runtime match tables from AttachVarnode/AttachNumber tables.

### Peephole Optimizer (`pcode-ir/src/lib.rs`)

Three passes:
1. **Identity Subpiece elimination** — `Subpiece { lsb: 0 }` with same input/output size → Copy
2. **Copy chain forwarding** — single-use Copy to Unique → substitute and remove
3. **Dead code elimination** — writes to Unique varnodes never read → remove

### sleigh-rs Fixes

Patches to the forked sleigh-rs semantic layer:

- Allow non-exporting tables as read values in execution expressions
  (needed for AARCH64 NEON pcodeop arguments)
- Handle tables without exports in FieldSizeMut (return default instead of panic)
- Implement write-to-table-export for Const/Value export types
  (needed for RISC-V float instructions)

---

## Remaining Known Limitations

- **ExprValue::Context** — stub returns constant(0). Context fields are never used
  in P-code execution expressions for any of our 3 architectures. Would need context
  passed to lift() to properly support.

- **ExprNew / ExprCPool** — stub returns constant(0). Only appears in JVM bytecode
  and WASM specs, not in x86/ARM/RISC-V.

- **Branch target off-by-one** — subtable `inst_next` computed from local pattern_len,
  not parent's full instruction length. Partially fixed by recomputing disassembly
  variables in lift(), but some edge cases may remain for deeply nested subtables.

---

## What We Are NOT Building (scope boundary)

- **SSA construction** — done in Spectra's analysis layer
- **Structure recovery** (if/else, loops) — done in Spectra
- **Type inference** — done in Spectra
- **Pseudocode generation** — P-code is the output, LLM does the rest
- **An interpreter** — we generate code, we don't interpret at runtime

---

## Next Steps

1. **Spectra integration** — wire `parse_instruction()` as Ghidra JVM replacement
2. **More architectures** — MIPS, PowerPC, ARM32, SPARC (~15 min each)
3. **CI** — GitHub Actions `make test` on push
4. **Generated code size reduction** — share common flag computation patterns
