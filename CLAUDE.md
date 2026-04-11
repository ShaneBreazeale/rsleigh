# CLAUDE.md — rsleigh

## What This Is

A unified Rust workspace that:
1. Parses Ghidra's `.slaspec` architecture definitions
2. Generates Rust code that decodes instructions and emits P-code IR
3. Decompiles P-code into C-like pseudocode with string literals, import names, and condition recovery

**Goal:** Pure Rust, zero C++ deps — a complete disassembly + decompilation pipeline
using the same `.slaspec` files Ghidra ships (Apache 2.0).

Wired into Spectra as a native analysis backend replacing the Ghidra JVM daemon.

---

## Current Status

**Working end-to-end for 6 architectures:**

| Architecture | Constructors | Extensions |
|---|---|---|
| x86-64 | 5700+ | full |
| x86-32 | 4200+ | SSE/AVX, PE32 import resolution |
| AArch64 | 3500+ | NEON + SVE |
| ARM32 | 1200+ | ARMv7 + Thumb |
| MIPS32 | 900+ | FPU + DSP + MIPS16 + microMIPS |
| RISC-V 64 | 500+ | F/D/B/K/P/Q/V/C |

**9 test categories, ~6000 assertions:** golden P-code, stress/boundary, functional
sequences, bug probes, compiled code patterns, Ghidra differential, decompiler
comparison, CTF binary validation, fuzz (5000 random byte sequences, zero panics).

**Decompiler output (real binary, with DWARF debug info):**
```
return a + b;                                    // add() — DWARF param names recovered
printf("add(3, 4) = %d\n", add(3, 4));
printf("factorial(5) = %d\n", factorial(5));
printf("reversed: %s\n", reverse_string(RBP + 0xd0));
```

---

## Workspace Structure

```
rsleigh/
├── Cargo.toml                  ← workspace root
├── src/                        ← SLEIGH parser + Rust codegen library
│   ├── codegen/                ← code generation from SLEIGH
│   │   └── builder/disassembler/constructor/
│   │       ├── execution.rs    ← P-code emission + dynamic register lookup
│   │       ├── pattern.rs      ← pattern matching codegen
│   │       ├── disassembly.rs  ← disassembly variable codegen
│   │       └── mod.rs          ← constructor struct generation
│   └── semantic/               ← SLEIGH semantic analysis (forked sleigh-rs)
├── pcode-ir/                   ← P-code types + peephole optimizer (no_std, zero deps)
├── rsleigh-api/                ← High-level Decoder API + register name resolution
├── rsleigh-decompile/          ← 5-pass decompiler (CFG → SSA → fold → structure → print)
│   ├── cfg.rs                  ← P-code to basic blocks + control flow graph
│   ├── ssa.rs                  ← SSA construction with Phi insertion
│   ├── fold.rs                 ← expression folding, dead code, condition recovery
│   ├── structure.rs            ← if/else, while loop recovery from dominators
│   ├── printer.rs              ← C printer with RegTracker for copy elision
│   ├── imports.rs              ← PLT/GOT/stub → import name resolution
│   └── dwarf.rs               ← DWARF debug info parsing (gimli) + macOS dSYM
├── rsleigh-generate/           ← CLI: parse slaspecs, write generated crate source
├── generated/                  ← Output crates (gitignored /out/ dirs)
│   ├── x86-{shared,subtables,instr-00..07,root}/       (64-bit)
│   ├── x86-32-{shared,subtables,instr-00..03,root}/    (32-bit, native ESP/EBP)
│   ├── aarch64-{shared,subtables,instr-00..03,root}/
│   ├── arm32-*, mips-*, riscv-*/
├── test-harness/               ← golden tests, corpus, fuzz, decompiler validation
└── slaspec/                    ← Ghidra .slaspec files (Apache 2.0)
```

---

## Build

```bash
make test                           # generate + build + test (recommended)
cargo run -p rsleigh-generate       # parse slaspecs (~30s)
cargo test -p test-harness          # compile + run all tests
```

---

## Pipeline

```
.slaspec → parser → codegen → generated Rust crates → compile
                                                         ↓
bytes + addr → Decoder::decode() → Instruction { disassembly, ops: Vec<PcodeOp> }
                                                         ↓
                    decompile_with_binary() → CFG → SSA → fold → structure → C pseudocode
```

---

## Key Implementation Details

### Codegen (`src/codegen/builder/disassembler/constructor/execution.rs`)

- **Subtable cache:** lift() called once per subtable, results cached
- **Unique offset scheme:** parent uses `(num_fields*2+2)*0x10000` to avoid collision
  with subtable exports (fixed a deep bug where CMP operands collided)
- **Dynamic register lookup:** `dynamic_value_expr()` resolves aliased token fields
  by bit position (e.g., r32 and r64 share bits 0-2 — fixed a bug where all registers
  mapped to RAX)
- **Signed displacements:** `gen_dis_expr_for_lift()` casts signed token fields
  (simm8, simm16) to the appropriate signed type before widening to i128
- **Const-space references:** `export *[const]:4 simm8` resolved directly to
  `Varnode::constant()` instead of emitting a Load

### Decompiler (`rsleigh-decompile/`)

5-pass pipeline: CFG → SSA → fold → structure recovery → C printer

**SSA builder (ssa.rs):**
- Iterative dataflow: multi-pass convergence (max 4 passes) for loop headers and merge points
- Multi-predecessor blocks inherit from first processed predecessor
- Blocks re-processed when predecessor exit vars change (fixes back-edges)
- Phi insertion at join points from converged exit maps

**CFG builder (cfg.rs):**
- CallInd resolution: `CALL [IAT_addr]` → traces Load source to constant, converts to Direct
- x86-32 CALL boilerplate stripping: removes return address push from P-code ops
- x86-32 RET boilerplate stripping: removes stack pop from P-code ops

**Fold passes (fold.rs):**
- Algebraic simplification (x & x → x, x ^ x → 0)
- Single-use temp inlining
- Multi-level register copy propagation
- Dead flag elimination (x86 CF/ZF/SF/OF, ARM64 NG/ZR/CY/OV)
- Condition recovery: compound Jcc patterns → comparisons
  (BoolAnd(BoolNot(ZF), IntEq(OF,SF)) → JG → `a > b`)
- Call return value propagation
- Parameter naming from ABI registers (SysV or Windows x64, auto-detected)
- Call argument collection from arg register writes (x86-64 SysV: RDI/RSI/RDX/RCX/R8/R9,
  Windows x64: RCX/RDX/R8/R9)
- Stack-pushed argument collection for cdecl/thiscall (x86-32)
- Division-by-constant recognition (multiply+shift → `x / 7`, SAR+ADD → `x / 7`)
- Modulo pattern matching (`x - (x/D)*D` → `x % D`)
- Loop body preservation (register writes in back-edge blocks protected from DCE)
- **Type inference** (3-phase: seed → forward → backward propagation):
  - Float: FloatAdd/FloatMult/Int2Float → `float`/`double`
  - Signed: SDiv/SLess/Sext/Neg → `int`/`int64_t`
  - Unsigned: Div/Less/Zext → `uint32_t`/`uint64_t`
  - Pointer: Load/Store addresses → pointer type
  - Bool: comparisons, flag registers → boolean context

**Printer (printer.rs):**
- Function signatures: `int func_name(long param_0, int param_1)` with typed return
- Local variable declarations: `long lVar1; int iVar2;` Ghidra-style block
- Auto-named registers: `R14` → `lVar1`, `R12D` → `iVar2`, `DIL` → `bVar1`
- Array indexing: `->field10` → `[2]` for aligned offsets
- C++ demangling: `_ZN5phttp10InitializeEv` → `phttp::Initialize` (ELF + Mach-O)
- Errno recognition: `__error(); *(uint32_t*)(RAX) = 22` → `errno = 22 /* EINVAL */`
- POSIX errno annotations: `== 4 /* EINTR */`, `!= 35 /* EAGAIN */`
- RegTracker: per-block register value tracking at print time
- Call return inlining: `printf("...", add(3, 4))` not `add(); printf("...", add())`
- Stack alias resolution: var_c → var_8 → param_0 chain
- Save/restore elision: register spills across calls hidden
- Import name resolution: ELF PLT/GOT (CET bnd jmp), Mach-O indirect, PE IAT (UPX-unpacked)
- ELF32 PIE: GOT-relative string resolution, __x86.get_pc_thunk hiding
- DWARF debug info: parameter names from `.debug_info` (DWARF4/5, macOS dSYM auto-discovery)
- String literal detection from read-only binary sections (filters .data, magic constants)
- For-loop recovery: `while` + increment → `for (; cond; i++)`
- Switch/case: jump table → `switch (d) { case 0: return "Sunday"; }`
- Division-by-constant display: `x * 0x55555556 >> 32` → `x / 3`
- Modulo display: `x/D * D; x - result` → `x % D`
- Consecutive printf/puts merging into single call
- Dead store before return removal
- Unreachable return after complete if/else removal
- Constant-vs-constant comparison folding
- x86-32 ESP / x86-64 RSP stack noise elimination
- Duplicate ESP/RSP store dedup (cdecl arg push noise)

### Peephole Optimizer (`pcode-ir/src/lib.rs`)

- Identity Subpiece elimination
- Copy chain forwarding with batch analysis
- Dead code elimination (batch collection, reverse removal)
- Overwrite elimination
- Output sinking (unique → copy dest)
- Redundant IntAnd collapse

---

## Known Limitations

- **ExprValue::Context** returns 0 (not used by x86/ARM/RISC-V)
- **ExprNew / ExprCPool** returns 0 (JVM/WASM only)
- **Expression completeness** — some register values not traced back to their defining
  expression (e.g., `iVar1 * factorial(n-1)` instead of `n * factorial(n-1)`)
- **Type inference** — basic signed/float/pointer/bool propagation; no constraint-based
  inference, no struct/array recovery, no interprocedural types
- **RTTI / vtable resolution** — PE vtable addresses shown as hex, not resolved to C++ type names
- **Loop conditions** — `while (OF == SF)` not always recovered to source comparison
- **x86-32 control flow** — sequential TEST/JNZ patterns sometimes nest incorrectly
- **Register-indirect calls** — `CALL EDI` where EDI was loaded from IAT earlier
  not resolved to import names (only direct IAT calls resolved)

---

## Spectra Integration

Wired into Spectra via `rsleigh-api` + `rsleigh-decompile`:
- Settings > Analysis: toggle between "Native (rsleigh)" and "Ghidra"
- Function discovery: symbol tables + recursive descent from CALL targets
- ASM view: native disassembly via `get_disasm`
- P-code view: structured ops via `get_pcode`
- Code view: decompiled pseudocode with syntax highlighting
  (registers blue, variables amber, functions clickable, dangerous APIs red)
- All decode runs on 32MB stack threads (x86 pattern recursion depth)

## License

Apache 2.0
