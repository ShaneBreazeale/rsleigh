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
│   ├── lib.rs                  ← public API (re-exported)
│   └── src/
├── rsleigh-decompile/          ← 5-pass decompiler (CFG → SSA → fold → structure → print)
│   ├── data/
│   │   ├── signatures.json     ← 889 curated function signatures (Apache 2.0)
│   │   └── signatures.tsv.gz   ← 36K+ bulk signatures (gzipped, auto-loaded)
│   └── src/
│       ├── cfg.rs              ← P-code to basic blocks + control flow graph
│       ├── dominators.rs       ← dominator tree computation
│       ├── dwarf.rs            ← DWARF debug info parsing (gimli) + macOS dSYM
│       ├── fold.rs             ← expression folding, dead code, condition recovery
│       ├── imports.rs          ← PLT/GOT/stub → import name resolution
│       ├── ir.rs               ← decompiler IR types (VarDef with display_type)
│       ├── pdb_info.rs         ← PDB debug info parsing for PE binaries
│       ├── printer.rs          ← C printer with RegTracker for copy elision
│       ├── signatures.rs       ← signature DB: lookup, runtime JSON, embedded TSV
│       ├── signatures_libc.rs  ← 176 hand-tuned libc/POSIX signatures
│       ├── signatures_win32.rs ← 128 hand-tuned Win32 signatures (HKEY, HWND, etc.)
│       ├── ssa.rs              ← SSA construction with Phi insertion
│       └── structure.rs        ← if/else, while loop recovery from dominators
├── rsleigh-cli/                ← CLI: decompile any binary to C pseudocode
├── scripts/
│   └── extract-ghidra-sigs.py  ← extract signatures from Ghidra .gdt archives
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

**Requirements:** Rust 2021 edition (stable), `make` for the recommended workflow.

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
- Standard optimizations: algebraic simplification, single-use temp inlining, copy propagation, dead flag elimination (x86 CF/ZF/SF/OF, ARM64 NG/ZR/CY/OV)
- Condition recovery: compound Jcc flag patterns → comparisons
  (e.g., BoolAnd(BoolNot(ZF), IntEq(OF,SF)) → `a > b`)
- Call argument collection (runs BEFORE fold to prevent DCE of arg registers):
  x86-64 SysV, Windows x64 (auto-detected from PE), x86-32 cdecl/thiscall (stack-pushed)
- Division-by-constant (multiply+shift → `x / 7`) and modulo (`x - (x/D)*D` → `x % D`)
- Loop body preservation: register writes in back-edge blocks protected from DCE
- **Type inference** (3-phase: seed → forward → backward): float, signed, unsigned, pointer, bool propagation from P-code op semantics
- **Signature-based type propagation:** 38K+ function signatures auto-loaded; param types
  and return types propagate through call chains with `display_type` typedef system
- **Interprocedural types (two-pass):** first pass learns internal function types from
  API call arguments, second pass applies them (HKEY, REGSAM, DWORD propagate across calls)
- **Backward Load propagation:** `Load(param)` with typed result → param gets the type

**Printer (printer.rs):**
- Ghidra-style output: typed signatures, local var declarations, auto-named registers
- RegTracker: per-block register value tracking enables copy elision at print time
- Call return inlining: `printf("...", add(3, 4))` not `add(); printf("...", add())`
- Stack alias resolution: var_c → var_8 → param_0 chain; save/restore elision hides spills
- Import resolution: ELF PLT/GOT (CET bnd jmp), Mach-O indirect, PE IAT (UPX-unpacked)
- Manual PE import fallback: handles malformed binaries with corrupted import dirs (Stuxnet)
- ELF32 PIE: GOT-relative string resolution, `__x86.get_pc_thunk` hiding
- String literals: read-only section detection (filters .data, magic constants),
  wide strings (UTF-16LE: `L"ntdll.dll"`), C++ demangling (ELF + Mach-O)
- DWARF debug info: param names from `.debug_info` (DWARF4/5, macOS dSYM auto-discovery)
- PDB debug info: function names and types from PE `.pdb` files
- **Function signature database** (38K+ signatures, auto-loaded):
  - `/* param_name */` annotations at call sites: `fread(/*ptr*/ buf, /*size*/ 1, /*nmemb*/ 64, /*stream*/ file)`
  - Win32 typedef display: HANDLE, HKEY, HWND, DWORD, REGSAM, LSTATUS, LRESULT, WPARAM, LPARAM
  - 889 curated JSON + 304 macro + 36K embedded TSV — covers libc, POSIX, Linux, macOS, Win32, Android, OpenSSL
  - Interprocedural propagation: internal function params typed from API call context
- Ghidra-style local declarations: `WCHAR local_8[262]; int local_c;` with array sizing from offset gaps
- PE import thunk resolution: `JMP [IAT_addr]` stubs → import names
- MSVC CRT wrapper recognition: `__acrt_iob_func + __stdio_common_vfprintf` → `printf`
- Control flow recovery: for-loops, switch/case (jump tables), else-if chain collapse
- Simplifications: dead stores, unreachable returns, phi artifact cleanup, increment shorthand,
  constant folding, ESP/RSP stack noise elimination, pointer deref simplification
- MSVC RTTI: vtable → COL → TypeDescriptor → class name resolution
- **Malware analysis:** Win32 constant annotation, suspicious API flagging (24 APIs),
  stack cookie detection, dynamic resolve pattern recognition

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
- **Type inference** — basic signed/float/pointer/bool + Win32 typedef propagation;
  no constraint-based inference, no full struct recovery
- **Stack frame reconstruction** — buffer sizes inferred from offset gaps; no field-level typing
- **Loop conditions** — `while (OF == SF)` not always recovered to source comparison
- **x86-32 control flow** — sequential TEST/JNZ patterns sometimes nest incorrectly
- **Register-indirect calls** — `CALL EDI` where EDI was loaded from IAT earlier
  not resolved to import names (only direct IAT calls resolved)

---

## Spectra Integration

Wired into Spectra via `rsleigh-api` + `rsleigh-decompile`:
- Settings > Analysis: toggle between "Native (rsleigh)" and "Ghidra"
- Function discovery: symbol tables + recursive descent from CALL targets + prologue scanning
- ASM view: native disassembly via `get_disasm`
- P-code view: structured ops via `get_pcode`
- Code view: decompiled pseudocode with syntax highlighting
  (registers blue, variables amber, functions clickable, dangerous APIs red)
- All decode runs on 32MB stack threads (x86 pattern recursion depth)

## License

Apache 2.0
