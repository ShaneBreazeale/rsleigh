# rsleigh — Development Plan

> Technical reference: see CLAUDE.md
> Public-facing overview: see README.md

---

## Current State

rsleigh is a working end-to-end disassembly and decompilation pipeline for 6 architectures, producing Ghidra-comparable output for many function types. Tested against Sysinternals PE64 tools (PsExec, strings64), tinyssh, real CTF binaries, and compiled C/C++ code.

### Completed Milestones

- **SLEIGH parser + codegen** — parses all 6 architecture slaspecs, generates split Rust crates
- **Decoder API** — x86-64, x86-32, AArch64, ARM32, MIPS32, RISC-V 64
- **P-code IR + optimizer** — peephole optimization (no_std, zero deps)
- **5-pass decompiler** — CFG → SSA → fold → structure → print
- **Iterative SSA dataflow** — multi-pass convergence for loop headers and merge points
- **Type inference** — signed/unsigned/float/pointer/bool from P-code operation context
- **Calling convention detection** — SysV (Linux/macOS), Windows x64, x86-32 cdecl/thiscall
- **Import resolution** — ELF PLT/GOT (CET-enabled), Mach-O indirect symbols, PE IAT (UPX-unpacked)
- **C++ demangling** — ELF and Mach-O symbol demangling via cpp_demangle
- **Function signatures** — typed parameters, return type, real function names from symbols
- **Local variable declarations** — Ghidra-style `long lVar1; int iVar2;` blocks
- **Array indexing** — `param_0[2]` from struct field offsets
- **Pattern recognition** — division-by-constant, modulo, for-loops, switch/case, string merging
- **DWARF debug info** — parameter names, local variables, struct fields (DWARF4/5, macOS dSYM)
- **Errno recognition** — `__error()` + store → `errno = N /* EINVAL */`
- **ELF32 PIE support** — GOT-relative string resolution, __x86.get_pc_thunk hiding
- **PE function discovery** — entry point + CALL-target scanning for stripped binaries
- **Security hardening** — bounds-checked VarId, recursion limits, checked arithmetic, fuzz tests
- **CLI tool** — `rsleigh` binary for decompiling any supported binary
- **Spectra integration** — native backend with ASM/P-code/decompiler views

### Ghidra Comparison (PsExec64.exe)

| Feature | Ghidra 11.3 | rsleigh |
|---|---|---|
| Array indexing | `param_1[2] = 0` | `param_0[2] = 0` |
| String resolution | `"bad array new length"` | `"bad array new length"` |
| Local declarations | `ulonglong uVar2;` | `long lVar1;` |
| Function signature | `void FUN_140001100(...)` | `int func_140001100(...)` |
| Param count (Win64) | 3 (correct) | 3 (correct) |
| vtable resolution | `std::bad_array_new_length::vftable` | `0x14004a830` |
| C++ demangling | Yes (ELF) | Yes (ELF + Mach-O) |

---

## Active Work

### Expression Completeness (P1)
- Register values not always traced back to their defining expression
- `iVar1 * factorial(n - 1)` should show `n * factorial(n - 1)`
- Root cause: `format_var` shows auto-named register instead of SSA expression
- Needs SSA-level provenance tracking (distinguishing call returns from param copies)
- Printer-level Var chain following was attempted but caused regressions

### Control Flow Structure Recovery (P1)
- Sequential TEST/JNZ patterns sometimes nest incorrectly as deep if/else trees
- Dominator-based recovery doesn't distinguish sequential guards from nested conditionals

### RTTI / Vtable Resolution (P2)
- PE `.rdata` section contains vtable pointers with RTTI type info
- Could resolve `0x14004a830` → `std::bad_array_new_length::vftable`
- Requires parsing PE exception directory and type descriptors

### Pointer Type Propagation (P2)
- `long param_0` should be `undefined8 *param_0` when used as array base
- Track pointer arithmetic: `ptr + offset` stays pointer, `ptr - ptr` → integer
- Infer pointee types from Load/Store sizes

---

## Future Work

### Near-term
- **do-while loop detection** — Ghidra detects these, rsleigh only has while
- **Pointer cast cleanup** — `*(uint64_t*)(param_0)` → `*param_0` when type is known
- **Windows API constant annotation** — `0xfffffff5` → `STD_ERROR_HANDLE`
- **Return value propagation** — `return param_0` instead of `return 0x14004a830`

### Medium-term
- **Interprocedural analysis** — propagate types and signatures across call boundaries
- **Stack frame reconstruction** — infer local variable layout from access patterns
- **Full struct/array type recovery** — base+index*scale → typed arrays

### Long-term
- **Constraint-based type inference** — Hindley-Milner across the function
- **vtable dispatch recognition** — virtual method calls → readable form
- **Cross-function decompilation** — inline small callees, propagate constants

---

## Architecture

```
.slaspec → parser (src/) → codegen → generated Rust crates (generated/)
                                                    ↓
bytes + addr → Decoder (rsleigh-api) → Instruction { disassembly, ops: Vec<PcodeOp> }
                                                    ↓
                         Decompiler (rsleigh-decompile):
                           CFG (branch resolution, IAT, CALL stripping)
                             → SSA (iterative dataflow, phi insertion)
                               → fold (type inference, conditions, args, calling conv)
                                 → structure (if/else, while/for, switch, depth limit)
                                   → printer (signatures, declarations, auto-naming,
                                              demangling, imports, DWARF, strings, errno)
```

---

## Test Strategy

| Category | Count | What it validates |
|---|---|---|
| Golden P-code | 145 | Exact decode assertions per architecture |
| Stress/boundary | ~50 | Sign-extension, overflow, prefix edge cases |
| Functional | 14 | Multi-instruction sequences (prologues, calls, loops) |
| Bug probes | 55 | All 16 Jcc variants, IDIV, MOVZX/MOVSX, ARM LDR |
| Compiled patterns | ~100 | Canaries, switch tables, SETcc, LOCK, SSE2, PLT/GOT |
| Ghidra differential | ~300 | P-code output compared against Ghidra |
| Decompiler comparison | 11 | Side-by-side with Ghidra 12 |
| CTF validation | 30+ | Real stripped binaries decompiled successfully |
| Decoder fuzz | 1000 | Random bytes, zero panics |
| Decompiler fuzz | 200 | Random instruction sequences through full pipeline, zero panics |
