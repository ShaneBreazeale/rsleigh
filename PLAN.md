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
- **Call argument tracking** — function args visible inline: `GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString")`
- **RTTI vtable resolution** — `*param_0 = std::bad_array_new_length::vftable` from PE RTTI metadata
- **Wide string support** — UTF-16LE: `L"ntdll.dll"`, `L"Software\\Sysinternals"`
- **Global variable naming** — repeated addresses → `DAT_14008b128`
- **Malware analysis annotations** — 24 suspicious APIs flagged (VirtualAlloc, CreateRemoteThread, etc.), Win32 constants (STILL_ACTIVE, PAGE_EXECUTE_READWRITE), stack cookie detection
- **PE function discovery** — entry point + CALL-target scanning for stripped binaries
- **Malformed PE support** — manual PE parser fallback for corrupted import directories (Stuxnet)
- **x86-32 cdecl argument tracking** — `CreateProcessA(var_54, 0, 0, 134217728, ...)` with all args
- **Security hardening** — bounds-checked VarId, recursion limits, checked arithmetic, fuzz tests
- **CLI tool** — `rsleigh` binary for decompiling any supported binary
- **Spectra integration** — native backend with ASM/P-code/decompiler views

### Ghidra Comparison (PsExec64.exe)

| Feature | Ghidra 11.3 | rsleigh |
|---|---|---|
| Call arguments | `GetProcAddress(pHVar2, "RtlInit...")` | `GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInit...")` |
| Array indexing | `param_1[2] = 0` | `param_0[2] = 0` |
| String resolution | `"bad array new length"` | `"bad array new length"` |
| Wide strings | `L"ntdll.dll"` | `L"ntdll.dll"` |
| RTTI vtables | `std::bad_array_new_length::vftable` | `std::bad_array_new_length::vftable` |
| Local declarations | `ulonglong uVar2;` | `long lVar1;` |
| Function signature | `void FUN_140001100(...)` | `int func_140001100(...)` |
| Param count (Win64) | 3 (correct) | 3 (correct) |
| Global naming | `DAT_14008b128` | `DAT_14008b128` |
| Malware annotations | None | `⚠ spawn process`, `⚠ registry modification` |
| Malformed PE | Crashes on Stuxnet | Manual fallback with 48 kernel APIs resolved |
| PE32 cdecl args | `CreateProcessA(0, param_1, ...)` | `CreateProcessA(var_54, 0, 0, 134217728, ...)` |
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

### Stack Frame Reconstruction (P2)
- Buffer sizes not inferred from access patterns
- `long lVar1` should be `char buf[32]` when memset(lVar1, 0, 32) is visible
- Scan all Store/Load ops to stack-relative addresses, cluster by offset, infer sizes

### Pointer Type Propagation (P2)
- `long param_0` should be `undefined8 *param_0` when used as array base
- Track pointer arithmetic: `ptr + offset` stays pointer, `ptr - ptr` → integer
- Infer pointee types from Load/Store sizes

### Return Value → Argument Chaining (P3)
- `pHVar2 = GetModuleHandleW(L"ntdll.dll"); GetProcAddress(pHVar2, ...)` 
- Currently the return value assignment isn't shown; Ghidra creates a named local
- Need: when a call return register is used in the next call, emit assignment

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
