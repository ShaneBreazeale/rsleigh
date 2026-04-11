# rsleigh — Development Plan

> Technical reference: see CLAUDE.md
> Public-facing overview: see README.md

---

## Current State

rsleigh is a working end-to-end disassembly and decompilation pipeline for 6 architectures. It parses Ghidra `.slaspec` files, generates native Rust decoders, and decompiles P-code IR into C-like pseudocode. Integrated into Spectra as the native analysis backend.

### Completed Milestones

- **SLEIGH parser + codegen** — parses all 6 architecture slaspecs, generates split Rust crates
- **Decoder API** — `rsleigh-api` decodes instructions across x86-64, x86-32, AArch64, ARM32, MIPS32, RISC-V 64
- **P-code IR + optimizer** — `pcode-ir` crate with peephole optimization (no_std, zero deps)
- **5-pass decompiler** — CFG → SSA → fold → structure → print, producing readable C pseudocode
- **Type inference** — signed/unsigned/float/pointer/bool propagation from P-code operation context
- **Import resolution** — ELF PLT/GOT, Mach-O indirect symbols, PE IAT (including UPX-unpacked)
- **DWARF debug info** — parameter names, local variables, struct fields (DWARF4/5, macOS dSYM)
- **Binary format support** — ELF, Mach-O, PE32/PE64 auto-detected
- **CLI tool** — `rsleigh` binary for decompiling any supported binary
- **Spectra integration** — native backend with ASM/P-code/decompiler views, syntax highlighting
- **Test suite** — 9 categories, ~6000 assertions, 30+ CTF binaries, zero fuzz panics

---

## Active Work

### Decompiler Quality

**Control flow structure recovery** (P1)
- Sequential TEST/JNZ patterns sometimes nest incorrectly as deep if/else trees
- Should produce flat sequential `if (!result) { error(); }` blocks
- Root cause: dominator-based structure recovery in `structure.rs` doesn't distinguish
  sequential guards from nested conditionals
- Fix: detect chains of blocks with single-statement bodies targeting the same merge point

**Register-indirect call resolution** (P2)
- `CALL EDI` where EDI was loaded from IAT earlier in the function not resolved
- Direct IAT calls (`CALL [0x428298]`) already resolve via `resolve_callind_target`
- Need: forward dataflow tracking for register values loaded from known IAT addresses
- Scope: `fold.rs` constant propagation needs to track through register copies

**CMOV/CSEL return value recovery** (P2)
- `max_val` and `abs_val` at -O2 show empty `return;` instead of the conditional value
- CMOV expansion creates synthetic if/else blocks but the value doesn't flow to return
- Fix: track the output register of CMOV through the merge point to the return

**x86-32 ESP noise** (P3)
- Function prologues still show some raw ESP manipulation
- SSA-level stack argument collection works but prologue/epilogue PUSH/POP of
  callee-saved registers still visible
- Fix: recognize and elide EBP frame setup + callee-saved register save/restore patterns

### Type System

**Deeper pointer inference** (P2)
- Track pointer arithmetic: `ptr + offset` stays pointer, `ptr - ptr` → integer
- Infer pointee types from Load/Store sizes: `*(int*)(ptr)` when loading 4 bytes through a pointer
- Struct field access: consecutive loads at known offsets from same base → struct fields

**Float constant display** (P3)
- Float constants loaded from binary memory should display as `1.0f`, `3.14`, etc.
- Currently shows hex addresses for constants loaded via `MOVSD xmm0, [rip+offset]`
- Partial support exists for reciprocal detection (`* *(addr)` → `/ 1024.0`)

### Architecture Support

**PE32 calling convention refinement** (P2)
- stdcall: callee cleans stack (detected via `RET N`)
- fastcall: first 2 args in ECX/EDX, rest on stack
- Currently only cdecl (caller-cleans) and basic thiscall (ECX=this)

**MIPS delay slots** (P3)
- Delay slot instruction should be folded into the branch semantics
- Currently emitted as a separate instruction after the branch

---

## Future Work

### Near-term (well-understood, bounded scope)

- **Division-by-constant pattern matching** — recognize `x * 0x92492493 >> 34` as `x / 7`
- **Switch/case recovery** — jump table detection works, need structured `switch` output
- **For-loop recovery** — detect `init; while (cond) { body; increment; }` → `for` loops
- **String concatenation** — consecutive `printf` / `puts` with related strings → single operation

### Medium-term (significant engineering)

- **Interprocedural analysis** — propagate types and signatures across call boundaries
- **Stack frame reconstruction** — infer local variable layout from access patterns
- **Array/struct type recovery** — base+index*scale patterns → array access, field offsets → structs
- **Calling convention auto-detection** — infer from stack behavior instead of assuming

### Long-term (research-grade)

- **Full type inference** — Hindley-Milner style constraint solving across the function
- **Higher-level pattern recovery** — vtable dispatch, exception handling, coroutines
- **Cross-function decompilation** — inline small callees, propagate constants across calls

---

## Architecture

```
.slaspec → parser (src/) → codegen → generated Rust crates (generated/)
                                                    ↓
bytes + addr → Decoder (rsleigh-api) → Instruction { disassembly, ops: Vec<PcodeOp> }
                                                    ↓
                         Decompiler (rsleigh-decompile):
                           CFG → SSA → fold (type inference, conditions, args)
                                         → structure (if/else, while)
                                           → printer (C output, imports, DWARF, strings)
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
| Fuzz | 5000 | Random bytes, zero panics |
