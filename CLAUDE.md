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

**Working end-to-end for 7 architectures:**

| Architecture | Constructors | Extensions |
|---|---|---|
| x86-64 | 5700+ | full |
| x86-32 | 4200+ | SSE/AVX, PE32 import resolution |
| AArch64 | 3500+ | NEON + SVE |
| ARM32 | 1200+ | ARMv7 + Thumb + VFP/NEON floats |
| MIPS32 | 900+ | FPU + DSP + MIPS16 + microMIPS |
| RISC-V 64 | 500+ | F/D/B/K/P/Q/V/C |
| WebAssembly | — | WASM module decompilation |

**Supported binary formats:** ELF (32/64), PE (32/64), Mach-O (64), WASM (.wasm), Raw binary (any arch).

**240 tests, ~7200+ assertions:** golden P-code, stress/boundary, functional
sequences, bug probes, compiled code patterns, Ghidra differential, decompiler
comparison, CTF binary validation, fuzz (5000 random byte sequences, zero panics),
Spectra API contract tests (decoder/decompile/analysis/multi-arch), Spectra native
backend integration tests (10 tests covering end-to-end pipeline),
pseudocode quality regression tests (14 audit fixes), rsleigh-cli
per-fixture regression tests (12 integration tests covering flag-subexpr
recovery, Go preamble, STACKSTR pointer writes, bswap64 SiMBA, setne
sub-register write, thunk misdetection, REP-STOSB DF seed, and
phi-ternary rewrite — no phi() leaks, conditional ternaries emit,
self-identity ternaries collapse).
See `docs/TESTING.md` for the full test suite documentation.

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
│       ├── eqsat.rs            ← equality saturation MBA deobfuscation (egg crate)
│       ├── signatures.rs       ← signature DB: lookup, runtime JSON, embedded TSV
│       ├── signatures_libc.rs  ← 176 hand-tuned libc/POSIX signatures
│       ├── signatures_win32.rs ← 128 hand-tuned Win32 signatures (HKEY, HWND, etc.)
│       ├── ssa.rs              ← SSA construction with Phi insertion
│       ├── structure.rs        ← if/else, while/do-while loop recovery from dominators
│       ├── analysis.rs         ← FunctionMeta, VulnFinding, CallGraphEntry (serde::Serialize)
│       └── cpp_class.rs        ← C++ class/vtable/hierarchy recovery (MSVC + GCC RTTI)
├── rsleigh-fid/                ← Function ID: body fingerprinting against bundled DBs
│   ├── data/
│   │   ├── MANIFEST.tsv        ← source URL + SHA256 for each bundled .fidb
│   │   ├── glibc-{x86_64,aarch64}.fidb      ← Debian 12 libc 2.36 (2221/2330)
│   │   ├── libstdcxx-{x86_64,aarch64}.fidb  ← Debian 12 libstdc++ 12.2 (3463/3375)
│   │   ├── musl-{x86_64,aarch64}.fidb       ← Alpine 3.21 musl 1.2.5 (1083/1140)
│   │   └── qt_signatures.tsv.gz  (in rsleigh-decompile/data/; 23K Qt5 sigs)
│   └── src/
│       ├── hash.rs             ← xxh3 full + specific (callee-aware) hash quad
│       ├── mask.rs             ← per-arch operand masking (x86/AArch64/ARM32/MIPS/RISC-V)
│       ├── db.rs               ← compact gzipped binary FID format w/ hash indices
│       ├── ingest.rs           ← fingerprint() drives rsleigh-api Decoder
│       ├── lib.rs              ← identify() unique-match + C++ ABI variant resolver
│       └── bin/gen.rs          ← rsleigh-fid-gen CLI for building .fidb
├── rsleigh-cli/                ← CLI: decompile any binary to C pseudocode
├── scripts/
│   ├── extract-ghidra-sigs.py  ← extract signatures from Ghidra .gdt archives
│   ├── extract-qt-sigs.py      ← extract Qt5 .so dynsym → signatures.tsv rows
│   └── build-fid-dbs.sh        ← reproducible distro-pkg fetch → .fidb builder
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

### CLI (`rsleigh-cli`)

```bash
rsleigh <binary>                       # list functions
rsleigh <binary> <func> [func2..]      # decompile functions (name or 0xAddr)
rsleigh <binary> --all                 # decompile all (two-pass type propagation)
rsleigh <binary> --disasm <func>       # disassemble with P-code
rsleigh <binary> --sigs extra.json     # load additional signatures
rsleigh <binary> --fid file.fidb       # additional FID database (repeatable)
rsleigh <binary> --no-fid-auto         # disable bundled glibc/musl/libstdc++ DBs
rsleigh <binary> --pcode-json <func>   # raw decoded P-code (debug)
rsleigh <binary> --ssa-json <func>     # post-fold SSA state (debug)
rsleigh <binary> --json                # JSON output
rsleigh <binary> --search <query>       # find functions by string/pattern
rsleigh <binary> --search --api <name> # find functions calling specific API
rsleigh <binary> --search --const <hex> # find functions with constant value
rsleigh <binary> --summary             # AI summary (one-line per function)
rsleigh <binary> --xrefs <func>        # cross-references (callers + callees)
rsleigh <binary> --yara                # generate YARA rules from binary
rsleigh <binary> --diff <binary2>      # diff decompilation between two binaries
rsleigh <binary> --taint <func>        # taint analysis on function
rsleigh <binary> --vulnscan            # vulnerability scan (27 patterns, color-coded severity)
rsleigh <binary> --callgraph           # call graph export (JSON with behavioral tags)
rsleigh <binary> --classes             # recover C++ class hierarchies (MSVC + GCC RTTI)
rsleigh <binary> --classes --json      # class hierarchy as structured JSON
rsleigh <binary> --compact             # strip declarations, 2-space indent (24% smaller)
rsleigh <binary> --brief               # calls + control flow only (35% smaller)
rsleigh <binary> --min-complexity N    # skip functions with complexity below N
rsleigh --raw <arch> <binary>          # load raw firmware blob (any arch)
```

Function discovery (beats Ghidra on 15/21 test binaries):
symbol tables → recursive CALL descent → exhaustive CALL target scan (E8/BL) →
`.pdata` exception dirs (PE64 x86-64 + ARM64 8-byte entries) →
`LC_FUNCTION_STARTS` (Mach-O) → `__objc_stubs` + `__stubs` (Mach-O) →
prologue scanning (x86-32/x86-64/AArch64 STP+SUB+ADRP) →
JMP thunk detection (FF 25 / E9) → vtable pointer scanning (.rdata) →
`.rdata` function pointer refs (PE64, strict prologue check) →
ARM32 BL/Thumb BL target scanning.
PE machine type auto-detection: x86-64 (0x8664), ARM64 (0xAA64), i386 (0x014C).

**Stripped ELF discovery** (12 methods): `.eh_frame` FDE unwinding → RTTI vtable pointer
scanning → indirect call target resolution → prologue pattern matching (x86-64 push+sub,
AArch64 STP+SUB+ADRP, ARM32 PUSH+SUB, MIPS addiu sp/sw ra/lui gp) → CALL target enumeration
→ `.init_array`/`.fini_array` function pointer recovery → PLT stub enumeration →
cross-reference analysis. MIPS: JAL/BAL scanning + endian-aware parsing (busybox: 9→5,405).
MIPS PIC indirect call resolution: GP-relative GOT tracing (77% resolved, 423→98 unresolved).

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
- **MixOperations fix:** mixed AND/OR pattern blocks (common in VFP/NEON constructors
  like `(ARM_pattern | Thumb_pattern) & operands`) default to AND instead of erroring,
  treating OR-connected elements as subpatterns
- **Optional table lift fix:** OR-pattern subtables that produce optional table fields
  are lifted via `.as_ref().unwrap()` instead of direct call, preventing type errors
  when a subtable may not be present in all pattern alternatives

### Decompiler (`rsleigh-decompile/`)

5-pass pipeline: CFG → SSA → fold → structure recovery → C printer

**SSA builder (ssa.rs):**
- Iterative dataflow: multi-pass convergence (max 4 passes) for loop headers and merge points
- Multi-predecessor blocks inherit from first processed predecessor
- Blocks re-processed when predecessor exit vars change (fixes back-edges)
- Phi insertion at join points from converged exit maps
- **Deterministic Phi creation:** varnodes sorted by `(space, offset, size)`
  before iterating, so Phi VarId allocation is stable across runs on the same
  binary. HashMap iteration order previously made `rsleigh <binary> <func>`
  non-deterministic, which surfaced as semantically different ternary arms
  after the Phi→Ternary rewrite landed.
- **Sub-register Zext deferral:** groups P-code ops by instruction address; when
  `IntZext(EAX→RAX)` precedes an address calculation that reads RAX within the same
  instruction, the Zext write is deferred to preserve the original pointer value
- **Sub-register write propagation (both directions):** writing to a larger parent
  (RAX 8-byte) also updates the 4-byte alias at the same offset. Writing to a
  smaller child (AL/AX) blends back into any 4/8-byte parent via
  `Zext(child, parent_size)`. Fixes the x86 bool-return idiom
  (`xor eax, eax; setne al; ret`) — before, the stale `Const(0)` from the XOR
  survived through return; after, AL propagates to EAX.
- **Forward-edge predecessor priority:** prevents loop back-edge values from contaminating
  merge points; entry block protected from re-processing
- **ESP_OFFSET fix:** corrected register offset (was 16=EDX, should be 32=ESP) — root cause
  of `!= 0` conditions instead of `!= target` in x86-32 comparisons
- **Parameter naming before constant propagation:** ensures param names are established
  before constants are folded, preserving meaningful variable names
- **Memory SSA (two-phase stack slot forwarding):**
  - Phase 1: intra-block store/load forwarding, per-block exit stack state collection
  - Phase 2: fixed-point worklist with memory Phi insertion at join points
  - SlotKey = (base_reg, displacement, size) prevents conflating different stack accesses
  - Load resolution with safety guards (Phi/local/readonly)

**CFG builder (cfg.rs):**
- CallInd resolution: `CALL [IAT_addr]` → traces Load source to constant, converts to Direct
- x86-32 CALL boilerplate stripping: removes return address push from P-code ops
- x86-32 RET boilerplate stripping: removes stack pop from P-code ops

**Fold passes (fold.rs):**
- Standard optimizations: algebraic simplification, single-use temp inlining, copy propagation, dead flag elimination (x86 CF/ZF/SF/OF, ARM64 NG/ZR/CY/OV, ARM32 NG/ZR/CY/OV at offsets 96-99)
- Condition recovery: compound Jcc flag patterns → comparisons
  (e.g., BoolAnd(BoolNot(ZF), IntEq(OF,SF)) → `a > b`)
- **ARM32 condition recovery:** flag register offsets (NG=96, ZR=97, CY=98, OV=99) →
  CMP operand tracing → comparison operators (==, !=, <, >, <=, >=)
- **Phi → Ternary at 2-way merges:** `rewrite_conditional_phi_to_ternary`
  (runs after fold loop + signature propagation) rewrites `Expr::Phi(inputs)`
  at non-loop-header blocks to `Expr::Ternary(cond, then, else)` when the
  merge has a dominating `CBranch` and preds cleanly partition between its
  arms. Printer already renders `Ternary` as `(cond) ? t : e` — no new stmt
  kind needed. Same pass also collapses `Phi(x, x)` / `Ternary(c, x, x)`
  via leaf VarId or varnode equivalence (two SSA versions of the same
  register slot render identically in the printer, so the conditional is
  pure noise). Replaces the old lossy `#PHI_CLEANUP` that picked first
  operand regardless of which path was live. 2851 rewrites fire on
  clang-apply-replacements.exe; composites flat across bed/plm/git-repack/
  nano/clang-ar. 3+ way compound merges (e.g. `(a && b) ? 1 : 0`) still
  skipped — parked in `.opt/ideas.md` for nested-ternary follow-up.
- **x86 DF (direction flag) ABI-default seeding:** DF at register offset 522 is
  guaranteed 0 on function entry by SysV/Win64/Cdecl32/GoAmd64. REP STOSB/MOVSB
  expands to `RDI += 1 - 2*DF` per iteration; uninitialized DF used to leak
  `(uint8_t)DF` into output. Fold now rewrites uninit DF reads to `Const(0, 1)`
  at entry for x86 CCs only (AArch64/ARM32 excluded — offset 522 unrelated).
- Call argument collection (runs BEFORE fold to prevent DCE of arg registers):
  x86-64 SysV, Windows x64 (auto-detected from PE), x86-32 cdecl/thiscall (stack-pushed)
- Division-by-constant (multiply+shift → `x / 7`) and modulo (`x - (x/D)*D` → `x % D`)
- **CDQ+IDIV simplification:** x86 signed division `Or(Lsl(Zext(sign),32),Zext(val))/Sext(div)`
  simplified to `val / div` — eliminates 64-bit concatenation noise
- **Unnecessary cast removal:** `(int)high >= (int)low` → `high >= low` when both operands
  share the same cast type
- **Redundant assignment folding:** `x0 = X; x0 = Y + x0` → `x0 = Y + (X)` — collapses
  sequential assignments where the second reads the first
- **ADD-zero noise suppression:** eliminates `+ 0` artifacts from expression folding
- **Format string leak fix:** param alias preservation prevents format specifier arguments
  from being discarded during folding
- **Extra variadic arg trimming:** counts format specifiers to trim excess arguments
- **Call return over-inlining prevention:** return-fold protection prevents call results
  from being inlined into multiple use sites
- **Call return tracker priority:** ensures call returns are tracked before other folding
- Loop body preservation: register writes in back-edge blocks protected from DCE
- **Type inference** (3-phase: seed → forward → backward): float, signed, unsigned, pointer, bool propagation from P-code op semantics
- **Signature-based type propagation:** 38K+ function signatures auto-loaded; param types
  and return types propagate through call chains with `display_type` typedef system
- **Interprocedural types (two-pass):** first pass learns internal function types from
  API call arguments, second pass applies them (HKEY, REGSAM, DWORD propagate across calls)
- **Backward Load propagation:** `Load(param)` with typed result → param gets the type
- **MBA deobfuscation** (3-phase, architecture-independent):
  - Phase 1: Pattern-based — cancellation (`a-(a-b)→b`), absorption, double negation
  - Phase 2: SiMBA linear algebra — Möbius inversion recovers coefficients over
    boolean basis {1,a,b,a&b,...} from 2^N evaluations (1-4 variables);
    bottom-up tree walking enables cascade simplification of deep expressions.
    1-var probe set covers `u64::MAX`, alternating `0xAAAA...AA`, and
    `0x0123456789ABCDEF` in addition to small probes — without the wide probes,
    bit-masking expressions like `(x & 0xFF00FF00FF00FF00) >> 8` (bswap64 half)
    evaluate to 0 for every small probe and get wrongly folded to `Const(0)`.
  - Phase 3: Equality saturation via `egg` crate — 40+ rewrite rules explore all
    equivalent MBA forms, extract cheapest (50ms/10K nodes per expression);
    panic-safe wrapper suppresses egg crate panics on malformed expressions
- **Return type recovery:** multi-hop EAX/RAX search (3 hops), call_return tracking,
  call-site inference (if callers use result → not void), two-pass propagation;
  works across all 6 architectures (x86-64, x86-32, AArch64, ARM32, MIPS32, RISC-V)
- **x86-32 stack param modeling:** `Load(EBP+8)` = param value read (not pointer deref);
  `format_vardef_expr` suppresses `*(param_N)` for stack parameters
- **Taint analysis:** tracks data flow from user inputs (recv, read, fgets) through
  operations to sensitive sinks (exec, system, SQL queries) with per-function reports
- **String decryption:** identifies XOR/ADD/SUB loops over byte arrays, recovers plaintext
- **Crypto detection:** 20+ patterns including AES S-box, DES permutation tables, RC4
  key scheduling, SHA constants, CRC32 tables, custom XOR ciphers

**Printer (printer.rs):**
- Ghidra-style output: typed signatures, local var declarations, auto-named registers
- RegTracker: per-block register value tracking enables copy elision at print time
- Call return inlining: `printf("...", add(3, 4))` not `add(); printf("...", add())`
- Stack alias resolution: var_c → var_8 → param_0 chain; save/restore elision hides spills
- Import resolution: ELF PLT/GOT (CET bnd jmp), Mach-O indirect, PE IAT (UPX-unpacked)
- Manual PE import fallback: handles malformed binaries with corrupted import dirs (Stuxnet)
- ELF32 PIE: GOT-relative string resolution, `__x86.get_pc_thunk` hiding
- String literals: read-only section detection (filters .data, magic constants),
  wide strings (UTF-16LE: `L"ntdll.dll"`), C++ demangling (ELF + Mach-O),
  Swift symbol demangling (`$s...9fibonacciyS2iF` → `fibonacci`)
- DWARF debug info: param names from `.debug_info` (DWARF4/5, macOS dSYM auto-discovery)
- PDB debug info: function names and types from PE `.pdb` files
- **Function signature database** (38K+ signatures, auto-loaded):
  - `/* param_name */` annotations at call sites: `fread(/*ptr*/ buf, /*size*/ 1, /*nmemb*/ 64, /*stream*/ file)`
  - Win32 typedef display: HANDLE, HKEY, HWND, DWORD, REGSAM, LSTATUS, LRESULT, WPARAM, LPARAM
  - 889 curated JSON + 304 macro + 36K embedded TSV — covers libc, POSIX, Linux, macOS, Win32, Android, OpenSSL
  - Interprocedural propagation: internal function params typed from API call context
  - Cross-function struct propagation: struct types flow from callees to callers via two-pass system
- Ghidra-style local declarations: `WCHAR local_8[262]; int local_c;` with array sizing from offset gaps
- PE import thunk resolution: `JMP [IAT_addr]` stubs → import names
- MSVC CRT wrapper recognition: `__acrt_iob_func + __stdio_common_vfprintf` → `printf`
- **ObjC bracket syntax:** `objc_msgSend$setText:` → `[self setText:arg]` with receiver tracking
- **MSVC C++ demangling:** `??6?$basic_ostream@...` → `cout <<`, `cin >>`, `cin.ignore`
- **C++ wrapper inlining:** `func_XXX(cout, "text")` → `cout << "text"` (chained `<<` supported)
- **Global data naming:** `*(0x4326f4)` → `DAT_004326f4` (auto-detected from address range)
- **ARM64 prologue/epilogue elision:** complete elimination (71→0 noise lines);
  callee-saved saves, FP/LR setup, sp[] stack noise (42→0), ObjC ARC noise removal,
  Swift ARC noise removal (swift_retain/release/bridgeObjectRetain/Release),
  Swift runtime call elision (swift_beginAccess, swift_allocObject, objc_opt_self),
  Swift overflow check elimination (OV flag → trap patterns removed),
  flag leak elimination (CY/ZR → 0), dead trap removal (pc = ?)
- **ARM32 cleanup pass:** flag register elision (NG/ZR/CY/OV writes removed from output),
  register renaming (r0-r15 → named registers), carry flag artifact cleanup
- **Architecture-aware register auto-naming:** x86-32 ESI/EDI → iVar, ARM64 x19-x28 → lVar,
  ARM64 x0→param_0, x30→return, x86-64 XMM0-15 → dVar,
  x86-64 param regs (RDI/RSI/RDX/RCX/R8/R9) → lVar in function body
- **Heuristic struct field naming:** without debug info, infers field semantics from usage
  patterns (e.g., `head->field_8` → `head->next` for linked list traversal)
- **Named expression substitution:** propagates named intermediate variables into complex
  expressions (e.g., `arr[low+high/2]` → `arr[mid]`)
- **Loop counter naming heuristics:** `iVar1` → `i`, `j`, `k` for induction variables
- **For-loop init recovery:** `for (;` → `for (i = 0;` by tracing pre-header assignments
- **Pointer deref simplification:** `*(param_N)` → `*param_N`, `*(uint64_t*)(lVar)` → `*lVar`
- **x86-64 RBP/RSP → local_XX:** `RBP + 560` → `local_230`, `N + RSP` → `local_N`
- Control flow recovery: for-loops, **do-while** (back-edge post-test), switch/case, else-if
- Simplifications: dead stores, unreachable returns, phi artifact cleanup, increment shorthand,
  constant folding, ESP/RSP stack noise elimination, pointer deref simplification
- MSVC RTTI: vtable → CompleteObjectLocator → TypeDescriptor → ClassHierarchyDescriptor → BaseClassArray; resolves class names, inheritance chains, and virtual method tables
- GCC RTTI: `_ZTV` (vtable) + `_ZTI` (typeinfo) symbol parsing with template demangling; multi-level inheritance from typeinfo base class lists
- **Malware analysis:** Win32 constant annotation, suspicious API flagging (24 APIs),
  stack cookie detection, dynamic resolve pattern recognition
- **YARA rule generation:** auto-generates YARA rules from binary patterns and string signatures
- **Diff decompilation:** side-by-side comparison of two binaries highlighting changed functions
- **STACKSTR pointer-write guard:** the stack-string merge pass (3+ consecutive
  `X = "...";` → `// stack string: "..."`) now skips lines whose LHS begins with
  `*(` — those are global pointer-table writes like
  `*(uint64_t*)(DAT_00602948) = "gone";`, not stack-slot inits. Without the
  guard, Ghidra-parity pointer-table setup got collapsed into a single comment.
- **Thunk misdetection guard:** the "empty body → emit
  `return target(); // thunk`" heuristic now requires BOTH (a) zero body lines
  AND (b) no Call stmt/terminator anywhere in the function AND (c) the branch
  target is an address NOT in `ssa.blocks` (covers self-loops and any in-function
  edge). `Branch(BlockId)` always targets a block in the SSA graph, so a
  self-loop terminator used to emit `return func_<self_addr>(); // thunk` and
  erase real calls.

### Function signatures + discovery (cross-cutting)

- **Adding a `SigType` variant touches 3 match sites.** `c_str()` and
  `to_inferred()` in `rsleigh-decompile/src/signatures.rs`, and
  `sigtype_to_cast()` in `rsleigh-decompile/src/printer.rs`. Missing
  the third breaks compile with non-exhaustive-match.
- **248 Python C API sigs** live in
  `rsleigh-decompile/src/signatures_python.rs`. Nine Python-specific
  `SigType` variants: `PyObjectPtr`, `ConstPyObjectPtr`,
  `PyObjectPtrPtr`, `PyTypeObjectPtr`, `PyFrameObjectPtr`, `PySsizeT`,
  `PyHashT`, `PyCFunction`, `PyRichCmpOp`.
- **PyMethodDef scanner** in `rsleigh-cli/src/main.rs::scan_pymethoddef`
  ALWAYS runs for PE64 (not gated on `symbols.is_empty()`). Validates
  struct shape — name → ASCII ident, meth → .text range, flags < 0x1000,
  doc → NULL or printable. Scans sections by characteristics rather than
  name so obfuscated section names (e.g. PyVMProtect's `.424um`) work.
- **`segs` in `discover_pe_functions` is executable-only.** For data
  scans (PyMethodDef string resolution, handler-body RIP-relative reads)
  build a separate `all_segs` over readable sections.
- **Underscore filter.** Listing hides `_dl_*`, `__do_global*`,
  `__libc_*`, `__pthread_*`, `_GLOBAL__sub_I_`, plus named entries
  `_init`, `_fini`, `_start`, `_DYNAMIC`, `_GLOBAL_OFFSET_TABLE_`. A
  blanket `_`-prefix reject is wrong — Python method names start with
  `_` by convention.

### SEH static-analysis pipeline (`rsleigh-decompile/src/seh_static.rs`)

PE64-only. Backbone of SMC-aware static lift (PyVMProtect v5 class).
Dependency: `iced-x86` in `rsleigh-decompile/Cargo.toml`.

- **`parse_pe64_seh(image)`** — walks `.pdata` + UNWIND_INFO. Resolves
  `UNW_FLAG_CHAININFO` plus the undocumented low-bit chain trick
  (`UnwindData & 1` → "this is an RVA to another RUNTIME_FUNCTION").
- **`read_scope_table(image, va)`** — parses MSVC
  `_C_specific_handler` / `__except_handler4` SCOPE_TABLE records
  (`{begin, end, handler, jump_target}`).
- **`scope_table_addresses(image)`** — BFS (depth 8) over nested
  scope tables. Surfaces filter and `__except` resumption blocks
  that are unreachable from any CALL site.
- **`analyse_handler(image, va)`** → `HandlerAnalysis` (flags
  `redirects_rip` / `skips_rip` / `calls_wpm` / `calls_vprotect` /
  `uses_rep_movs`, plus `resumption_va`, `iat_calls`).
  `is_smc_candidate()` rolls the SMC-relevant flags up.
- **`extract_handler_patches(image, va)`** — control-flow-aware
  abstract interpreter over a `RegVal` lattice (`Top | Imm | Addr`).
  Handles `mov [tracked+disp], imm/reg`, `rep movsb/d/q`, and
  indirect jumps (`jmp reg`, `jmp [rip+disp]`, indexed jump tables
  with stride 8 and MSVC i32-relative stride 4).
- **`smc_fixpoint(image, max_iters, discover_fn)`** —
  extract → apply → re-discover until stable. CLI `--seh-fixpoint`
  wires the full discovery oracle. Hard cap 16 iterations.
- **Fixture**: `test-harness/fixtures/crackmev3.pyd` (308 KB,
  PyVMProtect v4 sample). Regression tests lock in its handler
  classification and zero-patch baseline.
- **Walkthrough**: `docs/pe64-seh-pipeline.md` (feature matrix +
  crackmev3 / clang-apply-replacements / 7za / NumPy benchmarks).

### Peephole Optimizer (`pcode-ir/src/lib.rs`)

- Identity Subpiece elimination
- Copy chain forwarding with batch analysis
- Dead code elimination (batch collection, reverse removal)
- Overwrite elimination
- Output sinking (unique → copy dest)
- Redundant IntAnd collapse

---

## Key Features

- **String decryption:** identifies XOR/ADD/SUB encryption loops, recovers plaintext strings
- **Crypto detection:** 20+ patterns (AES S-box, DES tables, RC4 KSA, SHA constants, CRC32, custom XOR)
- **YARA generation:** `--yara` flag auto-generates YARA rules from binary patterns and strings
- **Diff decompilation:** `--diff` compares two binaries, highlights changed/added/removed functions
- **Taint tracking:** `--taint` traces data from inputs (recv, read) to sinks (exec, system, SQL)
- **Raw firmware loading:** `--raw <arch>` loads raw binary blobs at base address for any supported arch
- **WebAssembly decompilation:** WASM module parsing, function/type recovery, pseudocode output
- **AI-assisted RE toolkit:** `--summary` (one-line per function), `--xrefs` (callers + callees), `--search` (find functions by string, API call, or constant)
- **Vulnerability scanner:** `--vulnscan` checks 27 patterns (buffer overflows, format strings, UAF, integer overflows, command injection, path traversal) with color-coded HIGH/MEDIUM/LOW severity
- **Call graph export:** `--callgraph` emits JSON with behavioral tags (network_io, crypto, process_injection) and reverse caller map
- **Analysis API:** `FunctionMeta`, `VulnFinding`, `CallGraphEntry` structs with `serde::Serialize` for Spectra integration and tool pipelines
- **Token-efficient output:** `--compact` (24% reduction), `--brief` (35%), `--min-complexity N` (skip trivial functions); combined `--brief --min-complexity 5` = 40% token reduction for LLM-assisted analysis
- **ARM32 VFP/NEON float instructions:** vmul.f64, vldr, vmov decoded via ARM7_le.slaspec (not ARM7_le_base); full VFP/NEON constructor support
- **C++ class/vtable/hierarchy recovery:** `CppClass` (name, base classes, vtable address, virtual methods, fields), `VirtualMethod` (name, vtable slot index, address), `ClassField` (offset, size, inferred type) structs. MSVC RTTI chain: CompleteObjectLocator → TypeDescriptor → ClassHierarchyDescriptor → BaseClassArray for multi-level inheritance. GCC RTTI: `_ZTV` vtable symbols + `_ZTI` typeinfo symbols with template demangling (`std::vector<int, std::allocator<int>>`). Field inference from decompiled output (offset gaps, typed API arguments). `--classes` and `--classes --json` CLI output.
- **Swift ARM64 decompilation:** Swift mangled symbol demangling (classes, methods, properties, init/deinit, metadata), Swift ARC noise elision (swift_retain/release/bridgeObjectRetain/Release), runtime call elision (swift_beginAccess, swift_allocObject), overflow check elimination, flag leak cleanup
- **Cross-function struct propagation:** struct types identified in callees propagate to callers via two-pass decompilation; field names resolve across call boundaries (195→201 struct IDs on main.exe)
- **MIPS stripped ELF discovery:** JAL/BAL scanning, prologue detection (addiu sp/sw ra/lui gp), endian-aware ELF parsing; busybox-mips: 9 → 5,405 functions
- **MIPS PIC indirect call resolution:** GP-relative GOT tracing with GP invariance detection (lui+addiu+addu t9 pattern), addiu t9 adjustment accumulation; 423→98 unresolved (77% resolved)
- **Memory SSA:** two-phase stack slot store/load forwarding with fixed-point worklist and memory Phi insertion at join points; restores values passed through stack (e.g., strlen(input))
- **Pseudocode quality (14-point audit):** CDQ+IDIV simplification, Zext deferral, smart array base validation, call return tracking, format string preservation, variadic arg trimming, return-fold protection, AArch64 stack/prologue noise elimination, 6-arch return type inference, heuristic struct field naming, cast removal, assignment folding, ADD-zero suppression, register auto-naming, for-loop init recovery, loop counter naming, named expression substitution
- **Function ID database (rsleigh-fid):** Ghidra-FID-style body fingerprinting in pure Rust. xxh3 full + callee-aware specific hash over operand-masked instruction bytes; per-arch mask tables (x86 opcode+ModR/M keep, fixed-width class masks for AArch64/ARM32/MIPS/RISC-V). Bundled blobs (287KB, 13,612 entries): glibc 2.36, libstdc++ 12.2, musl 1.2.5 for x86_64 + aarch64, auto-loaded based on target arch. `rsleigh-fid-gen` builds .fidb from ELF/Mach-O/PE/`.a`. `identify()` accepts C++ ABI ctor/dtor variants (C1/C2/C3, D0/D1/D2 share bodies by spec). `scripts/build-fid-dbs.sh` = reproducible distro-pkg fetch + SHA256-pinned MANIFEST.
- **Qt5 signature database (23,274 entries):** auto-loaded alongside libc TSV. `scripts/extract-qt-sigs.py` walks libQt5Core/Gui/Widgets/Network/DBus/Svg/XcbQpa/X11Extras dynsyms, demangles via `c++filt -n`, maps param types to rsleigh TSV codes. Return types default to void (Itanium doesn't mangle return for non-template funcs); rsleigh's own return-inference fills from use sites.
- **AArch64 AAPCS64 full param recovery:** x0-x7 (int) + v0-v7 (float/SIMD, aka s0-s7/d0-d7/q0-q7) all map to `param_N` / `fparam_N` with typed signatures. Previously only x0 was recovered — wrappers now show full 4-param signatures.
- **AArch64 stack-canary recognition:** text-level pattern detector in post_process strips the `RET = A ^ B;` XOR, adjacent reload, and intervening dead stores, replacing the trailing `return RET;` with `return;`. Works without ADRP-resolved `__stack_chk_guard` symbol.
- **R_*_GLOB_DAT import resolution:** `resolve_elf` now walks GLOB_DAT dynrelas (R_X86_64_GLOB_DAT=6, R_AARCH64_GLOB_DAT=1025, R_ARM_GLOB_DAT=21) so data-symbol GOT slots (`__stack_chk_guard`, vtable pointers, QObject::staticMetaObject) resolve to names instead of leaking as DAT_XXXX.

---

## Known Limitations

- **ExprValue::Context** returns 0 (not used by x86/ARM/RISC-V)
- **ExprNew / ExprCPool** returns 0 (JVM/WASM only)
- **Expression completeness** — some register values not traced back to their defining
  expression (e.g., `iVar1 * factorial(n-1)` instead of `n * factorial(n-1)`)
- **Type inference** — basic signed/float/pointer/bool + Win32 typedef propagation +
  interprocedural two-pass + heuristic struct field naming; no constraint-based inference
- **Stack frame reconstruction** — buffer sizes inferred from offset gaps; array sizing works;
  heuristic field naming (head->next) but no full constraint-based struct recovery
- **MBA deobfuscation** — SiMBA handles 1-4 variable linear MBA; non-linear and 5+ variable
  expressions need synthesis-based approaches (equality saturation catches some)
- **Loop conditions** — `while (OF == SF)` not always recovered to source comparison
- **x86-32 control flow** — sequential TEST/JNZ patterns sometimes nest incorrectly
- **Register-indirect calls** — `CALL EDI` where EDI was loaded from IAT earlier
  not resolved to import names (only direct IAT calls resolved)
- **ARM32 VFP/NEON decompiler** — VFP/NEON instructions decode correctly (vmul.f64, vldr, vmov);
  floating-point register values not yet fully traced through decompiler expression folding

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
- Analysis API: `extract_function_meta()` and `scan_vulns()` provide structured metadata
  (FunctionMeta, VulnFinding, CallGraphEntry) with serde::Serialize for JSON transport
- **14 integration tests:** 10 native backend tests (decoder/decompile/analysis/discovery/
  end-to-end) + 4 API contract tests in rsleigh test-harness

## Ghidra Comparison Setup

Ghidra installs (try in order — `bench-compare.sh` does this auto):
- `~/tools/ghidra_11.4.3_PUBLIC/` ← use for `ghidra-export-decompile.py` (Jython OK)
- `~/tools/ghidra_12.0.4_PUBLIC/` ← needs PyGhidra (`pip install pyghidra`); script will fail otherwise

```bash
export JAVA_HOME=$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
export GHIDRA_HOME=~/tools/ghidra_11.4.3_PUBLIC
```

Headless function counting:
```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj proj \
  -import <binary> -postScript /tmp/CountFunctions.py -deleteProject
```

**Current score: rsleigh 15 — Ghidra 6** on PE/Mach-O/ELF/ARM32 binaries (21 compared).
Stripped ELF: eh_frame + RTTI vtable + prologue scanning now competitive.
ARM32 binaries: BL/Thumb scanning + condition recovery tested.

## Bench: rsleigh vs Ghidra

```bash
scripts/bench-compare.sh <binary> [--sample N]   # full run (Ghidra + score)
scripts/bench-score.py --binary X --rsleigh Y \
  --ghidra cached.json --sample 50 --out DIR     # re-score only (no Ghidra rerun)
```

Ghidra path + JDK path auto-resolved. Composite score weights: discovery 25,
cflow_similarity 25, leak_parity 20, line_parity 15 (elision-aware), empty_rate 15.
`line_parity` gives full credit when rsleigh has fewer lines AND fewer leaks.
Latest scores: bed (Go) 89.7, plm (AArch64 C++) 84.3, git-repack (AArch64 C) 92.2,
nano (ARM32 static stripped) 80.8, clang-apply-replacements (PE x86-64 MSVC C++) 90.1.

**Bench noise band:** composite score has ~0.2 spread across repeat runs on the
same build (sample of 50 funcs has some non-determinism). When evaluating a
single-shot fix, treat `<1%` composite movement on any fixture as noise; real
regressions are usually `>1%` or show up on two+ runs.

## macOS gotchas

- Apple `c++filt` strips leading `_` by default → use `c++filt -n` for Itanium `_Z...`.
- No `timeout` cmd → use `gtimeout` (brew coreutils) or Bash `run_in_background`.
- `pip3` aliased to `uv` → install via `uv pip install --system` or in a venv.
- `cargo test -p test-harness` has pre-existing stack overflow in unit tests; iterate
  via `cargo test -p rsleigh-decompile --release` (26 tests, ~0.1s).
- **rtk caches aggressively.** If `cargo build` reports `0 crates compiled`
  when something clearly changed, use `/opt/homebrew/bin/cargo` directly and
  optionally `cargo clean -p <crate>` to force real rebuild.
- **`test-harness/examples/*.rs` includes stale files.** At least
  `probe_check2_ssa` has a pre-existing non-exhaustive match on
  `Expr::UserOp` unrelated to current work. Run
  `cargo test -p <crate> --release --lib` to skip examples when checking
  regressions.
- **`.DS_Store` sneaks into initial commits.** Put it in `.gitignore` on
  any new repo first thing.

## Debugging fold/structure passes

- Insert temp `eprintln!("[tag] ...")` in fold.rs/structure.rs → run targeted func →
  inspect prefix → remove. `--ssa-json <addr>` shows post-fold state without instrumentation.
- For new SSA passes: gate on `CallingConv::*` or arch when behavior is target-specific.
- **printer.rs post_process is multi-pass.** Lines not present at entry can be
  synthesized mid-pipeline — e.g. `sp = (((sp - 8) - 12) - 0x10);` only appears
  AFTER the `mult_addr → sp` rename (line ~2243). Any strip that needs to catch
  the final form must run either inside that same ARM32 retain block (before
  rename, matching `mult_addr = (`) OR at the very end right before
  `*out = result`. Early post_process retains do not see renamed forms.
- **`cargo build` may report `0 crates compiled` when rtk caches aggressively.**
  Use `/opt/homebrew/bin/cargo build -p rsleigh-cli --release` to force the
  real cargo binary + re-examine timestamps. `cargo clean -p rsleigh-decompile`
  before rebuild if in doubt.
- **/fix-leaker single-shot protocol:** declare a failing regression test FIRST,
  commit test + fix together. 3-attempt cap per target; log aborted attempts to
  `.opt/failed.md`. Campaign mode (`.opt/campaigns/<slug>.md`) is opt-in for
  arcs that need bounded temporary regression — declare hypothesis, budget,
  horizon upfront; auto-revert if numbers miss at horizon. Do not move
  goalposts mid-arc.

## License

Apache 2.0
