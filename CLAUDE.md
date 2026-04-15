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
pseudocode quality regression tests (14 audit fixes).
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

### CLI (`rsleigh-cli`)

```bash
rsleigh <binary>                       # list functions
rsleigh <binary> <func> [func2..]      # decompile functions (name or 0xAddr)
rsleigh <binary> --all                 # decompile all (two-pass type propagation)
rsleigh <binary> --disasm <func>       # disassemble with P-code
rsleigh <binary> --sigs extra.json     # load additional signatures
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
- **Sub-register Zext deferral:** groups P-code ops by instruction address; when
  `IntZext(EAX→RAX)` precedes an address calculation that reads RAX within the same
  instruction, the Zext write is deferred to preserve the original pointer value
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
    bottom-up tree walking enables cascade simplification of deep expressions
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

Ghidra 11.3.1 is installed at `~/ghidra_install/ghidra_11.3.1_PUBLIC/`.

```bash
export JAVA_HOME=$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
export GHIDRA_HOME=~/ghidra_install/ghidra_11.3.1_PUBLIC
```

Headless function counting:
```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj proj \
  -import <binary> -postScript /tmp/CountFunctions.py -deleteProject
```

**Current score: rsleigh 15 — Ghidra 6** on PE/Mach-O/ELF/ARM32 binaries (21 compared).
Stripped ELF: eh_frame + RTTI vtable + prologue scanning now competitive.
ARM32 binaries: BL/Thumb scanning + condition recovery tested.

## License

Apache 2.0
