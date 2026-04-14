# rsleigh Roadmap

## Current State

**7 architectures** (x86-64, x86-32, AArch64, ARM32, MIPS32, RISC-V 64, WebAssembly), **7 binary formats** (ELF 32/64, Mach-O, PE32, PE64, ARM64 Windows, WASM, raw firmware).

**rsleigh 15 — Ghidra 6** on function discovery across PE32, PE64, Mach-O, ELF x86-64, and ARM32 ELF test binaries.

**Key features:** 38K+ function signatures with param annotations, MSVC C++ demangling, ObjC bracket syntax, C++ stream wrapper inlining, Win32 typedef propagation (HKEY, HWND, REGSAM), MBA deobfuscation (SiMBA + equality saturation), interprocedural two-pass type propagation, do-while recovery, Ghidra-style local declarations with array sizing, type cast emission (constant type casts + return value casts), struct recovery (30 known structs, 1,861 named fields), string decryption engine (XOR auto-decrypt, stack strings, base64, ROT13), crypto algorithm detection (20+ patterns), WebAssembly decompilation (native stack-VM parser), taint analysis (24 sources, 32 sinks), YARA rule generation, diff decompilation, raw binary/firmware loading, ARM32 VFP/NEON float support (vmul.f64/vldr/vmov), AI-assisted RE toolkit (--summary, --xrefs, --search), vulnerability scanner (--vulnscan, 27 patterns), call graph export (--callgraph, JSON with behavioral tags), analysis API (FunctionMeta/VulnFinding/CallGraphEntry with Serialize).

---

## Completed

### Token-Efficient Output Modes
`--compact` strips local declarations and reduces indent to 2 spaces (24% output reduction). `--brief` emits only calls and control flow (35% reduction). `--min-complexity N` skips trivial functions below cyclomatic complexity N. Combined `--brief --min-complexity 5` achieves 40% total reduction. Designed for LLM context window optimization and automated analysis pipelines.

### Enhanced Search for LLM Workflows
`--search` extended with `--tag` (behavioral tag filtering), `--json` (structured JSON output for tool integration), and `--decompile` (include pseudocode in search results). Enables LLM-driven binary analysis workflows that query, filter, and process function metadata programmatically.

### Vulnerability Scanner
`--vulnscan` flag scans all discovered functions against 27 vulnerability patterns: buffer overflows (gets, strcpy, sprintf without bounds), format string bugs (printf with user-controlled format), use-after-free, double-free, integer overflows before allocation, command injection (system/exec with user input), path traversal, uninitialized reads, and more. Output is color-coded by severity (HIGH/MEDIUM/LOW) with function name, address, and description.

### Call Graph Export
`--callgraph` flag exports a JSON call graph with nodes (functions), edges (call relationships), behavioral tags per function (network_io, crypto, file_system, process_injection, registry, anti_debug), and a reverse caller map showing which functions call each API. Designed for automated triage pipelines and Spectra's graph visualization.

### Analysis API for Spectra
New `rsleigh_decompile::analysis` module exposing `extract_function_meta()` and `scan_vulns()`. Three core structs -- `FunctionMeta` (name, address, calls, strings, complexity, pseudocode), `VulnFinding` (severity, pattern, function, address, description), `CallGraphEntry` (caller, callee, tags) -- all derive `serde::Serialize` for direct JSON serialization. Powers Spectra's vulnerability panel and call graph view.

### Rich JSON Output
`--json` flag now emits structured per-function metadata: calls list, string literals, cyclomatic complexity score, and full pseudocode. Combined with `--all` for whole-binary JSON export suitable for LLM-assisted analysis pipelines and CI integration.

### AI-Assisted RE Toolkit
Three new CLI modes for reverse engineering workflows: `--summary` (one-line per function with calls, strings, and behavioral patterns), `--xrefs` (callers, callees, and string cross-references for any function), `--search` (string, API, and constant search with raw byte pre-scan for fast filtering). Designed to support AI-driven binary analysis pipelines.

### Constant Type Casts + Return Value Casts
Closes the remaining type cast gap: constant arguments now get sized/typed casts matching their context, and return values from known-signature functions propagate casts to assignment targets. Brings cast emission to parity with Ghidra.

### ARM32 VFP/NEON Float Support
Fixed slaspec configuration (ARM7_le_base to ARM7_le), MixOperations fix, Optional table lift fix. VFP/NEON float instructions (vmul.f64, vldr, vmov, etc.) now decode correctly. Generated ARM32 code grew from 4.8MB to 18.8MB with the additional float instruction coverage.

### Taint Analysis
3-phase taint tracking: 24 input sources (read, recv, scanf, GetDlgItemText, etc.) and 32 security-sensitive sinks. Phase 1: seed taint from source calls. Phase 2: forward propagation through assignments, arithmetic, memory operations. Phase 3: sink reachability analysis. Highlights taint paths in output for vulnerability research and CTF solving.

### YARA Rule Generation
`--yara` flag generates YARA rules from decompilation results. Extracts: unique string literals, crypto algorithm signatures (AES S-box, SHA-256 K table, etc.), import names, entry point hex bytes. Rules target the analyzed binary's unique characteristics for threat hunting and malware classification.

### Diff Decompilation
`--diff` flag compares two versions of a binary and highlights changed functions. LCS-based line diff algorithm with color output (green additions, red deletions). Useful for patch analysis and understanding what a security update fixed.

### Raw Binary / Firmware Loading
`--raw` flag loads raw binary blobs with user-specified base address and architecture. MIPS JAL and ARM BL instruction scanning for function discovery in headerless firmware images. Essential for embedded firmware analysis where there's no standard binary format header.

### Control Flow Improvements
If-return flattening eliminates unnecessary nesting when if-bodies end with return. Text-level switch/case collapse merges sequential case blocks. Indent normalization fixes deeply nested output. Reduces visual complexity of decompiled output.

### Thunk Function Detection
Empty JMP stub functions now show tail call targets instead of appearing as empty bodies. Reduced empty function count from 986 to 426 on test corpus. `JMP [IAT_addr]` and `JMP rel32` stubs display the resolved target.

### ARM32 CMP Operand Tracing
93% of CMP result references now substitute the original variable name. Conditions show `param < value` instead of `*(addr) < 0`. Traces CMP operands back through register assignments to recover meaningful comparisons.

### ARM32 Return Type Detection
BranchInd instructions (POP {PC}, BX LR) correctly identified as function returns. r0 register tracked as return value. Enables proper return type inference and eliminates spurious indirect call artifacts in ARM32 output.

### Printer Pipeline Refactor
Added `#FINAL_PASS` at end of post-processing to re-run critical simplifications after earlier passes create new patterns. Reduced `param_N[RSP]` from 768 to 3 on main.exe. Surgical fix — no full rewrite needed.

### Do-While Recovery Fixes
Fixed 3 bug classes: `if (} while (cond))` text corruption from call-return inlining treating `} while` as function calls; impossible constant conditions (`} while (1 < 0)`); dead do-while loops where body unconditionally returns.

### ELF Linux Binary Testing
Tested on stripped ELF x86-64 bash (905KB, 1,242 functions). Fixed: RBP callee-saved spill elision (201→0), bare RBP→lVar auto-naming (1,099→18 RBP leaks), call-return inlining guard. 1,424 string literals, 979 API annotations recovered.

### Type Cast Emission
0 → 4,616 casts on main.exe (94% of Ghidra's 4,911). Sources: narrowing (Subpiece 64→32), Zext/Sext with sized casts, signed/unsigned comparison casts, bitwise/shift casts, call argument casts from signatures (DWORD, void *, LPCWSTR), typed Load dereferences `*(uint32_t*)(addr)`, float conversions.

### Struct Recovery
30 known struct definitions (Win32: STARTUPINFOW, CONTEXT, WNDCLASSEXW, PROCESS_INFORMATION, SECURITY_ATTRIBUTES, OSVERSIONINFOW, EXCEPTION_RECORD, WIN32_FIND_DATAW, OVERLAPPED, RECT, POINT, MSG, PAINTSTRUCT, LOGFONTW, BITMAP, CRITICAL_SECTION, SYSTEM_INFO, MEMORY_BASIC_INFORMATION, FILETIME, LARGE_INTEGER, WSADATA, SERVICE_STATUS, SERVICE_TABLE_ENTRYW, OPENFILENAMEW, SOCKADDR_IN; POSIX: stat, sockaddr_in, addrinfo, timeval, iovec, pollfd, sigaction, pthread_attr_t). 50+ API hints for automatic struct identification. PE/ELF architecture filtering. 198 struct IDs, 1,861 named fields on main.exe.

### String Decryption Engine
No other decompiler does this automatically:
- XOR auto-decrypt: detect key from nearby loop, decrypt stack bytes in-place (found real encrypted strings in PsExec, key=0x5A)
- Stack string detection: packed dword/word stores, byte-by-byte construction, string literal concatenation
- XOR .rdata brute-force: single-byte (0x01-0xFE) scan with strict validation
- Multi-byte XOR: known-plaintext attack using common prefixes (http, cmd, C:\)
- Base64 decode: detect base64 in string literals, decode and annotate
- ROT13 decode: common English word matching after ROT13 transform

### Crypto Algorithm Detection
Binary-level scanning (20+ byte patterns): AES S-box/inverse/Rcon, SHA-256 K table + init vector (LE+BE), SHA-1 init + K constants, MD5 init + T table (LE+BE), CRC32 IEEE polynomial table (LE+BE), Blowfish P-array, ChaCha20/Salsa20 constants, DES permutation, Whirlpool S-box, Twofish MDS, CAST5 S-box. Plus inline constant detection (TEA delta, Base64 alphabets).

### Stripped ELF Function Discovery
12-method pipeline for stripped ELF x86-64: entry point + .init/.fini + .init_array/.fini_array, PLT enumeration (.plt/.plt.sec/.plt.got) with symbol resolution, .eh_frame_hdr FDE table parsing, .eh_frame direct CIE/FDE parsing, C++ RTTI vtable chain walking, decoder-based CALL discovery with register tracking (2 rounds), indirect call resolution (CALL [RIP+disp], CALL REG via LEA/MOV), FF 15/FF 25 GOT resolution, data pointer scanning (.data.rel.ro vtables + .rodata consecutive runs), 12 prologue patterns with boundary detection, E9 JMP thunk detection, gap analysis.

### ARM32/AArch64/Thumb Function Discovery
ARM32 BL scanning (condition + imm24 offset), PUSH {regs, lr} prologue detection (E92D with boundary verification), Thumb PUSH {regs, lr} (B5xx), Thumb BL (F000 Fxxx 32-bit encoding), AArch64 BL imm26 scanning. Results: busybox 3→2,062 functions (beats Ghidra's 1,945 by 6%).

### ARM32 Output Cleanup
Comprehensive ARM32 decompiler cleanup: flag computation removal (shift_carry 5,346→0, tmpNG/tmpZR/tmpCY/tmpOV eliminated), prologue/epilogue elision (mult_addr 3,991→0, PUSH/POP/stack frame hidden), register renaming (r0-r3→param_0-param_3, r4-r11→lVar1-lVar8, r12→iVar1, lr→lrVar), condition recovery (7,801 comparisons from ARM CPSR flags: NG/OV→signed, CY/ZR→unsigned), ARM32 flag offsets (96-99) added to fold pass, empty block removal. 56% line reduction.

### WebAssembly Decompilation
Native WASM parser (not SLEIGH-based — WASM is a stack VM): auto-detect .wasm via \0asm magic, parse type/function/export/code sections via wasmparser crate, stack simulation for expression reconstruction. Supports: arithmetic, bitwise, comparisons, memory load/store, control flow (block/loop/if/else/br/br_if), function calls, conversions, select/ternary. Example: `factorial(param_0 - 1) * param_0`.

### CI Pipeline
3 parallel GitHub Actions jobs: test (generate slaspecs → build all → golden P-code tests → decompiler unit tests → CLI release build), clippy (lint core crates), check (fast pcode-ir compile). Makefile: `make test-all`, `make check`, `make release`, `make benchmark`.

### Benchmark Suite
`scripts/benchmark.py` — runs rsleigh on all test_bin binaries, compares function counts against Ghidra baselines, detects regressions. 17+ binaries in test corpus across PE, ELF, ARM32.

---

## Ship Quality — Make It Production-Ready

### Spectra Integration Testing
rsleigh is the decompilation backend for Spectra. The `rsleigh-api` + `rsleigh-decompile` API contract is untested in the UI context. Verify function discovery, ASM view, P-code view, and Code view all work correctly with the latest changes.

### MIPS/RISC-V Real-World Testing
Two supported architectures with zero real-world validation beyond golden P-code tests. Need: MIPS BL/JAL function discovery for stripped ELF, end-to-end decompilation testing on real firmware images (MIPS routers) and RISC-V toolchain output.

---

## Output Quality — Close the Gap with Ghidra

### Cross-Function Struct Propagation
When a struct is identified in one function, propagate to callers/callees. Infer field types from usage context (field passed to `strlen` → `char *`).

---

## Deeper Deobfuscation

### Full MBA Synthesis
Use the `egg` crate more aggressively with custom rewrite rules per obfuscation tool (Tigress, O-LLVM, Themida). Add rules for specific MBA expansion templates. Current SiMBA handles 1-4 variable linear MBA; extend to non-linear patterns via program synthesis (QSynth-style).

### Control Flow Unflattening
Detect and reverse O-LLVM/Tigress-style flat dispatch loops:
- Identify the dispatcher block (switch on state variable)
- Reconstruct the original CFG from state transitions
- Emit clean if/else/while instead of the flat switch

### Opaque Predicate Elimination
Detect always-true/false conditions inserted by obfuscation tools:
- `x * x >= 0` (always true for integers)
- `(x & 1) == (x | 1)` (always false)
- Hash-based predicates that resolve to constants

---

## Platform Expansion

### .NET IL / Java Bytecode
Managed code decompilation alongside native code. Many malware samples use .NET packers or Java droppers. Could leverage existing tools (ilspy, cfr) via command-line integration, or implement basic IL/bytecode lifting to P-code.

### Kernel Drivers
Windows `.sys` file support with:
- IOCTL dispatch table recognition
- `DriverEntry` / `DriverUnload` identification
- IRP handler discovery
- Pool allocation tracking (`ExAllocatePool` → tagged allocations)

---

## Benchmarking

### Expanded Test Corpus
Add binaries covering:
- macOS code-signed apps
- Android NDK native libraries
- Windows kernel drivers
- Packed/UPX binaries
- Go/Rust/Swift/Zig compiled binaries
- Real malware samples (with appropriate warnings)
- MIPS firmware images
- RISC-V toolchain output
