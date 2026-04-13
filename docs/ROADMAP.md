# rsleigh Roadmap

## Current State

**6 architectures** (x86-64, x86-32, AArch64, ARM32, MIPS32, RISC-V 64), **5 binary formats** (ELF 32/64, Mach-O, PE32, PE64 including ARM64 Windows).

**Beats Ghidra on function discovery** on 10 of 11 compared test binaries across PE32, PE64, Mach-O, ELF, and ARM64.

**Key features:** 38K+ function signatures with param annotations, MSVC C++ demangling, ObjC bracket syntax, C++ stream wrapper inlining, Win32 typedef propagation (HKEY, HWND, REGSAM), MBA deobfuscation (SiMBA + equality saturation), interprocedural two-pass type propagation, do-while recovery, Ghidra-style local declarations with array sizing, type cast emission (94% of Ghidra), struct recovery (9 known Win32 structs, 1,824 named fields), string decryption engine (XOR auto-decrypt, stack strings, base64, ROT13).

---

## ✅ Completed

### Printer Pipeline Refactor ✅
Added `#FINAL_PASS` at end of post-processing to re-run critical simplifications after earlier passes create new patterns. Reduced `param_N[RSP]` from 768 to 3 on main.exe. Surgical fix — no full rewrite needed.

### Do-While Recovery Fixes ✅
Fixed 3 bug classes: `if (} while (cond))` text corruption from call-return inlining treating `} while` as function calls; impossible constant conditions (`} while (1 < 0)`); dead do-while loops where body unconditionally returns.

### ELF Linux Binary Testing ✅
Tested on stripped ELF x86-64 bash (905KB, 1,242 functions). Fixed: RBP callee-saved spill elision (201→0), bare RBP→lVar auto-naming (1,099→18 RBP leaks), call-return inlining guard. 1,424 string literals, 979 API annotations recovered.

### Type Cast Emission ✅
0 → 4,616 casts on main.exe (94% of Ghidra's 4,911). Sources: narrowing (Subpiece 64→32), Zext/Sext with sized casts, signed comparison casts, unsigned comparison casts, bitwise/shift casts, call argument casts from signatures (DWORD, void *, LPCWSTR), typed Load dereferences `*(uint32_t*)(addr)`, float conversions.

### Struct Recovery ✅
9 known Win32 struct definitions (STARTUPINFOW, CONTEXT, WNDCLASSEXW, PROCESS_INFORMATION, SECURITY_ATTRIBUTES, OSVERSIONINFOW, EXCEPTION_RECORD, WIN32_FIND_DATAW, OVERLAPPED). API-based identification (GetStartupInfoW → STARTUPINFOW *). Field offset matching with 3+ field / >50% threshold. 195 struct identifications, 1,824 named fields on main.exe.

### String Decryption Engine ✅
No other decompiler does this automatically:
- XOR auto-decrypt: detect key from nearby loop, decrypt stack bytes in-place (found real encrypted strings in PsExec, key=0x5A)
- Stack string detection: packed dword/word stores, byte-by-byte construction, string literal concatenation
- XOR .rdata brute-force: single-byte (0x01-0xFE) scan with strict validation
- Multi-byte XOR: known-plaintext attack using common prefixes (http, cmd, C:\)
- Base64 decode: detect base64 in string literals, decode and annotate
- ROT13 decode: common English word matching after ROT13 transform

### Benchmark Suite ✅
`scripts/benchmark.py` — runs rsleigh on all test_bin binaries, compares function counts against Ghidra baselines, detects regressions. 14 binaries in test corpus.

---

## Ship Quality — Make It Production-Ready

### CI Pipeline
Automated builds and testing to prevent regressions. Run benchmark suite on every push, compare function counts against saved baselines, flag output quality regressions. GitHub Actions with matrix testing.

### MIPS/RISC-V/ARM32 Testing
Three supported architectures with zero real-world validation beyond golden P-code tests. Need end-to-end decompilation testing on real firmware images (MIPS routers), IoT binaries (ARM32), and RISC-V toolchain output.

### Spectra Integration Testing
rsleigh is the decompilation backend for Spectra. The `rsleigh-api` + `rsleigh-decompile` API contract is untested in the UI context. Verify function discovery, ASM view, P-code view, and Code view all work correctly with the latest changes.

---

## Output Quality — Close the Gap with Ghidra

### Better Control Flow
The remaining 282 deeply nested if/else chains should use `goto` for complex multi-exit patterns. Add `break` label support for nested loops. Detect and emit `switch` for computed jump tables that the current pattern matcher misses.

### Expand Struct Recovery
Add more known structs (CRITICAL_SECTION, LARGE_INTEGER, SOCKADDR_IN, sockaddr, stat, dirent, etc.). Cross-function struct propagation — when a struct is identified in one function, propagate to callers/callees. Infer field types from usage context (field passed to `strlen` → `char *`).

### Remaining Type Cast Gap (6%)
Currently at 94% of Ghidra's cast count. Remaining: casts inside deeply nested expressions, cross-function return type mismatches, constant type annotations for large hex values.

---

## New Capabilities — Things Ghidra Doesn't Do

### Crypto Algorithm Detection
Recognize cryptographic constants in .rdata and annotate their usage:
- AES S-box (256-byte table starting with `0x63, 0x7c, 0x77...`)
- SHA-256 round constants (`0x428a2f98, 0x71374491...`)
- RC4 state initialization pattern
- CRC32 polynomial tables

Annotate as `// AES S-box lookup` or `// SHA-256 round constant` in the output.

### Taint Tracking
Trace user input (from `read()`, `recv()`, `scanf()`, `GetDlgItemText()`) through the program to find where it's validated, compared, or used in security-sensitive operations. Highlight the taint path in the output. Useful for vulnerability research and CTF solving.

### Diff Decompilation
Compare two versions of a binary (e.g., patched vs unpatched) and highlight changed functions. Show a unified diff of the pseudocode. Useful for patch analysis and understanding what a security update fixed.

### YARA Rule Generation
Auto-generate YARA rules from unique strings, constants, and byte patterns found during decompilation. Export rules that match the analyzed binary's unique characteristics. Useful for threat hunting and malware classification.

---

## Deeper Deobfuscation

### Full MBA Synthesis
Use the `egg` crate more aggressively with custom rewrite rules per obfuscation tool (Tigress, O-LLVM, Themida). Add rules for specific MBA expansion templates. Current SiMBA handles 1-4 variable linear MBA; extend to non-linear patterns via program synthesis (QSynth-style).

### Control Flow Unflattening
Detect and reverse O-LLVM/Tigress-style flat dispatch loops:
- Identify the dispatcher block (switch on state variable)
- Reconstruct the original CFG from state transitions
- Emit clean if/else/while instead of the flat switch

This is a well-studied problem with known algorithms (back-and-forth analysis, symbolic execution of the dispatcher).

### Opaque Predicate Elimination
Detect always-true/false conditions inserted by obfuscation tools:
- `x * x >= 0` (always true for integers)
- `(x & 1) == (x | 1)` (always false)
- Hash-based predicates that resolve to constants

Evaluate symbolically or via sampling and fold the dead branch.

---

## Platform Expansion

### WebAssembly
Decompile `.wasm` binaries using Ghidra's WebAssembly slaspec. WASM is increasingly used in malware (cryptominers) and browser exploits. The slaspec already exists — needs integration and testing.

### .NET IL / Java Bytecode
Managed code decompilation alongside native code. Many malware samples use .NET packers or Java droppers. Could leverage existing tools (ilspy, cfr) via command-line integration, or implement basic IL/bytecode lifting to P-code.

### Firmware / Raw Binary Loading
Support raw binary loading with user-specified base address and architecture. Essential for embedded firmware analysis where there's no standard binary format header. Add memory map specification for split ROM/RAM regions.

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
- Linux ELF (stripped CTF binaries, server daemons)
- macOS code-signed apps
- Android NDK native libraries
- Windows kernel drivers
- Packed/UPX binaries
- Go/Rust/Swift/Zig compiled binaries
- Real malware samples (with appropriate warnings)
