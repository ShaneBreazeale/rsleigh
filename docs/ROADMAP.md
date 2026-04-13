# rsleigh Roadmap

## Current State

**6 architectures** (x86-64, x86-32, AArch64, ARM32, MIPS32, RISC-V 64), **5 binary formats** (ELF 32/64, Mach-O, PE32, PE64 including ARM64 Windows).

**Beats Ghidra on function discovery** on 11 of 13 test binaries across PE32, PE64, Mach-O, and ARM64.

**Key features:** 38K+ function signatures with param annotations, MSVC C++ demangling, ObjC bracket syntax, C++ stream wrapper inlining, Win32 typedef propagation (HKEY, HWND, REGSAM), MBA deobfuscation (SiMBA + equality saturation), interprocedural two-pass type propagation, do-while recovery, Ghidra-style local declarations with array sizing.

---

## Ship Quality — Make It Production-Ready

### ELF Linux Binary Testing
Completely untested against real Linux binaries this session. High risk of hidden bugs in ELF PLT/GOT resolution, DWARF parsing, and function discovery for stripped Linux executables. Test against common CTF binaries, server daemons, and malware samples.

### MIPS/RISC-V/ARM32 Testing
Three supported architectures with zero real-world validation beyond golden P-code tests. Need end-to-end decompilation testing on real firmware images (MIPS routers), IoT binaries (ARM32), and RISC-V toolchain output.

### Spectra Integration Testing
rsleigh is the decompilation backend for Spectra. The `rsleigh-api` + `rsleigh-decompile` API contract is untested in the UI context. Verify function discovery, ASM view, P-code view, and Code view all work correctly with the latest changes.

### CI Pipeline
Automated builds and testing to prevent regressions. Run on all test_bin binaries, compare function counts against saved baselines, flag any output quality regressions. GitHub Actions with matrix testing across architectures.

---

## Output Quality — Close the Gap with Ghidra

### Printer Pipeline Refactor
The printer has 20+ post-processing passes that sometimes conflict (RSP simplification undone by later passes, causing 768 `param_N[RSP]` regressions on main.exe). Refactor into a clean single-pass pipeline with well-defined ordering. This would fix the largest remaining output quality issue.

### Struct Recovery
Detect repeated field access patterns (`param_0->field_0`, `param_0->field_8`, `param_0->field_10`) and create struct type definitions. Map field offsets to names when the struct is passed to known APIs (e.g., `WNDCLASS`, `STARTUPINFO`). This is a significant analysis pass — Ghidra does it via Pspec type archives.

### Type Cast Emission
Ghidra shows 4,911 explicit casts on main.exe (`(uint)`, `(DWORD)`, `(char *)`). rsleigh shows zero. Emit casts when narrowing (64→32 bit), widening (32→64), changing signedness (signed→unsigned), or converting between pointer types. Makes implicit truncation visible.

### Better Control Flow
The remaining 282 deeply nested if/else chains should use `goto` for complex multi-exit patterns. Add `break` label support for nested loops. Detect and emit `switch` for computed jump tables that the current pattern matcher misses.

---

## New Capabilities — Things Ghidra Doesn't Do

### String Decryption
Detect common string obfuscation patterns at decompile time:
- XOR with single-byte or multi-byte key
- ROT13/ROT47 rotation
- Base64 decode from .rdata constants
- Stack string construction (byte-by-byte push/mov)

Show the decoded string as a comment next to the encoded reference. This would be uniquely valuable for malware analysis — no other decompiler does this automatically.

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

### String Deobfuscation
Recognize stack string construction patterns where bytes are assigned one at a time:
```
mov [rbp-0x10], 0x48  // 'H'
mov [rbp-0x0f], 0x65  // 'e'
mov [rbp-0x0e], 0x6c  // 'l'
```
Reconstruct the full string and show it as a comment or replace the individual stores.

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

### Reproducible Benchmark Suite
Script that runs rsleigh on all test_bin binaries and reports:
- Function counts vs saved Ghidra baselines
- String recovery counts
- Output line counts
- Key crackme findings (flag strings, secret keys)
- Timing (seconds per binary)

Run as part of CI to catch regressions. Store baselines in the repo.

### Expanded Test Corpus
Add binaries covering:
- Linux ELF (stripped CTF binaries, server daemons)
- macOS code-signed apps
- Android NDK native libraries
- Windows kernel drivers
- Packed/UPX binaries
- Go/Rust/Swift/Zig compiled binaries
- Real malware samples (with appropriate warnings)
