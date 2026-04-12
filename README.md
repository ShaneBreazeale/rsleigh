# rsleigh

Compile Ghidra's SLEIGH architecture specs into native Rust decoders that disassemble and decompile binaries to C-like pseudocode. No JVM, no C++, just `cargo build`.

## What it does

rsleigh parses `.slaspec` files (the same architecture definitions Ghidra ships), generates Rust code that decodes machine instructions into [P-code IR](https://ghidra.re/courses/languages/html/pcoderef.html), then decompiles that IR into readable pseudocode with function signatures, typed local variables, string literals, import names, DWARF variable recovery, and control flow reconstruction.

It is the disassembly and decompilation backend for [Spectra](https://github.com/ShaneBreazeale/spectra), replacing the Ghidra JVM daemon entirely.

## CLI

```bash
cargo install --path rsleigh-cli
```

```bash
rsleigh ./binary                       # list functions
rsleigh ./binary main                  # decompile a function
rsleigh ./binary main vuln init        # decompile multiple functions
rsleigh ./binary --all                 # decompile everything (two-pass type propagation)
rsleigh ./binary main --json           # JSON output for tool integration
rsleigh ./binary --disasm main         # disassembly with P-code
rsleigh ./binary --sigs extra.json     # load additional signatures from JSON
```

```
$ rsleigh ./ctf_challenge main
// main
init();
puts("Welcome to my intricate trap, where all who are not me shall fail.");
if (stage1() == 0) {
    fail();
    if (stage2() == 0) {
        fail();
        if (stage3() == 0) {
            fail();
            puts("Amazing");
            give_flag();
        }
    }
}
```

## Decompiler output

From compiled C with DWARF debug info:

```c
int factorial(int n) {
    if (n > 1) {
        return n * factorial(n - 1);
    } else {
        return 1;
    }
}

int main(void) {
    printf("add(3,4) = %d\n", add(3, 4));
    printf("factorial(6) = %d\n", factorial(6));
    printf("sum = %d\n", sum_array(nums, 5));
    printf("strlen = %d\n", string_length("hello world"));
    return 0;
}
```

From real CTF binaries (stripped ELF, no source):

```c
// hkcert UAF — win function immediately visible
void get_shell(void) {
    system("/bin/sh");
}

// Crypto-Cat login — buffer overflow with all strings resolved
puts("Enter admin password: ");
gets(var_12);                        // overflow here
strcmp(var_12);
puts("Correct Password!");

// Heap menu — full string + import resolution
void menu(long param_0) {
    print("Welcome to ABC Zoo!!!");
    print("1) Add animal");
    printf("> ");
    scanf("%d", buf);
}
```

From -O2 optimized code:

```c
// Division by constant recognized
return RAX % 3;                      // was: x * 0x55555556 >> 32

// Switch/case from jump table
switch (d) {
    case 0: return "Sunday";
    case 1: return "Monday";
    ...
}

// For-loop recovery
for (; len > i; i++) {
    total = arr[i] + total;
}
```

From PE64 binaries (PsExec, with malware analysis annotations):

```c
// Dynamic API resolution — arguments fully visible
GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"); // dynamic API resolution
GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile"); // dynamic API resolution

// RTTI vtable resolution
*param_0 = std::bad_array_new_length::vftable;

// Registry operations with annotations
RegCreateKeyExW(..., HKEY_LOCAL_MACHINE); // ⚠ registry modification
IsDebuggerPresent(); // ⚠ anti-debug check
```

From C++ binaries (Mach-O, demangled):

```c
phttp::Initialize();
phttp::Server::Server();
pthread_create();
phttp::Server::ListenAndRun();
phttp::Shutdown();
```

Tested against 30+ CTF binaries from CSAW, HSCTF, DiceCTF, Google CTF, hkcert, Crypto-Cat, fbctf, and Phoenix. Tested on Sysinternals PE64 tools (PsExec, strings64, whois64), tinyssh, phttp, and real malware samples from theZoo (WannaCry, Stuxnet/Duqu, Dyre, Emotet, Wildfire).

## Architectures

| Architecture | Constructors | Notes |
|---|---|---|
| x86-64 | 5700+ | Full instruction set, Windows x64 + SysV calling conventions |
| x86-32 | 4200+ | SSE/AVX, PE32 IAT, cdecl/thiscall, ELF32 PIE string resolution |
| AArch64 | 3500+ | NEON + SVE |
| ARM32 | 1200+ | ARMv7 + Thumb |
| MIPS32 | 900+ | FPU, DSP, MIPS16, microMIPS |
| RISC-V 64 | 500+ | RV64GC + F/D/B/K/P/Q/V/C |

**Binary formats:** ELF (32/64), Mach-O (x86-64, AArch64), PE (32/64) — auto-detected from headers. Function discovery from symbols, exports, CALL-target scanning, and prologue pattern matching for stripped binaries. Fallback manual PE parser handles malformed binaries with anti-analysis tricks (Stuxnet, packed malware).

**38K+ function signatures** auto-loaded — C stdlib, POSIX, Linux (syscall, ptrace, epoll, io_uring), macOS (GCD, ObjC runtime, CoreFoundation, IOKit, Mach, Security, CommonCrypto), Android, Win32/64 (with fine-grained typedefs: HKEY, HWND, REGSAM, LSTATUS), OpenSSL, zlib. Signatures propagate parameter names (`/* param_name */` at call sites) and Win32 typedef types through interprocedural two-pass analysis.

## How it works

```
.slaspec → parser → codegen → generated Rust crates → compile
                                                         ↓
bytes + addr → Decoder::decode() → Instruction { disassembly, ops: Vec<PcodeOp> }
                                                         ↓
             decompile_with_binary() → CFG → SSA → fold → structure → C pseudocode
```

**Decompiler pipeline (5 passes):**

1. **CFG** — P-code to basic blocks, branch resolution, IAT call target resolution, x86-32 CALL/RET boilerplate stripping
2. **SSA** — Iterative dataflow with phi insertion (multi-pass convergence for loop-carried variables)
3. **Fold** — Expression folding, dead code elimination, condition recovery, type inference (signed/float/pointer/bool), calling convention detection (SysV/Win64/cdecl), division-by-constant, modulo, signature-based type propagation (38K+ sigs), interprocedural typedef propagation (two-pass), backward Load propagation
4. **Structure** — If/else, while/for loop recovery, switch/case from jump tables, depth-limited recursion (max 256)
5. **Printer** — Function signatures with typed params and Win32 typedefs (HKEY, HWND, DWORD), `/* param_name */` annotations at call sites, Ghidra-style local declarations with array sizing (`WCHAR local_8[262]`), auto-naming (iVar/lVar), C++ demangling, import resolution (PLT/GOT/IAT + thunk + CRT wrapper), string literal detection, ELF32 PIE, stack noise elimination

## Rust API

```rust
use rsleigh_api::{Decoder, Architecture};

let mut dec = Decoder::new(Architecture::X86_64);
let inst = dec.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();
// MOV RAX,RBX (3 bytes)

let binary = std::fs::read("my_binary").unwrap();
let pseudocode = rsleigh_decompile::decompile_with_binary(
    Architecture::X86_64, &instructions, Some(&binary), Some(path));
```

## Quick start

```bash
make test                              # generate all archs + build + run tests
```

Or step by step:

```bash
cargo run -p rsleigh-generate          # parse slaspecs, emit generated Rust (~30s)
cargo test -p test-harness             # compile generated crates + run tests
```

## Repository structure

```
rsleigh/
  src/                    SLEIGH parser + Rust codegen library
  pcode-ir/               PcodeOp/Varnode types + peephole optimizer (no_std)
  rsleigh-api/            Decoder API — bytes to instructions + P-code
  rsleigh-decompile/      Decompiler — P-code to C pseudocode + 38K signature DB
  rsleigh-cli/            CLI binary (two-pass interprocedural decompilation)
  scripts/                Ghidra signature extraction script
  rsleigh-generate/       Slaspec parser, generates Rust crate source
  generated/              Output crates (regenerated from slaspecs)
  test-harness/           Golden tests, corpus, fuzz, decompiler validation
  slaspec/                Ghidra .slaspec files (Apache 2.0)
```

## Tests

~6000 assertions across 10 categories:

- **Golden P-code** — 145 exact decode assertions across all architectures
- **Stress/boundary** — sign-extension, overflow, REX prefix, SIB addressing edge cases
- **Functional** — 14 multi-instruction sequence tests (prologues, call conventions, loops)
- **Bug probes** — 55 semantic checks (all 16 x86 Jcc variants, IDIV, MOVZX/MOVSX, ARM LDR sizes)
- **Compiled code patterns** — canaries, switch tables, SETcc, LOCK, SSE2, PLT/GOT, TBZ/TBNZ
- **Ghidra differential** — ~300 instructions compared against Ghidra's P-code output
- **Decompiler comparison** — 11 functions decompiled side-by-side with Ghidra 12
- **CTF validation** — 30+ real binaries decompiled successfully
- **Decoder fuzz** — 1000 random byte sequences, zero panics
- **Decompiler fuzz** — 200 random instruction sequences through full pipeline, zero panics

## Security

The decompiler is hardened for untrusted input:
- Bounds-checked VarId access (sentinel return for OOB, no panics)
- Recursion depth limit (256) in structure recovery
- Checked arithmetic in PLT/GOT/IAT offset calculations
- Decompiler fuzz test catches panics from pathological P-code
- Zero `unsafe` blocks in the decompiler and API crates

## Known limitations

- Expression completeness — some register values not traced back to their defining expression
- Loop conditions not always recovered to source-level comparisons
- x86-32 sequential TEST/JNZ patterns sometimes nest incorrectly
- Register-indirect calls (`CALL EDI` loaded from IAT) not resolved to import names
- Packed malware — only stub functions visible (Emotet); need unpacking first
- Struct field typing — field offsets shown but not typed as struct members

## License

Apache 2.0. Bundled `.slaspec` files are from Ghidra (also Apache 2.0).
