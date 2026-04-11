# rsleigh

Compile Ghidra's SLEIGH architecture specs into native Rust decoders that disassemble and decompile binaries to C-like pseudocode. No JVM, no C++, just `cargo build`.

## What it does

rsleigh parses `.slaspec` files (the same architecture definitions Ghidra ships), generates Rust code that decodes machine instructions into [P-code IR](https://ghidra.re/courses/languages/html/pcoderef.html), then decompiles that IR into readable pseudocode with string literals, import names, DWARF variable recovery, and control flow reconstruction.

It is the disassembly and decompilation backend for [Spectra](https://github.com/ShaneBreazeale/spectra), replacing the Ghidra JVM daemon entirely.

## CLI

```bash
cargo install --path rsleigh-cli
```

```bash
rsleigh ./binary                       # list functions
rsleigh ./binary main                  # decompile a function
rsleigh ./binary main vuln init        # decompile multiple functions
rsleigh ./binary --all                 # decompile everything
rsleigh ./binary main --json           # JSON output for tool integration
rsleigh ./binary --disasm main         # disassembly with P-code
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
// factorial() — cleaner than Ghidra (no temp variable)
if (n > 1) {
    return n * factorial(n - 1);
} else {
    return 1;
}

// main() — imports, string literals, nested calls
printf("add(3,4) = %d\n", add(3, 4));
printf("factorial(6) = %d\n", factorial(6));
printf("sum = %d\n", sum_array(nums, 5));
printf("strlen = %d\n", string_length("hello world"));
return 0;
```

From real CTF binaries (stripped ELF, no source):

```c
// Buffer overflow — win function visible immediately
write(1, "-Warm Up-\n", 10);
sprintf(buf, "%p\n", easy);      // leaks easy() address
gets(buf);                        // overflow here

// Heap menu — full string + import resolution
puts("What would you like to do?");
puts("\t1. Add a friend");
if (var_10 == 4) { edit_friend(); }
else if (var_10 == 3) { display(); }
else if (var_10 == 2) { remove_friend(); }
else { add_friend(); }
```

From -O2 optimized code:

```c
// Branchless max (CMOV expansion)
if (EDI > ESI) { return EDI; }
return ESI;

// Compiler-inlined constants
printf("add(3,4) = %d\n", 7);
printf("factorial(6) = %d\n", 720);
```

Tested against 25+ CTF binaries from CSAW, HSCTF, DiceCTF, Google CTF, Nightmare, and UTCTF.

## Architectures

| Architecture | Constructors | Notes |
|---|---|---|
| x86-64 | 5700+ | Full instruction set |
| x86-32 | 4200+ | SSE/AVX, PE32 IAT resolution |
| AArch64 | 3500+ | NEON + SVE |
| ARM32 | 1200+ | ARMv7 + Thumb |
| MIPS32 | 900+ | FPU, DSP, MIPS16, microMIPS |
| RISC-V 64 | 500+ | RV64GC + F/D/B/K/P/Q/V/C |

**Binary formats:** ELF, Mach-O, PE — auto-detected from headers.

## How it works

```
.slaspec → parser → codegen → generated Rust crates → compile
                                                         ↓
bytes + addr → Decoder::decode() → Instruction { disassembly, ops: Vec<PcodeOp> }
                                                         ↓
             decompile_with_binary() → CFG → SSA → fold → structure → C pseudocode
```

**Decompiler pipeline (5 passes):**

1. **CFG** — P-code to basic blocks, branch resolution, IAT call target resolution
2. **SSA** — Static single assignment with phi insertion
3. **Fold** — Expression folding, dead code elimination, condition recovery from x86/ARM flags, call argument collection (register ABI for x86-64, stack pushes for x86-32 cdecl)
4. **Structure** — If/else and while loop recovery via dominators and back-edges
5. **Printer** — C emission with register tracking, copy elision, import resolution (PLT/GOT, IAT), DWARF name recovery, string literal detection, stack variable naming

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
  rsleigh-decompile/      Decompiler — P-code to C pseudocode
  rsleigh-cli/            CLI binary
  rsleigh-generate/       Slaspec parser, generates Rust crate source
  generated/              Output crates (regenerated from slaspecs)
  test-harness/           Golden tests, corpus, fuzz, decompiler validation
  slaspec/                Ghidra .slaspec files (Apache 2.0)
```

## Tests

~6000 assertions across 9 categories:

- **Golden P-code** — 145 exact decode assertions across all architectures
- **Stress/boundary** — sign-extension, overflow, REX prefix, SIB addressing edge cases
- **Functional** — 14 multi-instruction sequence tests (prologues, call conventions, loops)
- **Bug probes** — 55 semantic checks (all 16 x86 Jcc variants, IDIV, MOVZX/MOVSX, ARM LDR sizes)
- **Compiled code patterns** — canaries, switch tables, SETcc, LOCK, SSE2, PLT/GOT, TBZ/TBNZ
- **Ghidra differential** — ~300 instructions compared against Ghidra's P-code output
- **Decompiler comparison** — 11 functions decompiled side-by-side with Ghidra 12
- **CTF validation** — 30+ real binaries decompiled successfully
- **Fuzz** — 5000 random byte sequences, zero panics

## Known limitations

- No type inference — all variables are register-width integers
- Loop conditions not always recovered to source-level comparisons
- x86-32 sequential TEST/JNZ patterns sometimes nest incorrectly
- Register-indirect calls (`CALL EDI` loaded from IAT) not resolved to import names
- JVM/WASM-only SLEIGH features (`ExprNew`, `ExprCPool`) return 0

## License

Apache 2.0. Bundled `.slaspec` files are from Ghidra (also Apache 2.0).
