# rsleigh

Compiles Ghidra's SLEIGH architecture specs (`.slaspec`) into native Rust decoders that turn raw bytes into P-code IR, then decompiles that P-code into C-like pseudocode. No JVM, no C++, just `cargo build`.

This is the disassembly and decompilation backend for [Spectra](https://github.com/ShaneBreazeale/spectra) — it replaces the Ghidra JVM daemon entirely.

## Quick start

```bash
make test   # generate all archs + build + run tests
```

Or step by step:

```bash
cargo run -p rsleigh-generate          # parse slaspecs, emit generated Rust (~30s)
cargo test -p test-harness             # compile generated crates + run tests
```

## Decode + decompile

```rust
use rsleigh_api::{Decoder, Architecture};

let mut dec = Decoder::new(Architecture::X86_64);
let inst = dec.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();
println!("{} ({} bytes)", inst.disassembly, inst.len);
// MOV RAX,RBX (3 bytes)

// Decompile with string literal + import resolution + DWARF debug info
let binary = std::fs::read("my_binary").unwrap();
let instructions: Vec<(u64, _)> = /* decode a function's bytes */;
let pseudocode = rsleigh_decompile::decompile_with_binary(
    Architecture::X86_64, &instructions, Some(&binary),
    Some(Path::new("my_binary")));  // enables dSYM lookup on macOS
```

## Decompiler output

Given a real compiled C program:

```c
int add(int a, int b) { return a + b; }
int factorial(int n) { if (n <= 1) return 1; return n * factorial(n - 1); }

int main() {
    printf("add(3, 4) = %d\n", add(3, 4));
    printf("factorial(5) = %d\n", factorial(5));
    strcpy(buf, "hello world");
    printf("reversed: %s\n", reverse_string(buf));
}
```

rsleigh produces:

```
printf("add(3, 4) = %d\n", add(3, 4));
factorial(5);
printf("factorial(5) = %d\n", factorial(5));
__strcpy_chk(RBP + 0xd0, "hello world", 0x20);
printf("reversed: %s\n", reverse_string(RBP + 0xd0));
```

For factorial:

```
if (1 < var_8) {
    factorial(var_8 - 1);
    EAX = (int64_t)EAX * (int64_t)factorial(var_8 - 1);
    return;
} else {
    var_4 = 1;
}
```

The decompiler pipeline: P-code → CFG → SSA → expression folding → structure recovery → C printer.

What it does:
- Prologue/epilogue elimination (push/pop/leave/ret hidden)
- Stack variable naming (`var_8` instead of `*(RBP - 0x8)`)
- Parameter detection (`param_0`, `param_1` from ABI registers)
- DWARF debug info recovery (`param_0` → `a`, `param_1` → `b` from `.debug_info` / macOS `.dSYM`)
- Condition recovery (x86 flags → comparisons, ARM64 NG/ZR/OV → comparisons)
- If/else and while loop recovery from CFG back-edges
- Call return value inlining (`printf("...", add(3, 4))`)
- Function argument display (`factorial(5)` not `factorial()`)
- Import name resolution (PLT/GOT stubs → `printf`, `strlen`)
- String literal detection (`0x100000624` → `"hello world"`)
- Dead code elimination (unused flag writes, register shuffling)
- Save/restore elision (register spills across calls hidden)
- Register copy tracking at print time (no SSA modification)

## Architectures

| Arch | Constructors | Notes |
|------|-------------|-------|
| x86-64 | 5700+ | Full instruction set, 8 parallel compile batches |
| AArch64 | 3500+ | NEON + SVE, 4 batches |
| ARM32 | 1200+ | ARMv7 + Thumb |
| MIPS32 | 900+ | Big-endian, FPU + DSP + MIPS16 + microMIPS |
| RISC-V 64 | 500+ | RV64GC + F/D/B/K/P/Q/V/C extensions |

## Crates

```
rsleigh/
  src/                    # SLEIGH parser + Rust codegen library
  pcode-ir/               # PcodeOp, Varnode types + peephole optimizer (no_std, zero deps)
  rsleigh-api/            # Decoder API — decode bytes into instructions + P-code
  rsleigh-decompile/      # Decompiler — P-code to C-like pseudocode (5-pass pipeline)
  rsleigh-generate/       # CLI: parse .slaspec files, write generated crate source
  generated/              # Output crates (gitignored /out/ dirs, regenerated from slaspecs)
  test-harness/           # Golden tests, corpus validation, fuzz tests, decompiler validation
  slaspec/                # Ghidra .slaspec files (Apache 2.0)
```

## Tests

4 test suites:
- **Golden tests** — 23 exact P-code assertions + 301 corpus instructions across 5 architectures
- **Fuzz tests** — 5000 random decode attempts (empty, truncated, garbage), zero panics
- **Register resolution** — offset→name mapping verification
- **Decompiler validation** — compiles C source, decompiles with rsleigh, asserts string literals, import names, conditions, function calls

## Spectra integration

rsleigh is wired into Spectra as the native analysis backend. In Settings > Analysis, select "Native (rsleigh)" to use it instead of Ghidra. Functions are discovered from symbol tables + recursive descent, disassembly and P-code views are live, and clicking a function shows decompiled pseudocode with syntax highlighting.

## License

Apache 2.0. The bundled `.slaspec` files are from Ghidra (also Apache 2.0).
