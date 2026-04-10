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

// Decode
let mut dec = Decoder::new(Architecture::X86_64);
let inst = dec.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();
println!("{} ({} bytes)", inst.disassembly, inst.len);
// MOV RAX,RBX (3 bytes)

// Decompile a function
let instructions: Vec<(u64, _)> = /* decode a function's bytes */;
let pseudocode = rsleigh_decompile::decompile(Architecture::X86_64, &instructions);
```

## Decompiler output

Given a real compiled C function:

```c
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
```

rsleigh produces:

```
var_8 = EDI;
if (!ZF && OF == SF) {
    EAX = var_8;
    EDI = var_8;
    EDI = EDI - 1;
    func_100000490();
    EAX = EAX * ECX;
    var_4 = EAX;
    return;
} else {
    var_4 = 1;
}
```

The decompiler pipeline: P-code → CFG → SSA → expression folding → structure recovery → C printer. It handles:
- Prologue/epilogue elimination
- Stack variable naming (`var_8` instead of `*(RBP - 0x8)`)
- Flag elimination and condition recovery
- If/else from conditional branches
- While loops from back-edges
- Function call cleanup (argument setup preserved, return address push hidden)
- Dead code elimination
- Return value detection

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
  rsleigh-decompile/      # Decompiler — P-code to C-like pseudocode
  rsleigh-generate/       # CLI: parse .slaspec files, write generated crate source
  generated/              # Output crates (gitignored /out/ dirs, regenerated from slaspecs)
  test-harness/           # Golden tests, corpus validation, fuzz tests
  slaspec/                # Ghidra .slaspec files (Apache 2.0)
```

Generated code splits large instruction tables across parallel-compilable crates:

```
pcode-ir -> x86-shared -> x86-subtables -> x86-instr-00 -+
                                           x86-instr-01 -+
                                           ...           +-> x86-root -> rsleigh-api
                                           x86-instr-07 -+                    |
                                                              rsleigh-decompile
```

## Spectra integration

rsleigh is wired into Spectra as the native analysis backend. In Settings > Analysis, select "Native (rsleigh)" to use it instead of Ghidra. Functions are discovered from symbol tables + recursive descent, disassembly and P-code views are live, and clicking a function shows decompiled pseudocode.

## License

Apache 2.0. The bundled `.slaspec` files are from Ghidra (also Apache 2.0).
