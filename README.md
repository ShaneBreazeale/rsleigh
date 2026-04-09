# rsleigh

Compiles Ghidra's SLEIGH architecture specs (`.slaspec`) into native Rust decoders that turn raw bytes into P-code IR. No JVM, no C++, just `cargo build`.

This is the disassembly/lifting backend for [Spectra](https://github.com/ShaneBreazeale/spectra) — it replaces the Ghidra JVM daemon with generated Rust code.

## Quick start

```bash
make test   # generate all archs + build + run 301 tests
```

Or step by step:

```bash
cargo run -p rsleigh-generate          # parse slaspecs, emit generated Rust (~30s)
cargo test -p test-harness             # compile generated crates + run tests
```

You can also generate a single architecture:

```bash
cargo run -p rsleigh-generate -- x86-64
cargo run -p rsleigh-generate -- aarch64
cargo run -p rsleigh-generate -- riscv
cargo run -p rsleigh-generate -- mips
cargo run -p rsleigh-generate -- arm32
```

## Using it

```rust
use rsleigh_api::{Decoder, Architecture};

let mut dec = Decoder::new(Architecture::X86_64);
let inst = dec.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();

println!("{}", inst.disassembly);  // "MOV RAX,RBX"
println!("{} bytes", inst.len);    // 3
for op in &inst.ops {
    println!("  {:?}", op);        // Copy { out: RAX, input: RBX }
}
```

`Decoder` manages the SLEIGH context and global set internally. Create one per architecture, call `decode()` in a loop.

## What it does

SLEIGH is Ghidra's language for describing CPU instruction sets. A `.slaspec` file defines how to match byte patterns, extract fields, and emit P-code (Ghidra's register-transfer IL). rsleigh parses these specs and generates Rust code that does the same thing Ghidra's Java decoder does:

1. **Pattern match** — find which constructor matches the input bytes
2. **Disassemble** — produce human-readable text (`MOV RAX,RBX`)
3. **Lift** — emit P-code operations (`Copy { out: RAX, input: RBX }`)
4. **Optimize** — peephole passes eliminate redundant copies, dead code, identity operations

The output is `Vec<PcodeOp>` — the same IR Ghidra produces, ready for SSA construction, dataflow analysis, or decompilation.

## Architectures

| Arch | Constructors | Notes |
|------|-------------|-------|
| x86-64 | 5700+ | Full instruction set, 8 parallel compile batches |
| AArch64 | 3500+ | NEON + SVE, 4 batches |
| ARM32 | 1200+ | ARMv7 + Thumb |
| MIPS32 | 900+ | Big-endian, FPU + DSP + MIPS16 + microMIPS |
| RISC-V 64 | 500+ | RV64GC + F/D/B/K/P/Q/V/C extensions |

Adding a new architecture is just adding its `.slaspec` to `slaspec/` and a few lines in the generator.

## How it's structured

```
rsleigh/
  src/                    # SLEIGH parser + Rust codegen library
  pcode-ir/               # PcodeOp, Varnode types + peephole optimizer (no_std, zero deps)
  rsleigh-api/            # High-level Decoder API (what you import)
  rsleigh-generate/       # CLI that runs the parser and writes generated crates
  generated/              # Output crates (gitignored /out/ dirs, regenerated from slaspecs)
    x86-shared/           # Registers, context, token fields
    x86-subtables/        # Subtable constructors
    x86-instr-00..07/     # Instruction constructors (8 batches, compile in parallel)
    x86-root/             # Top-level instruction enum + parse_instruction()
  test-harness/           # Golden tests + corpus validation
  slaspec/                # Ghidra .slaspec files (Apache 2.0)
```

The generated code splits large tables across multiple crates so `cargo` compiles them in parallel. x86-64 hits ~500% CPU on an M4.

Crate dependency graph (x86 shown):

```
pcode-ir -> x86-shared -> x86-subtables -> x86-instr-00 -+
                                           x86-instr-01 -+
                                           ...           +-> x86-root -> rsleigh-api
                                           x86-instr-07 -+
```

## P-code output

After the peephole optimizer runs, the output matches or beats Ghidra's op counts:

```
MOV RAX,RBX   -> 1 op   (Copy)
ADD RAX,RBX   -> 9 ops  (IntCarry, IntSCarry, IntAdd, flags)
PUSH RAX      -> 2 ops  (IntSub RSP; Store)         -- Ghidra: 3
RET           -> 3 ops  (Load RIP; IntAdd RSP; Return)
MOV RAX,[RBP+8] -> 2 ops (IntAdd; Load)             -- Ghidra: 5
```

The optimizer eliminates identity subpieces, forwards single-use copies, removes dead writes to temporaries, and sinks unique outputs into their consumers.

## Known limitations

- **Context fields in P-code expressions** return 0. Not used by x86/ARM/RISC-V but would matter for some exotic archs.
- **ExprNew / ExprCPool** are stubbed (JVM/WASM only).
- Validation is 301 instructions across 5 archs — good coverage but not exhaustive.

## License

Apache 2.0. The bundled `.slaspec` files are from Ghidra (also Apache 2.0).
