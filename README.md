# rsleigh

Pure Rust SLEIGH compiler. Parses Ghidra's `.slaspec` architecture definitions and generates Rust code that decodes instructions and emits P-code IR.

Zero C++ dependencies, no JVM required.

## How it works

```
.slaspec file
    |
    v
rsleigh (parser + codegen)
    |
    v
Generated Rust crates (parallel compilation)
    |
    v
parse_instruction(bytes) -> (length, display, Vec<PcodeOp>)
```

rsleigh reads the same `.slaspec` files that ship with Ghidra (Apache 2.0) and generates standalone Rust crates that can decode any instruction for that architecture. The generated code depends only on `pcode-ir`, a zero-dependency crate defining `PcodeOp` and `Varnode` types.

## Supported architectures

| Architecture | Constructors | Extensions | Generated | Build time |
|---|---|---|---|---|
| x86-64 | 5700+ | full | 33 MB | ~3.5 min |
| AARCH64 | 3500+ | NEON + SVE | 34 MB | ~11 sec |
| RISC-V (RV64) | 500+ | F/D/B/K/P/Q/V/C | 5 MB | ~2.6 sec |

## Workspace

| Crate | Description |
|-------|-------------|
| `rsleigh` | SLEIGH parser and Rust code generator (merged from `sleigh-rs` + `sleigh2rust`) |
| `pcode-ir` | P-code IR types + peephole optimizer — zero dependencies, `no_std` |
| `rsleigh-generate` | Pre-build step: parses `.slaspec` files, writes generated crate source |
| `generated/x86-*` | Generated x86-64 crates (shared, subtables, 8 instruction batches, root) |
| `generated/aarch64-*` | Generated AARCH64 crates (shared, subtables, 4 instruction batches, root) |
| `generated/riscv-*` | Generated RISC-V crates (shared, subtables, 2 instruction batches, root) |
| `test-harness` | Golden P-code tests — 23 instructions across 3 architectures |

## Status

- [x] SLEIGH parser — x86-64, AARCH64 (NEON + SVE), RISC-V (RV64)
- [x] Instruction decoding — pattern matching and disassembly
- [x] P-code emission — `lift()` generates `Vec<PcodeOp>` per instruction
- [x] Export propagation — register, memory reference, and branch target exports
- [x] Disassembly variable resolution (branch targets, relocations)
- [x] Peephole optimizer — identity Subpiece, Copy chain forwarding, dead code elimination
- [x] Parallel crate compilation — instruction batches compile concurrently
- [x] Golden tests — 23 instructions validated (16 x86-64 + 4 AARCH64 + 3 RISC-V)
- [ ] P-code validation against Ghidra output at scale
- [ ] Additional architectures (MIPS, PowerPC, etc.)

### Example output

```
x86-64:
  MOV RDI,RAX  ->  Copy { Register(0x38, 8), Register(0, 8) }
  PUSH RAX     ->  IntSub { tmp, RSP, 8 }; Copy { RSP, tmp }; Store { [RSP], RAX }
  JZ 0x1007    ->  CBranch { dest: Ram(0x1007), cond: Register(ZF) }
  CALL RAX     ->  IntSub { tmp, RSP, 8 }; Copy { RSP, tmp }; Store { [RSP], inst_next }; CallInd { RAX }

aarch64:
  ADD X0, X1, X2  ->  IntAdd { X0, X1, X2 }
  RET             ->  Return { X30 }

riscv64:
  li ra,0x5     ->  Copy { ra, Const(5) }
  add x3,x0,x12 -> IntAdd { x3, x0, x12 }
```

## Building

```bash
# Generate + build + test (recommended)
make test

# Or manually:
cargo run -p rsleigh-generate       # parse all slaspecs, generate code (~30s)
cargo test -p test-harness           # parallel compile + test

# Single architecture:
cargo run -p rsleigh-generate -- x86-64
cargo run -p rsleigh-generate -- aarch64
cargo run -p rsleigh-generate -- riscv
```

The generator parses x86-64, AARCH64, and RISC-V `.slaspec` files and writes ~72 MB of Rust source across 27 crates. Instruction batch crates compile in parallel, achieving ~500% CPU utilization on Apple Silicon.

Requires Rust 1.70+.

## Architecture

Generated crate dependency graph (x86-64 shown; AARCH64 has 4 batches, RISC-V has 2):

```
pcode-ir  ->  x86-shared  ->  x86-subtables  ->  x86-instr-00 ─┐
                                                  x86-instr-01 ─┤
                                                  ...           ├─> x86-root -> test-harness
                                                  x86-instr-07 ─┘
```

## License

Apache 2.0
