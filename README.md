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
| ARM32 (ARMv7) | 1200+ | Thumb | 9 MB | ~4.3 sec |
| MIPS32 (BE) | 900+ | FPU + DSP + MIPS16 + microMIPS | 8 MB | ~3.2 sec |
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
| `generated/mips-*` | Generated MIPS32 crates (shared, subtables, 2 instruction batches, root) |
| `generated/arm32-*` | Generated ARM32 crates (shared, subtables, 2 instruction batches, root) |
| `test-harness` | Golden P-code tests + at-scale corpus validation (301 instructions) |

## Status

- [x] SLEIGH parser — x86-64, AARCH64 (NEON + SVE), ARM32 (Thumb), MIPS32 (MIPS16 + microMIPS), RISC-V (RV64)
- [x] Instruction decoding — pattern matching and disassembly
- [x] P-code emission — `lift()` generates `Vec<PcodeOp>` per instruction
- [x] Export propagation — register, memory reference, and branch target exports
- [x] Disassembly variable resolution (branch targets, relocations)
- [x] Peephole optimizer — identity Subpiece, Copy forwarding, DCE, output sinking (matches/beats Ghidra)
- [x] Parallel crate compilation — instruction batches compile concurrently
- [x] 301 validated instructions across 5 architectures (golden + capstone corpus)
- [x] Ghidra comparison — matches or beats Ghidra 12.0.4 P-code op counts
- [ ] Additional architectures (PowerPC, SPARC, etc.)

## Guarantees

- Generated decoders are standalone Rust crates with no JVM or native C++ runtime dependency.
- The generated lifting surface is `parse_instruction(bytes, addr) -> (length, display, Vec<PcodeOp>)`.
- Validation currently focuses on decode length, mnemonic agreement, and structural P-code sanity across curated golden cases plus corpus samples in `test-harness`.
- `pcode-ir` stays zero-dependency and `no_std`.

## Current Limits

- Validation is strong but not yet exhaustive semantic equivalence for every constructor on every bundled architecture.
- The generator currently targets the bundled `slaspec` set and the crate graph layout in this workspace.
- Some generated code paths are optimized for compile throughput and large-table splitting, so internal codegen structure is still evolving.
- Public library APIs are usable, but the project is still closer to a compiler workspace than a polished end-user crate.

### Example output (matches Ghidra)

```
x86-64:
  MOV RDI,RAX     ->  Copy { RDI, RAX }                    (1 op, Ghidra: 1)
  ADD RDI,RAX     ->  IntCarry; IntSCarry; IntAdd; flags... (9 ops, Ghidra: 9)
  PUSH RAX        ->  IntSub { RSP, RSP, 8 }; Store { [RSP], RAX }  (2 ops, Ghidra: 3)
  POP RAX         ->  Load { RAX, [RSP] }; IntAdd { RSP, RSP, 8 }   (2 ops, Ghidra: 4)
  RET             ->  Load { RIP, [RSP] }; IntAdd { RSP }; Return   (3 ops, Ghidra: 3)
  JZ 0x1007       ->  CBranch { Ram(0x1007), ZF }           (1 op)
  CALL RAX        ->  IntSub { RSP }; Store { [RSP], inst_next }; CallInd { RAX }  (3 ops)

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

## Validation

```bash
cargo test -p test-harness
```

The harness runs golden instruction checks plus corpus validation across x86-64, AARCH64, ARM32, MIPS32, and RISC-V. It is the main source of confidence for regressions and codegen changes.

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
