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

| Architecture | Constructors | NEON/SVE | Generated | Build time |
|---|---|---|---|---|
| x86-64 | 5700+ | n/a | 33 MB | ~3.5 min |
| AARCH64 | 3500+ | full | 34 MB | ~11 sec |

## Workspace

| Crate | Description |
|-------|-------------|
| `rsleigh` | SLEIGH parser and Rust code generator (merged from `sleigh-rs` + `sleigh2rust`) |
| `pcode-ir` | P-code IR types + peephole optimizer — zero dependencies, `no_std` |
| `rsleigh-generate` | Pre-build step: parses `.slaspec`, writes generated crate source files |
| `generated/x86-*` | Generated x86-64 crates (shared, subtables, 8 instruction batches, root) |
| `generated/aarch64-*` | Generated AARCH64 crates (shared, subtables, 4 instruction batches, root) |
| `test-harness` | Golden P-code tests — 16 x86-64 + 4 AARCH64 instructions |

## Status

- [x] SLEIGH parser — x86-64 and AARCH64 (including NEON + SVE)
- [x] Instruction decoding — pattern matching and disassembly
- [x] P-code emission — `lift()` generates `Vec<PcodeOp>` per instruction
- [x] Export propagation — register, memory reference, and branch target exports
- [x] Disassembly variable resolution (branch targets, relocations)
- [x] Peephole optimizer — identity Subpiece, Copy chain forwarding, dead code elimination
- [x] Parallel crate compilation — instruction batches compile concurrently
- [x] Golden tests — 20 instructions validated (16 x86-64 + 4 AARCH64)
- [ ] P-code validation against Ghidra output at scale
- [ ] Additional architectures (MIPS, RISC-V, etc.)

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
  B .             ->  Branch { Ram(target) }
```

## Building

```bash
# Generate + build + test (recommended)
make test

# Or manually:
cargo run -p rsleigh-generate       # parse slaspecs, generate code (~30s)
cargo test -p test-harness           # parallel compile + test
```

The generator parses both x86-64 and AARCH64 `.slaspec` files and writes ~67 MB of Rust source across 22 crates. Instruction batch crates compile in parallel, achieving ~500% CPU utilization on Apple Silicon.

Requires Rust 1.70+.

## Architecture

Generated crate dependency graph (x86-64 shown, AARCH64 similar with 4 batches):

```
pcode-ir  ->  x86-shared  ->  x86-subtables  ->  x86-instr-00 ─┐
                                                  x86-instr-01 ─┤
                                                  ...           ├─> x86-root -> test-harness
                                                  x86-instr-07 ─┘
```

## License

Apache 2.0
