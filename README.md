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

## Workspace

| Crate | Description |
|-------|-------------|
| `rsleigh` | SLEIGH parser and Rust code generator (merged from `sleigh-rs` + `sleigh2rust`) |
| `pcode-ir` | P-code IR types + peephole optimizer — zero dependencies, `no_std` |
| `rsleigh-generate` | Pre-build step: parses `.slaspec`, writes generated crate source files |
| `generated/x86-*` | Generated crates (shared types, subtables, 8 instruction batches, root) |
| `test-harness` | Golden P-code tests for 10 x86-64 instructions |

## Status

- [x] SLEIGH parser — parses x86-64 `.slaspec` (5700+ constructors)
- [x] Instruction decoding — pattern matching and disassembly
- [x] P-code emission — `lift()` generates `Vec<PcodeOp>` per instruction
- [x] Export propagation — register, memory reference, and branch target exports
- [x] Disassembly variable resolution (branch targets, relocations)
- [x] Peephole optimizer — identity Subpiece, Copy chain forwarding, dead code elimination
- [x] Parallel crate compilation — 8 instruction batches compile concurrently
- [x] Golden tests — 10 x86-64 instructions validated against expected P-code
- [ ] P-code validation against Ghidra output at scale
- [ ] ARM64 support

### Example output

```
MOV RDI,RAX  ->  Copy { Register(0x38, 8), Register(0, 8) }

PUSH RAX     ->  IntSub { tmp, RSP, 8 }
                 Copy { RSP, tmp }
                 Store { [RSP], RAX }

JZ 0x1007    ->  CBranch { dest: Ram(0x1007), cond: Register(ZF) }

CALL RAX     ->  IntSub { tmp, RSP, 8 }
                 Copy { RSP, tmp }
                 Store { [RSP], inst_next }
                 CallInd { RAX }
```

## Building

```bash
# 1. Generate code from slaspec (~30 seconds)
cargo run -p rsleigh-generate

# 2. Build and test (~3.5 minutes, parallel)
cargo test -p test-harness
```

The generator parses the full x86-64 `.slaspec` (5700+ constructors) and writes ~33 MB of Rust source across 11 crates. The 8 instruction batch crates compile in parallel, achieving ~500% CPU utilization on Apple Silicon.

Requires Rust 1.70+.

## Architecture

```
x86-shared      (108 KB)  shared types, registers, context
x86-subtables   (3.5 MB)  236 subtable enums + constructors
x86-instr-00..07 (3-5 MB) instruction constructors (8 parallel batches)
x86-root        (6.3 MB)  instruction enum, parse_instruction()
```

The instruction table (~4500 constructors, 30 MB) dominates build time. Splitting into 8 independent crates enables parallel compilation:

```
pcode-ir  ->  x86-shared  ->  x86-subtables  ->  x86-instr-00 ─┐
                                                  x86-instr-01 ─┤
                                                  ...           ├─> x86-root -> test-harness
                                                  x86-instr-07 ─┘
```

## License

Apache 2.0
