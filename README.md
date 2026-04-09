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
Generated Rust crate
    |
    v
parse_instruction(bytes) -> (length, display, Vec<PcodeOp>)
```

rsleigh reads the same `.slaspec` files that ship with Ghidra and generates a standalone Rust crate that can decode any instruction for that architecture. The generated code depends only on `pcode-ir`, a zero-dependency crate defining `PcodeOp` and `Varnode` types.

## Workspace

| Crate | Description |
|-------|-------------|
| `rsleigh` | SLEIGH parser and Rust code generator (merged from `sleigh-rs` + `sleigh2rust`) |
| `pcode-ir` | P-code IR types (`PcodeOp`, `Varnode`, `AddressSpaceId`) — zero dependencies |
| `test-harness` | Integration tests against `.slaspec` files |

## Status

Work in progress. Current state:

- [x] SLEIGH parser — parses x86-64 `.slaspec` (5700+ constructors)
- [x] Instruction decoding — pattern matching and disassembly
- [x] P-code emission — `lift()` function generating `Vec<PcodeOp>` per instruction
- [x] Export propagation — register, memory reference, and branch target exports
- [x] Disassembly variable resolution (branch targets, relocations)
- [x] Split-module codegen for faster compilation
- [x] Peephole optimizer — eliminates identity Subpiece and single-use Copy chains
- [ ] P-code semantic validation against Ghidra golden output
- [ ] ARM64 support

### Example output

```
MOV RDI,RAX  ->  Copy { out: Register(0x38, 8), input: Register(0, 8) }

PUSH RAX     ->  IntSub { RSP, RSP, 8 }
                 Copy { RSP, tmp }
                 Store { [RSP], RAX }

JZ 0x1007    ->  CBranch { dest: Ram(0x1007), cond: Register(ZF) }

CALL RAX     ->  IntSub { RSP, RSP, 8 }
                 Copy { RSP, tmp }
                 Store { [RSP], inst_next }
                 CallInd { RAX }
```

## Building

```
cargo build
```

The test-harness parses the full x86-64 `.slaspec` and generates ~24 MB of Rust code. First build takes several minutes; incremental rebuilds are faster.

Requires Rust 1.70+.

## License

Apache 2.0
