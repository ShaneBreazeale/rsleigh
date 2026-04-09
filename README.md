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

rsleigh reads the same `.slaspec` files that ship with Ghidra (Apache 2.0) and generates a standalone Rust crate that can decode any instruction for that architecture. The generated code depends only on `pcode-ir`, a zero-dependency crate defining `PcodeOp` and `Varnode` types.

## Workspace

| Crate | Description |
|-------|-------------|
| `rsleigh` | SLEIGH parser and Rust code generator (merged from `sleigh-rs` + `sleigh2rust`) |
| `pcode-ir` | P-code IR types (`PcodeOp`, `Varnode`, `AddressSpaceId`) — zero dependencies |
| `test-harness` | Integration tests against `.slaspec` files |

## Status

Work in progress. Current state:

- [x] SLEIGH parser — parses x86-64 `.slaspec` (4500+ constructors)
- [x] Instruction decoding — pattern matching and disassembly
- [ ] P-code emission — `lift()` function generating `Vec<PcodeOp>` per instruction
- [ ] ARM64 support (NEON instructions need work)

## Building

```
cargo build
```

Requires Rust 1.70+.

## License

Apache 2.0
