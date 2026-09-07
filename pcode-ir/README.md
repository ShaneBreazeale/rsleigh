# pcode-ir

**Rust types and analysis helpers for SLEIGH-generated P-code.**

Represent instruction semantics as typed operations over registers, memory,
temporaries, and constants. Use `pcode-ir` to inspect lifted instructions,
build analysis tools, or transform P-code in your own Rust project.

Part of [rsleigh](https://github.com/ShaneBreazeale/rsleigh). This crate provides
the shared intermediate representation; use
[rsleigh-api](https://crates.io/crates/rsleigh-api) to decode machine code and
lift it into P-code.

[crates.io](https://crates.io/crates/pcode-ir) ·
[API documentation](https://docs.rs/pcode-ir/0.5.0/pcode_ir/) ·
[Source](https://github.com/ShaneBreazeale/rsleigh/tree/master/pcode-ir)

## Features

- Typed operations for data movement, memory access, control flow, integer and
  floating-point arithmetic, bit manipulation, and architecture-specific calls.
- Helpers to inspect operation inputs and outputs and relocate temporary varnodes.
- In-place peephole optimization, including constant folding and copy-chain simplification.
- `no_std` with `alloc`, zero dependencies by default, and optional Serde support.

## Installation

Add this to your project's `Cargo.toml`:

```toml
[dependencies]
pcode-ir = "0.5.0"
```

The crate uses Rust 2021. It requires allocation support (`alloc`) even when
used without `std`; there is no feature flag needed to enable `no_std`.

## Quickstart

Create a project with `cargo new pcode-example`, add the dependency above, and
put this in `src/main.rs`. Run it with `cargo run`.

```rust
use pcode_ir::{get_output, reads_varnode, Instruction, PcodeOp, Varnode};

fn main() {
    // Offsets identify storage in the target architecture's register space.
    // These illustrative registers are each 8 bytes wide.
    let source = Varnode::register(0x00, 8);
    let destination = Varnode::register(0x08, 8);

    let op = PcodeOp::IntAdd {
        out: destination,
        left: source,
        right: Varnode::constant(1, 8),
    };

    assert!(reads_varnode(&op, &source));
    assert_eq!(get_output(&op), Some(destination));

    // The decoder normally supplies the byte length and disassembly text.
    let instruction = Instruction::new(4, "example: r1 = r0 + 1".into(), vec![op]);
    println!("{}: {:?}", instruction.disassembly, instruction.ops);
}
```

## The P-code model

A `Varnode` identifies a value with three fields: `space`, `offset`, and `size`.
**Sizes are in bytes.** Register offsets follow the target's Ghidra register
layout; they are not portable register numbers.

| Address space | Constructor | Meaning of `offset` |
|---|---|---|
| `Register` | `Varnode::register(offset, size)` | Register storage offset |
| `Ram` | `Varnode::ram(offset, size)` | Memory address |
| `Unique` | `Varnode::unique(offset, size)` | Temporary storage offset |
| `Const` | `Varnode::constant(value, size)` | The constant value itself (`u64`) |

`PcodeOp` is an enum you can pattern-match to inspect each operation's operands.
`Instruction` groups a byte length, disassembly text, and `Vec<PcodeOp>`, with
optional `ConstructorSpan` metadata identifying the SLEIGH rule that produced it.

The inspection helpers work on individual operations:

| Helper | Purpose |
|---|---|
| `get_output` | Return the output varnode, if present |
| `writes_to` | Check whether the output exactly matches a varnode |
| `reads_varnode` / `count_reads` | Check or count exact operand matches |
| `visit_reads` | Visit each input varnode |
| `offset_unique_varnodes` | Shift all temporary offsets in an operation |

Operand matching compares the complete varnode, including its size. These
helpers do not perform memory alias analysis. When combining independently
lifted instructions, assign their `Unique` varnodes disjoint ranges using
`offset_unique_varnodes` to avoid temporary collisions.

## Optimize operations

Call `optimize` on an instruction's operation vector to fold small constant
expressions, simplify identity operations, and collapse eligible temporary
copy chains. Constant folding is limited to supported operations and widths
that fit the `u64` constant representation.

```rust
use pcode_ir::{optimize, PcodeOp, Varnode};

fn main() {
    let destination = Varnode::register(0, 4);
    let mut ops = vec![PcodeOp::IntAdd {
        out: destination,
        left: Varnode::constant(40, 4),
        right: Varnode::constant(2, 4),
    }];

    optimize(&mut ops);

    assert_eq!(ops, vec![PcodeOp::Copy {
        out: destination,
        input: Varnode::constant(42, 4),
    }]);
}
```

## Optional serialization

Enable `serde` to derive `Serialize` and `Deserialize` for `AddressSpaceId`,
`Varnode`, and `PcodeOp`:

```toml
[dependencies]
pcode-ir = { version = "0.5.0", features = ["serde"] }
```

Operations use an internally tagged representation with an `opcode` field and
snake-case variant names, such as `"int_add"`. Add a format crate such as
`serde_json` separately if needed. `Instruction`, `ConstructorSpan`, and
`DecodeError` do not implement Serde serialization in 0.5.0.

## Contributing

From a checkout of the rsleigh repository:

```bash
git clone https://github.com/ShaneBreazeale/rsleigh.git
cd rsleigh
cargo test -p pcode-ir
cargo test -p pcode-ir --features serde
```

This crate can be tested without generating architecture decoders. Issues and
pull requests are welcome; include a minimal operation sequence and a regression
test for changes to analysis or optimization behavior. See the repository's
[contribution guidance](../README.md#contributing) for broader development workflows.

## License

Licensed under [Apache-2.0](../LICENSE).
