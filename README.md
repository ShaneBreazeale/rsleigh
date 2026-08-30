# rsleigh

[![crates.io](https://img.shields.io/crates/v/rsleigh.svg)](https://crates.io/crates/rsleigh)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20stable-orange.svg)](https://www.rust-lang.org)

rsleigh is a scriptable, pure-Rust reverse-engineering workbench that turns PE,
ELF, Mach-O, WebAssembly, and raw firmware into C-like pseudocode, disassembly,
P-code, SSA, xrefs, call graphs, and structured output. It is built for
static-analysis loops—especially when an LLM helps search the output,
explain behavior, and turn findings into scripts—without requiring a Ghidra JVM
or C++ bindings.

The decoder and P-code lifter are the stable core. The decompiler and
analysis passes are useful but experimental: verify important conclusions
against the assembly, P-code, or another tool.

## Contents

- [A real-world solve](#a-real-world-solve)
- [Capabilities](#capabilities)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Triage workflow](#triage-workflow)
- [Packed-code and custom-VM analysis](#packed-code-and-custom-vm-analysis)
- [SMT-assisted analysis](#smt-assisted-analysis)
- [Supported targets](#supported-targets)
- [Rust API](#rust-api)
- [Development and testing](#development-and-testing)
- [Project status](#project-status)
- [Contributing](#contributing)
- [License](#license)

## A real-world solve

rsleigh recovered `CTF{pyvm_r0cks}` from a PyVMProtect-packed PE64 Python
extension using static analysis—no live debugger and no Ghidra JVM. The sample
contained a 53-opcode custom VM, a 117-stage init chain, two PCG decryption
passes, compressed bytecode, anti-debug checks, and per-entry VARINT data.
rsleigh found the real entry point, annotated the crypto, classified the VM
handlers, and disassembled the bytecode; a short Python decoder finished it.

- [Read the in-repo walkthrough](docs/showcase/crackme3-pyvmprotect.md)
- [Read the full v3 white paper](https://github.com/ShaneBreazeale/pyvmprotect-static-lift/blob/main/WHITEPAPER.md)
- [See the v5 follow-up](https://github.com/ShaneBreazeale/crackme-pyvmprotect-v5#11-tooling--rsleigh-recon-suite)

## Capabilities

| Task | Useful output |
|---|---|
| Understand a function | C-like pseudocode, disassembly, P-code, post-fold SSA |
| Navigate a binary | Function discovery, xrefs, call graphs, search by string, API, constant, or behavior |
| Triage an unknown sample | Hashes, IOCs, Authenticode metadata, resources, XOR strings, YARA, vulnerability heuristics |
| Investigate packed code | Crypto annotations, API-hash recognition, PEB/timing checks, SEH/TLS patch discovery, VM helpers |
| Work with an LLM or script | Compact text, brief summaries, JSON, P-code/SSA JSON, ranked NDJSON findings |
| Embed the decoder | A small multi-architecture Rust API returning disassembly and P-code |

When pseudocode is unclear, drop to disassembly, P-code, or SSA without leaving
the workflow. Feed the smallest useful artifact to your model or script.

## Installation

Install the CLI from crates.io:

```bash
cargo install rsleigh
```

For library use:

```toml
[dependencies]
rsleigh-api = "0.4"
pcode-ir = "0.4"
```

The optional Z3-backed SMT analysis requires a source build; see
[SMT analysis](#smt-assisted-analysis).

## Quickstart

Using rsleigh from a coding agent? Copy the bounded workflow contract in
[docs/AGENTS-rsleigh.md](docs/AGENTS-rsleigh.md) into the target-analysis
workspace, see the [agent workflow reference](docs/agent-workflow.md) for
schemas and caps, then start with one capped JSON map:

```bash
rsleigh ./sample.exe --agent-brief
```

Choose the artifact that matches the question instead of asking for the largest
possible dump:

| Question | Start with | Escalate only when needed |
|---|---|---|
| What kind of sample is this? | `rsleigh FILE --agent-brief` | Complete `--ioc`, `--sigcheck`, or `--resources` producers |
| Which functions matter? | `--agent-brief`, `--search`, or `--xrefs` | `--index DIR` for repeated queries |
| What does one function do? | `FUNCTION --card --pcode` | Add `--decompile` after checking the lift |
| What instruction semantics were lifted? | `--pcode-json FUNCTION` | `--ssa-json FUNCTION` for data-flow reasoning |
| Is a source-to-sink path reachable? | `--vulnscan --findings-ndjson` | `--smt-candidates FUNCTION` with the optional `smt` build |
| Is this raw firmware? | `--raw ARCH --base ADDR` | Keep both values explicit on every follow-up command |

For model-assisted work, preserve the file hash, architecture, image base,
function address, command, warnings, and truncation limits with every
conclusion. The [agent workflow reference](docs/agent-workflow.md) defines the
evidence and reporting contract.

Start with discovered functions, then narrow the analysis:

```bash
rsleigh ./sample.exe                         # list discovered functions
rsleigh ./sample.exe main                    # decompile by name
rsleigh ./sample.exe 0x140001000             # decompile by address
rsleigh ./sample.exe --xrefs main            # callers, callees, and strings
rsleigh ./sample.exe --disasm main           # assembly plus lifted P-code
rsleigh ./sample.exe --pcode-json main       # raw P-code for a script or model
rsleigh ./sample.exe --ssa-json main         # post-fold SSA
```

For a large binary, generate a compact map first:

```bash
rsleigh ./sample.exe --agent-brief              # capped JSON + trust labels + next commands
rsleigh ./sample.exe --summary
rsleigh ./sample.exe --callgraph > callgraph.json
rsleigh ./sample.exe --all --brief --min-complexity 10 > sample.brief.txt
rsleigh ./sample.exe --index sample-index/      # reusable functions/xrefs/findings/imports
```

Inspect one function without allowing an unbounded dump:

```bash
rsleigh ./sample.exe 0x140001000 --card
rsleigh ./sample.exe 0x140001000 --card --pcode
rsleigh ./sample.exe 0x140001000 --card --pcode --decompile
```

Search modes pivot directly to interesting functions:

```bash
rsleigh ./sample.exe --search "password"
rsleigh ./sample.exe --search --api LoadLibraryA
rsleigh ./sample.exe --search --const 0xCAFEBABE
rsleigh ./sample.exe --search --tag network,crypto --decompile
```

Raw firmware accepts an architecture and optional base address:

```bash
rsleigh ./firmware.bin --raw arm32 --base 0x08000000
rsleigh ./firmware.bin --raw arm32 --base 0x08000000 --disasm 0x08001234
```

## Triage workflow

Lightweight file-structure and string scans are good first passes:

```bash
rsleigh ./sample.exe --hashes
rsleigh ./sample.exe --ioc --json
rsleigh ./sample.exe --ioc --findings-ndjson > findings.ndjson
rsleigh ./sample.exe --sigcheck --json
rsleigh ./sample.exe --resources --dump extracted/
rsleigh ./sample.exe --xor-strings --json
rsleigh ./sample.exe --sections
```

Then move into semantic analysis:

```bash
rsleigh ./sample.exe --vulnscan --findings-ndjson >> findings.ndjson
rsleigh ./sample.exe --yara
rsleigh old.exe --diff new.exe
rsleigh ./sample.exe --classes --json
```

These modes surface leads, not proofs. See the
[triage reference](docs/cli-triage.md) for schemas and limitations.

## Packed-code and custom-VM analysis

PE64 analysis flags API-hash resolvers, PEB walks, timing probes, indirect
trampolines, suspicious dispatchers, scratch-buffer leaks, and SHA-256 regions.
Focused helpers can then inspect a candidate VM:

```bash
rsleigh ./packed.exe main --annotate-crypto
rsleigh ./packed.exe --vm-dispatch 0x18001fc70
rsleigh ./packed.exe --vm-classify-handlers 0x18001eb00,0x180018960
rsleigh ./packed.exe --summarise-handlers 0x180018960
rsleigh ./packed.exe --vm-bytecode 0x180063858:0x400 \
  --vm-handlers handlers.json
```

Add `--findings-ndjson` to any VM helper to emit the shared confidence-bearing
schema documented in [Findings NDJSON](docs/findings-ndjson.md).

These are pattern-based recon tools, not a general virtualization deobfuscator.
See the [feature notes](docs/features.md) and
[PyVMProtect walkthrough](docs/showcase/crackme3-pyvmprotect.md).

## SMT-assisted analysis

The optional `smt` feature adds Z3-backed, interprocedural source-to-sink
analysis and ranked NDJSON candidates for an analyst or LLM.

On macOS with Homebrew Z3:

```bash
CPATH=$(brew --prefix z3)/include LIBRARY_PATH=$(brew --prefix z3)/lib \
  cargo build --release --features smt -p rsleigh-cli

target/release/rsleigh ./binary --smt-candidates main > candidates.ndjson
```

See [SMT backend](docs/smt-backend.md) for setup and scope,
[SMT candidates](docs/smt-candidates.md) for taint evidence, and the shared
[findings NDJSON schema](docs/findings-ndjson.md) used across recon emitters.

## Supported targets

Decode coverage is not the same as lift or decompile coverage. The public
[architecture support matrix](docs/architectures.md) reports decode, lift,
discovery, and decompile separately for each ISA/mode.

The CLI loads ELF32/64, PE32/64, Mach-O 64, WebAssembly, and raw blobs. See
[architecture support](docs/architectures.md) for discovery details and gaps.

### Documentation map

| Need | Reference |
|---|---|
| Bounded LLM/coding-agent loop | [Agent workflow](docs/agent-workflow.md) |
| Drop-in workspace instructions | [Agent contract](docs/AGENTS-rsleigh.md) |
| Finding fields and confidence semantics | [Findings NDJSON](docs/findings-ndjson.md) |
| Decode/lift/discovery/decompile limits | [Architecture matrix](docs/architectures.md) |
| IOC, signature, and resource extraction | [CLI triage](docs/cli-triage.md) |
| Solver scope and interpretation | [SMT backend](docs/smt-backend.md) and [SMT candidates](docs/smt-candidates.md) |
| Pipeline internals and validation | [Decompiler passes](docs/decompiler-passes.md) and [testing](docs/TESTING.md) |
| Context7 library ID | `/ShaneBreazeale/rsleigh` |

## Rust API

`rsleigh-api` is the stable embedding surface for decoding instructions and
lifting them to P-code:

```rust
use rsleigh_api::{Architecture, Decoder};

let mut decoder = Decoder::new(Architecture::X86_64);
let inst = decoder.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();

assert_eq!(inst.disassembly, "MOV RAX,RBX");
assert_eq!(inst.len, 3);
```

The stable surface includes `Decoder`, `Architecture`, register-name lookup,
and re-exported `pcode-ir` types. Pin a version when embedding the experimental
`rsleigh-decompile` IR, passes, or printer.

## Development and testing

Building from a checkout requires Rust 2021 stable and `make`:

```bash
make test                                      # generate decoders and run the harness
cargo test -p rsleigh-decompile --release --lib
make decomp-bench                              # pseudocode regression gate
cargo install --path rsleigh-cli
```

The suite includes P-code tests, Ghidra oracle fixtures, decompiler regressions,
random-byte panic checks, real binaries, SMT calibration, and pseudocode
scoring. See [testing](docs/TESTING.md) and
[decompiler passes](docs/decompiler-passes.md).

## Project status

rsleigh is a v0.x, single-maintainer project. The decoder/lifter API has a narrow
stability promise; the CLI, pseudocode, discovery, and analysis passes remain
experimental. It has not received a dedicated security audit, so isolate it in
automated malware-processing systems.

## Contributing

Issues and pull requests are welcome. Bug fixes should include a regression
test, and changes to generated decoders should include architecture-level
coverage. Before opening a pull request, run:

```bash
make test
cargo test -p rsleigh-decompile --release --lib
```

The best starting points are [testing](docs/TESTING.md),
[decompiler passes](docs/decompiler-passes.md), and
[architecture support](docs/architectures.md).

## License

Apache-2.0. Bundled Ghidra `.slaspec` files are also Apache-2.0.
