# rsleigh

[![crates.io](https://img.shields.io/crates/v/rsleigh.svg)](https://crates.io/crates/rsleigh)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org)

**A reverse engineering framework written in Rust. No JVM. Built for LLM workflows.**

rsleigh turns binaries into evidence you can query: disassembly, P-code, SSA,
C-like pseudocode, cross-references, call graphs, and structured findings.
Use it from a terminal, give a coding agent a bounded view of a target, or
embed the decoder and lifter in your own Rust tools.

The workflow is simple: map the binary, find the functions that matter, inspect
their semantics, and carry the evidence into the next question. Compact output,
explicit limits, and machine-readable artifacts keep that loop practical for
LLMs and scripts.

## Contents

[Features](#features) · [Installation](#installation) · [Quickstart](#quickstart) ·
[LLM workflows](#built-for-llms-and-coding-agents) · [Framework](#under-the-hood) ·
[Targets](#supported-targets) · [Documentation](#documentation) ·
[Contributing](#contributing)

## Features

- **Rust throughout the core.** SLEIGH parsing, decoder generation, P-code
  lifting, and the decompiler live in Rust. Analysis runs without a Ghidra
  installation, Java runtime, or bindings to Ghidra's C++ decompiler.
- **Designed around a context budget.** Ranked briefs and bounded function
  cards let an agent inspect a few useful functions at a time. Reusable indexes
  support follow-up queries across turns.
- **Evidence at multiple levels.** Move from pseudocode to SSA, P-code, and
  instruction bytes. Outputs expose confidence, analysis stage, warnings, and
  truncation so a model can distinguish an observation from a hypothesis.
- **Useful beyond decompilation.** Search strings and API calls, trace xrefs,
  triage executables, identify library functions, and investigate packed code
  or custom VMs.
- **A framework you can embed.** Rust crates expose the decoder, intermediate
  representation, function identification, and experimental analysis pipeline.

The decoder and P-code lifter are the stable core. Decompilation, discovery,
and higher-level analysis remain experimental; check important conclusions
against the assembly and lifted semantics.

## Installation

Install the CLI with a Rust toolchain:

```bash
cargo install rsleigh
```

The default build needs no JVM. Optional SMT analysis adds a native Z3
dependency; see the [SMT setup and scope](docs/smt-backend.md).

## Quickstart

Replace `./sample.exe` with your target. Start with a capped JSON map:

```bash
rsleigh ./sample.exe --agent-brief
```

The brief includes file hashes, architecture, ranked functions, findings,
warnings, output limits, and address-specific follow-up commands. Pick a
function from the map, then inspect it by name or address:

```bash
rsleigh ./sample.exe --xrefs main               # callers, callees, and strings
rsleigh ./sample.exe main --card --pcode        # bounded assembly and lifted semantics
rsleigh ./sample.exe main --card --pcode --decompile
```

For direct exploration, list discovered functions or request pseudocode:

```bash
rsleigh ./sample.exe
rsleigh ./sample.exe main
rsleigh ./sample.exe 0x140001000
```

Use an address from your own target when symbols are unavailable.

## Built for LLMs and coding agents

rsleigh exposes a CLI that agents can call through their shell tools. Copy the
[drop-in agent instructions](docs/AGENTS-rsleigh.md) into your analysis
workspace to give an agent the workflow and evidence rules.

| Artifact | What it gives the agent |
|---|---|
| `--agent-brief` | One JSON map: 25 functions by default, at most 50 findings, hashes, trust labels, warnings, and next commands |
| `FUNCTION --card --pcode` | A focused view capped at 40 instructions and 120 P-code operations |
| `FUNCTION --card --pcode --decompile` | The same evidence plus up to 4,096 bytes of pseudocode |
| `--pcode-json FUNCTION` / `--ssa-json FUNCTION` | Structured instruction semantics or post-fold data flow for deeper reasoning |
| `--index DIR` | Reusable function, xref, import, and finding files with a manifest |
| `--findings-ndjson` | Confidence- and stage-labeled records from supported analysis modes |

For analysis spanning several turns, build an index once and query its files:

```bash
rsleigh ./sample.exe --index sample-index/
jq '.functions[] | select(.imports | index("recv"))' sample-index/functions.json
```

Preserve the binary hash, function address, exact command, and relevant warnings
with each conclusion. Pseudocode is a reconstruction; heuristic findings are
leads. Check schemas, top-level errors, and reported limits before consuming
output automatically.

The brief and index currently support PE, ELF, and Mach-O inputs. See the
[agent workflow reference](docs/agent-workflow.md) for schemas, hard caps,
ranking, and the reporting contract.

## Explore, triage, investigate

Find an entry point into an unfamiliar binary:

```bash
rsleigh ./sample.exe --search "password"
rsleigh ./sample.exe --search --api LoadLibraryA
rsleigh ./sample.exe --search --const 0xCAFEBABE
rsleigh ./sample.exe --callgraph > callgraph.json
```

Extract file-level indicators and collect analysis leads:

```bash
rsleigh ./sample.exe --ioc --findings-ndjson > findings.ndjson
rsleigh ./sample.exe --sigcheck --json
rsleigh ./sample.exe --resources --dump extracted/
rsleigh ./sample.exe --vulnscan --findings-ndjson >> findings.ndjson
```

Packed-code analysis includes crypto annotations, API-hash recognition,
PEB and timing probes, SEH/TLS patch discovery, and custom-VM dispatcher,
handler, and bytecode helpers. Optional Z3-backed analysis produces ranked
source-to-sink candidates within its documented model.

See the [feature catalog](docs/features.md), [triage reference](docs/cli-triage.md),
and [SMT candidates](docs/smt-candidates.md) for the specialized workflows.

### In practice: a PyVMProtect solve

rsleigh helped recover `CTF{pyvm_r0cks}` from a packed PE64 Python extension
through static analysis. The sample contained a 53-opcode custom VM, a
117-stage initialization chain, PCG decryption, compressed bytecode, and
anti-debug checks.

rsleigh found the real entry point, annotated crypto, classified VM handlers,
and disassembled bytecode. A short Python decoder completed the solve—a
concrete example of using the framework's evidence to build a focused tool.

Read the [walkthrough](docs/showcase/crackme3-pyvmprotect.md) for the analysis
and links to the full write-up.

## Under the hood

rsleigh uses Ghidra's SLEIGH processor specifications as input to its own Rust
parser and code generator. Generated Rust decoders produce disassembly and
P-code, an intermediate representation of instruction semantics. The analysis
pipeline builds on that representation to recover data flow and pseudocode.

```text
SLEIGH specifications → Rust parser + code generator → Rust decoders
                                                           │
Binary → load + discover → decode + lift → P-code → SSA → C-like pseudocode
                              │              │       │          │
                              └──────────────┴───────┴──────────┘
                                  CLI artifacts + Rust APIs
```

Ghidra provides the specification lineage and oracle fixtures for validation;
it is not required to run rsleigh. WebAssembly uses a dedicated frontend.

| Crate | Role |
|---|---|
| `rsleigh` / `rsleigh-generate` | SLEIGH parsing and Rust decoder generation; the root package also installs the CLI |
| `rsleigh-api` | Stable multi-architecture decoder and lifter API |
| `pcode-ir` | Shared instruction and P-code types |
| `rsleigh-fid` | Function identification from instruction fingerprints |
| `rsleigh-decompile` | Experimental IR, analysis passes, and pseudocode reconstruction |
| `rsleigh-cli` | Binary loading and command-line workflows |

### Embed in Rust

```toml
[dependencies]
rsleigh-api = "0.4"
```

```rust
use rsleigh_api::{Architecture, Decoder};

let mut decoder = Decoder::new(Architecture::X86_64);
let inst = decoder.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();

assert_eq!(inst.disassembly, "MOV RAX,RBX");
assert_eq!(inst.len, 3);
```

`rsleigh-api` exposes `Decoder`, `Architecture`, register-name lookup, and
re-exported P-code types. Pin an exact patch version when depending on the
experimental `rsleigh-decompile` internals.

## Supported targets

The CLI loads **PE32/64, ELF32/64, Mach-O 64, WebAssembly, and raw firmware**.
CPU targets include **x86-64, x86-32, AArch64, ARM32/Thumb, MIPS32 big-endian,
and RISC-V RV64GC**.

Coverage varies by architecture and stage. x86-64 and scalar AArch64 have the
strongest coverage; successful decoding does not imply complete lifting or
decompilation. Consult the [architecture matrix](docs/architectures.md) for
tested paths and known gaps.

For raw firmware, supply the architecture and image base on every command:

```bash
rsleigh ./firmware.bin --raw arm32 --base 0x08000000
rsleigh ./firmware.bin --raw arm32 --base 0x08000000 0x08001235
```

The second raw example selects a Thumb function for pseudocode. Raw firmware
uses a separate frontend; see [raw workflow limits](docs/cli-reference.md#raw-firmware-and-webassembly).

## Documentation

Start with the [documentation hub](docs/README.md),
[command guide](docs/cli-reference.md), and [output format reference](docs/output-formats.md).

| Topic | Reference |
|---|---|
| Agent setup and bounded analysis | [Agent instructions](docs/AGENTS-rsleigh.md) · [Workflow and schemas](docs/agent-workflow.md) |
| Analysis capabilities | [Feature catalog](docs/features.md) · [CLI triage](docs/cli-triage.md) |
| Structured findings | [NDJSON schema and confidence semantics](docs/findings-ndjson.md) |
| Architecture coverage | [Support matrix](docs/architectures.md) |
| Solver-assisted analysis | [SMT backend](docs/smt-backend.md) · [Candidate interpretation](docs/smt-candidates.md) |
| Pipeline and validation | [Decompiler passes](docs/decompiler-passes.md) · [Testing](docs/TESTING.md) |

Context7 library ID: `/shanebreazeale/rsleigh`.

## Contributing

rsleigh is a v0.x, single-maintainer project. Issues and pull requests are
welcome, especially reproducible cases that improve decode, lift, discovery,
or pseudocode quality.

From a checkout with a Rust toolchain and `make`:

```bash
make test                                      # generate decoders and run the harness
cargo test -p rsleigh-decompile --release --lib
make decomp-bench                              # pseudocode regression gate
cargo install --path rsleigh-cli
```

Include regression tests with bug fixes and architecture-level coverage for
generated-decoder changes. The suite covers P-code, committed Ghidra oracle
fixtures, decompiler regressions, random-byte panic checks, real binaries,
and pseudocode scoring. See [testing](docs/TESTING.md) for validation workflows,
including optional Ghidra comparisons and SMT calibration.

## License

[Apache-2.0](LICENSE). Bundled Ghidra `.slaspec` files are also Apache-2.0.
