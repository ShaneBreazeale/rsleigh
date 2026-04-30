# rsleigh

[![crates.io](https://img.shields.io/crates/v/rsleigh.svg)](https://crates.io/crates/rsleigh)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20stable-orange.svg)](https://www.rust-lang.org)

rsleigh is a Rust workspace for decoding machine code with Ghidra SLEIGH
specifications, lifting instructions to P-code, and experimenting with C-like
decompilation and binary triage workflows.

> **Showcase:** [crackme3 PyVMProtect white paper v3](https://github.com/ShaneBreazeale/pyvmprotect-static-lift/blob/main/WHITEPAPER.md)
> [crackme3 PyVMProtect white paper v5]ttps://github.com/ShaneBreazeale/crackme-pyvmprotect-v5#11-tooling--rsleigh-recon-suite

The short version:

- It parses `.slaspec` files and generates Rust decoder crates.
- `rsleigh-api` exposes a reusable decoder/lifter API.
- `rsleigh-cli` can list, disassemble, and decompile functions from common
  binary formats.
- `rsleigh-decompile` is an active, useful, but still experimental decompiler.

This is not a drop-in replacement for Ghidra, IDA, or Binary Ninja. The decoder
and lifter are the most stable part of the project. The decompiler, malware
heuristics, and text output are moving quickly and should be treated as analysis
assistance, not ground truth.

## Contents

- [Showcase](#showcase)
- [Why this exists](#why-this-exists)
- [Status](#status)
- [Supported targets](#supported-targets)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Rust API](#rust-api)
- [Decompiler](#decompiler)
- [Malware and Triage Features](#malware-and-triage-features)
- [Testing and Benchmarks](#testing-and-benchmarks)
- [Known Limitations](#known-limitations)
- [Security Posture](#security-posture)
- [Workspace Layout](#workspace-layout)
- [Prior Art](#prior-art)
- [Contributing](#contributing)
- [License](#license)

## Showcase

End-to-end real-world solve, no live debugger, no Ghidra JVM:

- **[crackme3 PyVMProtect — `CTF{pyvm_r0cks}`](docs/showcase/crackme3-pyvmprotect.md)**
  — PE64 Python C-extension with a 53-opcode custom VM, 117-stage polymorphic
  init chain, two-pass PCG + zlib bytecode decryption, sbox-permuted handler
  dispatch, and per-entry VARINT-encoded flag bytes. rsleigh's
  `--annotate-crypto`, `--vm-classify-handlers`, `--summarise-handlers`, and
  `--vm-bytecode` modes did the heavy lifting; the finishing decoder is a
  short Python script.

## Why this exists

rsleigh started as the native analysis backend for
[Spectra](https://github.com/ShaneBreazeale/spectra). The goal was to get a
SLEIGH-driven decoder and P-code pipeline without depending on a long-running
Ghidra JVM process or C++ libsla bindings.

The project is now useful as:

- a pure-Rust SLEIGH decoder/lifter for supported architectures;
- a scriptable CLI for batch disassembly, pseudocode, xrefs, and triage;
- a testbed for P-code based decompilation passes;
- a place to experiment with malware-oriented static-analysis heuristics.

It is still a v0.x, single-maintainer project. If correctness on a specific
target matters, compare against another tool and inspect the P-code or assembly.

## Status

The stable surface is intentionally narrow:

- `rsleigh-api::Decoder`
- `Architecture`
- `Decoder::decode`
- register-name lookup
- re-exported `pcode-ir` types such as `Instruction`, `PcodeOp`, `Varnode`,
  `AddressSpaceId`, and `DecodeError`

Everything else should be considered experimental unless documented otherwise:
the CLI output format, decompiler internals, pseudocode text, signature
heuristics, function-ID behavior, malware annotations, and analysis passes may
change without a deprecation cycle.

## Supported targets

Instruction decoding and P-code lifting are generated from SLEIGH for:

| Architecture | Notes |
|---|---|
| x86-64 | 64-bit mode, SysV and Windows x64 decompiler conventions |
| x86-32 | 32-bit protected mode, cdecl/thiscall heuristics |
| AArch64 | AAPCS64-oriented decompiler support |
| ARM32 | ARMv7 and Thumb; floating-point folding is incomplete |
| MIPS32 | Big-endian MIPS, including PIC-oriented call resolution work |
| RISC-V 64 | RV64-oriented decoder support |

The CLI handles ELF, PE, Mach-O, raw blobs, and WebAssembly. WASM uses a native
parser path rather than SLEIGH because it is a stack VM and does not fit the
same register-machine model cleanly.

Generated decoder crates are large. Compile time and final binary size are real
costs, especially for x86 and AArch64.

## Installation

From crates.io (CLI only):

```bash
cargo install rsleigh               # installs `rsleigh` binary
```

The `rsleigh-api` and `pcode-ir` crates are published for library use:

```toml
[dependencies]
rsleigh-api = "0.3"
pcode-ir    = "0.3"
```

### From source

Requires Rust 2021 stable and `make`. From a checkout:

```bash
make test                          # generate + build + test (~30s slaspec parse, then build)
cargo install --path rsleigh-cli   # install the `rsleigh` binary
```

Step by step, if `make test` is too coarse:

```bash
cargo run -p rsleigh-generate      # parse .slaspec → generate decoder crates
cargo test -p test-harness         # compile and run the regression suite
cargo install --path rsleigh-cli
```

## Quickstart

Basic CLI usage:

```bash
rsleigh ./binary                         # list discovered functions
rsleigh ./binary main                    # decompile one function
rsleigh ./binary 0x140001000             # decompile by address
rsleigh ./binary --all                   # decompile all discovered functions
rsleigh ./binary --disasm main           # disassembly plus P-code
rsleigh ./binary --json                  # machine-readable output where supported
rsleigh ./binary --xrefs main            # callers and callees
rsleigh ./binary --raw x86-64            # treat input as a raw blob
```

Debug and integration-oriented output:

```bash
rsleigh ./binary --pcode-json main       # raw lifted P-code
rsleigh ./binary --ssa-json main         # post-fold SSA
rsleigh ./binary --sigs extra.json       # load extra function signatures
rsleigh ./binary --fid custom.fidb       # load an extra function-ID database
rsleigh ./binary --no-fid-auto           # disable bundled FID databases
```

Output-reduction modes for large binaries and LLM workflows:

```bash
rsleigh ./binary --all --compact         # remove some declarations and blank space
rsleigh ./binary --all --brief           # calls and control-flow oriented output
rsleigh ./binary --all --min-complexity 10
```

Experimental analysis modes:

```bash
rsleigh ./binary --search "recv"
rsleigh ./binary --search --api LoadLibrary --const 0xCAFEBABE
rsleigh ./binary --summary
rsleigh ./binary --callgraph
rsleigh ./binary --classes [--json]
rsleigh ./binary --diff ./binary_v2
rsleigh ./binary --taint main
rsleigh ./binary --vulnscan
rsleigh ./binary --yara
rsleigh ./binary --ioc        [--json]
rsleigh ./binary --sigcheck   [--json]
rsleigh ./binary --resources  [--dump DIR] [--json]
```

Those modes are heuristics over the current analysis pipeline. They are useful
for triage, but they are not sound vulnerability detection, taint analysis, or
semantic differencing. The last three (`--ioc`, `--sigcheck`, `--resources`)
are constant-time string + structure scans; see [`docs/cli-triage.md`](docs/cli-triage.md)
for the full reference, JSON schemas, and a recommended IR workflow.

Custom-VM packer recon helpers (PE64-focused; auto-banners run on every PE64
binary, the flags below take comma-separated hex VA lists):

```bash
rsleigh ./packed.exe --vm-dispatch 0x18001fc70           # dispatcher data slots
rsleigh ./packed.exe --vm-classify-handlers 0x18001eb00,0x180018960
rsleigh ./packed.exe --tag-dispatch 0x180012ec0          # CMP/JZ chain extract
rsleigh ./packed.exe --summarise-handlers 0x180018960    # IAT-API per handler
rsleigh ./packed.exe --vm-bytecode 0x180063858:0x400 \
                    --vm-handlers handlers.json          # bytecode disasm
rsleigh ./packed.exe main --annotate-crypto              # rewrite crypto consts
```

Auto-banners surface family fingerprint, JMP `<reg>` trampolines, XOR-encoded
dispatchers, hash-resolved API resolvers (ROR13/DJB2/DJB2a/FNV-1), PEB-walk
sites, RDTSC/RDPMC timing-probe pairs, scratch-buffer leak candidates, and
SHA-256 implementation regions. See `docs/features.md` for the full module list.

## Rust API

```rust
use rsleigh_api::{Architecture, Decoder};

let mut decoder = Decoder::new(Architecture::X86_64);
let inst = decoder.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();

assert_eq!(inst.disassembly, "MOV RAX,RBX");
assert_eq!(inst.len, 3);
```

The decompiler can also be embedded via `rsleigh-decompile`. Top-level entry
points — `decompile`, `decompile_with_binary`, `extract_learned_types`,
`extract_learned_structs` — rarely change in shape. Internal IR
(`ssa::*`, `fold::Expr`, `printer::*`, signature enums) churns between
releases as passes evolve, and public enums are not yet `#[non_exhaustive]`.
Pin an exact version or commit if you build on the internals.

## Decompiler

The decompiler turns lifted P-code into C-like pseudocode through:

1. CFG construction
2. SSA conversion
3. expression folding and type hints
4. control-flow structuring
5. printing and annotations

It can produce readable output for many simple and moderately complex
functions, especially when imports, signatures, strings, and straightforward
control flow are available.

Example shape:

```c
int factorial(int n) {
    if (n > 1) {
        return n * factorial(n - 1);
    }
    return 1;
}
```

Expect output quality to degrade on optimized code, unusual ABI patterns,
floating-point-heavy code, complex stack layouts, exception-heavy code,
indirect calls, hand-written assembly, and aggressive obfuscation. In normal
use, falling back to `--disasm`, `--pcode-json`, or another reverse-engineering
tool is part of the workflow.

More detail:

- `docs/decompiler-passes.md`
- `docs/architectures.md`
- `docs/features.md`

## Malware and Triage Features

The PE-focused analysis code is intentionally practical and pattern-based. It
tries to surface useful hints without pretending to be a full program-analysis
system.

Current examples include:

- PE64 SEH/TLS static patch discovery for some self-modifying-code patterns
- direct x64 syscall annotation for a Win11 24H2-oriented table
- ROR13 / DJB2 / DJB2a / FNV-1 API-hash resolver classification
- bundled function-ID databases for selected libc/libstdc++/musl builds
- Win32 and C/POSIX signature hints used by the decompiler printer
- C++ RTTI-oriented class recovery experiments
- Custom-VM packer recon (PyVMProtect / Themida / Stantinko / Trickbot Anchor style):
  vm-fingerprint, JMP `<reg>` trampoline gadgets, XOR-encoded dispatcher detection,
  PEB-walk anti-debug, RDTSC/RDPMC timing-pair anti-emu, scratch-buffer leak heuristic,
  SHA-256 constant-density region detection, crypto-constant inline annotation.
- `--vm-dispatch <addr>` extracts dispatcher metadata; `--vm-classify-handlers`
  classifies variable-length opcode handlers; `--tag-dispatch` extracts
  `CMP r8, imm; JZ` chains; `--summarise-handlers` reports IAT-API + stack-pop
  signature per handler; `--vm-bytecode <bc_va>:<size> --vm-handlers <path.json>`
  disassembles VM bytecode once handlers are classified.
- `--annotate-crypto` rewrites raw hex literals and `DAT_<hex>` labels to stable
  symbolic names (`KNUTH_9E3779B9`, `PCG_045D9F3B`, `SHA_256_6A09E667`) for
  readability across crypto-heavy functions.

These features can miss real behavior and can produce false positives. Treat
them as leads to inspect, not conclusions.

## Testing and Benchmarks

The test suite is a regression net for the project, not proof of full SLEIGH or
decompiler correctness.

Coverage includes:

- golden P-code tests across supported architectures;
- focused regression tests for previously fixed decoder/decompiler bugs;
- CLI integration tests against curated fixtures;
- Ghidra-oracle comparisons for selected instructions and binaries;
- fuzz-style panic checks for random byte streams;
- SEH/static-analysis fixture tests.

There is also a benchmark harness that compares rsleigh output against cached or
fresh Ghidra output:

```bash
make decomp-bench
python3 scripts/decomp-regress.py --binary ./some.bin --sample 12
scripts/bench-compare.sh <binary> [--sample N]
scripts/bench-score.py --binary X --rsleigh target/release/rsleigh --ghidra cached.json --out DIR
```

`decomp-regress.py` is the fast local gate: it compiles deterministic C fixtures
at `-O0` and `-O2`, decompiles selected functions, and fails if output quality
drops against `test-harness/fixtures/bench/pseudocode_baseline.json`. The Ghidra
bench is the heavier reference comparison for periodic runs. These scores are
coarse regression signals, not scientific rankings. Small movements are
expected; repeated and larger drops matter more than single-run noise.

See `docs/TESTING.md` for the current test philosophy and gaps.

## Known Limitations

The most important limitations today:

- The decompiler still loses some use-def links, which can leave variables like
  `iVar1` where the original source-level value should be recoverable.
- Type recovery is shallow. There are useful pointer, bool, signedness, Win32,
  and signature hints, but no full constraint-based type system.
- Stack-frame recovery is heuristic and can misrepresent aliased stack slots or
  structs.
- Control-flow structuring is improving but still prints some awkward or wrong
  shapes for loops, nested branches, and dead regions.
- Floating-point value propagation is incomplete, especially in ARM32 VFP/NEON
  paths.
- Register-indirect calls are only partly resolved.
- MBA/deobfuscation support handles a useful subset, not arbitrary obfuscation.
- Syscall annotations are Windows-build-specific hints.
- Full virtualization protectors remain out of scope for static recovery of the
  original program.

If you need trustworthy answers, use rsleigh as one signal among several.

## Security Posture

The project is intended to run on untrusted binaries, but it has not gone
through a dedicated security audit.

Current posture:

- safe Rust in the API and decompiler crates;
- bounds checks and recursion limits in analysis code;
- fuzz tests aimed at panic-freedom, not semantic correctness;
- no claim of sandboxing, exploit resistance, or service-hardening.

If you expose rsleigh in a network service or automated malware pipeline, isolate
the process and audit the code for your threat model.

## Workspace Layout

```text
rsleigh/
  src/                  SLEIGH parser and code-generation library
  pcode-ir/             P-code IR types and peephole optimizer
  rsleigh-api/          stable decoder/lifter API
  rsleigh-decompile/    experimental P-code to C-like decompiler
  rsleigh-fid/          function-ID database support
  rsleigh-cli/          command-line interface
  rsleigh-generate/     slaspec to generated Rust crates
  generated/            generated decoder crates
  test-harness/         fixtures, oracle tests, fuzz and integration tests
  slaspec/              bundled Ghidra SLEIGH specs
  scripts/              benchmark, oracle, signature, and FID tooling
  docs/                 detailed design and testing notes
```

## Prior Art

- [rbran/sleigh-rs](https://github.com/rbran/sleigh-rs): pure-Rust SLEIGH
  parser work. rsleigh's parser layer is independent; early semantic work was
  forked from sleigh-rs and has since diverged substantially.
- [mnemonikr/libsla](https://github.com/mnemonikr/libsla): Rust bindings to
  Ghidra's C++ libsla.
- jingle_sleigh and related projects: libsla-oriented bindings and tools.

If you only need a SLEIGH frontend and do not need rsleigh's generated Rust
decoder crates or decompiler experiments, one of those projects may be a better
fit.

## Contributing

Issues and PRs welcome. Before opening a PR:

```bash
make test                              # full regression sweep
cargo test -p rsleigh-decompile --release --lib   # fast inner loop
```

Guidelines:

- Land regression tests with bug fixes — the harness in `test-harness/` is the
  primary safety net.
- Keep `rsleigh-api` source-compatible; experimental changes belong in
  `rsleigh-decompile` or behind a CLI flag.
- For new SLEIGH targets, generate decoder crates via `cargo run -p
  rsleigh-generate` and add golden P-code coverage.
- See `docs/TESTING.md` for the test philosophy and `docs/decompiler-passes.md`
  for the pass pipeline.

Near-term focus is reliability over new analysis modes: tighter use-def
linking, broader Ghidra-differential coverage, encoded-instruction fuzzing,
reproducible benchmark fixtures, and clearer separation between stable and
experimental CLI surface.

## License

Apache-2.0. Bundled `.slaspec` files are from Ghidra and are also Apache-2.0.
