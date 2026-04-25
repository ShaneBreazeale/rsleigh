# rsleigh

rsleigh is a Rust workspace for decoding machine code with Ghidra SLEIGH
specifications, lifting instructions to P-code, and experimenting with C-like
decompilation and binary triage workflows.

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

## Quick Start

From a checkout:

```bash
make test
```

Or step by step:

```bash
cargo run -p rsleigh-generate
cargo test -p test-harness
cargo install --path rsleigh-cli
```

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
```

Those modes are heuristics over the current analysis pipeline. They are useful
for triage, but they are not sound vulnerability detection, taint analysis, or
semantic differencing.

## Rust API

```rust
use rsleigh_api::{Architecture, Decoder};

let mut decoder = Decoder::new(Architecture::X86_64);
let inst = decoder.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();

assert_eq!(inst.disassembly, "MOV RAX,RBX");
assert_eq!(inst.len, 3);
```

The decompiler can also be embedded, but its API is not stable yet. Pin an exact
version or commit if you build on `rsleigh-decompile`.

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
- ROR13 API-hash comments for a curated set of common Windows APIs
- bundled function-ID databases for selected libc/libstdc++/musl builds
- Win32 and C/POSIX signature hints used by the decompiler printer
- C++ RTTI-oriented class recovery experiments

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
scripts/bench-compare.sh <binary> [--sample N]
scripts/bench-score.py --binary X --rsleigh target/release/rsleigh --ghidra cached.json --out DIR
```

The score is a coarse regression signal, not a scientific ranking. It combines
function discovery, control-flow similarity, leakage of unresolved temporary
names, rough line-count parity, and empty-output rate. Small movements are
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

## Roadmap

Near-term work is focused on making the existing pipeline more trustworthy
rather than adding more analysis modes:

- improve use-def linking and diagnostic reporting;
- broaden differential testing against Ghidra;
- add encoded-instruction fuzzing rather than only random-byte fuzzing;
- make benchmark fixtures easier to reproduce;
- tighten type recovery and indirect-call resolution;
- separate stable CLI/API behavior from experimental output more clearly;
- document changes in a changelog once releases settle down.

The longer roadmap lives in `ROADMAP.md`.

## License

Apache-2.0. Bundled `.slaspec` files are from Ghidra and are also Apache-2.0.
