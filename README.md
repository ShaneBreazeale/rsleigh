# rSleigh

A pure-Rust backend that compiles Ghidra's SLEIGH architecture specs into native decoders, then decompiles the resulting P-code to C-like pseudocode. No JVM, no C++ FFI.

## Honest framing

This started as the disassembly + decompilation backend for [Spectra](https://github.com/ShaneBreazeale/spectra), my reverse engineering tool. I wanted to drop the Ghidra JVM daemon, so I wrote a SLEIGH compiler and decompiler in Rust and am open-sourcing the backend.

It is **not** a drop-in replacement for Ghidra or IDA. It is a single-author project at v0.x, with limited testing relative to the size of the surface, and rough edges in the decompiler output. Treat it as exploratory infrastructure, not production tooling. If correctness on a specific binary matters to you, cross-check against Ghidra or BN.

## Prior art (and why this exists)

There are existing Rust efforts in this space:

- **[rbran/sleigh-rs](https://github.com/rbran/sleigh-rs)** — pure-Rust SLEIGH parser. Self-described as unfinished. The parser layer here is independent of sleigh-rs; the semantic layer was originally forked from it and has since diverged substantially.
- **[mnemonikr/libsla](https://github.com/mnemonikr/libsla)** + sleigh-compiler — FFI bindings to Ghidra's libsla. Solid if you accept a C++ dependency.
- **jingle_sleigh** — another FFI layer over libsla.

Why a greenfield reimplementation rather than contributing upstream: I wanted full codegen control (constructor cache layout, dynamic register lookup, generated-crate splitting) and a decompiler tightly coupled to the decoder. That is a defensible choice for a personal backend; it is not obviously the right choice for the ecosystem. If you need a SLEIGH frontend in Rust today and don't need the decompiler, sleigh-rs or the libsla bindings will likely serve you better.

## What works

A SLEIGH-driven decoder that emits P-code, plus a 5-pass decompiler (CFG → SSA → fold → structure → print) for 7 targets:

| Architecture | Constructors | Notes |
|---|---|---|
| x86-64 | 5700+ | SysV + Windows x64 calling conventions |
| x86-32 | 4200+ | SSE/AVX, PE32 IAT, cdecl/thiscall, ELF32 PIE |
| AArch64 | 3500+ | NEON + SVE |
| ARM32 | 1200+ | ARMv7 + Thumb, VFP/NEON (decode only; FP folding incomplete) |
| MIPS32 | 900+ | FPU, DSP, MIPS16, microMIPS |
| RISC-V 64 | 500+ | RV64GC + F/D/B/K/P/Q/V/C |
| WebAssembly | — | native parser, not SLEIGH-driven |

**Binary formats:** ELF (32/64), Mach-O (x86-64, AArch64), PE (32/64 incl. ARM64), WASM, raw firmware.

The generated decoder crates are large. x86-64 ships split across 8 compile batches and AArch64 across 4; downstream compile time and binary size are real costs you should expect.

## CLI

```bash
cargo install --path rsleigh-cli
```

```bash
rsleigh ./binary                       # list functions
rsleigh ./binary main                  # decompile a function
rsleigh ./binary --all                 # decompile everything
rsleigh ./binary --disasm main         # disassembly + P-code
rsleigh ./binary --json                # JSON output
rsleigh ./binary --xrefs main          # callers + callees
rsleigh ./binary --search "recv"       # find functions by string/API/constant
rsleigh ./binary --vulnscan            # pattern-based vulnerability scan
rsleigh ./binary --callgraph           # call graph as JSON
rsleigh ./binary --classes             # MSVC/GCC RTTI class recovery
rsleigh ./binary --diff ./binary_v2    # decompilation diff
rsleigh ./binary --taint main          # taint analysis
rsleigh --raw --arch arm32 fw.bin      # raw firmware blob
```

The `--vulnscan`, `--summary`, and `--search` flags are pattern-matching heuristics over decompiled output, not sound analyses. They are useful for triage; they will both miss real bugs and flag false positives.

## Decompiler output

A reasonable output on a CTF challenge with imports resolved and string literals inlined:

```c
// main
init();
puts("Welcome to my intricate trap, where all who are not me shall fail.");
if (stage1() == 0) {
    fail();
    if (stage2() == 0) {
        fail();
        if (stage3() == 0) {
            fail();
            puts("Amazing");
            give_flag();
        }
    }
}
```

A reasonable output on compiled C with DWARF:

```c
int factorial(int n) {
    if (n > 1) {
        return n * factorial(n - 1);
    } else {
        return 1;
    }
}
```

Output quality degrades on optimized code, complex stack frame layouts, indirect calls, and floating point. Expect to fall back to the disassembly + P-code view (`--disasm`) regularly.

## Token-efficient output

Three flags reduce decompiler output size for LLM-assisted analysis. Numbers below are from one 200-function PE64 binary; your mileage will vary.

| Flag | Effect | Reduction (sample) |
|---|---|---|
| `--compact` | Strip local declarations, 2-space indent | ~24% |
| `--brief` | Calls + control flow only | ~35% |
| `--min-complexity N` | Skip functions below cyclomatic complexity N | varies |
| `--brief --min-complexity 5` | Combined | ~40% |

## How it works

```
.slaspec → parser → codegen → generated Rust crates → compile
                                                         ↓
bytes + addr → Decoder::decode() → Instruction { disassembly, ops: Vec<PcodeOp> }
                                                         ↓
             decompile_with_binary() → CFG → SSA → fold → structure → C pseudocode
```

5-pass decompiler:

1. **CFG** — P-code to basic blocks, IAT call resolution, x86-32 CALL/RET boilerplate stripping
2. **SSA** — iterative dataflow with phi insertion and memory SSA for stack slots
3. **Fold** — expression folding, dead code elimination, condition recovery, type inference, calling-convention detection, signature-based propagation, MBA deobfuscation (SiMBA + equality saturation via `egg`)
4. **Structure** — if/else, while/for/do-while, switch/case from jump tables (depth-limited recursion, max 256)
5. **Printer** — function signatures, local declarations, register auto-naming, import resolution, prologue/epilogue elision

## Rust API

```rust
use rsleigh_api::{Decoder, Architecture};

let mut dec = Decoder::new(Architecture::X86_64);
let inst = dec.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();

let binary = std::fs::read("my_binary").unwrap();
let pseudocode = rsleigh_decompile::decompile_with_binary(
    Architecture::X86_64, &instructions, Some(&binary), Some(path));
```

`FunctionMeta`, `VulnFinding`, `CallGraphEntry` derive `serde::Serialize` for tool integration.

## Testing — what's there and what isn't

The current test suite (~6000 assertions) is best understood as a **regression net for changes I make**, not as evidence of correctness across the SLEIGH spec or the decompiler.

| Category | Count | What it actually proves |
|---|---|---|
| Golden P-code | 145 across 7 archs | ~20/arch — smoke tests, not coverage |
| Functional sequences | 14 | a handful of common patterns |
| Bug probes | 55 | regression pins for fixed bugs |
| Ghidra differential | ~300 instructions | the happy path I thought to write down |
| Decompiler-vs-Ghidra | 11 functions | qualitative spot checks |
| CTF validation | 30+ binaries | "produces output that looks right" |
| Decoder fuzz | 1000 random byte sequences | no panics — not correctness |
| Decompiler fuzz | 200 random P-code sequences | no panics — not correctness |

What is missing and would make this credible:

- Differential testing against Ghidra on millions of instructions, with a public divergence report
- Structural fuzzing of encoded instructions (not random bytes), which is what catches real decoder bugs
- A decompiler benchmark suite vs. Ghidra / Binary Ninja free / IDA free
- Round-trip emulator tests (decode → execute → compare against a reference CPU model)

I haven't done any of that yet.

## Security posture

The decoder and decompiler are intended to be safe to run on untrusted binaries:

- Zero `unsafe` in the decompiler and API crates
- Bounds-checked VarId access (sentinel on OOB, no panic)
- Recursion depth limit (256) in structure recovery
- Checked arithmetic in PLT/GOT/IAT offset math
- Fuzz tests cover panic-freedom, not correctness

I am not making a hardening claim beyond that. If you intend to run this on adversarial input as part of a service, audit it yourself.

## Known limitations

- Expression completeness — some register values not traced back to their defining expression, producing `iVar1 * factorial(n - 1)` instead of `n * factorial(n - 1)`
- Type inference is shallow: signed/float/pointer/bool + Win32 typedefs + heuristic struct field naming, no constraint-based recovery
- Stack frame reconstruction is heuristic; struct fields show offsets, not typed members
- Loop conditions are not always recovered to the source-level comparison; `while` sometimes appears where `for` would read better
- Loop-invariant expressions are not hoisted
- x86-32 sequential TEST/JNZ patterns occasionally nest incorrectly
- Register-indirect calls (`CALL EDI` after IAT load) not resolved to import names
- Packed malware — only stub functions visible without prior unpacking
- ARM32 VFP/NEON decodes correctly but FP register values are not fully traced through fold
- MBA deobfuscation handles 1-4 variable linear MBA; non-linear forms need synthesis
- "Pure Rust, no JVM" is mostly relevant if you are embedding analysis in a Rust tool. For long-running interactive RE the JVM startup tax is amortized; this project does not yet target `no_std` / WASM / embedded.

## Quick start

```bash
make test                              # generate all archs + build + run tests
```

Or step by step:

```bash
cargo run -p rsleigh-generate          # parse slaspecs, emit generated Rust (~30s)
cargo test -p test-harness             # compile generated crates + run tests
```

## Repository structure

```
rsleigh/
  src/                    SLEIGH parser + Rust codegen library
  pcode-ir/               PcodeOp/Varnode types + peephole optimizer (no_std)
  rsleigh-api/            Decoder API — bytes to instructions + P-code
  rsleigh-decompile/      Decompiler — P-code to C pseudocode + signature DB
  rsleigh-cli/            CLI binary
  rsleigh-generate/       Slaspec parser, generates Rust crate source
  generated/              Output crates (regenerated from slaspecs)
  test-harness/           Golden tests, corpus, fuzz, decompiler validation
  slaspec/                Ghidra .slaspec files (Apache 2.0)
```

## License

Apache 2.0. Bundled `.slaspec` files are from Ghidra (also Apache 2.0).
