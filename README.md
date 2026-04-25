# rsleigh

pure-Rust SLEIGH-driven multi-arch decoder/lifter with an experimental decompiler and malware-analysis heuristics.
## Why

Started as the disassembly + decompilation backend for [Spectra](https://github.com/ShaneBreazeale/spectra), my reverse engineering tool. I wanted to drop the Ghidra JVM daemon, so I wrote a SLEIGH compiler and decompiler in Rust and am open-sourcing the backend.

It is **not** a drop-in replacement for Ghidra or IDA. Single-author project at v0.x with limited testing relative to the surface area, and rough edges in decompiler output. Treat as exploratory infrastructure, not production tooling. If correctness on a specific binary matters, cross-check against Ghidra or BN.

## Prior art

- **[rbran/sleigh-rs](https://github.com/rbran/sleigh-rs)** — pure-Rust SLEIGH parser, self-described as unfinished. Parser layer here is independent; semantic layer was forked from sleigh-rs and has diverged substantially.
- **[mnemonikr/libsla](https://github.com/mnemonikr/libsla)** — FFI bindings to Ghidra's libsla. Solid if you accept C++ deps.
- **jingle_sleigh** — another libsla FFI layer.

If you need a SLEIGH frontend in Rust today and don't need the decompiler, sleigh-rs or libsla bindings will likely serve you better. Greenfield reimplementation here is justified by full codegen control (constructor cache layout, dynamic register lookup, generated-crate splitting) and a decompiler tightly coupled to the decoder.

## What works

7 architectures end-to-end. SLEIGH-driven decoder emits P-code; 5-pass decompiler turns P-code into C-like output.

| Architecture | Notes |
|---|---|
| x86-64 | SysV + Windows x64 calling conventions |
| x86-32 | SSE/AVX, PE32 IAT, cdecl/thiscall, ELF32 PIE |
| AArch64 | NEON + SVE, AAPCS64 (x0-x7 + v0-v7 typed) |
| ARM32 | ARMv7 + Thumb, VFP/NEON (decode only; FP folding incomplete) |
| MIPS32 | FPU, DSP, MIPS16, microMIPS, PIC GP-relative resolution |
| RISC-V 64 | RV64GC + F/D/B/K/P/Q/V/C |
| WebAssembly | native parser (WASM is a stack VM, SLEIGH model fits poorly, this path bypasses it) |

**Binary formats:** ELF (32/64), Mach-O (x86-64, AArch64), PE (32/64 incl. ARM64), WASM, raw firmware.

Generated decoder crates are large. x86-64 ships split across 8 compile batches, AArch64 across 4. Downstream compile time and binary size are real costs to expect.

## PE64 malware analysis

Static-analysis features aimed at modern malware and packers. All gated to known patterns to keep false-positive rate low.

- **SEH SMC pipeline** — walks `.pdata` + UNWIND_INFO, parses MSVC scope tables (BFS depth 8), abstract-interp over `mov [tracked+disp], imm` + `rep movs` + indirect jumps + jump tables (stride 8 / MSVC i32-rel stride 4). Fixpoint loop (`extract → apply → re-discover`, hard cap 16) recovers code-on-demand patches. Solves the PyVMProtect v4 class. Walkthrough in `docs/pe64-seh-pipeline.md`.
- **TLS-callback SMC** — extends SMC fixpoint past SEH-only via `IMAGE_TLS_DIRECTORY64.AddressOfCallBacks`. Catches packers that hide unpack stubs in TLS callbacks instead of SEH handlers.
- **x64 syscall annotation** — block-local pattern detector for `mov eax, IMM; syscall` gadget; matches against Win11 24H2 ntdll table (~120 entries) and emits `// syscall 0xNN -> likely NtXxx` annotation. Resolves shellcode, Donut, Cobalt Strike, SysWhispers output.
- **PEB-walk ROR13 hash resolver** — when a 32-bit constant matches a known API hash (ROR13 over ~130 curated kernel32/ntdll/ws2_32/advapi32/wininet/user32 names), inline `/* ROR13("LoadLibraryA") */` annotation in decompiled output. Covers Metasploit `block_api`, Donut, public shellcode.
- **Function ID database** — Ghidra-FID-style body fingerprinting in pure Rust. xxh3 full + callee-aware specific hash over operand-masked instruction bytes. Bundled glibc 2.36, libstdc++ 12.2, musl 1.2.5 (x86_64 + aarch64), 13,612 entries auto-loaded by target arch. `rsleigh-fid-gen` builds custom .fidb from ELF/Mach-O/PE/`.a`.
- **38K+ function signatures** — auto-loaded; param-name annotations at call sites, Win32 typedef display (HANDLE, HKEY, REGSAM, ...), interprocedural propagation, cross-function struct propagation.

## CLI

```bash
cargo install --path rsleigh-cli
```

**Core:**

```bash
rsleigh ./binary                       # list functions
rsleigh ./binary main                  # decompile a function
rsleigh ./binary --all                 # decompile everything
rsleigh ./binary --disasm main         # disassembly + P-code
rsleigh ./binary --json                # JSON output
rsleigh ./binary --xrefs main          # callers + callees
rsleigh ./binary --raw x86-64          # raw firmware blob
rsleigh ./binary --pcode-json main     # raw P-code (debug)
rsleigh ./binary --ssa-json main       # post-fold SSA (debug)
rsleigh ./binary --sigs extra.json     # additional signatures
rsleigh ./binary --fid file.fidb       # additional FID database
rsleigh ./binary --no-fid-auto         # disable bundled FID DBs
```

**Token-reduced output (LLM workflows):**

```bash
rsleigh ./binary --compact             # -24% (strip locals)
rsleigh ./binary --brief               # -35% (calls + cflow only)
rsleigh ./binary --min-complexity N    # skip trivial functions
rsleigh ./binary --brief --min-complexity 5  # -40% combined
```

**Experimental:**

```bash
rsleigh ./binary --vulnscan            # 27 vuln patterns (heuristic)
rsleigh ./binary --search "recv"       # string/API/constant search
rsleigh ./binary --search --api LoadLibrary --const 0xCAFEBABE
rsleigh ./binary --summary             # one-line per function
rsleigh ./binary --callgraph           # JSON + behavioral tags
rsleigh ./binary --classes [--json]    # MSVC/GCC RTTI class recovery
rsleigh ./binary --diff ./binary_v2    # decompilation diff
rsleigh ./binary --taint main          # taint (intra-procedural, partial)
rsleigh ./binary --yara                # generate YARA from binary
```

Experimental flags are pattern-matching heuristics over decompiled output, not sound analyses. Will both miss real bugs and flag false positives. Treat as triage hints.

## Decompiler output

CTF challenge with imports + strings inlined:

```c
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

DWARF-compiled C:

```c
int factorial(int n) {
    if (n > 1) {
        return n * factorial(n - 1);
    } else {
        return 1;
    }
}
```

Output quality degrades on optimized code, complex stack frame layouts, indirect calls, and floating point. Expect to fall back to `--disasm` regularly.

## How it works

```
.slaspec → parser → codegen → generated Rust crates → compile
                                                         ↓
bytes + addr → Decoder::decode() → Instruction { disasm, ops: Vec<PcodeOp> }
                                                         ↓
             decompile_with_binary() → CFG → SSA → fold → structure → C pseudocode
```

5-pass decompiler:

1. **CFG** — P-code to basic blocks, IAT call resolution, x86-32 CALL/RET boilerplate stripping.
2. **SSA** — iterative dataflow with phi insertion + memory SSA for stack slots; deterministic Phi creation (varnodes sorted) so repeated runs produce identical output.
3. **Fold** — expression folding, DCE, condition recovery (compound flag patterns → comparisons), type inference (3-phase), CC detection, signature-based propagation, MBA deobfuscation (SiMBA + equality saturation via `egg`), Phi → Ternary at 2-way merges.
4. **Structure** — if/else, while/for/do-while, switch/case from jump tables (depth-limited recursion, max 256).
5. **Printer** — function signatures, local declarations, register auto-naming, import resolution, prologue/epilogue elision, syscall + ROR13 hash annotations.

Detail per pass: `docs/decompiler-passes.md`. Architectures: `docs/architectures.md`. Feature catalog: `docs/features.md`.

## Crates.io

Workspace published as namespaced crates:

- `rsleigh-cli` — CLI binary (`cargo install rsleigh-cli`)
- `rsleigh-api` — Decoder + P-code emitter
- `rsleigh-decompile` — Decompiler library
- `rsleigh-fid` — Function ID database
- `pcode-ir` — P-code IR types (no_std, zero deps)
- `rsleigh` — SLEIGH parser library
- `rsleigh-generate` — codegen CLI
- `rsleigh-gen-{x86,x86-32,aarch64,arm32,mips,riscv}-{shared,subtables,instr-NN,root}` — generated decoder crates (~40 internal crates, transitive deps; do not depend on directly)

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

## Bench vs Ghidra

```bash
scripts/bench-compare.sh <binary> [--sample N]   # full Ghidra + score
scripts/bench-score.py --binary X --rsleigh Y --ghidra cached.json --out DIR
```

Composite score weights: discovery 25, cflow_similarity 25, leak_parity 20, line_parity 15 (elision-aware), empty_rate 15.

Current scores on 4 fixtures: bed (Go x86-64) 89.7, plm (AArch64 C++) 84.3, git-repack (AArch64 C) 93.5, nano (ARM32 static stripped) 81.7, clang-apply-replacements (PE x86-64 MSVC C++) 91.2. Noise band: ~1% per repeat run.

Function discovery comparison (21 binaries): rsleigh wins 15, Ghidra 6.

## Testing — what's there and what isn't

~7200 assertions, ~240 tests. Best understood as a **regression net for changes I make**, not as evidence of correctness across the SLEIGH spec or the decompiler.

| Category | What it actually proves |
|---|---|
| Golden P-code (~145 across 7 archs) | ~20/arch — smoke tests, not coverage |
| Functional sequences | a handful of common patterns |
| Bug probes | regression pins for fixed bugs |
| Ghidra differential (~300 instructions) | the happy path I thought to write down |
| Pseudocode quality regressions (14) | per-fixture audit fixes locked in |
| CLI integration | per-fixture flag-subexpr / Go preamble / STACKSTR / etc. |
| Decoder fuzz (5000 random byte sequences) | no panics — not correctness |
| Spectra API contract | decoder/decompile/analysis/multi-arch |
| Native backend integration (10) | end-to-end pipeline |
| SEH static analysis (16) | crackmev3 + handler classification + TLS + dedup |

Doc: `docs/TESTING.md`.

What's missing and would make this credible:

- Differential testing against Ghidra on millions of instructions, with public divergence report
- Structural fuzzing of encoded instructions (not random bytes), which catches real decoder bugs
- Decompiler benchmark suite vs. Ghidra / Binary Ninja free / IDA free
- Round-trip emulator tests (decode → execute → compare against reference CPU model)
- Golden-file CI for curated CTF corpus

## Security posture

Decoder and decompiler intended to be safe to run on untrusted binaries:

- Zero `unsafe` in decompiler and API crates
- Bounds-checked VarId access — currently returns sentinel on OOB. **This is a problem, not a feature**: silent fallback on unexpected SSA state means decoder/decompiler bugs get swallowed and produce plausible-but-wrong output. Planned: tracing diagnostic channel + debug assertion so OOB hits are visible.
- Recursion depth limit (256) in structure recovery
- Checked arithmetic in PLT/GOT/IAT offset math
- Fuzz tests cover panic-freedom, not correctness

Not making a hardening claim beyond that. If you intend to run this on adversarial input as part of a service, audit it yourself.

## Known limitations

**Top priority — use-def linking failure.** Some register values are not traced back to their defining expression. `factorial` decompiles as `iVar1 * factorial(n - 1)` instead of `n * factorial(n - 1)`. SSA/fold layer doesn't always reach the original definition. Single most important correctness problem in the decompiler; gates further analysis features built on top of the pipeline (taint, vulnscan, diff all inherit it).

Other limitations:

- Type inference shallow: signed/float/pointer/bool + Win32 typedefs + heuristic struct field naming, no constraint-based recovery
- Stack frame reconstruction heuristic; struct fields show offsets, not typed members
- Loop conditions not always recovered to source-level comparison; `while` sometimes appears where `for` would read better
- Loop-invariant expressions not hoisted
- x86-32 sequential TEST/JNZ patterns occasionally nest incorrectly
- Register-indirect calls (`CALL EDI` after IAT load) not resolved to import names
- ARM32 VFP/NEON decodes correctly but FP register values not fully traced through fold
- MBA deobfuscation handles 1-4 variable linear MBA; non-linear forms need synthesis
- Syscall annotations are Win11 24H2-specific; numbers shift across Windows builds
- Win32k syscalls (0x1000+) not in syscall table — process-attach gated, rare in malware triage
- Full virtualization protectors (VMProtect 3.x, Themida) — VM dispatcher visible, original code not

## Quick start

```bash
make test                              # generate all archs + build + run tests
```

Step by step:

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
  rsleigh-fid/            Function ID database (xxh3 fingerprinting)
  rsleigh-cli/            CLI binary
  rsleigh-generate/       Slaspec parser, generates Rust crate source
  generated/              Output crates (40 internal crates)
  test-harness/           Golden tests, corpus, fuzz, decompiler validation
  slaspec/                Ghidra .slaspec files (Apache 2.0)
  scripts/                Ghidra/Qt sig extraction, FID DB build, publish
  docs/                   Detail docs (architectures, features, passes, SEH, testing)
```

## Roadmap

- Stable / experimental split enforced in API crate (currently only documented at CLI layer)
- `CHANGELOG.md` — none yet; treat `git log` as source of truth
- Fix use-def linking failure (top of Known Limitations) before adding more analysis features
- Diagnostic channel for VarId OOB instead of silent sentinel
- Golden-file CI for CTF corpus
- Mutation-based end-to-end binary fuzzing
- Multi-binary token-reduction benchmark
- PEB-walk hash table extension to FNV-1a / DJB2 / custom hashers (currently ROR13 only)
- Syscall tables for Win10 22H2 + Win11 23H2 (currently 24H2 only)
- ARM64 PAC pointer modeling

## License

Apache 2.0. Bundled `.slaspec` files are from Ghidra (also Apache 2.0).
