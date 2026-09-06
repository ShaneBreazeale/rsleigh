# CLI command guide

Use this guide to choose an artifact before running analysis. `FILE` means an
input binary, `FUNCTION` means a discovered function name or `0x` virtual
address, and `DIR` means an output directory. Substitute real values; sample
addresses are illustrative.

## Invocation conventions

```bash
rsleigh ./sample.exe --agent-brief
rsleigh ./sample.exe --xrefs 0x140001000
rsleigh ./sample.exe 0x140001000 --card --pcode
```

- Put the binary path first. Quote paths and names containing spaces. Use
  `./` for a filename that begins with a dash.
- Use virtual addresses from the current binary's output, not file offsets or
  addresses copied from another sample. Keep hexadecimal addresses as strings
  in JSON tooling to avoid numeric precision loss.
- Run one primary mode per invocation. For example, run `--ioc` and
  `--sigcheck` separately; combining them does not run both producers.
- Modifiers apply only to the modes that document them. `--json` is not a
  universal output switch; `--limit` controls the agent brief/index, not every
  command. Unknown flags may be ignored instead of rejected.
- For local usage text, invoke `rsleigh` without arguments: it writes usage to
  stderr and exits nonzero. The current CLI treats `--help` and `--version` as
  input filenames. Record the package version from installation metadata or
  the source commit used to build it.
- `--features smt` is a Cargo build option, never an `rsleigh` runtime option.

The tables below show the supported combinations to use. They are a task guide,
not a promise that arbitrary combinations of flags compose.

## Map and select functions

These analysis modes operate on parsed PE, ELF, and Mach-O binaries.

| Question | Invocation after `rsleigh FILE` | Output / cost |
|---|---|---|
| Where should I start? | `--agent-brief --limit 5` | Capped JSON map; ranking still examines the discovered function map |
| What functions were discovered? | No extra arguments | Text address/name list |
| Where is a string used? | `--search "password"` | Matching functions; inspect xrefs next |
| Where is an API used? | `--search --api recv` | API-based function search |
| Where is a constant used? | `--search --const 0xCAFEBABE` | Constant-based function search |
| Who refers to this function? | `--xrefs FUNCTION` | Text callers, callees, and strings |
| How do I reuse a map across turns? | `--index DIR --limit 100` | JSON generation manifest plus artifact files; more work than a small brief |
| What is the whole call graph? | `--callgraph` | JSON; whole-binary analysis, with calls recovered from pseudocode |
| What is a compact overview? | `--summary` | Text summaries; whole-binary analysis |

Prefer the index's direct-call edges for instruction-based navigation. The
standalone call graph and analysis tags use reconstruction heuristics. Neither
captures every indirect or dynamically resolved call.

## Inspect one function

| Question | Invocation after `rsleigh FILE` | Output |
|---|---|---|
| What evidence fits in one model turn? | `FUNCTION --card --pcode` | Text; first 40 instructions and 120 P-code operations |
| What might it do? | `FUNCTION --card --pcode --decompile` | Text; adds at most 4,096 bytes of pseudocode |
| What are the decoded instructions? | `--disasm FUNCTION` | Assembly text; does not include P-code |
| What are the instruction metadata? | `--disasm FUNCTION --json` | JSON instruction array with P-code operation **counts** |
| What are the lifted semantics? | `--pcode-json FUNCTION` | JSON with constructor provenance and operation debug strings |
| What is the post-fold data flow? | `--ssa-json FUNCTION` | JSON blocks and variables with debug strings |
| What is the full pseudocode? | `FUNCTION` | Text; no card output cap |

Cards support `--json` (`rsleigh.card/v1`) and independent
`--instruction-cursor N` / `--operation-cursor N` pagination.
`--ssa-slice FUNCTION --var ID [--max-nodes N] [--max-depth N]` returns bounded
backward expression dependencies with unresolved boundaries.
`--verify-index DIR` checks version 2 generation identity and artifact checksums.
Agent commands exit 0 on completion, 2 for partial evidence, and 1 on failure.
P-code/SSA JSON dumps are not capped like
cards and are not a typed, versioned IR serialization. Save a full-function
dump to a file, select the relevant instructions/blocks, and preserve its
address and command. See [output formats](output-formats.md).

## Triage file contents

| Question | Invocation after `rsleigh FILE` | Scope / output |
|---|---|---|
| What are the hashes? | `--hashes` | Text file hashes; brief JSON also includes hashes |
| What strings look like indicators? | `--ioc --findings-ndjson` | NDJSON findings from file bytes |
| What are the IOC categories? | `--ioc --json` | One legacy aggregate JSON object |
| What Authenticode metadata is present? | `--sigcheck --json` | PE signature metadata; does not verify cryptographic validity |
| What embedded resources exist? | `--resources --json` | PE resource metadata |
| How do I extract resources? | `--resources --dump DIR` | Writes resource files; inspect diagnostics and resulting files |
| What vulnerability patterns appear? | `--vulnscan --findings-ndjson` | Heuristic findings from parsed native binaries; whole-binary analysis |
| What XOR-obscured strings appear? | `--xor-strings --json` | Aggregate JSON of candidates |

`--vulnscan --json` does not select a JSON renderer; use
`--findings-ndjson`. Signature/resource modes can report absence for non-PE
inputs; that is not an ELF or Mach-O signature verification result. See
[triage details](cli-triage.md).

## Packed code and custom VMs

Use these only after identifying candidate addresses in a parsed native binary:

```bash
rsleigh ./packed.exe main --annotate-crypto
rsleigh ./packed.exe --vm-dispatch 0x18001fc70 --findings-ndjson
rsleigh ./packed.exe --vm-classify-handlers 0x18001eb00,0x180018960 --findings-ndjson
rsleigh ./packed.exe --summarise-handlers 0x180018960 --findings-ndjson
rsleigh ./packed.exe --vm-bytecode 0x180063858:0x400 --vm-handlers handlers.json
```

Handler tables and bytecode addresses are analysis inputs; do not invent them
from a family label. These helpers identify patterns and recovered artifacts,
not a complete devirtualization. See [features](features.md) and the
[worked case study](showcase/crackme3-pyvmprotect.md).

## Solver-assisted questions

Use the executable built with SMT support and an address verified in the
function map:

```bash
target/release/rsleigh ./sample.exe --smt-candidates 0x140001000 \
  --smt-candidates-cap 16 --smt-candidates-top 5 > candidates.ndjson
```

An unresolved function name can become an empty scope and trigger a
whole-binary scan. Confirm the name/address first. The record cap limits
collected records per function; top-N is applied after collection and ranking.
Neither is a wall-clock or memory budget for the entire analysis.

See [SMT setup](smt-backend.md) and [candidate interpretation](smt-candidates.md).

## Raw firmware and WebAssembly

These use separate frontends. Do not carry native-container mode assumptions
into them.

| Input | Supported starting workflow | Important difference |
|---|---|---|
| Raw firmware | `--raw ARCH --base ADDR`, then add a function address | Text discovery / pseudocode; the native brief, index, card, P-code JSON, and SSA JSON paths do not apply |
| WebAssembly | List with `rsleigh FILE`, then select a listed name or `func_N` | Text reconstruction; no SLEIGH/P-code/SSA or native cards |

```bash
rsleigh ./firmware.bin --raw arm32 --base 0x08000000
rsleigh ./firmware.bin --raw arm32 --base 0x08000000 0x08001235
rsleigh ./module.wasm
rsleigh ./module.wasm func_0
```

Raw architecture names: `x86-64`, `x86-32`, `aarch64`, `arm32`, `mips32`,
`riscv64`. The example odd ARM32 address carries the Thumb mode bit; use the
mode established for your target. The base and ISA are caller-supplied facts,
not autodetected guarantees.

The raw path currently ignores `--disasm` as a rendering request and emits
pseudocode for a selected function. Likewise, adding `--json` or `--card` does
not provide their native-container contracts. For instruction-level raw
analysis, use the [Rust decoder API](../README.md#embed-in-rust) with explicit
architecture/context, or another verified decoder. Raw `--xrefs` is ARM32-only;
consult the [architecture matrix](architectures.md) before interpreting it.
