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
  command. Agent operations reject flags outside their contract with
  `error_code: "unsupported_option"`; legacy modes may still ignore unknown flags.
- `rsleigh --help` writes usage to stdout and exits 0. Invoking `rsleigh`
  without arguments still writes usage to stderr and exits 1.
  `rsleigh --version` prints the package version; `--version --json` adds the
  linked build identity. A first argument beginning with `-` is always an
  option, so write a file named `--help` as `./--help`.
- Plain decompilation (`FILE FUNCTION...`, `--all`) exits 2 when any printed
  body stops at a branch it could not follow, such as an unrecognised jump
  table. Text output marks the function with a `// WARNING: unresolved control
  flow at ADDR` line; `--json` sets that function's `status` to `partial` and
  lists the branch in `diagnostics`.
- `--features smt` is a Cargo build option, never an `rsleigh` runtime option.

The tables below show the supported combinations to use. They are a task guide,
not a promise that arbitrary combinations of flags compose.

## Discover supported operations

```bash
rsleigh --capabilities --json > capabilities.json
rsleigh --capabilities            # the same catalog as text
```

Discovery is target-free: it reads no binary and builds no SSA. The
`rsleigh.capabilities/v1` catalog is generated from the same typed contracts
that validate agent invocations, so an accepted flag cannot be missing from it.
Each `operations[]` entry lists its schema, generated `usage`, typed `flags`
(`kind`: switch, count, address, function, path, or text), `effects` such as
`writes_cache`, output `limits`, and runnable `examples` with their accepted
exit statuses. Placeholders are `FILE`, `FUNCTION`, and `DIR`.

Availability and quality are reported separately. `frontends[]` lists which
operations each input frontend implements; raw images and WASM list none.
`architectures[]` reports per-stage quality (`tested` or `partial`) and
dependency-query support. For example, MIPS32 and RISC-V scalar returns are
`supported`, while their call-argument selectors and helper argument binding
are `unsupported` and fail with `selection_error.code: "unsupported_root"`.

Agent failures keep `status: "failed"`, `error`, and a `command` diagnostic,
and add a stable `error_code`. Card and slice failures found during analysis
keep their own diagnostics and metrics instead of a `command` diagnostic and
still set `error_code`; for example, a deadline that stops work before the first
instruction decodes reports `execution_limit`, and a slice `selection_error`
reports `invalid_selector`:

| `error_code` | Meaning |
|---|---|
| `multiple_modes` | More than one operation was selected |
| `unknown_option` | A target-free invocation named no known operation |
| `unsupported_option` | The flag is not part of the selected operation's contract |
| `unexpected_argument` | A positional argument is not accepted here |
| `missing_value` | A flag that requires a value has none |
| `duplicate_option` | A non-repeatable flag appears more than once |
| `invalid_value` | A flag value has the wrong type or range |
| `invalid_selector` | Slice root flags do not select exactly one supported root |
| `invalid_combination` | Individually valid flags cannot be combined |
| `invalid_target` | The function target is missing, repeated, or malformed |
| `target_not_found` | No discovered function matches the target |
| `invalid_cursor` | A pagination cursor is beyond the available evidence |
| `unsupported_input` | The input frontend does not implement agent operations |
| `input_unreadable` | The binary or a referenced file cannot be read |
| `unsupported_format` | The container or architecture is not supported |
| `verification_failed` | Stored evidence failed an integrity or identity check |
| `missing_evidence` | Referenced evidence is unavailable in the store or bundle |
| `stale_revision` | The investigation changed since the expected revision |
| `requirements_unmet` | Cited evidence does not satisfy the question's requirements |
| `write_failed` | Publishing output files failed; previous output is unchanged |
| `execution_limit` | An execution limit stopped analysis before any evidence was produced |
| `analysis_failed` | Analysis could not produce any evidence |
| `command_failed` | Unclassified failure; inspect the error message |

Codes are stable; messages may change. Exit statuses are unchanged: 0 complete,
2 partial evidence, 1 failed.

## Serve operations over MCP

```bash
rsleigh --mcp        # Model Context Protocol server: JSON-RPC 2.0 on stdin/stdout
```

The server exposes the operations an agent needs first: `capabilities`,
`agent-brief`, `card`, `xrefs`, `search`, `ssa-slice`, and `verify-bundle`. Each tool's input
schema is generated from the same catalog as the CLI:

- `file` is the binary.
- `function` is the card target, and `query` is the search text.
- The mode value uses the flag name (`xrefs`, `ssa-slice`, `verify-bundle`).
- Each other flag becomes a property named after it without its dashes, such as
  `max-nodes` or `evidence-store`. Switches are booleans, counts are integers,
  and repeatable flags are arrays.

Output is always JSON. A tool result is the CLI's JSON document, delivered both
as `structuredContent` and as JSON text. `isError` is true exactly when the CLI
would exit 1. A partial result is not an error; check its `status`. Failures
carry the same `error_code` values as the CLI, and evidence records get the
same content IDs.

The server writes only protocol messages to stdout and diagnostics to stderr.
It handles one call at a time, so a cancellation notice arrives after its call
has finished and is ignored; bound work with `deadline-ms` instead.

Supported protocol revisions are 2025-11-25, 2025-06-18, 2025-03-26, and
2024-11-05. To register the server with an MCP client:

```json
{"mcpServers": {"rsleigh": {"command": "rsleigh", "args": ["--mcp"]}}}
```

## Map and select functions

These analysis modes operate on parsed PE, ELF, and Mach-O binaries.

| Question | Invocation after `rsleigh FILE` | Output / cost |
|---|---|---|
| Where should I start? | `--agent-brief --limit 5` | Capped JSON map; ranking still examines the discovered function map |
| What functions were discovered? | No extra arguments | Text address/name list |
| Where is a string used? | `--search "password"` | Matching functions; inspect xrefs next |
| Where is an API used? | `--search --api recv` | API-based function search |
| Where is a constant used? | `--search --const 0xCAFEBABE` | Constant-based function search |
| Which functions carry a behavior tag? | `--search --tag network,crypto` | Tag search; decompiles every function |
| Who refers to this function? | `--xrefs FUNCTION` | Text callers, callees, and strings |
| How do I reuse a map across turns? | `--index DIR --limit 100` | JSON generation manifest plus artifact files; more work than a small brief |
| What is the whole call graph? | `--callgraph` | JSON; whole-binary analysis, with calls recovered from pseudocode |
| What is a compact overview? | `--summary` | Text summaries; whole-binary analysis |

`--search` and `--xrefs` print text by default. With `--json` they emit
`rsleigh.search/v1` and `rsleigh.xrefs/v1`. `--api`, `--const`, and `--tag` are
mutually exclusive, and QUERY may come before or after the selector.
`--decompile` adds each match's pseudocode. Both modes decode at most the first
4,096 bytes of each function, so a call or match past that point is missed.
When any function is longer, the status is `partial` (exit 2) and
`limits.truncated_scans` counts those functions. On `--raw` input both modes
keep their raw-image text output.

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
| What are the lifted semantics? | `--pcode-json FUNCTION` | `rsleigh.pcode/v2` with raw typed operations and readable text |
| What is the post-fold data flow? | `--ssa-json FUNCTION` | JSON blocks and variables with typed expressions, origins, and legacy debug strings |
| What is the full pseudocode? | `FUNCTION` | Text; no card output cap |

Cards support `--json` (`rsleigh.card/v2`) and independent
`--instruction-cursor N` / `--operation-cursor N` pagination.
`--ssa-slice FUNCTION --var ID [--max-nodes N] [--max-depth N]` returns bounded
backward expression, exact-memory, and bounded helper dependencies with unresolved boundaries.
Replace `--var ID` with `--call-site 0xADDRESS --arg INDEX`,
`--return [--at 0xADDRESS]`, or `--condition 0xADDRESS` to select by intent.
See the [selector semantics and calling-convention limits](agent-workflow.md#bounded-backward-ssa-query).
Cards and slices support `--analysis-cache DIR`, `--max-decode-instructions N`,
`--max-ssa-work N`, and cooperative `--deadline-ms N`; see
[execution limits](agent-workflow.md#limit-execution-work).
Slices also support `--max-call-depth N`, `--max-functions N`, and
`--max-traversal-work N`; defaults are 2, 16, and 100,000 respectively.
`--verify-index DIR` checks version 2 generation identity and artifact checksums.
Briefs, cards, and slices accept `--evidence`, `--evidence-store STORE`, and
`--derived-from ID` to emit or persist content-addressed evidence records;
`--export-bundle BUNDLE --evidence-store STORE [--record ID]...`,
`[FILE] --verify-bundle BUNDLE`, and `--import-bundle BUNDLE --evidence-store STORE`
move them between sessions. See [portable evidence](agent-workflow.md#portable-evidence).
`FILE --investigate DIR --question TEXT` starts a durable investigation;
`[FILE] --investigation DIR` shows it (`--handoff` for Markdown) or applies one
`--expect-revision N` update. Export it with
`FILE --export-bundle BUNDLE --investigation DIR` and import it with
`--import-bundle BUNDLE --investigation NEW_DIR`. See
[tracking questions](agent-workflow.md#track-questions-across-sessions).
Agent commands exit 0 on completion, 2 for partial evidence, and 1 on failure.
P-code/SSA JSON dumps are not capped like cards. SSA dumps retain legacy
inspection fields alongside typed expressions. Save a full-function
dump to a file, select the relevant instructions/blocks, and preserve its
address and command. See [output formats](output-formats.md).

## Compare two builds

```bash
rsleigh old.bin --compare new.bin --json                     # every uniquely named function
rsleigh old.bin --compare new.bin --pair parse --pair 0x401000:0x402000 --json
rsleigh old.bin --diff new.bin                               # legacy colored text, same model
```

`--compare NEW` emits `rsleigh.function-comparison/v1` with `--json` and text
otherwise. Pairs come from `--pair OLD[:NEW]` (a name or `0x` address per side;
a bare target names both sides; `::` in C++ names is not a separator) or, by
default, from names that are unique and not address-derived (`FUN_`, `sub_`,
...) in both binaries. Duplicate names are reported as `ambiguous`; an explicit
request that is ambiguous or missing is reported under `unresolved_requests`.
Identical body bytes may produce `suggestions` for unmatched functions, always
with `established: false`; they never become pairs. `--limit N` bounds compared
pairs (default 100, cap 10,000).

Each pair reports six dimensions as `changed`, `unchanged`, or `unknown` with a
reason:

| Dimension | Compared evidence |
|---|---|
| `bytes` | Raw bytes of the reachable body (trailing padding excluded) |
| `instructions` | Raw P-code with function-relative locations, renumbered temporaries, and mapped references |
| `calls` | Direct callees as imports, matched pairs, or shared unique symbols; indirect calls counted |
| `strings` | Strings recovered from the body's pseudocode |
| `cfg` | Block successor structure, independent of block sizes and addresses |
| `pseudocode` | Pseudocode of the reachable body with own name and address-derived labels normalized; bounded line diff |

A reference is mapped only when justified: inside the function, an import, a
matched pair, or a symbol name unique in both binaries. Equal virtual addresses
alone never identify the same function. A difference only at unmapped
references is `unknown` (`unmapped_reference`). Incompatible architectures or
calling conventions make every dimension except `bytes` `unknown`
(`incompatible_profile`). Undecodable targets, truncated bodies
(`body_truncated`), indirect jumps, unresolved indirect calls, and failed
decompilation are propagated as `unknown`; an unchanged prefix of incomplete
evidence is never `unchanged`.

The verdict combines the dimensions as follows. Only a code dimension
(`instructions`, `calls`, `strings`, or `cfg`) can make a pair `changed`. Any
`unknown` dimension keeps the verdict `unknown`. When every dimension is
established, two differences are explained in `explanation` without counting as
a change:

- Raw-byte differences: relocation.
- Pseudocode differences: the decompiler works from the same instructions plus
  context such as callee names and library signatures, so a pseudocode-only
  difference reflects that context, not a code change.

The `pseudocode` dimension still reports `changed` and its diff.

Unmatched functions are `absent` only when the other binary's inventory is
complete (an unstripped ELF symbol table); PE exports, Mach-O, and heuristic
discovery are partial, so their unmatched names are `unknown`. The result is
`partial` (exit 2) when pairs are truncated or any verdict, inventory, or
request is unresolved. Unreadable or unparseable input fails (exit 1).
Comparison is evidence comparison, not proof of semantic equivalence.

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
