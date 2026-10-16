# Changelog

All notable user-facing changes to rsleigh are documented here.

## [Unreleased]

### Fixed

- MSVC and clang-cl x86-64 jump tables print as `switch`. Their entries are
  32-bit offsets from the image base (`mov eax, [base + idx*4 + disp]; add
  rax, base`), which were not recognised, so the body stopped at the jump.
  An unchecked sign-extended index also takes entries below the table
  (`case -1`). On CrashLoggerSSE 1.25.0 this recovers 73 tables, against 0
  before.
- Conditions whose operands share subexpressions print in linear time. A
  double-to-decimal routine in CrashLoggerSSE never finished decompiling,
  which stalled `--all` for the whole binary; it now takes 0.12 s.
- Operands in `if`/`while` conditions are parenthesized by C precedence:
  `x & 0xf000 != 0x4000` printed as written means `x & (0xf000 != 0x4000)`.

- Field accesses on untyped values print as valid C. A variable used only
  through `->field_N` with a consistent layout gets a packed struct type;
  any other access prints as `*(T *)(base + 0xN)`. Constant-offset stores
  no longer print as `param_0[80]`, which dropped the access width. On
  CrashLoggerSSE, member-reference compile errors halve and none remain on
  `field_N` names.

- Stack slots named `local_N` by the stack-pointer rewrites are declared.
  They were never declared, the most common compile error on CrashLoggerSSE.
  A slot used through a dereference or address arithmetic is declared as a
  byte array (it stands for the slot's address); one used only as a value is
  a `long`.

- `int 0x29` prints as `__fastfail(code)` and `int 3` as `__debugbreak()`
  instead of a call through an undeclared `tmp_N`; other calls through a
  temporary print the pointer they load.

## [0.6.1] - 2026-10-12

### Fixed

- `rsleigh-generate` output is byte-identical across runs. Token readers and
  pattern operand lists were emitted in hash-map order, so two builds of the
  same source differed.
- A recovered jump table with more than about 250 entries prints every case.
  The `switch` for Debian `ls`'s 277-entry table stopped after case 253.

## [0.6.0] - 2026-10-11

### Added

- `rsleigh --capabilities [--json]`: a target-free `rsleigh.capabilities/v1`
  catalog of agent operations (schemas, typed flags with evidence roles,
  effects, limits, runnable examples), input frontends, per-architecture stage
  quality and dependency-query support, and stable error codes. Dispatch
  validation and `--help` usage are generated from the same typed contracts.
- `--help` (stdout, exit 0) and `--version [--json]`, including the linked
  build identity.
- Stable `error_code` on every agent failure envelope.
- Portable evidence: `--evidence`, `--evidence-store DIR`, and
  `--derived-from ID` wrap brief/card/slice/comparison payloads in
  content-addressed `rsleigh.evidence/v1` records; `--export-bundle`,
  `--verify-bundle` (offline, optional source binding), and `--import-bundle`
  move them between sessions as `rsleigh.evidence-bundle/v1` generations.
- Investigations: `--investigate DIR --question TEXT` and
  `--investigation DIR` with revision-checked updates, deduplicated slice
  boundary issues, supporting/contradicting evidence, evidence-checked answers
  distinct from withdrawals, platform-aware next queries, and Markdown handoff.
  Investigation documents are treated as untrusted. Suggested commands quote
  every argument other than catalog flags, numbers, and addresses (including
  PowerShell typographic quotes), and never read or substitute the recorded
  binary path. Malformed boundary or requirement fields fail verification,
  and handoff text is escaped.
- `--compare NEW` (`rsleigh.function-comparison/v1`): per-dimension
  bytes/instructions/calls/strings/CFG/pseudocode comparison with explicit
  `unknown`, ambiguous, unmatched, and suggested-but-unestablished pairs.
  Only code dimensions establish `changed`. A pseudocode-only difference is
  explained as decompiler context.
- `agent_re_eval --workflows`: seven end-to-end workflow tasks in CI.
- `rsleigh --mcp`: a Model Context Protocol server on stdio that exposes
  `capabilities`, `agent-brief`, `card`, `ssa-slice`, and `verify-bundle`.
  Tool schemas are generated from the operation catalog, and each result is
  the CLI's JSON document with the same error codes and evidence IDs.

### Changed

- Bare invocation usage is generated from the operation catalog; a first
  argument beginning with `-` is now an option (write such files as `./NAME`).
- `--diff` renders the structured comparison model. Duplicate names are
  reported as ambiguous instead of overwriting each other, unreadable inputs
  fail instead of comparing against an empty set, and functions missing from a
  partial inventory are no longer reported as removed.
- `imagebase` for ELF and Mach-O is the load base (lowest `PT_LOAD` page,
  `__TEXT` vmaddr), as Ghidra reports it, not the first executable section.
  It is part of evidence subject identity, so content IDs for ELF and Mach-O
  records differ from earlier builds; existing records still verify.
- `--xrefs` and `--search` are catalog operations, also served over MCP. They
  print text as before; `--json` emits `rsleigh.xrefs/v1` (callers with call
  site and tail-call counts) and `rsleigh.search/v1`. `--xrefs` counts a
  direct jump to the function or its import stub as a tail-call site. Unknown flags are now rejected with
  `unsupported_option`. A function longer than the 4,096-byte scan window makes
  the result `partial` (exit 2) and is counted in `limits.truncated_scans`.
  `--raw` input keeps the raw-image output. The agent brief's suggested xrefs
  command now asks for JSON.

### Fixed

- Decompiler output is identical across runs; three passes no longer depend
  on hash-map iteration order (#7).
- Function output keeps code reached through jumps: PLT slot jumps, jumps
  out of the decoded window, and GCC `.cold` fragments. A shared return now
  keeps each path's value instead of the first predecessor's.
- Generated lift code runs an explicit SLEIGH `build` where it stands, fixing
  x86-64 `MOV r32` zero extension and ARM LDM/STM address order.
- x86-64 PIC and absolute jump tables print as `switch`; unsigned division
  and modulo by a constant print as `/` and `%`.
- Stripped-ELF discovery no longer lists jump-table targets and other
  addresses inside a function's FDE as functions.
- Card and slice failures report a stable `error_code` (`execution_limit`,
  `analysis_failed`, `invalid_selector`).
- Jump tables whose base is set far before the dispatch, that declare more
  than 256 entries, or whose index the table load overwrites are recovered
  (both `ls` tables from #7; #14, thanks @CassieFox23).
- Constant folding no longer overflows the stack on a value that defines
  itself, which aborted `--search` and decompiles on Fedora's libsqlite3.
- Calls and jumps through a pointer stored in data print as
  `(*DAT_<slot>)(...)` instead of naming the slot as a function.
- `--xrefs` no longer prints decoder panics on input that ends mid-instruction,
  no longer reports internal temporaries as callees (`func_c3b500000`), and
  counts calls through PLT and `.plt.got` stubs as callers.

## [0.5.0] - 2026-09-07

### Added

- JSON function cards with binary hashes, instruction/operation evidence IDs,
  and independent pagination cursors.
- `--ssa-slice FUNCTION --var ID` for bounded backward expression dependencies,
  with phi inputs, block IDs, budgets, and explicit memory/call boundaries.
- `--verify-index DIR` for binary/version identity and artifact integrity checks.
- CI coverage for CLI integrations, agent investigations, pagination, partial
  analysis, and interrupted index publication. Default-build SMT integration
  coverage now asserts the unsupported solver result for synthesized paths.

### Changed

- Agent commands expose `ok`, `partial`, or `failed` status and diagnostics;
  exit codes are respectively 0, 2, and 1. Decoder and decompiler failures no
  longer masquerade as successful empty analysis.
- Index manifests use `rsleigh.index/v2`, record effective options and artifact
  checksums, and publish immutable generations through an atomic root-manifest
  replacement. Consumers must follow manifest paths; rebuild version 1 indexes.
- SSA JSON and bounded queries share function boundaries and calling-convention
  selection, including Win64 for PE64 inputs.

### Fixed

- Emitted generated P-code in SLEIGH pattern-operand order, correcting
  operation sequencing for constructors whose operands are declared out of
  order.

## [0.4.3] - 2026-08-30

### Added

- Bounded agent-oriented reverse-engineering workflows with `--agent-brief`,
  `--index`, and `--card` output modes for fast triage, symbol lookup, and
  compact per-function analysis.
- A shared `rsleigh.finding/v1` finding schema across IOC, vulnerability,
  SMT, and VM-helper output, including confidence and analysis-stage metadata.
- Constructor and source-span provenance for decoded instructions, exposed
  through the stable API and P-code JSON output.
- Strict Ghidra-oracle fixtures, provenance manifests, and raw/optimized score
  baselines for real x86-64, AArch64, and ARM32 text slices.

### Changed

- Hardened decompilation analysis with recursion and output budgets, clearer
  diagnostics, and more accurate architecture capability reporting by stage.
- Reworked the README around practical reverse-engineering and agent workflows.
- Updated CI and release jobs for current action runtimes and bounded build
  memory on hosted runners.

### Fixed

- Corrected SSA edge classification and changed-block propagation so cross
  edges remain acyclic while only true back edges carry loop state.
- Aligned generated x86 and ARM P-code behavior with Ghidra, including ARM
  flag and condition handling.
- Closed decompiler and oracle-audit gaps that could hide provenance or
  analysis regressions.

## [0.4.2] - 2026-08-15

### Added

- Feature-gated SMT-aided taint-flow analysis with branch exploration,
  interprocedural function summaries, region-aware memory lineage, concrete
  models, diagnostic output, and ranked NDJSON candidate export.
- Labeled synthetic and real-world calibration fixtures for Heartbleed-shaped
  flows, dnsmasq, dropbear, and BusyBox.
- Raw ARM32 and Thumb firmware discovery, including Cortex-M vector-table
  seeds, Thumb-2 calls, ARM `BLX` targets, prologue validation, ADR and
  MOVW/MOVT references, literal-pool references, raw xrefs, and constant
  search.
- `CStringRead` candidate sinks for string-read flows.

### Changed

- Bound per-function SMT path collection and lazily build summaries around
  source/sink-relevant call-graph closures to control memory and runtime on
  large binaries.
- Retry PE parsing without attribute-certificate decoding for carved or
  truncated images, and supplement rather than replace normal function
  discovery.
- Expanded build, testing, raw-mode, and CLI troubleshooting documentation.

### Fixed

- Preserved signed token-field semantics when widening exported constants,
  fixing sign extension for negative x86 displacements.
- Kept valid in-range CFG edges when bounded decoding omits the other side of
  a conditional branch, including stack-canary fallthrough returns.
- Prevented decompiler cleanup from dropping branch-local values,
  side-effecting calls, and recursive-call operands.
- Preferred authoritative `PyMethodDef` registration names over generic
  heuristic PE function labels.
- Improved SMT precision for stack regions, spills, global slots, Phi-derived
  bounds, bounded copy lengths, and compiler-emitted store loops.
- Reduced false-positive ARM function discovery and added ARM-to-Thumb call
  discovery.

[Unreleased]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.4.1...v0.4.2
