# Changelog

All notable user-facing changes to rsleigh are documented here.

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

[0.4.3]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.4.1...v0.4.2
