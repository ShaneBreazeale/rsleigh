# Changelog

All notable user-facing changes to rsleigh are documented here.

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

[0.4.2]: https://github.com/ShaneBreazeale/rsleigh/compare/v0.4.1...v0.4.2
