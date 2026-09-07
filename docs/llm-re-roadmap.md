# Roadmap: higher-yield LLM-assisted reverse engineering

Status: implemented and locally validated in `ecfd1cd`. Baseline commit: `8ed1cde`.

All five milestones are complete within the documented native dependency scope.
The final corpus contains 18 tasks across six architectures. See
[measured results](agent-re-evaluation.md) and the
[requirement-by-requirement completion audit](llm-re-completion-audit.md).
Hosted CI has not been run for this local revision; its gate commands pass locally.

## Goal

Improve rsleigh so an LLM can answer concrete reverse-engineering questions
with fewer commands, less context, and traceable evidence. Implement semantic
slice selectors, reusable analysis with execution budgets, instruction
provenance through SSA transformations, and bounded memory/interprocedural
dependency traversal. Demonstrate the improvements on a reproducible corpus
of 15–20 ground-truth RE tasks.

Keep the default implementation in Rust without adding a required JVM,
Ghidra installation, native solver, or hosted model service.

Unchecked items below remain implementation targets. Checked items have
observed implementation and validation evidence recorded in the progress log.

## Starting point

The baseline already provides:

- Agent briefs and per-function `ok`, `partial`, and `failed` statuses.
- JSON/text cards with binary hashes and instruction/operation pagination.
- Immutable index generations, atomic manifest publication, and verification.
- Bounded backward SSA slices starting from a variable ID.
- CLI integration tests and decompiler unit tests in CI.

Baseline gaps driving this roadmap:

- Selecting a slice root generally requires inspecting a full SSA dump.
- Follow-up queries rebuild analysis; output caps do not bound execution work.
- SSA slices expose variable/block IDs without complete instruction origins.
- Slices stop at unresolved memory and calls.
- Interface tests do not measure the cost and accuracy of completed RE tasks.

See [agent workflow](agent-workflow.md), [output contracts](output-formats.md),
and [testing](TESTING.md) for the current behavior.

## Execution order

Effort estimates include implementation and tests; they are planning estimates.

| Order | Milestone | Estimated effort | Main outcome |
|---|---|---|---|
| Start | Seed milestone 5 | Initial fixture/baseline work | Measure the workflow before changing it |
| 1 | Semantic slice selectors | 1–2 days | Ask about arguments, returns, and conditions directly |
| 2 | Cached analysis and execution budgets | 2–4 days | Cheap follow-up queries and bounded work |
| 3 | Instruction provenance and typed operations | 3–5 days | Trace transformed values to instruction evidence |
| 4 | Selected memory and call traversal | 5–10 days | Follow useful dependencies beyond current boundaries |
| Finish | Complete milestone 5 | Expand throughout the work | Validate all milestones on 15–20 tasks |

## 1. Query by analyst intent

Allow a slice root to be selected by a call-site argument, a function return
value, or a conditional branch. Keep variable-ID selection available.

Implementation entry points:

- `rsleigh-cli/src/cli/agent/slice.rs`
- `rsleigh-decompile/src/slice.rs`
- `rsleigh-decompile/src/ir.rs`

Tasks:

- [x] Define selectors for call-site address plus argument index, return value,
  and branch-condition address.
- [x] Specify argument numbering, calling-convention handling, and behavior
  when several return sites or candidate roots exist.
- [x] Resolve selectors against the same snapshot used for slicing; include
  the selected root and its interpretation in output.
- [x] Return explicit ambiguity, missing-target, and unsupported-root results.
- [x] Document the final syntax and add end-to-end tests.

Acceptance:

- [x] Complete argument-origin, return-origin, and branch-condition tasks
  without consuming a full SSA dump.
- [x] Selecting by intent and selecting the corresponding variable ID produce
  equivalent dependencies in the same snapshot.
- [x] Repeated calls to one callee can be distinguished by call-site address.
- [x] The evaluation records fewer commands and fewer returned bytes for these
  tasks, with unchanged correct answers and supporting evidence.

## 2. Cache analysis and bound execution work

Reuse decoded instructions and SSA snapshots across follow-up queries. Preserve
the existing distinction between output limits and execution limits.

Implementation entry points:

- `rsleigh-cli/src/cli/agent.rs`
- `rsleigh-cli/src/cli/agent/card.rs`
- `rsleigh-cli/src/cli/agent/index.rs`
- `rsleigh-decompile/src/lib.rs`

Tasks:

- [x] Define a versioned cache identity covering binary content, actual tool
  build, architecture/mode/base, and effective analysis options. Include debug
  or signature inputs whenever they affect the cached artifact.
- [x] Persist reusable snapshots using complete-generation publication and
  integrity validation.
- [x] Add cache hit/miss and analysis-work counters to diagnostics or metrics.
- [x] Introduce explicit decode/SSA work limits and deadlines; report the stage,
  consumed work, and stop reason when a limit is reached.
- [x] Preserve usable evidence on budget exhaustion. Do not publish an
  incomplete snapshot as a complete cache entry.
- [x] Document cache lifecycle, invalidation, and removal behavior.

Acceptance:

- [x] A second page/query over the same snapshot does not rebuild SSA.
- [x] Relevant binary, build, mode, option, and auxiliary-input changes
  invalidate the cache.
- [x] Corrupt and interrupted cache writes cannot become successful hits.
- [x] Work-limit fixtures terminate with explicit partial/failed results.
- [x] Warm-query latency improves against the recorded baseline; cold-query
  costs and cache storage are reported separately.

## 3. Preserve provenance through SSA and folding

Connect transformed expressions to their original instruction/P-code evidence.
An instruction address plus operation index identifies a raw P-code operation;
transformations may combine several such origins. See the
[P-code reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html).

Implementation entry points:

- `pcode-ir/src/lib.rs`
- `rsleigh-decompile/src/ir.rs`, `ssa.rs`, and `fold.rs`
- `rsleigh-cli/src/cli/agent/card.rs` and `slice.rs`

Tasks:

- [x] Define snapshot-scoped origin references and bounded origin sets.
- [x] Preserve and merge origins through SSA construction, copy propagation,
  constant folding, phi handling, and expression rewrites.
- [x] Label synthetic nodes and unavailable or truncated origins explicitly.
- [x] Serialize typed opcodes and operand fields for machine consumption;
  retain readable text rendering from the same evidence model.
- [x] Version changed output contracts and document migration.

Acceptance:

- [x] Supported slice nodes expose instruction origins or an explicit reason
  origins are unavailable.
- [x] Regression fixtures verify provenance across the transformations above,
  including expressions derived from multiple instructions.
- [x] Every emitted origin resolves to the matching binary/snapshot evidence.
- [x] Consumers can inspect opcode and operands without parsing Rust debug
  strings; origin growth remains bounded and truncation remains visible.

## 4. Traverse selected memory and call dependencies

Extend the existing expression slice conservatively. Reuse the repository's
function summaries and call-target resolution instead of duplicating them.

Implementation entry points:

- `rsleigh-decompile/src/slice.rs`, `ssa.rs`, and `region.rs`
- `rsleigh-decompile/src/function_summary.rs` and `callgraph.rs`

Tasks:

- [x] Follow stores to loads for supported, unambiguous stack slots and
  constant-address memory locations.
- [x] Map direct-call arguments into callee parameters and supported callee
  return dependencies back to callers.
- [x] Use existing resolved-call information with its confidence and provenance.
- [x] Add limits for call depth, functions visited, and total traversal work.
- [x] Preserve explicit boundaries for ambiguous aliases, unknown calls,
  unsupported side effects, recursion limits, and exhausted budgets.

Acceptance:

- [x] Recover a stack spill/reload dependency with supporting store evidence.
- [x] Recover a supported constant-address store/load dependency.
- [x] Trace a value through a direct helper call and back through its return.
- [x] Negative fixtures keep ambiguous stores and unresolved calls unknown.
- [x] Recursive/cyclic fixtures terminate with reported bounds.
- [x] Results remain dependency claims; no output upgrades them to proved
  reachability or a confirmed vulnerability without separate evidence.

## 5. Evaluate completed RE tasks

Seed this milestone before implementing selectors and extend it with each
milestone. Finish with 15–20 reproducible tasks spanning the six native decoder
architectures: x86-64, x86-32, AArch64, ARM32, MIPS32, and RISC-V 64.

Proposed artifacts:

- `test-harness/fixtures/agent-re/`: fixture sources, binaries or reproducible
  build instructions, provenance/licenses, and expected answers/evidence.
- A Rust evaluation runner: recorded command workflows, bounded execution,
  answer/evidence checks, and machine-readable measurements.
- `docs/agent-re-evaluation.md`: task catalog, baseline, comparison results,
  limitations, and reproduction commands.

Tasks:

- [x] Seed argument, return, condition, and explicit-unknown tasks.
- [x] Add comparison identification, length tracing, supported dispatch-target
  recovery, memory dependencies, and helper-call tasks as capabilities land.
- [x] Include positive cases and cases whose correct answer is unresolved.
- [x] Establish ground truth from fixture source and instruction evidence;
  generated pseudocode alone is not the oracle.
- [x] Record answer accuracy, evidence accuracy, command count, bytes returned,
  elapsed time, cache state, tool build, and binary identity.
- [x] Compare identical tasks and environments against the baseline. Separate
  cold/warm runs and repeat timings to expose noise.
- [x] Run deterministic task/evidence checks in CI. Optional live-LLM runs must
  record model and prompt settings and must not become a required runtime
  dependency.

Acceptance:

- [x] Publish results for 15–20 tasks with reproducible inputs and expected
  answers, covering all six native architectures.
- [x] No unexplained answer/evidence regressions on previously supported tasks.
- [x] Demonstrate command/context reductions for semantic selectors and
  avoided recomputation for cached follow-up queries.
- [x] Report unresolved cases and model limitations rather than counting them
  as successful recoveries.
- [x] Keep raw-firmware/WASM frontend limitations explicit; this roadmap does
  not implicitly require extending the native brief/card/index contract.

## Validation and completion

For each milestone, add behavior-focused regressions and record the commands,
results, and commit that establish completion. Update this checklist only from
observed results. Keep schema changes and workflow documentation together.

Existing release-mode regression commands:

```bash
cargo test --release -p rsleigh-cli --lib --tests
cargo test --release -p rsleigh-decompile --lib
```

Run relevant decoder/oracle tests when changing instruction or lifting
semantics. Add the evaluation command to CI once its runner exists.

- [x] Semantic selectors implemented, documented, and validated.
- [x] Cache invalidation, integrity, and execution budgets validated.
- [x] Typed operation output and transformation provenance validated.
- [x] Selected memory/call traversal and conservative boundaries validated.
- [x] Full task corpus, baseline comparison, and reproduction guide published.
- [x] Relevant regression suites and new CI gates pass.
- [x] Final review verifies every acceptance criterion against current code
  and recorded evidence; incomplete work remains unchecked.

## Progress log

Append an entry after each completed milestone or material change of direction.

| Date | Milestone / commit | Evidence and measured result | Remaining work |
|---|---|---|---|
| 2026-09-06 | Baseline `8ed1cde` | 45 CLI tests and 191 decompiler tests passed; initial evidence interfaces committed | All roadmap milestones remain planned |
| 2026-09-06 | Milestone 1 / working tree | Eight source-backed tasks, 24/24 correct runs versus baseline 12/24; commands 2 → 1, stdout −88.4%; selector/variable equivalence and error cases tested | Cache/budgets, provenance, traversal, full multi-architecture corpus; finalize revision evidence |
| 2026-09-06 | Milestone 2, partial / working tree | Slice queries cache decoded operations and SSA in verified immutable generations; follow-up, identity, corruption, and interrupted-publication tests added | Card cache, decode/SSA work limits and deadlines, budget-exhaustion evidence, latency/storage evaluation |
| 2026-09-06 | Milestone 2 / working tree | 52 CLI and 196 decompiler tests pass; card/slice cache and execution limits validated; warm card median 15.35 ms vs baseline 72.73 ms | Provenance, memory/call traversal, full corpus, final revision evidence |
| 2026-09-06 | Milestone 3 / working tree | 54 CLI tests, 198 decompiler unit tests, 27 targeted integration tests, and 2 P-code oracle tests pass; 24/24 answer and instruction-origin checks pass; typed raw operations and bounded origins survive folding/cache restore; stdout −74.2% vs baseline | Memory/call traversal, full six-architecture corpus, final revision evidence |
| 2026-09-06 | Milestone 4 / working tree | 283 decompiler unit/integration tests and 56 CLI tests pass; exact stack/global store evidence, context-specific helper arguments/returns, clobbered arguments, ambiguous memory, recursion, and traversal budgets validated; seed answer/evidence checks remain 24/24; slice v3 documented and focused CI gate added | Full six-architecture corpus, repeated baseline/cache comparison, known test-harness factorial failure, final revision evidence |

| 2026-09-06 | Milestone 5 / implementation `ecfd1cd` | 18 tasks, six architectures, 162/162 current answer/raw-origin checks across repeated uncached/cold/warm states; baseline 24/54 answers, 90.4% less aggregate uncached output, zero new work on every warm function; all 365 combined regression tests pass, including the former factorial failure | None within the roadmap scope; unsupported conventions/frontends remain explicit |

Validation details and raw measurements: [agent RE evaluation](agent-re-evaluation.md).
