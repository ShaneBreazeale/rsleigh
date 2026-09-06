# LLM-assisted RE roadmap completion audit

Audit date: 2026-09-06. Baseline: `8ed1cde`.

The implementation, fixtures, tests, and reports in this revision cover all five
milestones in [the roadmap](llm-re-roadmap.md). The final implementation is
recorded as one local commit; `git log -1` identifies that revision. Earlier
progress rows describe intermediate working-tree measurements, whose executable
hashes remain in their reports. No hosted CI execution or live-model evaluation
is claimed.

## Requirement-to-evidence mapping

| Roadmap requirement | Implementation / contract | Observed validation |
|---|---|---|
| 1: semantic call-argument, return-site, and condition selectors; retain variable selection | [selector.rs](../rsleigh-decompile/src/slice/selector.rs), [CLI slice](../rsleigh-cli/src/cli/agent/slice.rs), [workflow](agent-workflow.md#bounded-backward-ssa-query) | `semantic_selectors_answer_ground_truth_tasks_and_match_variable_slices` checks answers and identical dependency slices; first/second calls and distinct return sites are separate corpus tasks |
| 1: ABI numbering, ambiguous/missing/unsupported roots, same-snapshot identities, documentation | Selector resolution uses typed SSA and the decoded snapshot; argument slots follow the applicable ABI; unsupported MIPS/RISC-V argument roots fail explicitly | `semantic_selector_errors_do_not_guess_roots`, missing-register-slot unit test, CLI origin/identity tests, all six native return-register tests |
| 1: command/context reduction with correct answers and evidence | [Evaluation report](agent-re-evaluation.md#final-six-architecture-comparison) and raw baseline/current JSON | Seed answers stay 24/24; full uncached commands 93 → 54 and stdout 4,759,227 → 454,548 bytes; per-task increases and baseline limitations are disclosed |
| 2: complete cache identity, immutable publication, integrity validation, invalidation and lifecycle | [cache.rs](../rsleigh-cli/src/cli/agent/cache.rs), [card analysis](../rsleigh-cli/src/cli/agent/card/analysis.rs), [generation publication](../rsleigh-cli/src/cli/agent/index.rs), [cache workflow](agent-workflow.md#reuse-analysis) | CLI tests change binary/analysis settings and companion debug inputs, corrupt snapshots, and leave interrupted generations; build-ID unit tests cover Mach-O, ELF, and hash fallback |
| 2: metrics, decode/SSA limits, deadlines, partial evidence, no stopped-snapshot publication | [budget.rs](../rsleigh-decompile/src/budget.rs), CLI analysis boundaries; immutable cache publication follows successful analysis | `execution_limits_preserve_decoded_evidence_and_never_publish_stopped_snapshots`, budget unit tests, zero-work warm queries, native helper budget regressions |
| 2: warm queries avoid rebuilding and beat recorded baseline latency; report cold/storage costs | Full-corpus cache-state measurements and final card workload | Every warm function is a hit with zero decode/SSA work; all slice/evidence graphs equal across cache states. Large-card warm median 21.548 ms versus historical baseline 72.735 ms; cold cost/storage and small-task cache overhead are reported |
| 3: bounded snapshot-scoped origins through SSA, copies, constants, phi and rewrites; explicit synthetic/unavailable/truncated state | [provenance.rs](../rsleigh-decompile/src/provenance.rs), SSA/fold rewrites and raw CFG terminator origins | Four [instruction-provenance tests](../rsleigh-decompile/tests/instruction_provenance.rs), provenance cycle/cap unit tests, memory/copy regressions, cache-origin validation |
| 3: typed opcodes/operands, readable rendering, original operation indices, versioned migration | PcodeOp serde is optional in pcode-ir; raw decoder operations feed cards/slices/P-code JSON; card v2, P-code v2, slice v3 | CLI typed-card/slice operation equality; all 162 full-corpus raw-origin checks; [output migration](output-formats.md#typed-evidence-and-origin-migration); no-default-features pcode-ir build |
| 4: supported stack/global reaching stores and evidence; ambiguous aliases remain unknown | [memory.rs](../rsleigh-decompile/src/memory.rs), exact SSA-base addresses in region.rs; store proxies retain write evidence | Eight [memory tests](../rsleigh-decompile/tests/memory_dependencies.rs), native stack/global/alias CLI cases, corresponding corpus tasks |
| 4: helper argument/return bindings and existing call-resolution confidence/provenance | [context traversal](../rsleigh-decompile/src/slice/interprocedural.rs), dependency summaries, existing callgraph classification | Six [interprocedural tests](../rsleigh-decompile/tests/interprocedural_dependencies.rs), native helper result and warm-cache tests; repeated invocations keep separate contexts; x86-64 dispatch task checks heuristic resolution metadata |
| 4: unknown calls/effects/aliases, recursion and node/depth/function/work limits; dependency claims only | Explicit boundaries, limits, stop records, and conservative unsupported conventions in slice v3 | Negative calls, missing/clobbered arguments, unused effects, alias, loop/recursion, and every traversal-limit regression; CLI trust scope and documentation disclaim reachability/vulnerability proof |
| 5: 15–20 tasks, all six native architectures, source/bytes ground truth, positive and unresolved cases | [18-task catalog](../test-harness/fixtures/agent-re/corpus.md), seed/traversal/corpus generators with original Apache-2.0 encodings | 14 recovered-fact tasks and four correct unresolved tasks, repeated in three cache states; ARM comparison identifies a constant while preserving its unknown input |
| 5: answer/evidence accuracy, command/byte/time/cache/build/binary measurements; same-input baseline and repeated cold/warm comparisons | [Rust runner](../rsleigh-cli/examples/agent_re_eval.rs), [full runner](../rsleigh-cli/examples/agent_re_eval/full_corpus.rs), compressed raw reports | Identical 18 fixture hashes and host environment verified; baseline 24/54 answer runs versus current 162/162 across states; strict raw-origin availability distinguished from weaker historical evidence checks |
| 5: deterministic CI gates; optional model work; explicit frontend limits | [.github/workflows/ci.yml](../.github/workflows/ci.yml) runs seed, full corpus, card-cache equivalence, and focused provenance/traversal tests | Gate commands pass locally. No hosted service or live model is required. Raw firmware/WASM and unsupported MIPS/RISC-V argument/frame-memory conventions remain documented boundaries |
| Final regression/review requirement | Native return layouts, bounded executable-section decoding, and copy/call printing corrections exposed by the expanded corpus | 288 decompiler tests, 56 CLI tests, and all 21 harness tests pass; the previously failing compiled factorial case now passes; no unchecked roadmap item is hidden behind a skipped local regression |

## Commands and raw measurements

These commands passed on the audited source tree:

```bash
cargo build --release -p rsleigh-cli
cargo test --release -p rsleigh-decompile --lib --tests
cargo test --release -p rsleigh-cli --lib --tests
cargo test --release -p test-harness
cargo check -p pcode-ir --no-default-features
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  target/release/rsleigh seed-results.json
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  target/release/rsleigh full-results.json --full-corpus
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  target/release/rsleigh cache-results.json --cache-benchmark
```

The final combined run also passed all **365 tests across 49 suites**:

```bash
cargo test --release -p rsleigh-cli -p rsleigh-decompile -p test-harness --lib --tests
```

Its [raw validation log](../test-harness/fixtures/agent-re/results/validation.log.gz)
is retained with the measurements. The native-return regression was rerun after
the final call-origin correction and is also included in this combined run.

The baseline runner uses the executable preserved from commit `8ed1cde` with
`--full-corpus --baseline`; it retains its incorrect/unsupported task results
instead of suppressing them. All measurements are in the committed
[results directory](../test-harness/fixtures/agent-re/results/). Reports carry
actual executable SHA-256, fixture SHA-256, commands, outputs, and per-run
measurements. [Evaluation documentation](agent-re-evaluation.md) records the
numerical comparisons and their limitations. The raw reports establish the
linked build independently of a package version or cache hit.

The supported scope is bounded dependency recovery and traceable instruction
evidence. The audit does not claim exhaustive alias analysis, complete calling
conventions, path feasibility, confirmed vulnerabilities, universal speedups,
or autonomous LLM accuracy.
