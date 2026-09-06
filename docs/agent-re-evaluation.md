# Agent reverse-engineering task evaluation

The completed corpus has **18 original tasks across all six native architectures**.
All 18 answers and their raw-operation evidence pass in uncached, cold-cache,
and warm-cache runs, repeated three times (**162/162**). Four tasks correctly
remain unresolved; they are counted separately from recovered facts below.

The [task catalog and ground truth](../test-harness/fixtures/agent-re/corpus.md)
links the deterministic fixture sources, expected answers, and instruction
addresses. No compiler, external binary download, JVM, solver, or model service
is required. Earlier milestone measurements are retained below; the final
comparison follows them.

## Initial selector results

Baseline: commit `8ed1cde`. Comparison: milestones 1–2 (working tree; cache disabled for these
selector measurements). Recorded on 2026-09-06 on a macOS/AArch64 host, with
three repetitions per task,
same input binary and environment. Both workflows have caching disabled.
The runner records the actual executable SHA-256, fixture SHA-256, command
arguments, output, exit status, bytes, and elapsed microseconds for every run.

| Task | Ground truth | Baseline correct | Selector correct | Baseline stdout bytes | Selector stdout bytes |
|---|---|---|---|---:|---:|
| Return origin | 7 | Yes | Yes | 2,351 | 1,599 |
| First call, argument 0 | 11 | No | Yes | 27,839 | 1,537 |
| First call, argument 1 | 22 | No | Yes | 27,839 | 1,537 |
| Second call to same callee, argument 0 | 33 | No | Yes | 27,841 | 1,540 |
| Branch condition | Incoming eax remains unknown | No | Yes | 10,604 | 2,680 |
| First return site | 1 | Yes | Yes | 9,896 | 1,604 |
| Second return site | 2 | Yes | Yes | 9,896 | 1,604 |
| Loaded return value | Memory remains unresolved | Yes | Yes | 2,472 | 1,722 |

All three repetitions agree on correctness and bytes. Selectors reduce commands
from two to one per task and total stdout from 356,214 to 41,469 bytes (88.4%).
Correct runs improve from 12/24 to 24/24. The comparison includes two necessary
correctness fixes: cdecl argument order and removal of register-offset-based
constant propagation that could overwrite earlier unknown reads with later
assignments. Every previously correct task stays correct.

Raw measurements (gzip-compressed JSON):
[baseline](../test-harness/fixtures/agent-re/results/baseline-8ed1cde.json.gz),
[selectors](../test-harness/fixtures/agent-re/results/selectors.json.gz).
Timings include process startup and polling overhead; no latency claim is made
from this small corpus. The runner repeats timing measurements to expose noise.

## Reproduce

```bash
cargo build --release -p rsleigh-cli
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  target/release/rsleigh agent-re-results.json
```

To compare an executable built from baseline commit `8ed1cde`, preserve that
executable at a separate path before building the comparison revision:

```bash
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  /path/to/baseline/rsleigh agent-re-baseline.json --baseline
```

The baseline workflow reads `--ssa-json`, resolves the relevant block/root from
the legacy debug-text terminator, and calls `--ssa-slice --var`. The selector
workflow sends the semantic query directly. Expected answers come from the
fixture source and instruction bytes, not generated pseudocode. Each command
has a 30-second deadline and is killed and reaped on expiration. Output goes
to files while the child runs to avoid blocked pipes. Temporary inputs and
output captures are removed after the report is written.

CI requires all selector answers to pass. Baseline runs retain incorrect answers
as measured failures while still producing the report. Integration tests also
compare every semantic root's slice with its corresponding variable-ID slice
and check ambiguity, missing targets, unsupported roots, and option errors.

Milestones 1–2 validation: 52 CLI tests and 196 decompiler unit tests pass. The
full `cargo test --release -p test-harness` run exposes an existing macOS
`tests::decompiler_validation` factorial reconstruction failure (missing
`n - 1` in the printed recursive call). Baseline and comparison executables
produce identical output for that compiled fixture. Running the remainder
with `-- --skip tests::decompiler_validation` passes 20 tests. This known
failure remains open; it is not counted as a passing full-suite gate.

## Cached card measurements

The original [cache workload](../test-harness/fixtures/agent-re/cache_workload.rs)
encodes `mov eax,0`, 900 additions of one, NOP padding, and a return in a
4 KiB x86-32 function. Ground truth is a return value of 900. It exercises
many SSA definitions while the requested card page stays capped at 120 ops.
The runner verifies identical operation evidence across uncached, cold, and
warm queries. Three repetitions use separate cold cache directories.

| Query | Median elapsed ms |
|---|---:|
| Baseline `8ed1cde`, uncached | 72.73 |
| Current, uncached | 73.20 |
| Current, cold cache creation | 97.77 |
| Current, warm cache hit | 15.35 |

Warm queries perform zero decoder attempts, zero SSA work, and no SSA rebuilds.
Each cache occupies 1,852,822 bytes, including the snapshot and both
manifests. Cold creation includes serialization, checksums, and synchronized
publication. Measurements include process startup; results describe this
workload and host, not a performance promise for every function.

Raw reports: [baseline](../test-harness/fixtures/agent-re/results/cache-baseline-8ed1cde.json.gz)
and [current](../test-harness/fixtures/agent-re/results/cache.json.gz).
The runner records the actual executable SHA-256 independently of the faster
linker build ID used for runtime cache lookup.

```bash
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  target/release/rsleigh agent-re-cache-results.json --cache-benchmark
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  /path/to/baseline/rsleigh agent-re-cache-baseline.json --cache-benchmark --baseline
```

CI checks card equivalence and avoided recomputation; it does not assert a
wall-time threshold. Integration tests cover decode and SSA work exhaustion,
zero deadlines, evidence preservation, unpublishable stopped work, and cached
queries with zero new-work allowance. Unit tests also check elapsed deadlines
after earlier work, nested-scope restoration, and linker build identity.

## Evaluation scope

The seed's evidence checks cover binary identity, selected dependency values,
explicit unresolved boundaries, and matching raw instruction/P-code origins.
The deterministic runner measures prescribed command workflows, not autonomous
LLM reasoning. Optional future live-model runs must record models and prompts.

The final corpus adds comparison, length, dispatch, memory, helper, alias, and
recursion tasks across six architectures. Integration tests cover task-level
execution and traversal limits. Raw firmware and WASM remain separate frontends;
this evaluation does not establish native brief/card/index support for them.

## Instruction provenance results (milestone 3)

The eight seed tasks still pass in all three repetitions: **24/24 correct
answers and 24/24 correct instruction-evidence checks**. The runner now checks
source-backed defining instruction addresses, resolves every emitted operation
index against an independently decoded raw instruction, and compares typed
opcode/operands. It checks explicit unavailable origins and the 32-origin cap.
CI fails on an evidence mismatch as well as an answer mismatch. Baseline
measurements retain their older evidence check (answer plus binary identity);
they are not retroactively counted as having instruction provenance.

Cards and slices use raw P-code before the decoder optimizer. This preserves
original operation indices and exposed a missing signed/zero immediate
extension fold; width-aware regression tests cover that fix. Cards/slices use
v2 schemas at this milestone; migration is documented in [output formats](output-formats.md#typed-evidence-and-origin-migration).

The richer output totals **91,860 bytes**, versus baseline **356,214 bytes**:
**74.2% less output**, with one command per task versus two. These measurements
supersede the initial selector-only byte comparison for milestone 3;
the earlier measurements remain available above.

| Query | Median elapsed ms |
|---|---:|
| Baseline, uncached | 72.735 |
| Provenance, uncached | 157.567 |
| Provenance, cold cache | 183.400 |
| Provenance, warm cache | 20.571 |

Cache storage is **2,641,515 bytes** per complete card generation. Raw operation
storage and provenance processing increase cold costs. Warm cards still avoid
all decode and SSA work and remain faster than the recorded baseline. The
runner verifies identical typed operations across the three current cache
states; v1 and v2 operation indices must not be compared directly because v1
used optimized P-code.

Raw reports:
[provenance](../test-harness/fixtures/agent-re/results/provenance.json.gz),
[cache with provenance](../test-harness/fixtures/agent-re/results/cache-provenance.json.gz).
Both reports include executable SHA-256 and the exact commands. Reproduction
uses the same evaluator commands above, built from this working tree.

Validation: 54 CLI tests; 198 decompiler unit tests; four instruction-provenance,
21 semantic-simplification, and two SSA-edge integration tests; and two Ghidra
P-code oracle tests pass. The pcode-ir no-default-features check also passes.
Regressions cover merged constants, copies, cyclic phi dependencies, synthetic
conditional selects, raw call indices after bookkeeping removal, bounded origin
growth, typed cache round trips, and rejection of invalid cached origins.
The pre-existing full-harness factorial failure documented above remains open.
At this measurement, milestone 4 and the full milestone 5 corpus were incomplete.

## Memory and helper traversal validation

Milestone 4 adds exact reaching-store dependencies and bounded helper contexts.
The original [traversal fixture](../test-harness/fixtures/agent-re/traversal.rs)
encodes stack/global spill-reload values of 73, a helper adding 5 to argument 17,
and a recursive call. CLI regressions verify native instruction/store origins,
caller/callee bindings, warm-cache equivalence with zero new decode/SSA work,
ambiguous aliases after folding, and explicit traversal limits. These are
dependency checks; the helper slice exposes the addition and bound argument
without claiming path feasibility or a vulnerability.

Validation on 2026-09-06: all **283 decompiler unit/integration tests** and
**56 CLI tests** pass. Targeted tests include six helper-context cases and eight
memory cases, covering repeated calls, spilled call results, clobbered argument
registers, overlapping stores, joins, loops, and unsupported effects. The focused
provenance/traversal suite is now a CI gate. Commands:

```bash
cargo test --release -p rsleigh-decompile --lib --tests
cargo test --release -p rsleigh-cli --lib --tests
```

The unchanged eight seed tasks retain **24/24 correct answer and raw-operation
evidence checks**. Slice v3's context, memory, per-function identity, and metrics
fields increase their total output to **197,586 bytes**, still **44.5% below**
the baseline's 356,214 bytes. Command count remains one per task versus two.
Raw report: [traversal](../test-harness/fixtures/agent-re/results/traversal.json.gz).
Earlier cache timings above describe their recorded builds; full-corpus
cold/warm comparisons remain milestone 5 work.

At this measurement, the full corpus and full-harness factorial failure were
still outstanding. The final validation below resolves both.

## Final six-architecture comparison

Baseline commit: `8ed1cde`. Both executables ran the same 18 fixture hashes on the
same macOS/AArch64 host on 2026-09-06, with three repetitions. The final runner
credits the baseline's dispatch target directly from its SSA dump; other tasks
use its dump-then-variable-slice workflow. Missing roots remain measured
failures. The current workflow uses one semantic query per task.

| Measure | Baseline | Current |
|---|---:|---:|
| Correct task answers (one repetition) | 8/18 | 18/18 |
| Recovered facts | 6/14 | 14/14 |
| Correct unresolved cases | 2/4 | 4/4 |
| Correct uncached answer runs | 24/54 | 54/54 |
| Correct raw-origin checks, all current cache states | Unavailable in v1 | 162/162 |
| Commands, three uncached repetitions | 93 | 54 |
| Stdout bytes, three uncached repetitions | 4,759,227 | 454,548 |

Total uncached output falls **90.4%**. The per-task table shows where richer
metadata increases output for small cases. The aggregate reduction includes
fixing executable-section decode bounds; baseline over-decoding makes the ARM
comparison dump especially large. It also includes expression/SSA improvements,
not just selector syntax. Every task answered correctly by the baseline remains
correct in the current workflow.

Baseline v1 has no retained raw-operation origin graph. The final report records
`origin_evidence_available: false` and does not award an instruction-evidence
pass for matching a binary hash alone. Its earlier seed report used that weaker
check; those historical evidence scores are not directly comparable. Current
checks resolve each origin against a separate decode of fixture bytes using
rsleigh-api; this validates reference integrity, not an independent decoder
implementation. Source instruction encodings and separate oracle regressions
provide additional semantic validation.

| Task | Baseline answer | Baseline stdout bytes | Current stdout bytes |
|---|---|---:|---:|
| return-seven | Correct | 2,351 | 4,296 |
| first-call-arg-zero | Unsolved | 27,839 | 10,813 |
| first-call-arg-one | Unsolved | 27,839 | 8,977 |
| second-call-arg-zero | Unsolved | 27,841 | 19,049 |
| branch-input-unknown | Unsolved | 10,604 | 8,660 |
| first-return-site | Correct | 9,896 | 4,303 |
| second-return-site | Correct | 9,896 | 4,303 |
| memory-unknown | Correct | 2,472 | 5,461 |
| stack-spill | Unsolved | 10,651 | 10,069 |
| global-store | Correct | 2,898 | 7,032 |
| helper-return | Unsolved | 12,246 | 21,970 |
| recursive-boundary | Unsolved | 670,769 | 4,978 |
| ambiguous-store | Correct | 11,176 | 8,171 |
| x64-dispatch | Correct | 4,104 | 7,376 |
| aarch64-length | Unsolved | 5,217 | 10,813 |
| arm-comparison | Correct | 736,667 | 5,795 |
| mips-return | Unsolved | 12,264 | 4,299 |
| riscv-return | Unsolved | 1,679 | 5,151 |

Each task's bytes and correctness agree across repetitions. Cache metrics add
small byte differences between cache states. Across the full corpus:

| Query state | Median elapsed ms per task | Answer/evidence runs |
|---|---:|---:|
| Baseline, uncached | 6.544 | 24/54 answers; raw origins unavailable |
| Current, uncached | 3.275 | 54/54 |
| Current, cold cache | 21.157 | 54/54 |
| Current, warm cache | 3.304 | 54/54 |

These small tasks do not show a warm-latency advantage over the current uncached
path. Warm runs nevertheless perform **zero new decode and SSA work** across
every participating function. Cold publication includes serialization, checksums,
and synchronized writes. The median per-task cache directory is **35,035.5
bytes**; all individual sizes and timings are in the report. Runs use fixed
uncached/cold/warm order and include process startup and polling; medians describe
this host and workload, not a general performance guarantee.

The larger 900-addition card workload separately measures median uncached
**156.105 ms**, cold **180.411 ms**, and warm **21.548 ms**, with **2,641,515
bytes** of cache storage. Warm cards still avoid all decode/SSA work and beat
the recorded baseline's **72.735 ms**. That baseline timing is the historical
measurement above, not a simultaneous full-corpus run.

Raw reports:
[full baseline](../test-harness/fixtures/agent-re/results/full-baseline-8ed1cde.json.gz),
[full current corpus](../test-harness/fixtures/agent-re/results/full-corpus.json.gz),
and [final card cache workload](../test-harness/fixtures/agent-re/results/cache-final.json.gz).
Each records the actual executable SHA-256 and every command/output. Final tool
SHA-256: `4e2afabd5c095b37cd012a4205624507058c551f778a5a67633f41b0ce270993`.
Baseline tool SHA-256: `5591090d5825354fc7bc370b648ed6b5e7e11cf73b8fcfece7a71559cece4eab`.

Reproduction commands and fixture export are in the
[corpus guide](../test-harness/fixtures/agent-re/corpus.md). CI now runs both the
seed workflow and the full corpus, including cold/warm equivalence and zero-work
checks. Required runtime dependencies remain Rust-only; live-model evaluation
is optional and was not performed.

Final regression validation: **288 decompiler unit/integration tests, 56 CLI
tests, and all 21 test-harness tests pass**, including the previously failing
factorial case and both P-code oracle tests. `cargo check -p pcode-ir
--no-default-features` also passes. The corpus exposed incorrect MIPS/RISC-V
return offsets and ELF decode overrun; dedicated tests and native layouts now
cover those cases. Printer tests retain parameter names through store-evidence
copies and preserve call assignments across branch boundaries. Hosted CI has not
been run for this local revision; its added gate commands pass locally.

See the [completion audit](llm-re-completion-audit.md) for requirement-to-evidence
mapping and the exact validation commands.
