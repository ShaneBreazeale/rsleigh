# SMT-assisted analysis

The optional `smt` Cargo feature links native Z3. The default CLI still exposes
SMT analysis commands, but solving returns `Unsupported` when the feature is
absent. No JVM is required in either build.

Use SMT after identifying a specific source/sink question in a function. It
adds model-based evidence to the investigation; it does not establish runtime
exploitability or assign a CVE.

## Build the executable you will run

From the rsleigh source checkout, with a Rust toolchain and system Z3:

### macOS (Homebrew)

```bash
brew install z3
CPATH=$(brew --prefix z3)/include LIBRARY_PATH=$(brew --prefix z3)/lib \
  cargo build -p rsleigh-cli --release --features smt
```

### Linux (apt)

```bash
sudo apt install libz3-dev
cargo build -p rsleigh-cli --release --features smt
```

Run **`target/release/rsleigh`** after building. A plain `rsleigh` command may
still resolve to an older default-feature installation on your PATH.
`--features smt` belongs to Cargo, not to the analysis command. Header/linker
failures indicate a native toolchain or Z3 installation problem; preserve the
build diagnostic when reporting them.

## Start with one verified function

Replace the example address with one returned by the target's function map:

```bash
target/release/rsleigh ./sample.exe --agent-brief --limit 5 > brief.json
target/release/rsleigh ./sample.exe 0x140001000 --card --pcode
target/release/rsleigh ./sample.exe --smt-candidates 0x140001000 \
  --smt-candidates-cap 16 --smt-candidates-top 5 \
  > candidates.ndjson 2> candidates.stderr
```

Validate the brief and finding records using [output checks](output-formats.md).
Confirm the function before the SMT command: an unresolved name can leave an
empty scope and initiate a whole-binary scan. Scoped candidate analysis builds
summaries for the selected function's reachable direct callees; it can still
perform substantial work.

Read the candidate headers first, then the event trace for one selected record:

```bash
jq -c '{function, address, source, sink, sink_kind, verdict, filter_reasons}' \
  candidates.ndjson
```

The full record fields, ranking, deduplication, and consumer workflow are in
[SMT candidates](smt-candidates.md).

## What the verdict means

| Verdict | Interpretation |
|---|---|
| `Reachable` | The analysis accepted a source-to-sink lineage and the solver satisfied its sink-kind constraint. Review the model and trace before making a binary-level claim. |
| `NotReachable` | A lineage/bounds filter rejected the candidate, or the solver returned UNSAT. Inspect `filter_reasons` to distinguish these cases. |
| `Unsupported` | The build lacks SMT support, required slots/semantics are unavailable, or solving could not establish a result. This is an evidence gap. |

The current finding envelope labels both `Reachable` and `NotReachable` as
`confidence: "proved"`. That label alone does not tell you that Z3 ran:
`solve_diag` can return `NotReachable` before creating the solver. Neither an
empty file nor a negative verdict proves the binary has no vulnerability.

The solver uses a bounded symbolic byte model and sink-specific predicates.
It is not a full execution of every path condition, sanitizer, protocol state,
or allocation in the original program. Candidate `trigger` text is a preview
of model bytes, not a complete input file or automatically replayable exploit.

## Available modes

| Mode | Scope and output |
|---|---|
| `--smt-candidates FUNCTION` | Ranked shared-schema NDJSON with event traces; uses interprocedural summaries |
| `--smt-explore FUNCTION` | Per-path text for a function; `--json` emits a legacy object with `paths` |
| `--smt-explore FUNCTION --smt-summaries` | Adds interprocedural summaries to exploration; summary construction can cover the binary |
| `--smt-explore-all --json` | Whole-binary JSON array of Reachable hits only; use deliberately |
| `--smt-diag --json` | Aggregate diagnostics for source/sink resolution and analysis coverage |

The `--smt-candidates` and `--smt-explore` schemas are different. Candidates
have a string `verdict`; exploration nests it under `paths[].verdict.kind`.
Do not reuse a filter for one on the other.

## Scope and limitations

- Candidate collection follows modeled calls and taint events, including
  summaries. Unresolved indirect calls, missing functions, and missing
  source/sink specifications reduce recall.
- Region IDs and alias relationships are inferred. Shared region IDs are not
  independently verified runtime alias facts.
- Loop, length, buffer, and wrapper-return reasoning use approximations and
  filters. Check the emitted reasons against lifted semantics.
- Candidate caps, deduplication, and top-N intentionally omit records.
  `--smt-candidates-top` limits output after collection; it is not an analysis
  timeout. Results are emitted after ranking, not progressively during solving.
- Architecture and calling-convention recovery affect source/sink arguments.
  Consult the [support matrix](architectures.md).

## Rust implementation and tests

The experimental implementation is in
[`smt_explore.rs`](../rsleigh-decompile/src/smt_explore.rs) (collection and
solving), [`smt_verify.rs`](../rsleigh-decompile/src/smt_verify.rs) (branch
verification), and [`cli.rs`](../rsleigh-cli/src/cli.rs) (serialization and
ranking). Pin a source revision or exact patch version if embedding these
internals.

The CLI fixture tests require host-built samples:

```bash
bash test-harness/fixtures/smt/build.sh
cargo test -p rsleigh-cli --features smt --test smt_explore_integration
cargo test -p rsleigh-decompile --release --features smt --lib smt_explore
cargo test -p rsleigh-decompile --release --features smt --lib smt_verify
```

Use the same native header/library environment as the successful build above.
Read test output for skipped fixtures; a default-feature test run does not
validate Z3 solving. See [testing](TESTING.md) and the
[SMT calibration fixtures](../test-harness/fixtures/smt/calibration/README.md).
