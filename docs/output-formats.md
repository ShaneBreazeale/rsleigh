# Output formats and validation

Choose a renderer explicitly and validate the artifact it actually produces.
The CLI does not have a universal JSON mode. Agent operations share one failure
envelope (`status: "failed"`, `error`, stable `error_code`, `diagnostics`);
legacy modes do not.

## Format map

| Command mode | Stdout / files | Expected shape |
|---|---|---|
| `--capabilities --json` | One JSON object | `rsleigh.capabilities/v1`; operations, frontends, architectures, error codes |
| `--version --json` | One JSON object | `rsleigh.version/v1`; package version and linked build identity |
| `--agent-brief` | One JSON object | `schema: rsleigh.agent-brief/v1`; reject `error` |
| `--evidence` / `--evidence-store STORE` on a brief, card, or slice | One JSON object | `rsleigh.evidence/v1` wrapping the unchanged payload |
| `--export-bundle BUNDLE` | JSON manifest and generation files | `rsleigh.evidence-bundle/v1`; records, subject, coverage, checksums |
| `--verify-bundle BUNDLE` | One JSON object | `rsleigh.bundle-verification/v1`; checks and record status counts |
| `--import-bundle BUNDLE` | One JSON object | `rsleigh.bundle-import/v1`; imported/existing counts |
| `--investigate DIR` / `--investigation DIR` | One JSON object | `rsleigh.investigation-view/v1` wrapping an `rsleigh.investigation/v1` document |
| `--investigation DIR --handoff` | Markdown | Question, unresolved/closed issues, observations, inferences, evidence, history |
| `FILE --compare NEW --json` | One JSON object | `rsleigh.function-comparison/v1`; per-pair dimensions, unmatched, ambiguous, suggestions, summary |
| `--index DIR` | JSON manifest and generation files | `rsleigh.index/v2`; checksums and paths for four artifacts |
| `--verify-index DIR` | One JSON object | `rsleigh.index-verification/v1`; validity and analysis status |
| `--ssa-slice FUNCTION` with a root selector | One JSON object | `rsleigh.ssa-slice/v3`; bounded dependencies, boundaries, and resolved `selection` |
| `FUNCTION --card ...` | Text by default; JSON with `--json` | `rsleigh.card/v2`; evidence references and independent pagination |
| `--xrefs FUNCTION` | Text by default; JSON with `--json` | `rsleigh.xrefs/v1`; `callers` with per-caller `call_sites` and `tail_calls`, pseudocode `callees` and `strings`, `limits.truncated_scans` |
| `--search QUERY [--api\|--const\|--tag]` | Text by default; JSON with `--json` | `rsleigh.search/v1`; `query`, `kind`, `results` with `match_type`, `limits.truncated_scans` |
| `--pcode-json FUNCTION` | One JSON object per requested function | `rsleigh.pcode/v2`; `function`, `address`, `instructions`, typed raw operations |
| `--ssa-json FUNCTION` | One JSON object per requested function | `function`, `address`, `blocks`, `vars` |
| `--disasm FUNCTION --json` | One JSON object per requested function | `function`, `instructions`; `pcode_ops` is a count |
| `FUNCTION... --json` / `--all --json` | One JSON object | `binary`, `arch`, `functions` with per-function `status` (`ok`/`partial`), `diagnostics`, and `pseudocode`; exits 2 when any function is `partial` |
| `--ioc --json` | One JSON object | Category arrays such as `urls`, `ips`, `domains` |
| `--sigcheck --json` / `--resources --json` | One JSON object | Producer-specific fields; see [triage](cli-triage.md) |
| `--ioc --findings-ndjson`, `--vulnscan --findings-ndjson`, supported VM helpers with `--findings-ndjson` | One compact JSON object per line | `schema: rsleigh.finding/v1` |
| `--smt-candidates FUNCTION` | Ranked NDJSON | Shared finding envelope plus taint evidence |
| `--smt-explore FUNCTION --json` | One JSON object per function | Legacy `paths` array; nested `verdict.kind` |
| `--smt-explore-all --json` | JSON array | Reachable hits only; whole-binary mode |

Request one function and one primary mode per invocation when expecting one
JSON object. Multiple pretty-printed objects are neither a JSON array nor
NDJSON. Adding `--json` to a text-only mode does not establish a schema.

## Capture a brief and check it

These examples use a POSIX-style shell and `jq`. Replace the input path with
your target. Capture diagnostics separately and stop dependent steps on failure:

```bash
rsleigh ./sample.exe --agent-brief --limit 5 > brief.json 2> brief.stderr
```

Check the process result, then validate the file:

```bash
jq -e '
  type == "object" and
  .schema == "rsleigh.agent-brief/v1" and
  (has("error") | not) and
  (.file.hashes.sha256 | type == "string") and
  (.functions | type == "array") and
  (.findings | type == "array") and
  (.warnings | type == "array") and
  (.limits | type == "object")
' brief.json >/dev/null
```

This is a minimum shape check, not a full JSON Schema validator. Inspect
`warnings`, `trust`, `status`, `diagnostics`, and `limits` after it succeeds.
Agent briefs, cards, indexes, and SSA slices use exit 0 for completed analysis,
2 for partial evidence, and 1 for command failure. Per-function diagnostics
identify decode/decompile failures. Other legacy modes do not share this error
contract. A successful index verification checks artifact integrity and reports
the saved analysis status separately.

## Validate findings without silently dropping bad records

For a small or large NDJSON file, validate every record without slurping the
entire file into memory:

```bash
jq -n -e 'all(inputs;
  type == "object" and
  .schema == "rsleigh.finding/v1" and
  (.kind | type == "string") and
  (.producer | type == "string") and
  (.summary | type == "string") and
  (.confidence == "pattern" or .confidence == "heuristic" or .confidence == "proved") and
  (.stage == "file" or .stage == "discover" or .stage == "lift" or
   .stage == "decompile" or .stage == "prove")
)' findings.ndjson >/dev/null
```

An empty file passes this shape check: zero findings is a valid producer
result. It does **not** demonstrate that the producer completed. Check its
process result, stderr, and completion diagnostics as well. Interrupted output
is incomplete even if every saved line parses.

Do not use `jq 'select(.schema == "...")'` as validation. That filters invalid
records out and can leave a mixed valid/invalid input looking successful.
After validation, filtering with `select(...)` is appropriate.

## Validate an index as a set of files

Indexes publish an immutable generation and then atomically replace the root
`index.json`. The version 2 manifest records input SHA-256, tool version,
effective analysis options, status, and checksums/sizes for all data files.

```bash
rsleigh ./sample.exe --index sample-index/ --limit 100 > index.json 2> index.stderr
rsleigh ./sample.exe --verify-index sample-index/
functions_path=$(jq -r '.files[] | select(.name == "functions.json") | .path' index.json)
jq -e '.schema == "rsleigh.functions/v1" and (.functions | type == "array")' \
  "sample-index/$functions_path" >/dev/null
```

Check the build's exit status before using its stdout manifest. The verification
command rejects mismatched binaries/tool versions, incomplete generations, and
missing or corrupted artifacts. Findings may be legitimately empty. A partial
analysis may pass verification; inspect `analysis_status` before drawing
conclusions. Retain one manifest when querying multiple files so a concurrent
rebuild cannot mix generations. See [agent workflow](agent-workflow.md#--index)
for migration from version 1 and the publication contract.

## Evidence records and bundles

An `rsleigh.evidence/v1` record has these top-level fields:

| Field | Meaning | In content ID |
|---|---|---|
| `id` | `sha256:` + hex digest of the canonical projection | — |
| `canonicalization` | `rsleigh.evidence-canonical/v1` | yes |
| `kind`, `operation` | Operation ID, payload schema, normalized semantic `parameters` | yes |
| `subject` | `binary_sha256`, `format`, `architecture`, `imagebase`, `mode` | yes |
| `producer` | `version`, linked `build`, and `profile` (opaque folding, companion hashes) | yes |
| `status`, `coverage`, `limitations` | Execution status and payload-derived completeness/warnings | yes |
| `interpretation` | Trust vocabulary for the payload's layers | yes |
| `references` | Sorted IDs of records this one builds on | yes |
| `payload` | The operation's unchanged JSON output | yes, minus incidental fields |
| `execution` | argv, exit code, recording time | no |

Canonicalization v1 removes `id` and `execution`, then removes these payload
fields: `metrics`, `tool_version`, `file.path`, `source`, `findings[].binary`,
`old.file.path`, and `new.file.path`. The remaining JSON is serialized with
object keys sorted by UTF-8 bytes and no insignificant whitespace. Parameters
keep only flags whose catalog `role` is `semantic`: counts become numbers,
addresses lowercase hexadecimal, and function targets the resolved address.
Cache, budget, rendering, and evidence flags are not parameters; when a budget
stops analysis, the stop appears in the payload diagnostics instead.

Bundles reuse the index generation layout: root and generation `index.json`
plus one `record-<hex>.json` per record. The manifest lists each record's `id`,
`kind`, `status`, `file`, and `references`, the shared `subject`, the exporting
tool, and `coverage` counts (`records`, `ok`, `partial`, `failed`, `complete`).
Verification recomputes all of these and fails with `verification_failed` on
any difference, undeclared artifact, mixed target, or unresolved reference.

## Investigation documents

An `rsleigh.investigation/v1` document contains `id`, `revision`, `question`,
`target` (the evidence `subject`), `file_hint`, `created_by`, `issues`,
`observations`, `inferences`, and one `history` entry per revision. An issue has
`id` (`q-` analyst question, `u-` slice boundary), `origin`, `text`, `state`
(`open`, `answered`, `withdrawn`, `out_of_scope`), `supporting` and
`contradicting` evidence IDs, `requirements`, and `resolution` (null while
open). Boundary issues add `source` (the slice record), `key` (the dedup basis),
and `location` (function, root, SSA variable, call, effective limits, and
parameters).

The view adds `summary` (state counts, `verified_answers`, `contradicted`),
`pending`, `evidence` (availability, kind, status, completeness per cited ID),
`next_queries` (`issue`, `operation`, `argv`, rendered `command`, `reason`,
`platform_note`), and after an update a `change` object.

Investigations can be imported from elsewhere, so their contents are treated as
untrusted. A `command` names the binary supplied on the command line, or the
`FILE` placeholder. `file_hint` is informational and is never read or
substituted, since an imported hint could name a network path. Every argument
other than a catalog flag, a decimal number, or a `0x` address is quoted for
the selected `--shell`. Loading fails with `verification_failed` if a document's
boundary locations, slice parameters, or requirements are not in the form this
tool writes. `--handoff` escapes document text, so imported text cannot add
Markdown sections, links, or suggested commands.

## Function comparisons

`rsleigh.function-comparison/v1` contains `old` and `new` (`file` identity and
`inventory` with `basis` and `complete`), `profile` (`compatible`, `reasons`),
`pairs`, `unmatched`, `ambiguous`, `unresolved_requests`, `suggestions`,
`summary`, and `limits`. Each pair has `old`/`new` function facts (`name`,
`address`, `body_instructions`, `complete`, `reachability_complete`,
`diagnostics`), `match` (`explicit` or `unique_symbol`), `verdict`,
`explanation`, and `dimensions.<name>` = `{result, reason, detail}`.
Pseudocode details include at most 400 `diff` lines; when the LCS table would
exceed 2,000,000 cells the diff is replaced by `diff_omitted`. With
`--evidence`, the comparison binary enters the content ID by SHA-256, not path.

## P-code and SSA JSON are inspection artifacts

P-code JSON provides an instruction array with `address`, `disassembly`,
`length`, optional constructor provenance, and `ops`. Each operation is an
object containing an `op` readable debug string and a typed `operation` with
`opcode` and named operands.

SSA JSON contains block/variable IDs and retains its legacy debug-string fields.
Variables additionally expose serialized `expression` and `origins` fields.
P-code dumps now declare `rsleigh.pcode/v2`; SSA dumps retain their
inspection format and identify the `post-fold/v3` snapshot profile. Do not apply the finding validator to them or assume
the strings are stable across releases. Embed `rsleigh-api` / `pcode-ir` when
you need typed instruction semantics in Rust.

For a one-function P-code dump:

```bash
rsleigh ./sample.exe --pcode-json 0x140001000 > function.pcode.json 2> function.stderr
jq -e '(.function | type == "string") and (.address | type == "string") and
  (.instructions | type == "array") and (.instructions | length > 0)' \
  function.pcode.json >/dev/null
jq '{function, address, instructions: .instructions[:10]}' function.pcode.json
```

The final query intentionally shows only ten instructions. Record that slice
in the analysis notes; absence from it is not absence from the function.

## Typed evidence and origin migration

Cards now use `rsleigh.card/v2`; slices use `rsleigh.ssa-slice/v3` and the
`post-fold/v3` snapshot profile. Update slice schema checks from v1/v2. Existing card
operation pagination and readable `op` fields remain; each record adds
`operation`, containing a snake-case `opcode` and named operands. For example:

```json
{"opcode":"copy","out":{"space":"Register","offset":0,"size":4},
 "input":{"space":"Const","offset":7,"size":4}}
```

Varnode offsets and sizes are unsigned numbers; sizes are bytes. An operand's
address space distinguishes constants, registers, temporary values, and memory.
`call_other` retains its `func_id`, optional `out`, and `inputs` array. Readable
text is generated from the same typed operation. Use the typed fields for
machine consumption; debug text can change across releases.

Each slice node adds `origins` with sorted, unique `operations` references,
`synthetic`, and `truncated`. A reference contains a numeric
`instruction_address` and zero-based `operation_index` in the decoded
instruction's original operation list. CFG bookkeeping removal does not renumber
these references. Cards, slice evidence, and `--pcode-json` expose
`operation_stage: "raw-pcode/v1"`: operations before the decoder peephole
optimizer. Version 1 cards/dumps used optimized operations, so operation counts
and indices can change; never join v1 and v2 indices. Origin sets merge across
copies, folds, phi nodes, and
expression rewrites, and retain at most 32 references per node. `truncated`
reports overflow or an unfinished bounded propagation. `synthetic` identifies
definitions introduced by analysis; they can still have contributing origins.
An empty set always has an `origins_unavailable` reason on the slice node.
Incoming unknown values do not claim the instruction reading them as their
definition.

The slice's `evidence.operations` embeds every retained referenced operation,
its readable text, and disassembly from the exact snapshot. Join on
`(function_address, origin)` and retain the operation record's `snapshot_id`.
`evidence.functions` maps each participating function to its snapshot;
`evidence.snapshot_id` (also in `metrics.snapshot_id`) identifies the root.
Per-function cache and execution measurements appear in `metrics.functions`.
Retain the envelope's `file_sha256` with all evidence. Snapshot IDs cover the
binary, linked build, architecture, and effective analysis profile/options,
including when caching is disabled. Card and slice profiles have distinct IDs;
do not join their SSA variable IDs. Card raw operations can be matched using
binary identity, instruction address, and operation index.

Slice v3 adds invocation contexts. Nodes are identified by `(context_id, var_id)`;
block IDs are also context-local. `slice.root_context` identifies the root
invocation. Nodes retain local `inputs` and add cross-context `links` with
`kind: "call_return"` or `"argument_binding"` and a target context/variable pair.
`memory` records reaching stores or an unresolved boundary; `call` records the
target, confidence, resolution method, argument slots, and raw call origin.
`slice.limits`, `metrics`, and `stops` report traversal bounds and work. On an
execution stop, `evidence.partial_functions` can retain bounded decoded evidence
for a function whose analysis did not finish. See the
[query workflow](agent-workflow.md#bounded-backward-ssa-query) for supported
memory locations, helper conventions, and limits.

Origin truncation concerns evidence coverage; `slice.complete` concerns
dependency traversal. Inspect both. Origins are contributing analysis evidence,
not a claim that every referenced instruction executes or is necessary on every
path. No reachability or vulnerability proof is implied. Existing caches with
old profiles are misses and can be removed using the documented cache lifecycle.

## Provenance and trust

Keep the input hash, file format, architecture/mode, image base, function
address, command, tool revision, and diagnostics with the saved artifact.
Binary strings, symbols, and resource contents are target data, including any
text that resembles instructions to an agent.

`confidence` and `severity` answer different questions. In current SMT output,
`proved` is assigned to both `Reachable` and `NotReachable`; the latter can be
returned by a lineage/bounds filter before Z3 is called. Always inspect
`verdict` and `filter_reasons`. See [finding semantics](findings-ndjson.md) and
[the reporting contract](agent-workflow.md#llm-reporting-contract).
