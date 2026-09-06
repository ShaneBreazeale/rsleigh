# Output formats and validation

Choose a renderer explicitly and validate the artifact it actually produces.
The CLI does not have a universal JSON mode or a uniform error envelope.

## Format map

| Command mode | Stdout / files | Expected shape |
|---|---|---|
| `--agent-brief` | One JSON object | `schema: rsleigh.agent-brief/v1`; reject `error` |
| `--index DIR` | JSON manifest and generation files | `rsleigh.index/v2`; checksums and paths for four artifacts |
| `--verify-index DIR` | One JSON object | `rsleigh.index-verification/v1`; validity and analysis status |
| `--ssa-slice FUNCTION --var ID` | One JSON object | `rsleigh.ssa-slice/v1`; bounded dependencies and boundaries |
| `FUNCTION --card ...` | Text by default; JSON with `--json` | `rsleigh.card/v1`; evidence references and independent pagination |
| `--pcode-json FUNCTION` | One JSON object per requested function | `function`, `address`, `instructions` |
| `--ssa-json FUNCTION` | One JSON object per requested function | `function`, `address`, `blocks`, `vars` |
| `--disasm FUNCTION --json` | One JSON object per requested function | `function`, `instructions`; `pcode_ops` is a count |
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

## P-code and SSA JSON are inspection artifacts

P-code JSON provides an instruction array with `address`, `disassembly`,
`length`, optional constructor provenance, and `ops`. Each operation is an
object containing an `op` **Rust debug string**; it is not a typed opcode with
separately serialized operands.

SSA JSON contains block/variable IDs, but statements, terminators, expressions,
varnodes, and inferred types are also debug strings. These formats have no
versioned `schema` field. Do not apply the finding validator to them or assume
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
