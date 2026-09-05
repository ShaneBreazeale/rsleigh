# Troubleshooting an analysis run

Check the command's input type, renderer, stdout, and stderr before changing
analysis settings. Keep the original artifact and command so the failure is
reproducible.

| Symptom | Likely cause / next step |
|---|---|
| `cannot read --help` or `cannot read --version` | Those flags are treated as filenames. Invoke `rsleigh` with no arguments for usage; see [CLI conventions](cli-reference.md#invocation-conventions). |
| Exit status is zero, but there is no useful result | Some failures only print diagnostics, and a brief may contain `error`. Validate the expected artifact using [output checks](output-formats.md). |
| `jq` fails on a card or index command's stdout | Cards and index completion messages are text. Parse the brief, an explicit JSON mode, or the index files. |
| `jq` sees several JSON values instead of one | Multiple functions or output modes were requested. Run one function/mode per command. |
| `--vulnscan --json` prints text | Use `--vulnscan --findings-ndjson`. `--json` is not universal. |
| Only one of several requested scans runs | Primary modes have dispatch precedence. Run each producer separately. |
| Brief/index is unsupported for a raw blob or WASM | Use the [separate frontend workflow](cli-reference.md#raw-firmware-and-webassembly); adding native flags does not enable native artifacts. |
| Raw `--disasm` still prints pseudocode | The raw renderer does not implement that switch. Use the decoder API or another verified decoder for instruction evidence. |
| A function name produces no output | It may be stripped, renamed, or undiscovered. Copy an address from the current map and inspect stderr. An address is a virtual address, not a file offset. |
| An SMT run unexpectedly scans the whole binary | An unresolved name can become an empty scope. Verify the target in the map and use its address. |
| Brief has no functions or no `next` commands | Discovery found no usable entries. Check the architecture/container and diagnostics; do not infer that the binary has no code. |
| Pseudocode looks implausible | Inspect the function card's warnings, assembly, and P-code; check the [architecture matrix](architectures.md). Report the unresolved reconstruction gap. |
| A card omits the behavior you expected | It may be truncated. Save a single-function P-code dump and select relevant addresses outside the card slice. |
| “No callers” conflicts with runtime behavior | Direct xrefs omit unresolved indirect/virtual calls; discovery may also miss functions. Absence of an edge is not proof of unreachability. |
| A previous index still exists after a failed rebuild | Index writes are non-atomic. Use a fresh directory, verify all files, and compare external hashes. |
| An SMT record says `Unsupported` | Read `filter_reasons`: the feature may be absent or the semantics outside the model. Build the correct executable or report the gap. |
| SMT stdout stays empty for a long time | Candidates are collected and ranked before output. Scope to one verified function; top-N alone does not bound the analysis work. |
| No findings, or only `NotReachable` records | Check completion, caps, source/sink coverage, and filter reasons. This does not establish that the target is free of bugs. |
| `signed: true` on a suspicious PE | Signature metadata was found; cryptographic validity was not checked. See [signature limitations](cli-triage.md#known-limitations-1). |

## Keep work bounded

Briefs and cards bound emitted output, not total runtime. Discovery may examine
the whole file, and card metadata still invokes decompilation. An index can
analyze thousands of functions; a scoped SMT run may also build callee
summaries.

If a command times out under your runner, retain stdout/stderr, mark the result
incomplete, and narrow the question. Avoid retrying a whole-binary mode with
larger caps merely to get any result. Escalate from one function only when its
evidence identifies a concrete next function or data range.

## Report a reproducible issue

Include the source revision or installed package version, host OS, input
SHA-256, container/architecture/mode/base, exact command, function address,
process result, and relevant stdout/stderr. Include the smallest redistributable
fixture or byte sequence that reproduces the problem when available.

For decoding/lifting disagreements, include expected instruction semantics and
constructor provenance. For pseudocode disagreements, include the P-code or
assembly that contradicts the reconstruction. See [testing](TESTING.md) for
regression-test entry points.
