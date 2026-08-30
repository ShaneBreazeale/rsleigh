# Findings NDJSON

Recon emitters share one line-oriented schema: `rsleigh.finding/v1`. This lets
an analyst or model concatenate pattern matches, heuristic classifications, and
solver results without guessing which confidence vocabulary each flag uses.

```json
{
  "schema": "rsleigh.finding/v1",
  "kind": "vulnerability.taint_flow",
  "producer": "smt-candidates",
  "confidence": "proved",
  "stage": "prove",
  "severity": "HIGH",
  "function": "main",
  "address": "0x401000",
  "summary": "Command flow from recv to system (Reachable)",
  "source": "recv",
  "sink": "system",
  "verdict": "Reachable"
}
```

Required fields on every line:

| Field | Values / meaning |
|---|---|
| `schema` | Always `rsleigh.finding/v1`. |
| `kind` | Namespaced finding class such as `ioc.url`, `malware.capability`, or `vulnerability.taint_flow`. |
| `producer` | Emitter that made the record (`ioc`, `vulnscan`, `smt-candidates`, …). |
| `confidence` | `pattern`, `heuristic`, or `proved`. This describes evidence quality, not severity. |
| `stage` | `file`, `discover`, `lift`, `decompile`, or `prove`. |
| `summary` | Short human-readable statement. |

`severity`, `function`, and `address` are optional. Producer-specific evidence
is flattened into the same object so existing filters such as
`select(.sink_kind == "Command")` remain valid.

`proved` describes solver-backed evidence, not a positive vulnerability result.
Both `Reachable` and `NotReachable` SMT records have `confidence: "proved"`.
Dashboards looking for actionable flows must filter `verdict == "Reachable"`
and the producer-specific `kind`/`sink_kind`, rather than confidence alone.

Current emitters:

```bash
rsleigh sample --ioc --findings-ndjson
rsleigh sample --vulnscan --findings-ndjson
rsleigh sample --smt-candidates
rsleigh packed.exe --vm-classify-handlers 0x401000 --findings-ndjson
rsleigh packed.exe --tag-dispatch 0x402000 --findings-ndjson
rsleigh packed.exe --summarise-handlers 0x403000 --findings-ndjson
rsleigh packed.exe --vm-dispatch 0x404000 --findings-ndjson
rsleigh packed.exe --vm-bytecode 0x405000:0x400 --vm-handlers handlers.json --findings-ndjson
```

The agent-facing aggregators preserve this record unchanged:

```bash
rsleigh sample --agent-brief             # records embedded in the `findings` JSON array
rsleigh sample --index out/              # records written to out/findings.ndjson
```

`--agent-brief` returns at most 50 findings. `--index` writes at most 5,000.
Both report returned, total, and cap counts in their `limits` object. These are
bounded navigation artifacts, not replacements for running each complete
producer. See the [agent workflow reference](agent-workflow.md) for the exact
subset and ranking behavior.

`--smt-candidates` always emits this NDJSON schema. IOC and vulnscan preserve
their human and legacy aggregate JSON formats unless `--findings-ndjson` is
requested explicitly. VM recon helpers likewise preserve their concise human
rendering by default and emit one shared-schema record per recovered artifact
when the flag is present.

## Safe model and pipeline ingestion

Parse findings one line at a time and retain the original record. Do not merge
records solely because their summaries look similar: `producer`, `kind`,
`function`, `address`, and producer-specific evidence distinguish separate
claims.

```bash
# Reject malformed or wrong-version records.
jq -e 'select(.schema == "rsleigh.finding/v1")' findings.ndjson >/dev/null

# Show positive solver-backed reachability results only.
jq -c 'select(
  .schema == "rsleigh.finding/v1" and
  .stage == "prove" and
  .confidence == "proved" and
  .verdict == "Reachable"
)' findings.ndjson

# Keep lower-confidence leads separate for manual verification.
jq -c 'select(.confidence == "pattern" or .confidence == "heuristic")' \
  findings.ndjson
```

An LLM summary should cite the record's `producer`, `kind`, function/address,
confidence, stage, and relevant evidence fields. It must not translate
`severity: "HIGH"` into high confidence, or `confidence: "proved"` into a
positive verdict without also checking `verdict`.
