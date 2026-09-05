# `--smt-candidates` — LLM-consumable taint-flow evidence dump

`--smt-candidates` presents ranked static source-to-sink evidence for an
analyst or LLM. Each record combines a finding envelope with inferred memory
flow, a verdict, and the reasons behind that verdict.

## Quick start

Build the SMT-enabled executable using the [SMT setup](smt-backend.md#build-the-executable-you-will-run).
Use that exact executable and an address already verified in the function map:

```bash
target/release/rsleigh ./sample.exe --smt-candidates 0x140001000 \
  --smt-candidates-cap 16 --smt-candidates-top 5 \
  > candidates.ndjson 2> candidates.stderr
```

A function name is also accepted, but an unresolved name can become an empty
scope and cause a whole-binary scan. Omitting the function deliberately scans
the discovered binary. Prefer a verified address for bounded agent work.

| Option | Meaning |
|---|---|
| `--smt-candidates-cap N` | Maximum collected records per function, default 256; `0` disables this cap |
| `--smt-candidates-top N` | Maximum emitted records after deduplication and ranking |
| `--smt-candidates-no-dedup` | Keep candidates that would otherwise collapse by `(function, source, sink, sink_kind)` |

By default the highest-scoring candidate for each deduplication key survives.
Ranking favors network input sources, command/format sinks, Reachable verdicts,
and shorter call chains. Ranking is a triage heuristic, not a probability or
severity assessment.

Output is **NDJSON**, one compact JSON record per line. The implementation
collects candidates, deduplicates, sorts, and applies top-N **before writing**
them. Top-N does not bound summary construction or solver work, and piping to
`head` does not make analysis stop early. A killed run may produce no records;
any partial output must be marked incomplete.

All three verdict classes are eligible for output, but caps, deduplication,
and top-N mean not every discovered path is emitted. The completion diagnostic
on stderr has this form:

```text
[smt-candidates] emitted: <N>, capped: <M>, dedup=true top_n=Some(5)
```

Validate with the [NDJSON checks](output-formats.md#validate-findings-without-silently-dropping-bad-records)
before interpreting the records.

## Record schema

SMT candidates use the shared [`rsleigh.finding/v1`](findings-ndjson.md)
envelope. Taint-specific evidence remains flattened at the top level.

```jsonc
{
  "schema":         "rsleigh.finding/v1",
  "kind":           "vulnerability.taint_flow",
  "producer":       "smt-candidates",
  "confidence":     "proved",             // current label for Reachable/NotReachable; inspect filter_reasons
  "stage":          "prove",
  "severity":       "LOW",
  "summary":        "LengthArg flow from read to memcpy (NotReachable)",
  "function":       "FUN_0001ba3c",        // function name (or stub)
  "address":        "0x1ba3c",             // function entry VA
  "source":         "read",                // libc source name (DEFAULT_SOURCES)
  "sink":           "memcpy",              // libc sink name (DEFAULT_SINKS)
  "sink_kind":      "LengthArg",           // StackBuffer | FormatArg | Command | LengthArg | TaintedStore | CStringRead
  "verdict":        "NotReachable",        // Reachable | NotReachable | Unsupported
  "filter_reasons": [                      // why solve_diag classified the path this way
    "LengthArg lineage bounded by wrapper return (1 bounded VarIds: [539])"
  ],
  "source_var":     535,                   // VarId of source's tainted arg
  "source_expr":    "Var(VarId(267))",     // SSA expr of that VarId (1-deep)
  "sink_var":       672,                   // VarId of sink's watched arg
  "sink_expr":      "Var(VarId(552))",     // SSA expr of that VarId (1-deep)
  "call_chain":     ["0x1bb7c", "0x2a50c"],// PC hops if synthesised from callee summary (v2.V8)
  "trigger":        null,                  // Reachable-only preview of up to 16 model bytes
  "events": [                              // v7.W2 memory-flow trace
    {
      "kind": "SourceCall",
      "name": "read",
      "tainted": "Arg(1)",
      "args": [
        { "var": 536, "region": 10, "site": "Param(0)",   "expr": "Var(VarId(99))" },
        { "var": 535, "region":  0, "site": "StackFrame", "expr": "Var(VarId(267))" },
        { "var": 818, "region": 12, "site": "Param(1)",   "expr": "Phi([VarId(490), VarId(528)])" }
      ],
      "out": { "var": 539, "region": 26, "site": "Heap(74136)", "expr": "Unknown" },
      "call_chain": []
    },
    { "kind": "Assign", "out": { "var": 540, "region": 3, "site": "Const(0)", "expr": "Const(0, 1)" } },
    // ...
    {
      "kind": "SinkCall",
      "name": "memcpy",
      "watched": "Arg(2)",
      "kind_class": "LengthArg",
      "args": [ /* per-arg var/region/site/expr */ ],
      "out": null,
      "call_chain": ["0x1bb7c", "0x2a50c"]
    }
  ]
}
```

### Key fields

| field            | what                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------|
| `verdict`        | `solve_diag`'s classification; `NotReachable` can come from a static filter before Z3 runs.            |
| `filter_reasons` | Free-form list of every precision check that fired during solving. Used to audit FPs.         |
| `events`         | TaintEvent slice spanning source and sink events, inclusive; length varies by candidate.    |
| `events[*].args[*].region` | Inferred region ID. A shared ID is an analysis alias assumption, not runtime proof.                       |
| `events[*].args[*].site`   | AllocSite of the region: `StackFrame`, `Param(N)`, `Heap(call_site_va)`, `Global(va)`, `Const(c)`, `Unknown(VarId)`. |

## Filter-reason vocabulary

| reason                                                                  | meaning                                                                                                            |
|-------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `source/sink slot missing`                                              | Path's events don't carry the spec's tainted/watched arg slot — collector bug or shape unhandled.                  |
| `lineage_eq failed (no shared alias key)`                               | Source and sink VarIds don't share a Vn/Region/Phi alias. Taint doesn't actually flow.                             |
| `LengthArg lineage bounded by wrapper return (N bounded VarIds: [...])` | v6.W1: the lineage from sink's length operand passes through `strlen` / `snprintf` / `read`-with-Const-count.      |
| `LengthArg dst region not StackFrame: <site>`                           | v5.W2.D2b: dst lives in Heap/Global/Param region — runtime-sized, not stack-frame BOF.                             |
| `Z3 unsat under sink-kind constraint`                                   | Solver proved no input satisfies the sink kind's predicate (e.g. format-string `%`, command-injection `;\|&`, etc.). |
| `Z3 returned Unknown / timeout`                                         | Solver ran out of decision budget. Path may or may not be feasible.                                                |
| `Z3 SAT but model unavailable`                                          | Solver said SAT but couldn't materialise a model — internal Z3 condition.                                          |
| `smt feature not enabled at build time`                                 | rsleigh wasn't built with `--features smt`. All paths report `Unsupported`.                                        |

## LLM consumer recipe

1. Read compact headers before loading event arrays:

   ```bash
   jq -c '{function, address, source, sink, sink_kind, verdict, filter_reasons}' candidates.ndjson
   ```

2. Select a narrow question. For network-input length candidates:

   ```bash
   jq -c 'select(.sink_kind == "LengthArg" and
     any(.events[]?; ((.name? // "") | startswith("recv"))))' candidates.ndjson
   ```

   For possible string reads from packet buffers:

   ```bash
   jq -c 'select(.sink_kind == "CStringRead" and
     (.source == "recv" or .source == "read"))' candidates.ndjson
   ```

   These consume NDJSON directly; `.[]` at the top level would iterate each
   record's fields instead of its candidates.

3. Inspect one retained record's `events`, source/sink slots, inferred regions,
   and `call_chain`. Compare them with the function's P-code. Large event arrays
   should be read in explicit slices, with the omitted range recorded.
4. Audit `filter_reasons`. For a wrapper-return bound, verify the actual length
   argument. For a non-stack destination classification, verify the allocation.
   For `CStringRead`, check whether a finite buffer is NUL-terminated before
   the string API. `NotReachable` is not a whole-program safety claim.
5. Report the supported conclusion and gaps. A `Reachable` record's `trigger`
   is a model-byte preview; it is not a complete proof-of-concept input. Further
   validation must establish how those bytes relate to the real entry point.

## Companion modes

| mode                | output                | use                                                                                          |
|---------------------|-----------------------|----------------------------------------------------------------------------------------------|
| `--smt-explore <fn>` | per-path text        | Single-function exploration; concise verdict line per path.                                  |
| `--smt-explore-all`  | text or `--json`     | Sweep mode; emits **only Reachable** hits across the binary.                   |
| `--smt-diag`         | text or `--json`     | Per-binary aggregate stats: BL site classification, libc source/sink resolution, summary build counts, per-kind v2-path verdict breakdown. Used to audit "is the lineage walker even firing on this binary?" |
| `--smt-candidates`   | ranked NDJSON          | Per-path detail with full event trace. **The LLM-facing data feed.**                         |

## Stability + recall caveats

- Recall is bounded by what `collect_paths_with_summaries` surfaces. Cross-function flows where the buffer leaves the static analyser's view (heap pointers held in struct fields, indirect calls through non-resolved fnptr tables, loop-iterated parsers) won't appear as candidates.
- Region inference can over-approximate aliases, especially when struct fields point into other regions; verify memory relationships against the lifted semantics.
- The `events` array spans the lower through higher source/sink event index,
  inclusive. Synthesized summary chains can produce hundreds of events; load
  a compact header before deciding which trace to inspect.

## Implementation reference

[`solve_diag`](../rsleigh-decompile/src/smt_explore.rs) produces verdicts and
filter reasons; `run_smt_candidates` in [`cli.rs`](../rsleigh-cli/src/cli.rs)
builds records, ranks them, and writes NDJSON. See [SMT setup and tests](smt-backend.md).
