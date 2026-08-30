# `--smt-candidates` — LLM-consumable taint-flow evidence dump

After v7, rsleigh's SMT backend reframes the deliverable: rsleigh is
the **static evidence presenter**, the LLM (or human analyst) is the
CVE judge. `--smt-candidates` is the structured-JSON pipe between
the two.

## Quick start

```bash
# Build with z3 feature
CPATH=$(brew --prefix z3)/include LIBRARY_PATH=$(brew --prefix z3)/lib \
  cargo build -p rsleigh-cli --release --features smt

# Dump every v2 path in a binary as NDJSON candidate records
rsleigh /path/to/binary --smt-candidates > candidates.ndjson

# Scope to one function (by name or 0xVA):
rsleigh /path/to/binary --smt-candidates extract_name > candidates.ndjson
rsleigh /path/to/binary --smt-candidates 0x1ba3c       > candidates.ndjson

# Cap per-function record count (default 256). Useful on binaries
# with pathological config-parser functions that explode candidate
# generation. Cap of 0 disables (legacy behaviour).
rsleigh /path/to/binary --smt-candidates --smt-candidates-cap 16 > candidates.ndjson

# v11.B: dedup is on by default. Records sharing
# (function, source, sink, sink_kind) collapse to the highest-
# scoring instance. Disable with:
rsleigh /path/to/binary --smt-candidates --smt-candidates-no-dedup

# v11.B: top-N filter. After dedup + sort, emit only the highest
# N records. Score formula:
#   source kind: recv-class > read > fgets > getenv
#   sink kind:   Command > FormatArg > StackBuffer > TaintedStore > CStringRead > LengthArg
#   verdict:     Reachable > NotReachable > Unsupported (200 / 50 / 0 bonus)
#   call-chain:  shorter is better (5 pts/hop penalty, capped at 50)
rsleigh /path/to/binary --smt-candidates --smt-candidates-top 10
```

Output is **NDJSON** (one record per line, terminated by `\n`).
Each record is self-contained, so partial dumps from OOM/SIGINT
remain analyst-consumable. Stdout is flushed per record so a
downstream `jq` / `head` / `grep` sees results immediately.

**Every** v2 path appears, regardless of verdict — the analyst
chooses which static-bound classifications to trust.

A summary line is written to stderr at the end:
```
[smt-candidates] total emitted: <N>, total capped: <M>
```

## Record schema

SMT candidates use the shared [`rsleigh.finding/v1`](findings-ndjson.md)
envelope. Taint-specific evidence remains flattened at the top level.

```jsonc
{
  "schema":         "rsleigh.finding/v1",
  "kind":           "vulnerability.taint_flow",
  "producer":       "smt-candidates",
  "confidence":     "proved",             // proved for SAT/UNSAT; heuristic when unsupported
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
  "trigger":        null,                  // Reachable-only: 16 trigger bytes "00 ff 00 00 ..."
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
| `verdict`        | `solve_diag`'s SAT classification. `NotReachable` ≠ "no bug" — see filter reasons.            |
| `filter_reasons` | Free-form list of every precision check that fired during solving. Used to audit FPs.         |
| `events`         | TaintEvent walk between source_event and sink_event, inclusive. Mean ~76 events/candidate.    |
| `events[*].args[*].region` | Region ID from v4 region inference. Same ID = aliased memory.                       |
| `events[*].args[*].site`   | AllocSite of the region: `StackFrame`, `Param(N)`, `Heap(call_site_va)`, `Global(va)`, `Const(c)`, `Unknown(VarId)`. |

## Filter-reason vocabulary (v7)

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

1. **Filter for high-prior CVE patterns**:
   ```bash
   jq '[.[] | select(.sink_kind == "LengthArg" and (.events[] | .name? // "" | startswith("recv")))]' candidates.json
   ```
   For parser OOB-read candidates from unterminated packet buffers:
   ```bash
   jq 'select(.sink_kind == "CStringRead" and (.source == "recv" or .source == "read"))' candidates.ndjson
   ```
2. **Read the events array** to see how the source bytes flow into the sink. Each event's `args[*].region` tells the LLM which memory location is touched.
3. **Audit each `filter_reasons`** entry against the actual binary semantics:
   - "bounded by wrapper return" → check whether the wrapper really caps the value (e.g. `read(_, _, ATTACKER_CONTROLLED_COUNT, _)` would be a v7 false-negative if rsleigh classified the count as Const).
   - "dst region not StackFrame" → check whether the dst is actually a stack alloca that v4 region inference missed.
   - `CStringRead` → confirm the watched pointer references a finite packet/body buffer and that the code does not guarantee NUL termination before the string API call.
4. **Use `trigger` bytes** as PoC seed when verdict is Reachable.

## Companion modes

| mode                | output                | use                                                                                          |
|---------------------|-----------------------|----------------------------------------------------------------------------------------------|
| `--smt-explore <fn>` | per-path text        | Single-function exploration; concise verdict line per path.                                  |
| `--smt-explore-all`  | text or `--json`     | Sweep mode; emits **only Reachable** hits across the binary. Conservative.                   |
| `--smt-diag`         | text or `--json`     | Per-binary aggregate stats: BL site classification, libc source/sink resolution, summary build counts, per-kind v2-path verdict breakdown. Used to audit "is the lineage walker even firing on this binary?" |
| `--smt-candidates`   | always JSON          | Per-path detail with full event trace. **The LLM-facing data feed.**                         |

## Stability + recall caveats

- Recall is bounded by what `collect_paths_with_summaries` surfaces. Cross-function flows where the buffer leaves the static analyser's view (heap pointers held in struct fields, indirect calls through non-resolved fnptr tables, loop-iterated parsers) won't appear as candidates. See `.opt/failed.md` "M2 attempts #1-7" for the empirical recall ceiling on the AX6000 corpus.
- Region inference treats `Load(addr)` as same-region as `addr` (region.rs:191). Sometimes alias too aggressively (struct fields can point at other regions); sometimes correctly bridges spill/reload.
- The `events` array always covers `[source_event ..= sink_event]` inclusive. For v0 paths, source == sink == 0 events apart so events is short. For v2 paths with a long synthesised summary chain, events can be 100s long.

## Build sketch

`solve_diag` lives in `rsleigh-decompile/src/smt_explore.rs`; the
CLI wrapper is `run_smt_candidates` in `rsleigh-cli/src/cli.rs`.
v0..v6 SMT campaign retrospectives are in `.opt/campaigns/smt-backend{,-v1,-v2,-v4,-v5}.md` and `.opt/failed.md`.
