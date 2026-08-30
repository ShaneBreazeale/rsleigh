# Coding-agent workflow

rsleigh's agent-facing interface keeps reverse-engineering loops bounded and
labels which outputs are evidence versus hypotheses. It is a CLI contract, not
an MCP server, and does not require Ghidra or a JVM.

For instructions that can be copied into a target-analysis workspace, see
[the drop-in agent contract](AGENTS-rsleigh.md).

## Recommended sequence

Use the smallest sufficient layer:

1. Build a capped map with `--agent-brief`.
2. Select at most a few functions from the map.
3. Inspect xrefs and the bounded disassembly/P-code card.
4. Request pseudocode only after the lift looks coherent.
5. Use SMT only for a named source/sink question.

```bash
rsleigh sample.exe --agent-brief
rsleigh sample.exe --xrefs 0x140001000
rsleigh sample.exe 0x140001000 --card --pcode
rsleigh sample.exe 0x140001000 --card --pcode --decompile
```

The decoder and P-code are primary evidence. Pseudocode is an experimental
hypothesis. IOC, vulnerability, and VM-helper output is a lead until verified.
For SMT findings, `confidence == "proved"` means the solver established the
reported verdict; only `verdict == "Reachable"` is a positive reachability
claim.

## `--agent-brief`

```bash
rsleigh FILE --agent-brief [--limit N]
```

Produces one `rsleigh.agent-brief/v1` JSON object. It contains:

- file size, container, architecture, image base, MD5, SHA-256, and PE imphash;
- ranked function cards with address, size, lift-derived complexity, incoming
  direct-call xrefs, calls, imports, up to five strings, and behavior tags;
- confidence- and stage-labeled `rsleigh.finding/v1` records;
- architecture-specific warnings and an explicit trust policy;
- three follow-up commands with the highest-ranked address filled in;
- actual counts and enforced caps under `limits`.

Functions are ranked by incoming direct-call xrefs, then lifted conditional
branch complexity, then size. This ranking is for navigation, not a claim that
the first function is malicious or vulnerable.

Default and hard limits:

| Artifact | Default | Hard cap |
|---|---:|---:|
| Functions | 25 | 100 |
| Findings | 50 | 50 |
| Strings per function | 5 | 5 |
| Pseudocode | 0 bytes | 0 bytes |

`--limit` changes the requested function count but cannot raise the hard cap.
The brief decodes the discovered function map, then decompiles only the
returned slice to recover calls, strings, tags, and vulnerability leads.

Brief findings are intentionally bounded. They currently aggregate URL/IPv4
file patterns, family/capability heuristics, and vulnerability patterns from
the returned function slice. Use the complete producers when coverage matters:

```bash
rsleigh FILE --ioc --findings-ndjson
rsleigh FILE --vulnscan --findings-ndjson
rsleigh FILE --smt-candidates ADDR
```

### Schema outline

```json
{
  "schema": "rsleigh.agent-brief/v1",
  "file": {
    "path": "sample.exe",
    "stage": "file",
    "confidence": "proved",
    "size": 123456,
    "format": "pe",
    "arch": "X86_64",
    "imagebase": "0x140000000",
    "hashes": {
      "md5": "...",
      "sha256": "...",
      "imphash": "..."
    }
  },
  "functions": [
    {
      "name": "main",
      "addr": "0x140001000",
      "stage": "discover",
      "confidence": "pattern",
      "size": 448,
      "complexity": 14,
      "complexity_stage": "lift",
      "xrefs": 8,
      "imports": ["memcpy", "strcmp"],
      "strings": ["ok"],
      "calls": ["memcpy", "strcmp"],
      "tags": []
    }
  ],
  "findings": [],
  "warnings": [],
  "trust": {},
  "limits": {},
  "next": [
    "rsleigh 'sample.exe' --xrefs 0x140001000",
    "rsleigh 'sample.exe' --disasm 0x140001000",
    "rsleigh 'sample.exe' --pcode-json 0x140001000"
  ]
}
```

The agent brief and index currently support parsed PE, ELF, and Mach-O targets.
Use the normal `--raw ARCH --base ADDR` workflow for raw firmware and the
dedicated frontend for WebAssembly.

## `--card`

```bash
rsleigh FILE FUNCTION --card
rsleigh FILE FUNCTION --card --pcode
rsleigh FILE FUNCTION --card --pcode --decompile
```

The base card shows metadata, imports, up to five strings, constructor
provenance, trust labels, warnings, and the first 40 instructions. Optional
sections are capped at 120 P-code operations and 4,096 UTF-8-safe pseudocode
bytes. Truncation is repeated in `warnings[]` and at the cut point.

Cards warn when the architecture support matrix marks important lift or
decompile gaps and when the function contains an unresolved indirect call.
Absence of a warning does not upgrade pseudocode to primary evidence.

## `--index`

```bash
rsleigh FILE --index DIR [--limit N]
```

Builds a reusable on-disk map so later agent turns can query files with `jq`,
`rg`, or scripts instead of rediscovering the binary. The output directory
contains:

| File | Schema | Contents |
|---|---|---|
| `index.json` | `rsleigh.index/v1` | Source, architecture, trust policy, warnings, caps, and manifest |
| `functions.json` | `rsleigh.functions/v1` | Ranked function metadata without pseudocode |
| `xrefs.json` | `rsleigh.xrefs/v1` | Direct calls and reverse callers for indexed functions |
| `findings.ndjson` | `rsleigh.finding/v1` | One confidence/stage-labeled finding per line |
| `imports.json` | `rsleigh.imports/v1` | Resolved import addresses and names |

The index has hard caps of 10,000 functions and 5,000 findings. The manifest
reports `returned`, `total`, and cap values so truncation is visible. Indexing
may be substantially slower than `--agent-brief` because metadata and
vulnerability leads are recovered for every indexed function; it is intended
as a one-time cost for repeated analysis.

Example queries:

```bash
jq '.functions[] | select(.xrefs >= 5)' out/functions.json
jq '.functions[] | select(.imports | index("recv"))' out/functions.json
jq '.functions[] | select(.called_by | length > 10)' out/xrefs.json
jq 'select(.severity == "HIGH" or .severity == "CRIT")' out/findings.ndjson
```

## Limits and evidence gaps

- Direct-call xrefs do not prove the absence of indirect, virtual, or
  dynamically resolved calls.
- Function discovery and names can be heuristic on stripped binaries.
- Architecture warnings summarize known support gaps; consult the
  [architecture matrix](architectures.md) for detail.
- A card or brief is deliberately incomplete when a cap is reached. Follow the
  emitted address-specific commands instead of raising every budget at once.
- The index contains analysis results, not a cache of decoded IR; changing the
  binary requires rebuilding the index.
