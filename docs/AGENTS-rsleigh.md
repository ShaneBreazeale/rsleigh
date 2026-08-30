# rsleigh contract for coding agents

Copy this file into the target-analysis workspace as `AGENTS.md`, or link to it
from that workspace's agent instructions. The target workspace is the folder
that contains the firmware, executable, or malware sample—not the rsleigh
source checkout.

The complete schemas, caps, supported containers, and index-file reference are
documented in [agent-workflow.md](agent-workflow.md).

## Tool

- Use the local `rsleigh` CLI. Do not start Ghidra or a JVM.
- Treat the decoder and lifted P-code as primary evidence.
- Treat pseudocode as an experimental hypothesis that must be checked against
  disassembly or P-code.
- Treat IOC, vulnerability, and VM-helper results as pattern or heuristic leads.
- A solver result is a positive proof only when `verdict == "Reachable"`.
  `confidence == "proved"` alone also includes proved-unreachable results.

If pseudocode and P-code disagree, believe P-code and report the disagreement.

## Budget

- Start with `rsleigh FILE --agent-brief`. Its JSON output is capped.
- Default to one function at a time after the brief.
- Never run `--all --decompile` or feed a full pseudocode dump to the model.
- Prefer `--findings-ndjson`, `--pcode-json`, and `--ssa-json` over prose dumps.
- Use `--limit N` to ask for a larger map deliberately; `--agent-brief` still
  enforces a hard maximum of 100 functions and 50 findings.
- Use `rsleigh FILE --index DIR` once when repeated queries would otherwise
  rediscover and relift the same binary.

## Evidence ladder

Stop at the first layer that answers the current question.

1. File: `--agent-brief`, `--hashes`, `--ioc --findings-ndjson`, `--sections`
2. Map: the default function list, `--summary`, `--callgraph`, `--xrefs NAME`
3. Lift: `--disasm ADDR`, then `--pcode-json ADDR`
4. Read: `ADDR --card --decompile`, only after the lift looks sane
5. Prove: `--smt-candidates ADDR`, only with a named source and sink

For a bounded single-function view, use:

```bash
rsleigh FILE ADDR --card
rsleigh FILE ADDR --card --pcode
rsleigh FILE ADDR --card --pcode --decompile
```

Cards cap disassembly, P-code, and pseudocode and label architecture-specific
limitations in `warnings[]`.

## Closed analysis loop

Round 1:

```bash
rsleigh FILE --agent-brief
```

Choose at most three addresses from the returned map. For each address, run
Round 2:

```bash
rsleigh FILE --xrefs ADDR
rsleigh FILE ADDR --card --pcode
```

Only if the P-code is coherent, run Round 3:

```bash
rsleigh FILE ADDR --card --pcode --decompile
```

For raw firmware, keep the architecture and base explicit on every command:

```bash
rsleigh firmware.bin --raw arm32 --base 0x08000000
rsleigh firmware.bin --raw arm32 --base 0x08000000 --disasm 0x08001234
```

Do not guess the raw architecture or image base.
