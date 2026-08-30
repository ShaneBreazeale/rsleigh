# Oracle fixtures

Strict P-code parity tests against Ghidra. Layout:

```
test-harness/fixtures/oracle/
  <arch>/
    <case>.bin               # raw bytes (single function or instruction stream)
    <case>.ghidra.json       # exported via scripts/ExportRsleighOracle.java
```

## Schema (v1)

```json
{
  "schema_version": 1,
  "arch": "x86:LE:64:default",
  "binary_sha256": "...",
  "functions": [
    {
      "entry": 4096,
      "name": "FUN_00001000",
      "blocks": [{"start": 4096, "end": 4112, "succs": [4112]}],
      "instructions": [
        {
          "addr": 4096,
          "len": 3,
          "bytes": "4889d8",
          "disasm": "MOV RAX,RBX",
          "pcode": [
            {"op": "COPY",
             "out": {"space": "register", "offset": 0, "size": 8},
             "inputs": [{"space": "register", "offset": 24, "size": 8}]}
          ]
        }
      ]
    }
  ]
}
```

## Regenerate

```bash
GHIDRA_INSTALL_DIR=/opt/ghidra scripts/ghidra-refresh-oracles.sh

# Or refresh one fixture directly:
GHIDRA_INSTALL_DIR=/opt/ghidra \
  scripts/ghidra-export-oracle.sh \
    test-harness/fixtures/oracle/x86_64/ret_imm16.bin \
    x86:LE:64:default \
    test-harness/fixtures/oracle/x86_64/ret_imm16.ghidra.json
```

CI does not run Ghidra. Commit JSON; regenerate manually when fixtures change.
`manifest.tsv` is the exact public corpus. Add deterministic random-byte samples
or slices copied from a real executable's `.text` section there; the parity test
then scores every decoded instruction for length, op count, and varnode/target
agreement. The exporter records Ghidra's imported-file SHA-256 in each JSON.

## Comparison policy

- **Strict:** instruction `len`, p-code opcode sequence per instruction, varnode
  `space` and `size`, register/RAM offsets, direct branch targets, function
  entry addresses, block boundaries, block successor sets.
- **Normalized:** `unique` space offsets remapped to first-def order per
  function; raw values are not comparable.
- **Fuzzy:** disasm spelling, function names.

The test prints an `OracleScore` for every fixture: decode failures, missing
constructor provenance, length mismatches, missing/extra operations, normalized
operation/varnode mismatches, and direct branch/call destination mismatches.
Known semantic gaps have exact score baselines, so either a regression or an
improvement fails until the baseline and explanation are reviewed.
