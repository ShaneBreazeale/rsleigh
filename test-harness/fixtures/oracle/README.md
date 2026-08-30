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
`manifest.tsv` is the exact public corpus: the test fails when a listed binary or
JSON is missing, or when an unlisted oracle JSON is present. The corpus combines
focused instruction streams with one provenance-preserving real `.text` slice
per covered ISA. The exporter records Ghidra's imported-file SHA-256 in each
JSON.

## Real `.text` slice provenance

These fixtures were exported with Ghidra 12.0.4 and OpenJDK 21.0.11. Addresses
inside each raw slice are rebased to zero, so relative control-flow targets are
compared consistently by Ghidra and rsleigh.

| fixture | source | extraction |
|---|---|---|
| `x86_64/pseudocode_dispatch_o2_text.bin` | `dispatch_op` from `../bench/pseudocode_core.c`, built for x86-64 by Apple clang 17.0.0 with `-O2 -fno-inline -fno-omit-frame-pointer` | Mach-O file offset `0x6d0`, length `0x60` |
| `aarch64/bounded_loop_copy_text.bin` | `_copy_bounded` in checked-in `../smt/bin/bounded_loop` (parent SHA-256 `3d7d052a8978f01f40e528c47c57f13fdadbcb90635eed0391547514fc4a62bd`) | Mach-O file offset `0x410`, length `0x60` |
| `arm32/tdpserver_crypto_prefix_text.bin` | prefix of the documented TP-Link `tdpServer` function in `../printer-hangs/tdpserver_0x1591c_arm32.bin` (parent SHA-256 `201422f54c7cb01e0df008e5d891d83592d4c060d318e95ff953b8ac9ed7ed3b`) | function VA `0x1591c`, slice offset `0`, length `0x100` |

## Comparison policy

- **Strict:** instruction `len`, p-code opcode sequence per instruction, varnode
  `space` and `size`, register/RAM offsets, direct branch targets, function
  entry addresses, block boundaries, block successor sets.
- **Normalized:** `unique` space offsets remapped to first-def order per
  function; raw values are not comparable.
- **Fuzzy:** disasm spelling, function names.

The test prints raw and optimized `OracleScore` columns for every fixture:
decode failures, missing constructor provenance, length mismatches,
missing/extra operations, normalized operation/varnode mismatches, and direct
branch/call destination mismatches. Raw scores have exact per-fixture baselines
so generated-lifter changes are distinct from intentional peephole folds. Known
optimized semantic gaps also have exact score baselines, so either a regression
or an improvement fails until the baseline and explanation are reviewed.

When adding a fixture, print its initial scores without accepting them first:

```bash
RSLEIGH_ORACLE_RECORD_SCORES=1 \
  cargo test -p test-harness --test ghidra_oracle -- --nocapture
```

Review the P-code differences, then add the raw baseline and any explained
optimized divergence before running the strict test normally.
