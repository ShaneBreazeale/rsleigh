# SMT calibration corpus

Each subdirectory `<name>/` is one binary entry with two siblings:

  - `<binary_name>` — the executable to scan
  - `EXPECTED.json` — ground-truth CVE labels:

```json
{
  "binary": "vuln_app",
  "version": "1.0",
  "cves": [
    {
      "id": "CVE-YYYY-NNNNN",
      "function": "expected_function_name",
      "kind": "StackBuffer | FormatArg | Command | LengthArg | TaintedStore",
      "source": "recv | read | fgets | ...",
      "sink": "strcpy | memcpy | system | ...",
      "notes": "free-form description"
    }
  ]
}
```

Run the calibration:

```bash
python3 scripts/smt-calibrate.py test-harness/fixtures/smt/calibration
```

Outputs a per-CVE table:

| binary | cve | fn | kind | found | kind_m | reach | verdict |
|---|---|---|---|---|---|---|---|
| recv_strcpy | M1-recv-strcpy | vuln_recv_strcpy | StackBuffer | 1 | 1 | 1 | TP |

Plus totals: total / found / TP / FN.

## Verdict semantics

- **TP** (true positive): rsleigh emitted a Reachable candidate matching
  the expected function + kind.
- **FOUND-but-unproven**: candidate exists with matching function but
  verdict is NotReachable / Unsupported.
- **FN** (false negative): no candidate emitted for this function.

## Adding a new fixture

1. Build the binary with debug symbols (`-g -O1`, no stripping).
2. Place under `<name>/<binary_name>`.
3. Write `<name>/EXPECTED.json` listing the CVEs you expect rsleigh
   to surface.
4. Re-run the calibration script; new entry shows in table.
