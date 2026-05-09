#!/usr/bin/env python3
"""rsleigh SMT calibration harness.

Walks a CVE corpus directory:
  <corpus_root>/<binary_name>/
    EXPECTED.json    - ground-truth CVE labels
    <binary_file>    - the executable to scan

For each entry, runs `rsleigh <binary> --smt-candidates --smt-candidates-cap N`
and compares emitted candidates against EXPECTED.json. Prints a calibration
table:
    binary  | CVE-id  | expected_fn  | found?  | reachable?  | TP/FN
"""

from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
RSLEIGH = REPO / "target" / "release" / "rsleigh"
Z3_PREFIX = subprocess.check_output(["brew", "--prefix", "z3"]).decode().strip()


def run_rsleigh(binary: Path, cap: int = 256) -> list[dict]:
    """Invoke rsleigh --smt-candidates, parse NDJSON output."""
    env = os.environ.copy()
    env["CPATH"] = f"{Z3_PREFIX}/include"
    env["LIBRARY_PATH"] = f"{Z3_PREFIX}/lib"
    cmd = [
        str(RSLEIGH),
        str(binary),
        "--smt-candidates",
        "--smt-candidates-cap",
        str(cap),
    ]
    res = subprocess.run(
        cmd, env=env, capture_output=True, text=True, timeout=600
    )
    records = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records


def evaluate(entry_dir: Path) -> list[dict]:
    """Return list of per-CVE result rows."""
    expected_path = entry_dir / "EXPECTED.json"
    if not expected_path.exists():
        print(f"[skip] {entry_dir.name}: no EXPECTED.json", file=sys.stderr)
        return []
    expected = json.loads(expected_path.read_text())
    bin_name = expected.get("binary", entry_dir.name)
    binary = entry_dir / bin_name
    if not binary.exists():
        # try any executable in dir
        candidates = [p for p in entry_dir.iterdir() if p.is_file() and os.access(p, os.X_OK)]
        if not candidates:
            print(f"[skip] {entry_dir.name}: no binary found", file=sys.stderr)
            return []
        binary = candidates[0]

    print(f"[run] {entry_dir.name}: rsleigh {binary.name}", file=sys.stderr)
    records = run_rsleigh(binary)
    print(f"  -> {len(records)} candidates", file=sys.stderr)

    rows = []
    for cve in expected.get("cves", []):
        fn = cve["function"]
        kind = cve.get("kind", "")
        matching = [
            r for r in records
            if r.get("function") == fn or r.get("function", "").endswith(fn)
        ]
        kind_match = [r for r in matching if r.get("sink_kind") == kind] if kind else matching
        reachable = [r for r in kind_match if r.get("verdict") == "Reachable"]
        rows.append({
            "binary": bin_name,
            "version": expected.get("version", ""),
            "cve": cve["id"],
            "expected_fn": fn,
            "expected_kind": kind,
            "found_n": len(matching),
            "kind_match_n": len(kind_match),
            "reachable_n": len(reachable),
            "verdict": "TP" if reachable else ("FOUND-but-unproven" if matching else "FN"),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "corpus_root",
        type=Path,
        help="Directory containing <name>/EXPECTED.json + binary entries",
    )
    args = ap.parse_args()

    if not RSLEIGH.exists():
        print("Building rsleigh release …", file=sys.stderr)
        subprocess.run(
            ["cargo", "build", "--release", "-p", "rsleigh-cli", "--features", "smt"],
            cwd=REPO,
            env={**os.environ, "CPATH": f"{Z3_PREFIX}/include",
                 "LIBRARY_PATH": f"{Z3_PREFIX}/lib"},
            check=True,
        )

    rows = []
    for entry in sorted(args.corpus_root.iterdir()):
        if not entry.is_dir():
            continue
        rows.extend(evaluate(entry))

    if not rows:
        print("No CVE entries evaluated.", file=sys.stderr)
        sys.exit(2)

    # Print table
    print()
    print(f"{'binary':<14} {'cve':<18} {'fn':<25} {'kind':<13} {'found':>6} {'kind_m':>6} {'reach':>6} {'verdict':<20}")
    print("-" * 110)
    for r in rows:
        print(
            f"{r['binary']:<14} {r['cve']:<18} {r['expected_fn']:<25} "
            f"{r['expected_kind']:<13} {r['found_n']:>6} {r['kind_match_n']:>6} "
            f"{r['reachable_n']:>6} {r['verdict']:<20}"
        )

    # Aggregate
    n_total = len(rows)
    n_tp = sum(1 for r in rows if r["verdict"] == "TP")
    n_found = sum(1 for r in rows if r["found_n"] > 0)
    n_fn = sum(1 for r in rows if r["verdict"] == "FN")
    print()
    print(f"Total CVEs:        {n_total}")
    print(f"Found (any kind):  {n_found}  ({100*n_found/n_total:.0f}%)")
    print(f"True Positive:     {n_tp}  ({100*n_tp/n_total:.0f}%)")
    print(f"False Negative:    {n_fn}  ({100*n_fn/n_total:.0f}%)")

    print()
    print(json.dumps({"rows": rows, "totals": {
        "total": n_total, "tp": n_tp, "found": n_found, "fn": n_fn
    }}, indent=2))


if __name__ == "__main__":
    main()
