#!/usr/bin/env python3
"""rsleigh vs Ghidra scoring.

Reads a Ghidra export JSON produced by ghidra-export-decompile.py, runs
rsleigh on the same binary (single-function mode at the same address
adjusted for the image-base delta), and emits a side-by-side scorecard.

Metrics per function:
  - line count                    — higher isn't always better, but wild
                                    divergence signals over-fold/under-fold
  - leak tokens                   — count of `FUN_` / `DAT_` / `lVar` /
                                    `field_` markers = unresolved surface
  - empty body                    — decompile produced no statements
  - structural coverage           — presence of loops / ifs matches

Aggregate score (higher = closer to Ghidra, max 100):
  discovery_coverage * 30       — fraction of Ghidra funcs rsleigh also decompiles
  line_parity        * 25       — 1 - |avg_line_delta_ratio|
  leak_parity        * 25       — 1 - (rsleigh_leaks - ghidra_leaks)/max(rsleigh,1)
  empty_rate         * 20       — 1 - empty_body_rate

Outputs report.md and report.json to --out dir.
"""
import argparse
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path

LEAK_PATTERNS = [
    ("FUN_",     re.compile(r'\bFUN_[0-9a-f]+\b')),
    ("func_",    re.compile(r'\bfunc_[0-9a-f]+\b')),
    ("DAT_",     re.compile(r'\bDAT_[0-9a-f]+\b')),
    ("lVar",     re.compile(r'\blVar[0-9]+\b')),
    ("iVar",     re.compile(r'\biVar[0-9]+\b')),
    ("uVar",     re.compile(r'\buVar[0-9]+\b')),
    ("field_",   re.compile(r'->field_[0-9a-f]+')),
    ("local_",   re.compile(r'\blocal_[0-9a-f]+\b')),
    ("tmp_",     re.compile(r'\btmp_[0-9a-f]+\b')),
    ("?",        re.compile(r'(?<![a-zA-Z0-9_])\?(?![a-zA-Z0-9_])')),
]

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--rsleigh", required=True)
    p.add_argument("--ghidra",  required=True, help="ghidra_output.json")
    p.add_argument("--sample",  type=int, default=50)
    p.add_argument("--out",     required=True)
    return p.parse_args()


def detect_base_delta(ghidra_data, rsleigh, binary):
    """Ghidra PIE base often differs from rsleigh. Try (1) name match,
    (2) common PIE offsets (0x100000, 0x400000, 0), picking whichever
    yields the most ghidra_addr - delta matches in rsleigh's symbol
    address set."""
    try:
        out = subprocess.run([rsleigh, binary], capture_output=True, text=True, timeout=120).stdout
    except subprocess.TimeoutExpired:
        return 0
    rs_addrs = set()
    rs_by_name = {}
    for line in out.splitlines():
        m = re.match(r'\s+0x([0-9a-f]+)\s+(\S.*)$', line)
        if m:
            a = int(m.group(1), 16)
            rs_addrs.add(a)
            rs_by_name[m.group(2)] = a
    if not rs_addrs:
        return 0

    gh_addrs = [int(str(b["address"]).rstrip("L"), 16) for b in ghidra_data.values()]
    if not gh_addrs:
        return 0

    # Candidate deltas: name-matched + common PIE bases.
    candidates = {0, 0x100000, 0x400000, 0x10000}
    for name, body in ghidra_data.items():
        gh_addr = int(str(body["address"]).rstrip("L"), 16)
        if name in rs_by_name:
            candidates.add(gh_addr - rs_by_name[name])
        san = re.sub(r'[^A-Za-z0-9]+', "_", name).strip("_")
        if san in rs_by_name:
            candidates.add(gh_addr - rs_by_name[san])

    best = (0, 0)  # (delta, match_count)
    sample_gh = gh_addrs[: min(500, len(gh_addrs))]
    for delta in candidates:
        matches = sum(1 for a in sample_gh if (a - delta) in rs_addrs)
        if matches > best[1]:
            best = (delta, matches)
    return best[0]


def count_leaks(text):
    return {label: len(pat.findall(text)) for label, pat in LEAK_PATTERNS}


def run_rsleigh(rsleigh, binary, addr, timeout=30):
    try:
        r = subprocess.run(
            [rsleigh, binary, hex(addr)],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""


def body_is_empty(text):
    # Strip signature line + comment lines + braces; count meaningful stmts.
    sigs = 0
    stmts = 0
    for l in text.splitlines():
        t = l.strip()
        if not t: continue
        if t.startswith("//"): continue
        if t in ("{", "}"): continue
        if t.endswith("{") or t.startswith("}"): continue
        if "(" in t and ")" in t and "{" in t and "return" not in t:
            sigs += 1; continue
        stmts += 1
    return stmts <= 1


def has_control_flow(text):
    return any(kw in text for kw in ("while ", "for (", "if (", "do {", "switch "))


def main():
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.ghidra) as f:
        ghidra = json.load(f)

    # Adjust rsleigh addresses to Ghidra's image base.
    delta = detect_base_delta(ghidra, args.rsleigh, args.binary)
    print(f"[score] image-base delta: 0x{delta:x}")

    # Build Ghidra function index
    gh_items = []
    for name, body in ghidra.items():
        addr = int(str(body["address"]).rstrip("L"), 16)
        src = body.get("pseudocode", "")
        gh_items.append((name, addr, src))

    # Sample
    random.seed(42)
    picks = [g for g in gh_items if 10 < g[2].count("\n") < 200]
    random.shuffle(picks)
    picks = picks[: args.sample]

    per_func = []
    rs_total_lines = 0
    gh_total_lines = 0
    rs_total_leaks = 0
    gh_total_leaks = 0
    rs_empty = 0
    rs_missing = 0
    rs_control_matches = 0

    for name, gh_addr, gh_src in picks:
        rs_addr = gh_addr - delta
        rs_src = run_rsleigh(args.rsleigh, args.binary, rs_addr)
        rs_lines = rs_src.count("\n")
        gh_lines = gh_src.count("\n")
        rs_leaks = sum(count_leaks(rs_src).values())
        gh_leaks = sum(count_leaks(gh_src).values())
        empty = body_is_empty(rs_src)
        missing = rs_src.strip() == "" or "no instructions" in rs_src
        control_match = has_control_flow(rs_src) == has_control_flow(gh_src)

        rs_total_lines += rs_lines
        gh_total_lines += gh_lines
        rs_total_leaks += rs_leaks
        gh_total_leaks += gh_leaks
        if empty: rs_empty += 1
        if missing: rs_missing += 1
        if control_match: rs_control_matches += 1

        per_func.append({
            "name": name,
            "gh_addr": f"0x{gh_addr:x}",
            "rs_addr": f"0x{rs_addr:x}",
            "rs_lines": rs_lines,
            "gh_lines": gh_lines,
            "rs_leaks": rs_leaks,
            "gh_leaks": gh_leaks,
            "empty": empty,
            "missing": missing,
            "control_match": control_match,
        })

    n = len(picks) or 1
    avg_rs_lines = rs_total_lines / n
    avg_gh_lines = gh_total_lines / n
    avg_rs_leaks = rs_total_leaks / n
    avg_gh_leaks = gh_total_leaks / n

    line_ratio = 0.0
    if avg_gh_lines > 0:
        line_ratio = 1.0 - abs(avg_rs_lines - avg_gh_lines) / avg_gh_lines
    line_ratio = max(0.0, min(1.0, line_ratio))

    leak_ratio = 1.0
    if avg_rs_leaks > 0:
        leak_ratio = 1.0 - max(0.0, (avg_rs_leaks - avg_gh_leaks)) / avg_rs_leaks
    leak_ratio = max(0.0, min(1.0, leak_ratio))

    empty_ratio = 1.0 - (rs_empty / n)
    control_ratio = rs_control_matches / n

    # Discovery coverage: Ghidra funcs for which rsleigh found SOMETHING.
    discovery = 1.0 - (rs_missing / n)

    score = (
        discovery   * 30 +
        line_ratio  * 25 +
        leak_ratio  * 25 +
        empty_ratio * 20
    )

    report = {
        "binary": args.binary,
        "delta": f"0x{delta:x}",
        "ghidra_funcs": len(ghidra),
        "sample_size": n,
        "avg_rs_lines": round(avg_rs_lines, 1),
        "avg_gh_lines": round(avg_gh_lines, 1),
        "avg_rs_leaks": round(avg_rs_leaks, 1),
        "avg_gh_leaks": round(avg_gh_leaks, 1),
        "rs_empty_bodies": rs_empty,
        "rs_missing": rs_missing,
        "control_flow_matches": rs_control_matches,
        "scores": {
            "discovery_coverage": round(discovery, 3),
            "line_parity":        round(line_ratio, 3),
            "leak_parity":        round(leak_ratio, 3),
            "empty_rate":         round(empty_ratio, 3),
            "control_flow":       round(control_ratio, 3),
        },
        "composite_score": round(score, 1),
        "per_func": per_func,
    }

    with open(out_dir / "report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Markdown
    md = []
    md.append(f"# rsleigh vs Ghidra — {Path(args.binary).name}")
    md.append("")
    md.append(f"**Composite score:** `{score:.1f} / 100`")
    md.append("")
    md.append("## Aggregates")
    md.append("")
    md.append(f"| metric                 | rsleigh | ghidra |")
    md.append(f"|------------------------|---------|--------|")
    md.append(f"| avg lines / func       | {avg_rs_lines:.1f}  | {avg_gh_lines:.1f}  |")
    md.append(f"| avg leaks / func       | {avg_rs_leaks:.1f}  | {avg_gh_leaks:.1f}  |")
    md.append(f"| ghidra funcs total     |  —      | {len(ghidra)} |")
    md.append(f"| sample size            | {n}      | {n}      |")
    md.append(f"| rsleigh empty bodies   | {rs_empty}/{n}   |  —     |")
    md.append(f"| rsleigh missing        | {rs_missing}/{n}  |  —     |")
    md.append(f"| control-flow matches   | {rs_control_matches}/{n}  |  —     |")
    md.append("")
    md.append("## Score breakdown")
    md.append("")
    md.append("| component          | weight | value | contrib |")
    md.append("|--------------------|--------|-------|---------|")
    md.append(f"| discovery_coverage |  30    | {discovery:.3f} | {discovery*30:.1f} |")
    md.append(f"| line_parity        |  25    | {line_ratio:.3f} | {line_ratio*25:.1f} |")
    md.append(f"| leak_parity        |  25    | {leak_ratio:.3f} | {leak_ratio*25:.1f} |")
    md.append(f"| empty_rate         |  20    | {empty_ratio:.3f} | {empty_ratio*20:.1f} |")
    md.append(f"| **total**          | **100** |  —   | **{score:.1f}** |")
    md.append("")
    md.append("## Worst 10 (by rsleigh leak count)")
    md.append("")
    md.append("| fn | rs_lines | gh_lines | rs_leaks | gh_leaks |")
    md.append("|----|----------|----------|----------|----------|")
    worst = sorted(per_func, key=lambda x: -x["rs_leaks"])[:10]
    for w in worst:
        md.append(f"| `{w['name'][:50]}` | {w['rs_lines']} | {w['gh_lines']} | {w['rs_leaks']} | {w['gh_leaks']} |")

    with open(out_dir / "report.md", "w") as f:
        f.write("\n".join(md) + "\n")

    # Rich console summary — formatted for both humans and LLM parsers.
    bar = "=" * 62
    print()
    print(bar)
    print(f" rsleigh vs Ghidra — {Path(args.binary).name}")
    print(bar)
    print(f"  image-base delta:    0x{delta:x}")
    print(f"  ghidra funcs total:  {len(ghidra)}")
    print(f"  sample size:         {n}")
    print()
    print(f"  {'metric':<24} {'rsleigh':>10}  {'ghidra':>10}")
    print(f"  {'-'*24} {'-'*10}  {'-'*10}")
    print(f"  {'avg lines / func':<24} {avg_rs_lines:>10.1f}  {avg_gh_lines:>10.1f}")
    print(f"  {'avg leaks / func':<24} {avg_rs_leaks:>10.1f}  {avg_gh_leaks:>10.1f}")
    print(f"  {'empty bodies':<24} {rs_empty:>4}/{n:<5} {'—':>10}")
    print(f"  {'missing/no-instr':<24} {rs_missing:>4}/{n:<5} {'—':>10}")
    print(f"  {'control-flow matches':<24} {rs_control_matches:>4}/{n:<5} {'—':>10}")
    print()
    print(f"  {'component':<22} {'weight':>6} {'value':>6} {'pts':>6}")
    print(f"  {'-'*22} {'-'*6} {'-'*6} {'-'*6}")
    print(f"  {'discovery_coverage':<22} {30:>6} {discovery:>6.3f} {discovery*30:>6.1f}")
    print(f"  {'line_parity':<22} {25:>6} {line_ratio:>6.3f} {line_ratio*25:>6.1f}")
    print(f"  {'leak_parity':<22} {25:>6} {leak_ratio:>6.3f} {leak_ratio*25:>6.1f}")
    print(f"  {'empty_rate':<22} {20:>6} {empty_ratio:>6.3f} {empty_ratio*20:>6.1f}")
    print(f"  {'-'*22} {'-'*6} {'-'*6} {'-'*6}")
    print(f"  {'COMPOSITE':<22} {100:>6} {'':>6} {score:>6.1f}")
    print(bar)
    # Traffic-light summary for LLM parsing.
    verdict = "EXCELLENT" if score >= 80 else \
              "GOOD"      if score >= 60 else \
              "FAIR"      if score >= 40 else \
              "POOR"
    print(f"  VERDICT: {verdict} ({score:.1f}/100)")
    print(bar)
    print(f"  reports: {out_dir}/report.md , report.json")
    print()


if __name__ == "__main__":
    main()
