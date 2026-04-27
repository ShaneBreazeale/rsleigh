#!/usr/bin/env python3
"""Source-driven pseudocode regression bench for rsleigh.

The Ghidra comparison harness is the higher-fidelity oracle. This script is the
fast local gate: compile deterministic C fixtures, decompile named functions,
score noise/coverage metrics, and compare against a checked-in baseline.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test-harness" / "fixtures" / "bench" / "pseudocode_core.c"
BASELINE = ROOT / "test-harness" / "fixtures" / "bench" / "pseudocode_baseline.json"
BUILD_DIR = ROOT / "target" / "decomp-bench"
RESULTS_DIR = ROOT / "results" / "decomp-bench"

TARGET_FUNCS = [
    "add_mix",
    "factorial_iter",
    "classify_score",
    "sum_until_zero",
    "copy_trim",
    "dispatch_op",
    "fib_rec",
    "struct_accum",
    "main",
]

CASES = [
    {
        "name": "pseudocode_core_O0",
        "source": FIXTURE,
        "flags": ["-O0", "-g", "-fno-inline", "-fno-omit-frame-pointer"],
        "functions": TARGET_FUNCS,
    },
    {
        "name": "pseudocode_core_O2",
        "source": FIXTURE,
        "flags": ["-O2", "-g", "-fno-inline", "-fno-omit-frame-pointer"],
        "functions": TARGET_FUNCS,
    },
]

LEAK_PATTERNS = {
    "FUN": re.compile(r"\bFUN_[0-9a-fA-F]+\b"),
    "func": re.compile(r"\bfunc_[0-9a-fA-F]+\b"),
    "DAT": re.compile(r"\bDAT_[0-9a-fA-F]+\b"),
    "lVar": re.compile(r"\blVar\d+\b"),
    "iVar": re.compile(r"\biVar\d+\b"),
    "uVar": re.compile(r"\buVar\d+\b"),
    "tmp": re.compile(r"\btmp_[0-9a-fA-F]+\b"),
    "local": re.compile(r"\blocal_[0-9a-fA-F]+\b"),
    "field": re.compile(r"->field_[0-9a-fA-F]+"),
    "unknown": re.compile(r"(?<![A-Za-z0-9_])\?(?![A-Za-z0-9_])"),
}


def run(cmd: list[str], *, timeout: int = 120, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def host_id() -> str:
    return f"{platform.system()}-{platform.machine()}"


def find_rsleigh(explicit: str | None, build: bool) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise SystemExit(f"rsleigh binary not found: {path}")
        return path

    candidate = ROOT / "target" / "release" / "rsleigh"
    if build or not candidate.exists():
        print("[build] cargo build -p rsleigh-cli --release", flush=True)
        result = run(["cargo", "build", "-p", "rsleigh-cli", "--release"], timeout=600)
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit(result.returncode)
    return candidate


def compile_case(case: dict) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    binary = BUILD_DIR / case["name"]
    cmd = [
        os.environ.get("CC", "cc"),
        str(case["source"]),
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wno-unused-parameter",
        *case["flags"],
        "-o",
        str(binary),
    ]
    print(f"[cc] {case['name']} {' '.join(case['flags'])}", flush=True)
    result = run(cmd, timeout=120)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return binary


def parse_function_listing(text: str) -> dict[str, str]:
    funcs: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*(0x[0-9a-fA-F]+)\s+(.+?)\s*$", line)
        if not match:
            continue
        addr, name = match.groups()
        funcs[name] = addr
        if name.startswith("_"):
            funcs.setdefault(name[1:], addr)
    return funcs


def list_functions(rsleigh: Path, binary: Path) -> dict[str, str]:
    print(f"[list] {binary}", flush=True)
    result = run([str(rsleigh), str(binary)], timeout=120)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
    return parse_function_listing(result.stdout)


def decompile(rsleigh: Path, binary: Path, func: str, funcs: dict[str, str]) -> tuple[str, str]:
    targets = [func]
    if func in funcs:
        targets.append(funcs[func])
    if f"_{func}" in funcs:
        targets.extend([f"_{func}", funcs[f"_{func}"]])

    seen = set()
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        try:
            result = run([str(rsleigh), str(binary), target], timeout=60)
        except subprocess.TimeoutExpired:
            return target, "/* rsleigh timeout while decompiling this function */\n"
        text = result.stdout
        if result.returncode == 0 and text.strip() and "not found" not in text.lower():
            return target, text
    return targets[0], ""


def meaningful_lines(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"} or stripped.startswith("//"):
            continue
        lines.append(stripped)
    return lines


def count_leaks(text: str) -> dict[str, int]:
    return {name: len(pattern.findall(text)) for name, pattern in LEAK_PATTERNS.items()}


def score_text(text: str) -> dict:
    timed_out = "timeout while decompiling" in text
    lines = meaningful_lines(text)
    leaks = count_leaks(text)
    leak_total = sum(leaks.values())
    controls = {
        "if": text.count("if ("),
        "for": text.count("for ("),
        "while": text.count("while ("),
        "switch": text.count("switch "),
    }
    returns = len(re.findall(r"\breturn\b", text))
    calls = len(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", text))
    empty = len(lines) <= 1
    score = 100.0
    if timed_out or not text.strip():
        score = 0.0
    else:
        score -= leak_total * 2.0
        score -= max(0, len(lines) - 80) * 0.25
        if empty:
            score -= 45.0
        if returns == 0:
            score -= 8.0
        if "panic" in text.lower() or "internal error" in text.lower():
            score -= 50.0
    score = max(0.0, min(100.0, score))
    return {
        "found": bool(text.strip()) and not timed_out,
        "timeout": timed_out,
        "empty": empty,
        "lines": len(lines),
        "bytes": len(text.encode("utf-8")),
        "leaks": leaks,
        "leak_total": leak_total,
        "controls": controls,
        "returns": returns,
        "calls": calls,
        "score": round(score, 1),
    }


def run_source_cases(rsleigh: Path) -> dict:
    reports = []
    for case in CASES:
        binary = compile_case(case)
        funcs = list_functions(rsleigh, binary)
        function_reports = {}
        for func in case["functions"]:
            target, text = decompile(rsleigh, binary, func, funcs)
            metrics = score_text(text)
            metrics["target"] = target
            function_reports[func] = metrics
            status = "ok" if metrics["found"] and not metrics["empty"] else "weak"
            print(
                f"[decompile] {case['name']}::{func:<18} "
                f"{status} score={metrics['score']:>5.1f} leaks={metrics['leak_total']}",
                flush=True,
            )
        reports.append(
            {
                "name": case["name"],
                "binary": str(binary.relative_to(ROOT)),
                "source": str(case["source"].relative_to(ROOT)),
                "flags": case["flags"],
                "functions": function_reports,
            }
        )
    return aggregate_report(reports, mode="source")


def run_ad_hoc_binaries(rsleigh: Path, paths: list[str], sample: int) -> dict:
    reports = []
    for raw in paths:
        binary = Path(raw).expanduser()
        funcs = list_functions(rsleigh, binary)
        picks = list(funcs.items())[:sample]
        function_reports = {}
        for name, addr in picks:
            target, text = decompile(rsleigh, binary, name, funcs)
            metrics = score_text(text)
            metrics["target"] = target or addr
            function_reports[name] = metrics
            print(
                f"[decompile] {binary.name}::{name[:28]:<28} "
                f"score={metrics['score']:>5.1f} leaks={metrics['leak_total']}",
                flush=True,
            )
        reports.append(
            {
                "name": binary.name,
                "binary": str(binary),
                "source": None,
                "flags": [],
                "functions": function_reports,
            }
        )
    return aggregate_report(reports, mode="ad-hoc")


def aggregate_report(cases: list[dict], mode: str) -> dict:
    all_funcs = [
        metrics
        for case in cases
        for metrics in case["functions"].values()
    ]
    n = len(all_funcs) or 1
    found = sum(1 for f in all_funcs if f["found"])
    empty = sum(1 for f in all_funcs if f["empty"])
    leaks = sum(f["leak_total"] for f in all_funcs)
    avg_score = sum(f["score"] for f in all_funcs) / n
    return {
        "schema": 1,
        "mode": mode,
        "host": host_id(),
        "cases": cases,
        "aggregate": {
            "functions": len(all_funcs),
            "found": found,
            "empty": empty,
            "leak_total": leaks,
            "avg_score": round(avg_score, 1),
        },
    }


def load_baseline(path: Path) -> dict | None:
    if not path.exists():
        return None
    with path.open() as f:
        return json.load(f)


def compare_reports(current: dict, baseline: dict, score_drop: float, leak_tolerance: int) -> list[str]:
    failures = []
    cur_agg = current["aggregate"]
    base_agg = baseline["aggregate"]
    if cur_agg["found"] < base_agg["found"]:
        failures.append(f"found functions dropped {base_agg['found']} -> {cur_agg['found']}")
    if cur_agg["empty"] > base_agg["empty"]:
        failures.append(f"empty functions increased {base_agg['empty']} -> {cur_agg['empty']}")
    if cur_agg["leak_total"] > base_agg["leak_total"] + leak_tolerance:
        failures.append(
            f"leak total increased {base_agg['leak_total']} -> {cur_agg['leak_total']} "
            f"(tolerance {leak_tolerance})"
        )
    if cur_agg["avg_score"] < base_agg["avg_score"] - score_drop:
        failures.append(
            f"avg score dropped {base_agg['avg_score']} -> {cur_agg['avg_score']} "
            f"(allowed drop {score_drop})"
        )

    base_cases = {case["name"]: case for case in baseline["cases"]}
    for case in current["cases"]:
        base_case = base_cases.get(case["name"])
        if not base_case:
            continue
        for func, metrics in case["functions"].items():
            old = base_case["functions"].get(func)
            if not old:
                continue
            label = f"{case['name']}::{func}"
            if old["found"] and not metrics["found"]:
                failures.append(f"{label} no longer decompiles")
            if not old["empty"] and metrics["empty"]:
                failures.append(f"{label} became empty")
            if metrics["leak_total"] > old["leak_total"] + leak_tolerance:
                failures.append(
                    f"{label} leaks increased {old['leak_total']} -> {metrics['leak_total']}"
                )
            if metrics["score"] < old["score"] - score_drop:
                failures.append(f"{label} score dropped {old['score']} -> {metrics['score']}")
    return failures


def write_reports(report: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "report.json").open("w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    lines = [
        "# rsleigh pseudocode regression bench",
        "",
        f"- mode: `{report['mode']}`",
        f"- host: `{report['host']}`",
        f"- avg score: `{report['aggregate']['avg_score']}`",
        f"- found: `{report['aggregate']['found']}/{report['aggregate']['functions']}`",
        f"- empty: `{report['aggregate']['empty']}`",
        f"- leak total: `{report['aggregate']['leak_total']}`",
        "",
        "| case | function | score | lines | leaks | empty |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for case in report["cases"]:
        for func, metrics in case["functions"].items():
            lines.append(
                f"| `{case['name']}` | `{func}` | {metrics['score']:.1f} | "
                f"{metrics['lines']} | {metrics['leak_total']} | {metrics['empty']} |"
            )
    with (out_dir / "report.md").open("w") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rsleigh", help="path to an rsleigh CLI binary")
    parser.add_argument("--no-build", action="store_true", help="do not build target/release/rsleigh")
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--score-drop", type=float, default=5.0)
    parser.add_argument("--leak-tolerance", type=int, default=4)
    parser.add_argument("--binary", action="append", default=[], help="ad-hoc binary to decompile and score")
    parser.add_argument("--sample", type=int, default=12, help="functions per ad-hoc binary")
    args = parser.parse_args()

    rsleigh = find_rsleigh(args.rsleigh, build=not args.no_build)
    started = time.strftime("%Y%m%d-%H%M%S")

    if args.binary:
        report = run_ad_hoc_binaries(rsleigh, args.binary, args.sample)
    else:
        report = run_source_cases(rsleigh)

    out_dir = args.out or RESULTS_DIR / started
    report["rsleigh"] = str(rsleigh)
    write_reports(report, out_dir)

    print()
    print(
        "[summary] "
        f"avg_score={report['aggregate']['avg_score']} "
        f"found={report['aggregate']['found']}/{report['aggregate']['functions']} "
        f"empty={report['aggregate']['empty']} leaks={report['aggregate']['leak_total']}"
    )
    print(f"[reports] {out_dir / 'report.md'}")

    if args.binary:
        return 0

    if args.update_baseline:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline_report = dict(report)
        baseline_report.pop("rsleigh", None)
        with args.baseline.open("w") as f:
            json.dump(baseline_report, f, indent=2)
            f.write("\n")
        print(f"[baseline] updated {args.baseline.relative_to(ROOT)}")
        return 0

    baseline = load_baseline(args.baseline)
    if baseline is None:
        print(f"[baseline] missing {args.baseline}; rerun with --update-baseline", file=sys.stderr)
        return 2
    if baseline.get("host") != report["host"]:
        print(f"[baseline] warning: baseline host {baseline.get('host')} != current {report['host']}")

    failures = compare_reports(report, baseline, args.score_drop, args.leak_tolerance)
    if failures:
        print("[regression] detected:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("[regression] no score regressions vs baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
