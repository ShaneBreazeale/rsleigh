#!/usr/bin/env python3
"""rsleigh benchmark suite — runs decompilation on all test binaries and reports metrics.

Usage:
    python3 scripts/benchmark.py [test_bin_dir]

Outputs a comparison table of rsleigh vs saved Ghidra baselines.
Returns exit code 1 if any binary regresses below its baseline.
"""

import json
import os
import re
import subprocess
import sys
import time

# Ghidra baselines (function counts from Ghidra 11.3.1 headless analysis)
GHIDRA_BASELINES = {
    "main.exe":                         2539,
    "FrhedPortable_2017.11.paf.exe":    106,
    "rust-crackme-easy.exe":            301,
    "FLRSCRNSVR.SCR":                   71,
    "ChocolateFactory.exe":             514,
    "crackme_bobgambling.exe":          64,
    "vm-final.exe":                     175,
    "cb_baristas_secret_x64.exe":       111,
    "TRYCRACKME.EXE":                   141,
    "masoncrackmev2.exe":               2,
    "4RMMaster.exe":                    3366,
}

# Minimum function counts rsleigh should find (regression baselines)
RSLEIGH_BASELINES = {
    "main.exe":                         2700,
    "FrhedPortable_2017.11.paf.exe":    130,
    "rust-crackme-easy.exe":            400,
    "FLRSCRNSVR.SCR":                   75,
    "ChocolateFactory.exe":             600,
    "crackme_bobgambling.exe":          75,
    "vm-final.exe":                     230,
    "cb_baristas_secret_x64.exe":       130,
    "TRYCRACKME.EXE":                   100,
    "masoncrackmev2.exe":               10,
    "4RMMaster.exe":                    2900,
}


def find_rsleigh():
    """Find the rsleigh CLI binary."""
    candidates = [
        "target/release/rsleigh",
        "../target/release/rsleigh",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    # Try cargo run
    return None


def run_rsleigh(binary_path, rsleigh_bin=None):
    """Run rsleigh on a binary and collect metrics."""
    start = time.time()

    if rsleigh_bin:
        # List functions
        result = subprocess.run([rsleigh_bin, binary_path],
                                capture_output=True, text=True, timeout=120)
        func_count = len([l for l in result.stdout.split('\n') if l.strip().startswith('0x')])

        # Decompile all
        result = subprocess.run([rsleigh_bin, binary_path, "--all"],
                                capture_output=True, text=True, timeout=600)
        output = result.stdout
    else:
        result = subprocess.run(["cargo", "run", "-p", "rsleigh-cli", "--release", "--", binary_path],
                                capture_output=True, text=True, timeout=120)
        func_count = len([l for l in result.stdout.split('\n') if l.strip().startswith('0x')])

        result = subprocess.run(["cargo", "run", "-p", "rsleigh-cli", "--release", "--", binary_path, "--all"],
                                capture_output=True, text=True, timeout=600)
        output = result.stdout

    elapsed = time.time() - start

    # Collect metrics
    lines = output.count('\n')
    strings = len(set(re.findall(r'"[^"]{5,}', output)))
    annotations = output.count('/*')
    cookies = output.count('stack cookie')
    cout_ops = output.count('cout <<')
    cin_ops = output.count('cin >>')
    security_checks = output.count('__security_check_cookie')

    return {
        "functions": func_count,
        "lines": lines,
        "strings": strings,
        "annotations": annotations,
        "cookies": cookies,
        "cout": cout_ops,
        "cin": cin_ops,
        "security": security_checks,
        "time": elapsed,
    }


def main():
    test_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/Downloads/test_bin")

    if not os.path.isdir(test_dir):
        print(f"Error: test_bin directory not found: {test_dir}")
        print("Usage: python3 scripts/benchmark.py [test_bin_dir]")
        sys.exit(1)

    rsleigh_bin = find_rsleigh()

    # Find all test binaries
    binaries = []
    skip_ext = {'.ipa', '.apk', '.zip', '.tar', '.gz', '.json', '.txt', '.md'}
    for f in sorted(os.listdir(test_dir)):
        path = os.path.join(test_dir, f)
        ext = os.path.splitext(f)[1].lower()
        if os.path.isfile(path) and not f.startswith('.') and ext not in skip_ext:
            binaries.append((f, path))

    if not binaries:
        print(f"No binaries found in {test_dir}")
        sys.exit(1)

    print(f"rsleigh benchmark — {len(binaries)} binaries in {test_dir}")
    print(f"{'=' * 90}")
    print()

    results = {}
    regressions = []
    wins = 0
    losses = 0

    for name, path in binaries:
        print(f"  {name}...", end=" ", flush=True)
        try:
            metrics = run_rsleigh(path, rsleigh_bin)
            results[name] = metrics

            ghidra = GHIDRA_BASELINES.get(name, "?")
            baseline = RSLEIGH_BASELINES.get(name, 0)
            funcs = metrics["functions"]

            status = ""
            if isinstance(ghidra, int):
                if funcs > ghidra:
                    status = "BEATS GHIDRA"
                    wins += 1
                elif funcs < ghidra:
                    status = "behind"
                    losses += 1
                else:
                    status = "tied"
                    wins += 1

            if baseline > 0 and funcs < baseline:
                status += " REGRESSION!"
                regressions.append((name, funcs, baseline))

            print(f"{funcs} funcs, {metrics['lines']} lines, "
                  f"{metrics['strings']} strings, {metrics['time']:.1f}s  {status}")

        except subprocess.TimeoutExpired:
            print("TIMEOUT")
            results[name] = {"functions": 0, "error": "timeout"}
        except Exception as e:
            print(f"ERROR: {e}")
            results[name] = {"functions": 0, "error": str(e)}

    # Summary
    print()
    print(f"{'=' * 90}")
    print()
    print(f"{'Binary':<40s} {'rsleigh':>8s} {'Ghidra':>8s} {'Winner':>12s}")
    print(f"{'-' * 40} {'-' * 8} {'-' * 8} {'-' * 12}")

    for name, path in binaries:
        if name not in results:
            continue
        funcs = results[name].get("functions", 0)
        ghidra = GHIDRA_BASELINES.get(name, "?")
        if isinstance(ghidra, int):
            winner = "RSLEIGH" if funcs > ghidra else ("Ghidra" if funcs < ghidra else "tied")
        else:
            winner = "?"
        print(f"{name:<40s} {funcs:>8d} {str(ghidra):>8s} {winner:>12s}")

    print()
    print(f"Score: rsleigh {wins} — Ghidra {losses}")

    if regressions:
        print()
        print("REGRESSIONS DETECTED:")
        for name, actual, expected in regressions:
            print(f"  {name}: {actual} functions (baseline: {expected})")
        sys.exit(1)

    # Save results
    results_path = os.path.join(os.path.dirname(__file__), "..", "docs", "benchmark-results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {results_path}")


if __name__ == "__main__":
    main()
