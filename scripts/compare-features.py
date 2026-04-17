#!/usr/bin/env python3
"""
Compare rsleigh vs Ghidra decompiled output on feature coverage.
Scores: strings, variable names, function signatures, control flow, type inference.

Usage: python3 scripts/compare-features.py <binary_name> <work_dir>
"""

import json
import sys
import re
from pathlib import Path

def score_strings(pseudocode):
    """Count string literals in output."""
    # Match quoted strings (heuristic)
    strings = len(re.findall(r'"[^"]*"', pseudocode))
    return "✓" if strings > 0 else "✗"

def score_variable_names(pseudocode):
    """Check for meaningful vs generic variable names."""
    # Count param_N, lVar, iVar (generic) vs named identifiers
    generic = len(re.findall(r'\b(param_\d+|lVar\d+|iVar\d+|uVar\d+|rVar\d+)\b', pseudocode))
    named = len(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', pseudocode)) - generic

    if generic == 0 and named > 5:
        return "Good"
    elif named > generic:
        return "Partial"
    else:
        return "Generic"

def score_control_flow(pseudocode):
    """Detect loop/branch structures."""
    has_if = "if" in pseudocode and "(" in pseudocode
    has_while = "while" in pseudocode
    has_for = "for" in pseudocode
    has_switch = "switch" in pseudocode

    structures = sum([has_if, has_while, has_for, has_switch])
    if structures >= 2:
        return "Rich"
    elif structures >= 1:
        return "Some"
    else:
        return "Minimal"

def score_type_inference(pseudocode):
    """Check for type annotations."""
    # Look for C-style type declarations
    types = len(re.findall(r'\b(int|void|char|long|unsigned|float|double|uint\d+_t|int\d+_t)\b', pseudocode))
    if types > 3:
        return "Good"
    elif types > 0:
        return "Partial"
    else:
        return "None"

def score_readability(pseudocode):
    """Heuristic: line count, nesting depth."""
    lines = len([l for l in pseudocode.split('\n') if l.strip()])
    noise_lines = len(re.findall(r'(FUN_|DAT_|LAB_|0x[0-9a-f]+)', pseudocode))

    if lines > 0 and noise_lines < lines * 0.2:
        return "Good"
    elif noise_lines < lines * 0.4:
        return "Moderate"
    else:
        return "Noisy"

def main():
    binary_name = sys.argv[1]
    work_dir = Path(sys.argv[2])

    # Load data
    with open(work_dir / "functions.json") as f:
        functions = json.load(f)

    with open(work_dir / "ghidra_output.json") as f:
        ghidra_out = json.load(f)

    with open(work_dir / "rsleigh_output.txt") as f:
        rsleigh_text = f.read()

    # Parse rsleigh output (format: "=== func_name ===\n...\n---")
    rsleigh_funcs = {}
    current_func = None
    current_code = []

    for line in rsleigh_text.split('\n'):
        if line.startswith("===") and line.endswith("==="):
            if current_func:
                rsleigh_funcs[current_func] = '\n'.join(current_code)
            match = re.search(r'=== (\w+)', line)
            current_func = match.group(1) if match else None
            current_code = []
        elif line.startswith("---"):
            if current_func:
                rsleigh_funcs[current_func] = '\n'.join(current_code)
            current_func = None
            current_code = []
        elif current_func:
            current_code.append(line)

    # Score each function
    comparison = {}
    for func in functions[:5]:
        fname = func["name"]
        ghidra_code = ghidra_out.get(fname, {}).get("pseudocode", "")
        rsleigh_code = rsleigh_funcs.get(fname, "")

        comparison[fname] = {
            "ghidra": {
                "strings": score_strings(ghidra_code),
                "var_names": score_variable_names(ghidra_code),
                "control_flow": score_control_flow(ghidra_code),
                "type_inference": score_type_inference(ghidra_code),
                "readability": score_readability(ghidra_code),
            },
            "rsleigh": {
                "strings": score_strings(rsleigh_code),
                "var_names": score_variable_names(rsleigh_code),
                "control_flow": score_control_flow(rsleigh_code),
                "type_inference": score_type_inference(rsleigh_code),
                "readability": score_readability(rsleigh_code),
            },
        }

    # Save comparison matrix
    with open(work_dir / "comparison.json", 'w') as f:
        json.dump(comparison, f, indent=2)

    # Print summary table
    print(f"\n=== Feature Comparison Matrix: {binary_name} ===\n")
    print("Function        | Strings | Var Names | Control Flow | Type Inf | Readability")
    print("-" * 90)

    for func, scores in comparison.items():
        g = scores["ghidra"]
        r = scores["rsleigh"]

        strings = f"{r['strings']}/{g['strings']}"
        vars = f"{r['var_names']}/{g['var_names']}"
        flow = f"{r['control_flow']}/{g['control_flow']}"
        types = f"{r['type_inference']}/{g['type_inference']}"
        read = f"{r['readability']}/{g['readability']}"

        print(f"{func:15} | {strings:7} | {vars:9} | {flow:12} | {types:8} | {read:11}")

    print(f"\nDetailed comparison saved to {work_dir / 'comparison.json'}")

if __name__ == "__main__":
    main()
