#!/bin/bash
set -e

BINARY=$1
BINARY_NAME=$(basename "$BINARY" | sed 's/\..*//')
WORK_DIR="results/$BINARY_NAME"
GHIDRA_HOME=${GHIDRA_HOME:-~/ghidra_install/ghidra_11.3.1_PUBLIC}

mkdir -p "$WORK_DIR"

echo "=== Decompiler Comparison: $BINARY_NAME ==="
echo ""

# Extract functions to test
echo "[1/4] Extracting target functions..."
cargo run -p test-harness --example extract-functions -- "$BINARY" > "$WORK_DIR/functions.json"
echo "  Found functions in $WORK_DIR/functions.json"

# Get function list from JSON (names and addresses)
FUNCS=$(python3 -c "
import json
with open('$WORK_DIR/functions.json') as f:
    funcs = json.load(f)
    for fn in funcs[:5]:  # limit to 5 for focused test
        print(fn['name'])
" 2>/dev/null || echo "main")

echo "  Testing functions: $FUNCS"
echo ""

# Run Ghidra decompilation
echo "[2/4] Running Ghidra decompilation..."
rm -rf /tmp/ghidra_compare_proj 2>/dev/null || true
mkdir -p /tmp/ghidra_compare_proj

$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_compare_proj proj \
  -import "$BINARY" \
  -postScript scripts/ghidra-export-decompile.py "$WORK_DIR/ghidra_output.json" \
  -deleteProject 2>&1 | grep -v "^$" || true

echo "  Ghidra output saved to $WORK_DIR/ghidra_output.json"
echo ""

# Run rsleigh decompilation
echo "[3/4] Running rsleigh decompilation..."
cargo run -p rsleigh-cli --release -- "$BINARY" $FUNCS > "$WORK_DIR/rsleigh_output.txt" 2>/dev/null || true
echo "  rsleigh output saved to $WORK_DIR/rsleigh_output.txt"
echo ""

# Generate comparison
echo "[4/4] Generating comparison report..."
python3 scripts/compare-features.py "$BINARY_NAME" "$WORK_DIR"
echo ""

echo "=== Complete ==="
echo "Results in: $WORK_DIR/"
echo "- functions.json: selected functions"
echo "- ghidra_output.json: Ghidra pseudocode"
echo "- rsleigh_output.txt: rsleigh pseudocode"
echo "- comparison.json: feature scores"
