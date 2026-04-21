#!/usr/bin/env bash
# rsleigh vs Ghidra benchmark driver.
#
# Usage:  scripts/bench-compare.sh <binary> [--out DIR] [--sample N]
#
# Produces <out>/report.md + report.json with a side-by-side score.
# Ghidra path and JDK are resolved internally so the script is
# self-contained; no environment setup required.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# --- Hardcoded toolchain paths (resolve Ghidra once, never hunt again) ---
GHIDRA_CANDIDATES=(
  "$HOME/tools/ghidra_11.4.3_PUBLIC"
  "$HOME/ghidra_install/ghidra_11.3.1_PUBLIC"
  "$HOME/tools/ghidra_12.0.4_PUBLIC"
  "/opt/ghidra"
)
GHIDRA_HOME=""
for c in "${GHIDRA_CANDIDATES[@]}"; do
  if [[ -x "$c/support/analyzeHeadless" ]]; then
    GHIDRA_HOME="$c"; break
  fi
done
if [[ -z "$GHIDRA_HOME" ]]; then
  echo "error: Ghidra not found. Checked:" >&2
  printf '  %s\n' "${GHIDRA_CANDIDATES[@]}" >&2
  exit 1
fi

# Resolve JDK 17+ for Ghidra.
JAVA_CANDIDATES=(
  "$(brew --prefix openjdk@21 2>/dev/null)/libexec/openjdk.jdk/Contents/Home"
  "$(brew --prefix openjdk@17 2>/dev/null)/libexec/openjdk.jdk/Contents/Home"
  "/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home"
  "/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home"
)
JAVA_HOME=""
for c in "${JAVA_CANDIDATES[@]}"; do
  if [[ -d "$c" && -x "$c/bin/java" ]]; then JAVA_HOME="$c"; break; fi
done
if [[ -z "$JAVA_HOME" ]]; then
  echo "error: no JDK 17+ found via brew or /Library/Java/JavaVirtualMachines" >&2
  exit 1
fi

RSLEIGH="$ROOT/target/release/rsleigh"
if [[ ! -x "$RSLEIGH" ]]; then
  echo "building release rsleigh..."
  (cd "$ROOT" && cargo build -p rsleigh-cli --release)
fi

BIN=""
OUT=""
SAMPLE=50
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)    OUT="$2"; shift 2 ;;
    --sample) SAMPLE="$2"; shift 2 ;;
    -h|--help)
      echo "usage: bench-compare.sh <binary> [--out DIR] [--sample N]"; exit 0 ;;
    *) BIN="$1"; shift ;;
  esac
done
if [[ -z "$BIN" ]]; then
  echo "error: missing <binary>" >&2; exit 1
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
if [[ -z "$OUT" ]]; then
  STAMP="$(date +%Y%m%d-%H%M%S)"
  OUT="$ROOT/results/bench/$(basename "$BIN")-$STAMP"
fi
mkdir -p "$OUT"

echo "binary:    $BIN"
echo "out dir:   $OUT"
echo "Ghidra:    $GHIDRA_HOME"
echo "JDK:       $JAVA_HOME"
echo "rsleigh:   $RSLEIGH"
echo "sample:    $SAMPLE funcs"
echo

# --- Ghidra headless decompile ---
PROJ="$(mktemp -d)/ghidra_proj"
mkdir -p "$PROJ"
GHIDRA_JSON="$OUT/ghidra_output.json"
export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"
if [[ -f "$GHIDRA_JSON" ]]; then
  echo "[ghidra] cached $GHIDRA_JSON ($(wc -c < "$GHIDRA_JSON") bytes), skipping"
else
  echo "[ghidra] analyzing $BIN (may take several minutes for Go binaries)..."
  "$GHIDRA_HOME/support/analyzeHeadless" "$PROJ" proj \
    -import "$BIN" \
    -postScript "$ROOT/scripts/ghidra-export-decompile.py" "$GHIDRA_JSON" \
    -deleteProject \
    > "$OUT/ghidra.log" 2>&1 || {
      echo "error: ghidra headless failed — see $OUT/ghidra.log" >&2
      tail -30 "$OUT/ghidra.log" >&2
      exit 2
    }
  echo "[ghidra] wrote $GHIDRA_JSON"
fi

# --- Score ---
echo "[score] computing metrics..."
python3 "$ROOT/scripts/bench-score.py" \
  --binary "$BIN" \
  --rsleigh "$RSLEIGH" \
  --ghidra  "$GHIDRA_JSON" \
  --sample  "$SAMPLE" \
  --out     "$OUT"

echo
echo "done. Report:"
echo "  $OUT/report.md"
echo "  $OUT/report.json"
