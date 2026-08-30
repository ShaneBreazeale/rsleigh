#!/usr/bin/env bash
# Regenerate the committed per-instruction Ghidra parity corpus.
# Add random-byte samples or real .text slices to manifest.tsv to extend it.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
ORACLE_ROOT="$REPO_ROOT/test-harness/fixtures/oracle"
MANIFEST="${1:-$ORACLE_ROOT/manifest.tsv}"

while IFS=$'\t' read -r input processor; do
  [[ -z "$input" || "$input" == \#* ]] && continue
  fixture="$ORACLE_ROOT/$input"
  output="${fixture%.bin}.ghidra.json"
  "$REPO_ROOT/scripts/ghidra-export-oracle.sh" "$fixture" "$processor" "$output"
done < "$MANIFEST"
