#!/usr/bin/env bash
# Wrapper for ExportRsleighOracle.java.
#
# Usage:
#   GHIDRA_INSTALL_DIR=/opt/ghidra \
#   scripts/ghidra-export-oracle.sh <fixture.bin> <ghidra-proc-spec> <out.json>
#
# Example:
#   scripts/ghidra-export-oracle.sh \
#     test-harness/fixtures/oracle/x86_64/ret_imm16.bin \
#     x86:LE:64:default \
#     test-harness/fixtures/oracle/x86_64/ret_imm16.ghidra.json
#
# Requires GHIDRA_INSTALL_DIR pointing to a Ghidra release.
set -euo pipefail

if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
  echo "GHIDRA_INSTALL_DIR not set" >&2
  exit 2
fi

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <fixture.bin> <ghidra-proc-spec> <out.json>" >&2
  exit 2
fi

FIXTURE=$1
PROC=$2
OUT=$3

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROJ_DIR=$(mktemp -d)
trap 'rm -rf "$PROJ_DIR"' EXIT

"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  "$PROJ_DIR" rsleigh_oracle \
  -import "$FIXTURE" \
  -processor "$PROC" \
  -scriptPath "$REPO_ROOT/scripts" \
  -postScript ExportRsleighOracle.java "$OUT"

echo "wrote $OUT"
