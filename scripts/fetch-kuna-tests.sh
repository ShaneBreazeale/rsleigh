#!/usr/bin/env bash
# Fetch the Kuna decompiler-output test corpus used by
# test-harness/tests/kuna_datatests.rs.
#
# Kuna (https://github.com/Noelo-Lab/kuna, Apache-2.0) ships two XML corpora:
#   tests/datatests/  Ghidra's decompiler regression tests (Apache-2.0, NSA)
#   tests/stages/     Kuna's own issue testcases
# Each file is raw bytes + a Ghidra language id + regex assertions over the
# decompiled C. The corpus is not vendored; this script checks out the commit
# pinned in test-harness/fixtures/kuna-baseline.json (or the one given).
#
# Usage: scripts/fetch-kuna-tests.sh [<kuna-commit>] [<dest>]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
baseline="$root/test-harness/fixtures/kuna-baseline.json"
commit="${1:-$(sed -n 's/.*"kuna_commit": *"\([0-9a-f]*\)".*/\1/p' "$baseline")}"
dest="${2:-$root/test-harness/fixtures/kuna-tests}"

if [ -z "$commit" ]; then
  echo "no commit given and none pinned in $baseline" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q
git -C "$tmp" remote add origin https://github.com/Noelo-Lab/kuna.git
git -C "$tmp" config core.sparseCheckout true
printf 'tests/datatests/\ntests/stages/\nLICENSE\nNOTICE\n' > "$tmp/.git/info/sparse-checkout"
git -C "$tmp" fetch -q --depth 1 origin "$commit"
git -C "$tmp" checkout -q FETCH_HEAD

rm -rf "$dest"
mkdir -p "$dest"
cp -R "$tmp/tests/datatests" "$tmp/tests/stages" "$tmp/LICENSE" "$tmp/NOTICE" "$dest/"
echo "$commit" > "$dest/COMMIT"
echo "kuna tests @ $commit -> $dest ($(ls "$dest/datatests" "$dest/stages" | grep -c '\.xml$') files)"
