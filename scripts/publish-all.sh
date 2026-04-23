#!/usr/bin/env bash
# Publish rsleigh workspace crates to crates.io in topological order.
#
# Usage:
#   scripts/publish-all.sh           # live publish (IRREVERSIBLE)
#   scripts/publish-all.sh --dry-run # dry-run everything
#
# Prereqs:
#   cargo login <token>  (one-time)
#
# Order:
#   1. pcode-ir
#   2. generated/*-shared            (leaf: only pcode-ir)
#   3. generated/*-subtables         (needs -shared)
#   4. generated/*-instr-NN          (needs -shared + -subtables)
#   5. generated/*-root              (needs -shared, -subtables, all -instr-NN)
#   6. rsleigh-api                   (needs all 6 roots + pcode-ir)
#   7. rsleigh-decompile             (needs pcode-ir + rsleigh-api)
#   8. rsleigh-fid                   (needs pcode-ir + rsleigh-api)
#   9. rsleigh                       (root SLEIGH parser — standalone)
#  10. rsleigh-generate              (needs rsleigh)
#  11. rsleigh-cli                   (needs all of the above)

set -euo pipefail

DRY_RUN=""
# --allow-dirty always: generated/*/out/*.rs is gitignored by design (regenerated
# from slaspec). include = [...] in each Cargo.toml bundles them into the tarball.
EXTRA_FLAGS="--allow-dirty"
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="--dry-run"
  echo "=== DRY RUN MODE ==="
fi

# 30s sleep between publishes — registry index propagation
SLEEP_SECS=30

publish() {
  local crate="$1"
  echo "--- cargo publish -p $crate $DRY_RUN $EXTRA_FLAGS ---"
  # Capture output so we can detect idempotent "already exists" and continue.
  local out
  if out=$(cargo publish -p "$crate" $DRY_RUN $EXTRA_FLAGS 2>&1); then
    echo "$out"
  else
    echo "$out"
    if echo "$out" | grep -qE "crate version.*is already uploaded|already exists on crates.io"; then
      echo "  (already published — skipping)"
    else
      exit 1
    fi
  fi
  if [[ -z "$DRY_RUN" ]]; then
    echo "sleeping ${SLEEP_SECS}s for index propagation"
    sleep "$SLEEP_SECS"
  fi
}

ARCHES=(x86 x86-32 aarch64 arm32 mips riscv)

instr_count() {
  case "$1" in
    x86)     echo 8 ;;
    x86-32)  echo 4 ;;
    aarch64) echo 4 ;;
    arm32)   echo 2 ;;
    mips)    echo 2 ;;
    riscv)   echo 2 ;;
    *)       echo 0 ;;
  esac
}

# 1. pcode-ir
publish pcode-ir

# 2. all -shared
for arch in "${ARCHES[@]}"; do
  publish "rsleigh-gen-${arch}-shared"
done

# 3. all -subtables
for arch in "${ARCHES[@]}"; do
  publish "rsleigh-gen-${arch}-subtables"
done

# 4. all -instr-NN
for arch in "${ARCHES[@]}"; do
  n=$(instr_count "$arch")
  for i in $(seq 0 $((n-1))); do
    publish "rsleigh-gen-${arch}-instr-0${i}"
  done
done

# 5. all -root
for arch in "${ARCHES[@]}"; do
  publish "rsleigh-gen-${arch}-root"
done

# 6-11. main crates
publish rsleigh-api
publish rsleigh-decompile
publish rsleigh-fid
publish rsleigh
publish rsleigh-generate
publish rsleigh-cli

echo "=== DONE ==="
