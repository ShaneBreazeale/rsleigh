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
# Order (12 crates total — collapsed from 43):
#   1. pcode-ir
#   2. generated/<arch> × 6   (each: leaf, only pcode-ir)
#   3. rsleigh-api            (needs all 6 generated)
#   4. rsleigh-decompile      (pcode-ir + rsleigh-api)
#   5. rsleigh-fid            (pcode-ir + rsleigh-api)
#   6. rsleigh                (root SLEIGH parser — standalone)
#   7. rsleigh-generate       (rsleigh)
#   8. rsleigh-cli            (everything)

set -euo pipefail

DRY_RUN=""
EXTRA_FLAGS="--allow-dirty"
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="--dry-run"
  echo "=== DRY RUN MODE ==="
fi

# 30s sleep between publishes — registry index propagation
SLEEP_SECS=30

publish() {
  local crate="$1"
  local attempt=1
  local max_attempts=6
  local backoff=600  # 10min — crates.io new-crate token refill window
  while :; do
    echo "--- cargo publish -p $crate $DRY_RUN $EXTRA_FLAGS  (attempt $attempt/$max_attempts) ---"
    local out
    if out=$(cargo publish -p "$crate" $DRY_RUN $EXTRA_FLAGS 2>&1); then
      echo "$out"
      break
    fi
    echo "$out"
    if echo "$out" | grep -qE "crate version.*is already uploaded|already exists on crates.io|already been uploaded"; then
      echo "  (already published — skipping)"
      break
    fi
    if echo "$out" | grep -qiE "429|too many requests|rate.?limit|burst"; then
      if (( attempt >= max_attempts )); then
        echo "  rate-limit retries exhausted for $crate — aborting"
        exit 1
      fi
      echo "  rate-limited; sleeping ${backoff}s before retry"
      sleep "$backoff"
      attempt=$((attempt + 1))
      continue
    fi
    exit 1
  done
  if [[ -z "$DRY_RUN" ]]; then
    echo "sleeping ${SLEEP_SECS}s for index propagation"
    sleep "$SLEEP_SECS"
  fi
}

# 1. pcode-ir
publish pcode-ir

# 2. generated decoders (6, all leaf w.r.t. each other)
for arch in x86 x86-32 aarch64 arm32 mips riscv; do
  publish "rsleigh-gen-${arch}"
done

# 3-8. main crates
publish rsleigh-api
publish rsleigh-decompile
publish rsleigh-fid
publish rsleigh
publish rsleigh-generate
publish rsleigh-cli

echo "=== DONE ==="
