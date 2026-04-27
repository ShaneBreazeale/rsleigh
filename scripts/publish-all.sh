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
#   6. rsleigh-cli            (api + decompile + fid)
#   7. rsleigh                (root: optional `cli` feature → rsleigh-cli)
#   8. rsleigh-generate       (rsleigh)
#
# Cycle note: root `rsleigh` declares `rsleigh-cli` as an optional
# dependency (the `cli` feature). cargo publish validates ALL declared
# dep versions against the registry, even optional ones, so rsleigh-cli
# must be on crates.io before rsleigh publishes. rsleigh-cli does NOT
# depend back on root rsleigh, so the cycle is one-way and resolves by
# publishing rsleigh-cli first.

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
    if echo "$out" | grep -qiE "got 50[0-9]|HTTP/2 50[0-9]|503|502|504|gateway|service unavailable"; then
      if (( attempt >= max_attempts )); then
        echo "  5xx retries exhausted for $crate — aborting"
        exit 1
      fi
      local short_backoff=60
      echo "  registry 5xx; sleeping ${short_backoff}s before retry"
      sleep "$short_backoff"
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

# 3-8. main crates. rsleigh-cli MUST publish before root rsleigh —
# the root crate's optional `cli` feature declares a versioned dep
# on rsleigh-cli, and cargo publish requires every declared version
# to already exist on the registry.
publish rsleigh-api
publish rsleigh-decompile
publish rsleigh-fid
publish rsleigh-cli
publish rsleigh
publish rsleigh-generate

echo "=== DONE ==="
