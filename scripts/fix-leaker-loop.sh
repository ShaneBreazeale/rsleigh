#!/usr/bin/env bash
# Outer loop for /fix-leaker. Autonomous iteration with hard stops.
#
# Usage:
#   scripts/fix-leaker-loop.sh <binary> <cached-ghidra.json> [N]
#
# Runs up to N single-shot /fix-leaker invocations. Parses the output
# contract. Stops early on: 2 consecutive aborts, any bench global
# regression, or class-exhaustion detected from .opt/failed.md.
#
# Not a daemon — each iteration is one Claude Code /fix-leaker run
# driven by the human invoker. This wrapper enforces the stop rules
# that a greedy loop would ignore.
#
# Decision tree (derived from campaign goto-merge abort data):
#
#   1. Pull N worst-leakers from bench-score.
#   2. For each:
#      a. If .opt/failed.md has ≥ 3 entries matching this failure_mode
#         in the last 5 entries → SKIP CLASS (mark exhausted).
#      b. If failure_mode == "empty" AND target addr in .opt/ideas.md
#         → skip (known out-of-scope, e.g. int3).
#      c. Otherwise: queue for /fix-leaker invocation.
#   3. After each invocation:
#      a. Parse output contract's `result:` field.
#      b. If pass: reset consecutive-abort counter.
#      c. If aborted: increment counter. At 2 consecutive → STOP.
#      d. Re-run bench. If ANY metric regresses > 1% globally → STOP.
#   4. On stop: write summary to .opt/session.md.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:?usage: fix-leaker-loop.sh <binary> <ghidra.json> [N]}"
GHIDRA="${2:?missing ghidra cache}"
N="${3:-5}"

RSLEIGH="$ROOT/target/release/rsleigh"
OUT="$ROOT/results/bench/loop-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT" "$ROOT/.opt"

echo "[loop] binary=$BIN  N=$N  out=$OUT"

# Snapshot pre-loop bench as baseline.
"$ROOT/scripts/bench-score.py" \
  --binary "$BIN" --rsleigh "$RSLEIGH" --ghidra "$GHIDRA" \
  --sample 50 --out "$OUT" > /dev/null
cp "$OUT/report.json" "$ROOT/.opt/bench.loop-start.json"
BASELINE_COMPOSITE=$(jq '.composite_score' "$OUT/report.json")
echo "[loop] baseline composite: $BASELINE_COMPOSITE"

CONSECUTIVE_ABORTS=0
WINS=0
ABORTS=0
REGRESS=0

for i in $(seq 1 "$N"); do
  echo
  echo "=== iteration $i/$N ==="

  # Target selection.
  "$ROOT/scripts/bench-score.py" \
    --binary "$BIN" --rsleigh "$RSLEIGH" --ghidra "$GHIDRA" \
    --sample 50 --out "$OUT" --worst-leakers -n 5 > "$OUT/wl.json" 2>&1 || true

  if ! jq -e '.targets | length > 0' "$OUT/wl.json" > /dev/null 2>&1; then
    echo "[loop] no targets in worst-leakers — stop"
    break
  fi

  # Class exhaustion: has failed.md seen this target or a campaign
  # against this mode abort recently?
  FAIL_RECENT=$(cat "$ROOT/.opt/failed.md" 2>/dev/null || true)

  TARGET=""
  TARGET_ADDR=""
  TARGET_MODE=""
  while IFS= read -r line; do
    name=$(echo "$line" | jq -r '.name')
    addr=$(echo "$line" | jq -r '.rs_addr')
    mode=$(echo "$line" | jq -r '.failure_mode')
    # Rule 2b: parked in ideas.md (e.g. int3 trap).
    if grep -qF "$name" "$ROOT/.opt/ideas.md" 2>/dev/null; then
      echo "[loop] $name: in ideas.md, skip"
      continue
    fi
    # Rule 2a: target's addr previously aborted — skip to avoid
    # re-plowing known ground.
    if echo "$FAIL_RECENT" | grep -qF "$name"; then
      echo "[loop] $name: in failed.md recent, skip"
      continue
    fi
    # Rule 2c: mode has ≥ 3 recent aborts OR a CAMPAIGN ABORT exists.
    mode_fails=$(echo "$FAIL_RECENT" | grep -cF "$mode" || true)
    campaign_abort=$(echo "$FAIL_RECENT" | grep -c 'CAMPAIGN ABORT' || true)
    if [ "$mode_fails" -ge 3 ] || [ "$campaign_abort" -ge 1 ] && [ "$mode" = "line-gap" ]; then
      echo "[loop] $name: mode=$mode exhausted ($mode_fails recent, $campaign_abort campaigns), skip"
      continue
    fi
    TARGET="$name"; TARGET_ADDR="$addr"; TARGET_MODE="$mode"
    break
  done < <(jq -c '.targets[]' "$OUT/wl.json")

  if [ -z "$TARGET" ]; then
    echo "[loop] no viable targets (all filtered by ideas.md or class-exhaustion)"
    break
  fi
  echo "[loop] target=$TARGET addr=$TARGET_ADDR mode=$TARGET_MODE"

  # Hand off to human / Claude Code invocation.
  echo
  echo "Invoke: /fix-leaker $TARGET_ADDR"
  echo
  echo "When done, paste the output-contract block into $OUT/iter-$i.txt"
  echo "Press ENTER when complete (or type 'abort' to stop the loop):"
  read -r LINE
  if [ "$LINE" = "abort" ]; then
    echo "[loop] aborted by user"
    break
  fi

  # Parse result from iter-$i.txt.
  if [ ! -f "$OUT/iter-$i.txt" ]; then
    echo "[loop] iter-$i.txt missing — assuming aborted"
    CONSECUTIVE_ABORTS=$((CONSECUTIVE_ABORTS + 1))
    ABORTS=$((ABORTS + 1))
  else
    RESULT=$(grep -oE 'result:\s+(pass|fail|aborted)' "$OUT/iter-$i.txt" | awk '{print $2}' || echo "unknown")
    case "$RESULT" in
      pass)
        CONSECUTIVE_ABORTS=0
        WINS=$((WINS + 1))
        echo "[loop] PASS"
        ;;
      *)
        CONSECUTIVE_ABORTS=$((CONSECUTIVE_ABORTS + 1))
        ABORTS=$((ABORTS + 1))
        echo "[loop] $RESULT (consecutive aborts: $CONSECUTIVE_ABORTS)"
        ;;
    esac
  fi

  # Re-bench after iteration.
  "$ROOT/scripts/bench-score.py" \
    --binary "$BIN" --rsleigh "$RSLEIGH" --ghidra "$GHIDRA" \
    --sample 50 --out "$OUT" > /dev/null
  CURRENT=$(jq '.composite_score' "$OUT/report.json")
  DELTA=$(awk "BEGIN { printf \"%.2f\", $CURRENT - $BASELINE_COMPOSITE }")
  echo "[loop] composite: $BASELINE_COMPOSITE → $CURRENT ($DELTA)"

  # Global regression guard (> 1% of composite).
  REGRESS=$(awk "BEGIN { print ($CURRENT < $BASELINE_COMPOSITE - 1) }")
  if [ "$REGRESS" = "1" ]; then
    echo "[loop] GLOBAL REGRESSION detected — stop"
    break
  fi

  # Consecutive-abort guard.
  if [ "$CONSECUTIVE_ABORTS" -ge 2 ]; then
    echo "[loop] 2 consecutive aborts — stop"
    break
  fi
done

# Summary.
FINAL=$(jq '.composite_score' "$OUT/report.json")
DELTA=$(awk "BEGIN { printf \"%.2f\", $FINAL - $BASELINE_COMPOSITE }")

cat > "$ROOT/.opt/session.md" <<EOF
# Session: fix-leaker-loop  $(date +%Y-%m-%d-%H:%M:%S)

binary:         $BIN
iterations:     up to $N
wins:           $WINS
aborts:         $ABORTS
composite Δ:    $BASELINE_COMPOSITE → $FINAL ($DELTA)
stop reason:    $(if [ "$CONSECUTIVE_ABORTS" -ge 2 ]; then echo "2 consecutive aborts"; \
                  elif [ "$REGRESS" = "1" ]; then echo "global regression"; \
                  else echo "N iterations completed or class-exhausted"; fi)

Per-iteration artifacts in: $OUT/
EOF

echo
echo "=== summary ==="
cat "$ROOT/.opt/session.md"
