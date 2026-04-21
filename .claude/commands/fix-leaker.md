---
description: Single-target, test-first SSA/fold fix loop for a concrete bench gap
---

# /fix-leaker — rsleigh SSA/fold accuracy iteration

A single-target, test-first, commit-or-revert loop for closing concrete bench
gaps in rsleigh. `$ARGUMENTS` is the target (function name, address, or slug)
or empty for auto-select.

## Hard constraints (non-negotiable)

1. **One target per invocation.** No batching.
2. **No refactors.** Only `fold.rs` / `ssa.rs` edits unless the defect
   demonstrably lives elsewhere — and then say so explicitly before touching.
3. **Test before fix.** Failing regression test committed before any production
   code change.
4. **Bench must improve on targeted metric.** Other metrics regress >1% → revert.
5. **3-attempt cap.** Can't land in 3 tries → log to `.opt/failed.md`, hand back.
6. **No IR redesigns, no HIR layer, no new passes** from inside this loop.

## Workflow

### Phase 1 — Target selection

If no `$ARGUMENTS`:
```bash
scripts/bench-score.py --binary BIN --rsleigh target/release/rsleigh \
  --ghidra CACHED.json --sample 50 --out .opt \
  --worst-leakers -n 5
```
Pick #1 unless in `.opt/failed.md` within last 3 entries — then next.
State one line: `target=<X>  current_score=<Y>  failure_mode={leak|cflow|naming|param-count|line-gap}`.

If `$ARGUMENTS` given: resolve to (binary, address, function symbol). Fail loudly if ambiguous.

### Phase 2 — SSA inspection (read-only)

```bash
mkdir -p .opt
target/release/rsleigh <bin> --ssa-json <addr> > .opt/before.json
```

Identify the **concrete defect** — exactly one of:
- Wrong `VarDef` (name which field)
- Missing / extra `Phi` node
- Wrong parameter count (expected N, got M)
- Dangling `Def` with no use
- Line gap / if-count mismatch vs. Ghidra
- Other (name it)

**Stop rule:** can't state the defect in one sentence with a specific JSON
path → don't understand it yet. Inspect more. Don't fix on vibes.

Output: `defect: <one sentence> @ <json.path>`

### Phase 3 — Regression test FIRST

Create `rsleigh-decompile/tests/regression_<slug>.rs`:
- Load function bytes (inline `&[u8]` or fixture file).
- Build SSA via same path the binary uses.
- Assert the shape that *should* exist — not what currently exists.

Run it. **Must fail.** If it passes, bug already fixed or assertion wrong.

Commit: `test: failing regression for <bug_slug> (<metric>)`.

**No exceptions for "trivial" fixes.** Constant-widening, byte-check
relaxation, enum variant addition, and opcode-table updates all require
tests. If the code being changed isn't unit-testable, that's a blocker
to fix first, not a license to skip. File a `candidate: enables-testing`
entry in `.opt/ideas.md` and write an integration test in the meantime.

### Phase 4 — Fix

- Minimal diff, scoped to `fold.rs` / `ssa.rs`.
- Test passes. `cargo test -p rsleigh-decompile --release` green.
- Any existing assertion flips red → stop, inspect, don't paper over.

### Phase 5 — Verify

```bash
target/release/rsleigh <bin> --ssa-json <addr> > .opt/after.json
diff <(jq -S . .opt/before.json) <(jq -S . .opt/after.json) > .opt/ssa.diff
scripts/bench-score.py ... > .opt/bench.after.json
```

Compare bench.before vs bench.after:
- Targeted metric must improve.
- Other metrics must not regress > 1% absolute.
Fail either → Phase 6b.

### Phase 6a — Commit (pass)

```
fix(<fold|ssa>): <one-line summary>

Before: <metric> = X
After:  <metric> = Y  (Δ +Z)
Other metrics unchanged within ±1%.

SSA diff: .opt/ssa.diff
Test: tests/regression_<slug>.rs
```

Append to `.opt/wins.md`: `<date> <target> <metric> <Δ> <sha>`.

### Phase 6b — Abort (fail)

```bash
git reset --hard HEAD~1   # drop fix commit, keep test
```

Mark test `#[ignore]` with pointer to `.opt/failed.md`. Append:
```
<date>  <target>  attempt <N>/3  reason: <...>  hypothesis: <...>
```

Attempt 3 → stop. Write handoff in `.opt/failed.md`: defect summary, tried,
suspected root cause, next.

## Output contract (per invocation)

Exactly this, no prose padding:

```
target:   <name/addr>
defect:   <one sentence>
test:     <path> (sha: <committed>)
result:   pass | fail | aborted
bench Δ:  <metric>: X → Y (+Z)
commit:   <sha> | reverted
notes:    <one line or empty>
```

## Anti-patterns

- "While investigating I noticed X is also broken, let me fix both" → no.
  File to `.opt/ideas.md`. Next invocation.
- "The real fix is a new IR pass" → out of scope. `.opt/ideas.md`.
- "Bench noisy, regression probably fine" → no. Revert, re-run 3x, investigate noise.
- "I'll skip the test, fix is obvious" → no. Test first, always.

## State files

```
.opt/
├── before.json        # SSA pre-fix
├── after.json         # SSA post-fix
├── ssa.diff
├── bench.before.json
├── bench.after.json
├── wins.md            # append-only — full-protocol wins
├── failed.md          # append-only — aborted attempts
├── debt.md            # append-only — wins that skipped protocol,
│                      #   retroactive test landed after the fact
└── ideas.md           # parking lot for out-of-scope observations
```

**Ledger discipline:** wins.md, failed.md, debt.md are disjoint.
Don't cross-file entries. Mixing categories corrupts the ledger.

## Campaign mode (opt-in, multi-commit)

Strict monotonic improvement = greedy hill-climbing. Sometimes fixing a fold
rule that's masking a deeper SSA bug REQUIRES temporarily regressing funcs that
were coincidentally benefiting from the wrongness. Don't relax the default
guard — add a bounded, expensive exception mode.

### Invocation

```
/fix-leaker <target> --campaign <slug> --budget <N> --horizon <K>
```

- `--campaign <slug>` — declares multi-commit arc, not single-shot
- `--budget N` — max funcs allowed to regress (absolute count)
- `--horizon K` — max commits to realize net gain (default 3, hard cap 5)

### Declaration (mandatory, upfront)

Before any code change, write `.opt/campaigns/<slug>.md`:

```
hypothesis:   <what's actually wrong at a deeper level>
trade:        regress <N> funcs in <class A>, fix <M> funcs in <class B>
net claim:    M - N ≥ <threshold> within <K> commits
rollback:     git tag campaign-<slug>-start  (set automatically)
```

Can't fill this out in one sitting → don't have a campaign, have a hope.

### Rules

1. **Budget is a ceiling, not a target.** Each commit consumes budget. When
   exhausted, next commit must be net positive or auto-revert.
2. **Horizon is a deadline.** At commit K, net regression count must be ≤ 0
   on targeted metric AND ≤ 1% on all others. Otherwise:
   ```
   git reset --hard campaign-<slug>-start
   ```
   No negotiation. Whole campaign reverts. Full post-mortem in `.opt/failed.md`.
3. **Budget/horizon cannot be edited mid-campaign.** Raising either requires
   aborting + starting a new campaign with a new hypothesis. Key anti-
   rationalization guard — moving goalposts requires visibly starting over.
4. **Campaigns are serial.** One active at a time. No nesting. Second-order
   issues go to `.opt/ideas.md`.

### Anti-rationalization guards

- **Pre-commit to the numbers.** `M - N ≥ threshold` written before you start.
  At horizon, diff is mechanical — numbers hit or not.
- **Track campaign success rate in `.opt/wins.md`.** Drops below ~60% → signal
  you're using campaigns to rationalize refactors. Stop for a month.

### When to actually reach for it

Real campaign cases in SSA/fold work:
- Removing a fold rule that masked a phi-insertion bug — regresses beneficiaries,
  unlocks correct handling of a bigger class.
- Changing VarDef representation to carry extra provenance — temporarily breaks
  naming heuristics until downstream consumers updated.
- Fixing dominance calculation — cascades through every pass using wrong frontier.

NOT campaign cases:
- "This would be cleaner as a visitor pattern" (refactor)
- "I want to try a different fold strategy" (spike in branch)
- "Bench noise is probably hiding a real win" (fix bench)

## Outer loop

Don't build until single-shot has landed 3+ real wins.
