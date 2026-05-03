# SMT backend (`--features smt`)

Branch: `feat/smt-backend`. Off by default. Pulls the `z3` crate
which links libz3 (C++).

## Why

rsleigh's `--vulnscan` is pattern-class — it spots dangerous sinks
but cannot prove an attacker-controlled value can reach them. The
SMT backend lifts the SSA cone of a candidate sink into Z3
bitvector terms and asks the solver: "is there an input byte stream
that lands an attacker-controlled value at this sink slot?"

If `SAT`: extract a model and emit it as a concrete trigger-input
(byte offset → value). That's a CVE-class proof of reachability.
If `UNSAT`: the sink is unreachable from the configured source
under the path examined — a real false-positive cull.

The existing `rsleigh-decompile/src/opaque_pred.rs` already
classifies branches with sampling-based reasoning. The SMT
backend is the natural graduation: replace probabilistic sampling
with a real solver.

## Build

System libz3 required.

### macOS (Homebrew)

```sh
brew install z3
BINDGEN_EXTRA_CLANG_ARGS="-I$(brew --prefix z3)/include" \
RUSTFLAGS="-L $(brew --prefix z3)/lib" \
  cargo build -p rsleigh-decompile --release --features smt
```

### Linux (apt)

```sh
sudo apt install libz3-dev
cargo build -p rsleigh-decompile --release --features smt
```

System include + lib paths are picked up by default; no env
overrides needed.

### Tests

```sh
# macOS:
BINDGEN_EXTRA_CLANG_ARGS="-I$(brew --prefix z3)/include" \
RUSTFLAGS="-L $(brew --prefix z3)/lib" \
  cargo test -p rsleigh-decompile --release --features smt --lib smt_verify

# Linux:
cargo test -p rsleigh-decompile --release --features smt --lib smt_verify
```

Five tests live today:
- `z3_proves_themida_identity` — `x*x - x*(x-1) - x == 0`
  SAT-verified as a tautology.
- `z3_rejects_real_branch` — actual branch condition correctly
  classified as `Satisfiable`.
- `strict_policy_rejects_unknown` — `Expr::Unknown` under
  `LowerPolicy::RejectUnsupported` returns `None`, never silently
  becomes a free BV.
- `symbolic_policy_passes_unknown` — same `Expr::Unknown` under
  `LowerPolicy::Symbolic` lowers to a fresh BV (the legacy
  ∀-quantified semantic the verifier needs).
- `strict_policy_rejects_load` — pins the M0 boundary: `Expr::Load`
  is unsupported today, must surface as `None` under strict policy.

All green at the time of writing.

## Public API

```rust
pub use rsleigh_decompile::smt_verify::{
    verify_branch, lower, LowerPolicy, SmtVerdict,
};
```

`verify_branch(cond: VarId, vars: &[VarDef]) -> SmtVerdict` — lifts
the cone of definitions reachable from `cond` into Z3 bitvectors,
asks `forall vars . cond != 0`, returns:

```rust
pub enum SmtVerdict {
    Tautology,        // ∀ vars . cond != 0 — branch always taken
    Contradiction,    // ∀ vars . cond == 0 — branch never taken
    Satisfiable,      // both directions reachable, or solver Unknown
                      //   under timeout
    Unsupported,      // lowering hit an Expr variant it cannot translate
    Unknown,          // reserved for future use
}
```

`Tautology` and `Contradiction` are SMT-proven and safe to fold.

`lower(ctx, v, vars, env, policy) -> Option<BV>` — public lowering
entry point reused by `smt_explore` (M1). The `policy` parameter
selects between two semantics for `Expr` variants the translator
does not directly handle:

- **`Symbolic`** — uncovered variant becomes a fresh BV. Sound for
  the verifier's `∀ vars . cond` query, where the unknown variable
  is exactly the universally-quantified attacker input.
- **`RejectUnsupported`** — uncovered variant fails the lift
  (`None`). Required for SAT-as-CVE-proof so the SAT model is
  never satisfied by a free variable nobody constrained.

### Currently lowered Expr variants

The translator handles:

- `Const`, `Var`
- `BinOp`: Add, Sub, Mult, And, Or, Xor, Lsl, Lsr, Asr, Div, SDiv,
  Rem, SRem, Eq, NotEq, Less, LessEq, SLess, SLessEq
- `UnaryOp`: Neg, Not, BoolNot, Zext, Sext, Trunc

Everything else (`Phi`, `Load`, `Store`, `FieldAccess`, `Ternary`,
`UserOp`, `ExprNew`, `ExprCPool`, `Unknown`, etc.) is **unsupported
in M0**. Under `Symbolic` the variant falls through to a fresh BV;
under `RejectUnsupported` it returns `None`.

M1 (taint-flow) will add `Load`/`Store`/`FieldAccess` lowering
against a flat byte-array memory model.

## Roadmap (campaign: `feat/smt-backend`)

Spec lives in `.opt/campaigns/smt-backend.md` (local, not VCS-tracked).
Step-by-step implementation plan in
`.opt/campaigns/smt-backend-implementation-plan.md`.

- **M0 — scaffold (done)**: feature flag, z3 dep, Expr lowering for
  Const/Var/BinOp/UnaryOp. Branch-condition verifier wired.
  `LowerPolicy` parameter splits ∀-quantified verifier from strict
  CVE-proof lowering.
- **M1 — taint-flow CVE finder (in progress)**: source/sink spec,
  straight-line path collector, SAT+model emit on
  attacker-controlled flow to dangerous sinks (strcpy/sprintf/
  memcpy/system/popen/execve). New `--smt-explore <func>` CLI flag.
- **M2 — first real CVE candidate**: prove on a router-firmware
  binary that an attacker-controlled `recv()` byte reaches a
  network-handler `strcpy()`. Concrete trigger-input emitted.

After M2 lands, the branch merges to master with the feature still
default-OFF. Distros and library users not opting in pay no z3
linkage cost.

## Limitations (locked in M1)

- Straight-line paths only — no CBranch, no Phi, single basic
  block from entry to first sink call.
- Flat 64KB byte-array memory model. No region split, no alias
  reasoning. Marked unsound for v0; documented per call.
- No loops. v0 will reject any path containing back-edges with
  `Unsupported`.
- No inter-procedural callee summaries. Sinks reached through
  another function call are out of scope for v0.
- No symbolic input → fuzzer-corpus generation. SAT model only.

These are deferred to v1/v2 explicitly. Expanding scope mid-
campaign is an abort signal per `.opt/campaigns/smt-backend.md`.

## Why a feature flag (not always-on)

- libz3 is ~20MB linked. Default rsleigh stays lean.
- z3 build pulls in clang+bindgen at first compile. Slower CI for
  consumers that don't care.
- Distros (rsleigh on crates.io) don't always have libz3-dev
  available — leaving smt off keeps the default install tier
  identical to prior versions.

When stable: keep the flag, but document `--features smt` as the
"recommended for vuln research" build.
