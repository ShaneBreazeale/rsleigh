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

Two tests live today:
- `z3_proves_themida_identity` — `x*x - x*(x-1) - x == 0` SAT-verified.
- `z3_rejects_real_branch` — actual branch condition rejected as
  not provably constant.

Both green at the time of writing.

## Public API

```rust
pub use rsleigh_decompile::smt_verify::{verify_branch, SmtVerdict};
```

`verify_branch(cond: VarId, vars: &[VarDef]) -> SmtVerdict` — lifts
the cone of definitions reachable from `cond` into Z3 bitvectors,
asks `forall vars . cond`, returns:

```rust
pub enum SmtVerdict {
    AlwaysTrue,
    AlwaysFalse,
    NotConstant,
    Unsupported,
}
```

`AlwaysTrue` and `AlwaysFalse` are SMT-proven and safe to fold.
`NotConstant` is "the solver found a counterexample". `Unsupported`
is "the cone contains an Expr variant the lowering cannot handle"
(currently UserOp, ExprNew, Phi, ExprCPool).

## Roadmap (campaign: `feat/smt-backend`)

Spec lives in `.opt/campaigns/smt-backend.md` (local, not VCS-tracked).

- **M0 — scaffold (done)**: feature flag, z3 dep, Expr lowering for
  Const/Var/BinOp/UnaryOp/Load/Store/FieldAccess. Branch-condition
  verifier wired.
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
