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

Test surface (May 2026):

- `smt_verify` (5 tests) — opaque-pred verifier roundtrips,
  including the Themida `x*x - x*(x-1) - x == 0` identity, and the
  `LowerPolicy::Symbolic` vs `RejectUnsupported` boundary.
- `smt_explore` (16 lib + 6 SMT-gated) — spec-table sanity,
  call-name normalisation (PLT / `@@GLIBC_VER` / Mach-O `_`),
  collect_paths over linear fallthrough chains, lineage_eq through
  Var chains and Store→Load redirection, three v0 SAT round-trips
  through `solve()`.
- `smt_explore_integration` (3 CLI tests) — host-built C fixtures
  driven through the rsleigh binary, asserting `REACHABLE`.

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
- **M1 — taint-flow CVE finder (done)**: source/sink spec,
  linear-fallthrough path collector, SAT prover with concrete
  trigger-byte model extraction. New `--smt-explore <func>` CLI
  flag. 3-of-3 fixtures SAT end-to-end through CLI (recv→strcpy,
  read→system, fgets→printf).
- **M2 — first real CVE candidate (next)**: prove on a router-
  firmware binary that an attacker-controlled `recv()` byte reaches
  a network-handler `strcpy()`. Concrete trigger-input emitted.

After M2 lands, the branch merges to master with the feature still
default-OFF. Distros and library users not opting in pay no z3
linkage cost.

## `--smt-explore <func>` CLI usage

```sh
# Build with libz3 linked
cargo build -p rsleigh-cli --release --features smt

# Default text output: one line per Source -> Sink path
target/release/rsleigh ./vuln_binary --smt-explore handle_request
# // handle_request 0x401200 — 1 v0 path(s)
# //   [0] recv -> strcpy  (StackBuffer)  REACHABLE — trigger: ff ff ff ff …

# JSON output for scripted pipelines
target/release/rsleigh ./vuln_binary --smt-explore handle_request --json
```

JSON shape:

```json
{
  "function": "handle_request",
  "address":  "0x401200",
  "paths": [{
    "source":       "recv",
    "source_event": 23,
    "sink":         "strcpy",
    "sink_event":   42,
    "kind":         "StackBuffer",
    "verdict": {
      "kind":  "Reachable",
      "input": [
        { "offset": 0, "byte": "0xff" },
        { "offset": 1, "byte": "0xff" },
        ...
      ]
    }
  }]
}
```

Three terminal verdict kinds:

- `Reachable` — Z3 found a 32-byte symbolic input model that
  satisfies the per-`SinkKind` violation constraint. Bytes are
  shell-redirectable as a PoC against the live binary.
- `NotReachable` — taint lineage check failed (sink's watched arg
  doesn't trace back to source's tainted slot).
- `Unsupported` — out-of-v0-scope construct hit. Reason string
  exposed so the gap is auditable.

Path-rejection reasons (printed when `collect_paths` declines the
function):

- `UnsupportedTerminator(<kind>)` — CBranch / Indirect / Branch
  before any sink fired / loop back-edge.
- `PhiInPath` — Phi in entry chain.
- `IndirectCall` — indirect call before reaching a Sink.
- `NoSinkFound` — function never calls a configured Sink.

## v0 SAT prover internals

For each `(SourceSpec, SinkSpec)` path pair returned by
`collect_paths`, the prover:

1. Resolves `path.source.tainted` and `path.sink.watched` against
   the path's `Stmt::Call` / `SsaTerminator::Call` arg vectors.
2. Checks lineage: does the sink's watched VarId trace back to the
   source's tainted VarId? Two redirections supported in v0:
   - `Expr::Var(inner)` SSA-version chain;
   - one-step Store→Load through a `MemMap: HashMap<Varnode, VarId>`
     built from the path's events. The lifter routinely splits a
     buffer pointer into many SSA versions across stack save/reload;
     the memory map keeps the trace alive.
3. Builds a 32-byte fresh symbolic input array.
4. Asserts the per-`SinkKind` violation constraint:
   - `Command`     — at least one byte ∈ `{ ';', '&', '|' }`
   - `FormatArg`   — at least one byte == `'%'`
   - `StackBuffer` — every byte ≠ `'\0'` (no early NUL halts strcpy)
   - `LengthArg`   — Unsupported in v0 (size-vs-buffer modelling
                      needs the flat memory model planned for v1)
5. Calls `solver.check()`. SAT → extract the model and return
   `Reachable { input_bytes }`. UNSAT → `NotReachable`. Solver
   `Unknown` → `Unsupported("solver Unknown / timeout")`.

## Limitations (locked in M1)

- Linear fallthrough path only — no CBranch, no Phi, no loop
  back-edges. v0 walks `Call.fallthrough` and `Fallthrough(next)`
  terminators and rejects everything else with the rejection
  reason logged so the analyst sees the gap.
- 32-byte fresh symbolic input. No flat memory model in the SSA
  cone; lineage tracking handles the canonical Store/Load round-
  trip but not pointer arithmetic, alias reasoning, or struct
  field-access reads.
- Lineage walks `Expr::Var` and one-step Store→Load only. BinOp,
  Phi, FieldAccess do not propagate taint in v0.
- LengthArg sinks (memcpy/memmove/strncpy/strncat) return
  `Unsupported`. Length-vs-buffer modelling needs v1.
- No inter-procedural summaries. Sinks reached through another
  function call are out of scope for v0.
- No symbolic input → fuzzer-corpus generation. SAT model only.

These are deferred to v1/v2 explicitly. Expanding scope mid-
campaign is an abort signal per `.opt/campaigns/smt-backend.md`.

## Fixture results

`test-harness/fixtures/smt/{src,bin}/` carries three host-built
C fixtures. Run `test-harness/fixtures/smt/build.sh` once on the
host to populate `bin/`; CLI integration tests skip cleanly when
the directory is missing.

| Fixture          | Source → Sink     | SinkKind   | v0 verdict | Trigger preview     |
|------------------|-------------------|-----------|------------|----------------------|
| recv_strcpy      | recv → strcpy     | StackBuffer | Reachable  | `ff ff ff ff …` (no NUL → strcpy overruns 16-byte stack dst) |
| read_system      | read → system     | Command    | Reachable  | `7c 7c 7c 7c …` (`|` shell metachar) |
| fgets_printf     | fgets → printf    | FormatArg  | Reachable  | `25 25 25 25 …` (`%` format primitive) |

Test runner: `rsleigh-cli/tests/smt_explore_integration.rs`.
Default-build run skips with `[skip-no-smt]` (solve returns
`Unsupported` without the feature). `--features smt` run executes
the full Z3 pipeline and asserts `REACHABLE` in stdout.

## CVE-hunt workflow

End-to-end on an unknown binary:

```sh
# 1. Triage — is this hostile or just dirty?
rsleigh ./fw_blob --ioc                    # capabilities + family
rsleigh ./fw_blob --vulnscan               # pattern-class sinks
rsleigh ./fw_blob --callgraph > graph.json # who calls who

# 2. Surface the network attack-surface entry points
rsleigh ./fw_blob --search --api recv
rsleigh ./fw_blob --search --api read
rsleigh ./fw_blob --search --api accept

# 3. Pivot — for each network entry, follow taint to known sinks
for fn in $(jq -r '.callgraph | keys[]' graph.json | grep -E 'handle_|process_'); do
  rsleigh ./fw_blob --smt-explore "$fn" --json --features smt
done | jq -s '.[] | select(.paths[]?.verdict.kind == "Reachable")'

# 4. Extract trigger bytes from any Reachable hit, build PoC
```

Returns: a JSON-grep-able list of (function, source, sink, byte
model). Each Reachable entry is a CVE candidate awaiting live PoC.

False-positive surface: lineage-eq follows Var-chain + one-step
Store/Load only. A real flow obscured by indirect addressing,
phi-merged buffer pointers, or callee-summary indirection looks
`NotReachable`. Treat UNSAT as "v0 didn't prove it", not "no bug".

## Why a feature flag (not always-on)

- libz3 is ~20MB linked. Default rsleigh stays lean.
- z3 build pulls in clang+bindgen at first compile. Slower CI for
  consumers that don't care.
- Distros (rsleigh on crates.io) don't always have libz3-dev
  available — leaving smt off keeps the default install tier
  identical to prior versions.

When stable: keep the flag, but document `--features smt` as the
"recommended for vuln research" build.
