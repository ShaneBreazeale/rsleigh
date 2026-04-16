# SSA Call-Clobber Model + Printer Param-Name Chase Tightening

**Date:** 2026-04-16
**Audit:** `docs/audits/2026-04-16-x86-64-pseudocode-audit.md`
**Probe:** `test-harness/examples/probe_check2_ssa.rs`
**Status:** Design — approved for plan

---

## Problem

On x86-64, after any `Call` terminator or `Stmt::Call`, caller-saved registers
carry stale pre-call values through the SSA `current` map. The SSA builder emits
no clobber, so subsequent reads of RAX/RCX/RDX/etc. resolve to whatever VarId
they pointed to immediately before the call.

Probe confirmation on `cb_baristas_secret_x64.exe::main` (0x140001e41):

- `strcspn(input, "\n\r")` is called from block 4. Block 5 reads RAX to compute
  `input[strcspn_ret] = 0`. With no clobber, RAX in block 5 still resolves to
  the pre-call LEA that set up RCX (`input_ptr`). Output becomes
  `*(RBP - 96 + lVar1) = 0` with garbled base.
- `printf("...%s...", input + 5)`: fold correctly passes 2 args (v130, v127) at
  the Call terminator. But a later stale-register read is being used as the
  base for `puts(...) + 5` on a fail-path merge, corrupting downstream Phi
  inputs.
- `fold::propagate_call_returns` searches the fallthrough block for an
  `Expr::Unknown` RAX assignment to mark as the return value. That assignment
  never exists, because no P-code op clobbers RAX on call.

A secondary printer bug in `check2` renders byte[0]'s pointer as `*(C)` (the
parameter name) when the underlying register has an `Expr::Var` chain.
`printer.rs:8651–8662` applies `param_name` propagation through any Var or Phi
input regardless of whether the terminal varnode is an argument register.

---

## Design

### Fix 1 — SSA call-clobber (primary)

**Where:** `rsleigh-decompile/src/ssa.rs`

**When:** during `convert_terminator` for `Terminator::Call`, and during
`process_op` for any pcode Call that appears mid-block.

**What:** before returning the terminator (or after recording the Call stmt),
for each caller-saved register in the current architecture's ABI:

1. Create a fresh `VarDef { varnode, expr: Expr::Unknown, .. }` via
   `ssa.new_var()`.
2. Insert a `Stmt::Assign(new_var_id)` into the current block's stmts so the
   clobber is visible to fold passes.
3. Update `current[varnode] = new_var_id` so the fallthrough block inherits
   the clean value.
4. For RAX (or the arch's return register), set `call_return: true` on the new
   VarDef. This replaces the scan inside `propagate_call_returns` — that pass
   can be simplified or kept as a belt-and-braces check.

**ABI tables (caller-saved, to clobber):**

| Arch | Integer | Float/SIMD |
|---|---|---|
| x86-64 Win64 | RAX, RCX, RDX, R8, R9, R10, R11 | XMM0–XMM5 |
| x86-64 SysV  | RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11 | XMM0–XMM15 |
| AArch64 | x0–x18 | v0–v7, v16–v31 |
| ARM32 EABI | r0–r3, r12, lr | s0–s15, d0–d7 |
| MIPS32 O32 | v0, v1, a0–a3, t0–t9 | f0–f19 |
| RISC-V LP64 | ra, a0–a7, t0–t6 | fa0–fa7, ft0–ft11 |

ABI selection mirrors `fold::CallingConv` + architecture detection from the
binary format. Concretely: add `ssa::build_ssa_with_cc(cfg, cc)` that takes the
same `CallingConv` enum, with `build_ssa(cfg)` preserved as a default (SysV x86-64).
The decompile pipeline (`lib.rs::decompile_with_binary`) already knows the CC.

**The clobber list is conservative about what's NOT clobbered:**
RSP, RBP, R12–R15 (Win64/SysV callee-saved); x19–x28, sp, fp, lr (AArch64);
s0–s11, sp, ra, fp, gp (RISC-V). These keep their current VarId.

**Edge cases:**

- **Tail calls** (Call terminator whose successor is a return): clobber anyway;
  dead-code elimination removes unreachable reads.
- **Calls in entry block** where params are being set up: clobber must run
  AFTER arg register reads are resolved, so sequence is:
  resolve args → emit clobbers → record Call. This is the natural order in
  `convert_terminator`.
- **Indirect calls** (`CallTarget::Indirect`): treat same as Direct. Clobber
  applies regardless of target.
- **Intrinsics / non-clobbering calls**: not distinguished. The SysV list is
  the widest safe default.

### Fix 2 — Printer param-name chase tightening (secondary, contingent)

**Where:** `rsleigh-decompile/src/printer.rs:8651–8662`

**When:** only applied if Fix 1 does not eliminate the `*(C)` symptom in check2.

**What:** restrict the `Var`/`Phi` param_name chase so it fires only when the
chain ultimately terminates at an `Expr::Unknown` whose varnode IS in the
calling convention's argument register set. If the terminal expr is
`BinOp`/`Load`/`Const`, do not substitute — fall through to normal rendering.

Implementation: a helper `resolves_to_param(vid, ssa, cc) -> Option<String>` that
walks `Expr::Var` and `Expr::Phi` chains (bounded to depth 8 to prevent cycles),
returns `Some(name)` only when the terminal is `Expr::Unknown` on a register
that lives in `cc.arg_regs()` and has a `param_name` set.

### Fix 3 — Regression fixture (support)

Promote `test-harness/examples/probe_check2_ssa.rs` to
`test-harness/tests/call_clobber_regression.rs`. Two test cases:

1. **check2 byte loop**: decompile 0x140001a68, assert that
   `*(C)` does not appear in output AND `*(k` or `*(RSP` does.
2. **main strcspn**: decompile 0x140001e41, assert that
   `input[` appears (with a real return-value index) AND `RBP - 96 + lVar1`
   does not.

Both tests load the audit binary via goblin. If the binary isn't present,
tests skip with a warning (don't fail CI for machines without the fixture).

---

## Non-goals

- Windows x64 shadow-store modeling — memory SSA already handles RBP-relative
  stores correctly; the audit's recommendation was wrong about the root cause.
- Callee-saved register restoration tracking (save/restore elision) — already
  handled elsewhere in the printer.
- Indirect call target resolution — orthogonal.
- ObjC/Swift/C++ printer cleanup — out of scope for this spec.

---

## Testing

1. `cargo run -p test-harness --example probe_check2_ssa` — both check2 and
   main probes should show `Expr::Unknown` clobbers after each Call.
2. `cargo run --release -p rsleigh-cli -- ~/Downloads/test_bin/cb_baristas_secret_x64.exe 0x140001a68 0x140001e41` —
   compare against `docs/audits/2026-04-16-x86-64-pseudocode-audit.md`.
   Expected improvements listed there should appear.
3. `cargo test -p test-harness` — full suite must pass (240 tests, 7200+ asserts).
4. Smoke-test on `ChocolateFactory.exe` and `rust-crackme-easy.exe` for any
   cross-architecture regressions.
5. Manual re-audit: re-run Ghidra comparison, confirm the three main-function
   defects are resolved.

---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Clobber stmts blow up IR size | Fold's existing DCE removes Unknown assigns with use_count=0. Verify via line-count check on main before/after. |
| Over-clobbering breaks AArch64/MIPS where P-code carries values through calls | ABI-specific tables per `CallingConv`; MIPS delay-slot handling is not altered. |
| Printer fix regresses legitimate param forwarding | Tightened check terminates chain at Unknown/arg-reg only — passes existing cases by construction. |
| RAX double-marked `call_return` by both SSA clobber and fold pass | Fold pass becomes redundant; either remove it or make it idempotent (check `!call_return` before setting). |

---

## Implementation order

1. Add `CallingConv` → caller-saved register table mapping in `ssa.rs`.
2. Implement clobber emission in `convert_terminator::Call` and `process_op` Call paths.
3. Wire `build_ssa_with_cc` through `lib.rs::decompile_with_binary`.
4. Run `probe_check2_ssa` to confirm clobbers appear.
5. Run CLI on check2 + main; evaluate whether `*(C)` persists.
6. If yes, apply Fix 2 (printer tightening).
7. Add regression tests.
8. Run full test suite; fix any regressions.
9. Re-audit against Ghidra output.
