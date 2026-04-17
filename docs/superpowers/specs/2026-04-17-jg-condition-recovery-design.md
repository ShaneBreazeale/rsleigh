# Design Spec: JG Condition Recovery After mba_simplify

**Date:** 2026-04-17
**Status:** Ready for implementation

---

## Problem Statement

Decompiler output for `cb_baristas_secret_x64.exe` contains:

```c
if (local_c != 1 && OF == SF) {         // should be: if (local_c > 1)
if (lVar2->field_10 != 0 && OF == SF) { // should be: if (lVar2->field_10 > something)
```

Two instances in function `0x14000195e`. Flag registers `OF` and `SF` leak into printed output instead of being recovered as a signed `>` comparison.

---

## Root Cause

The x86 JG (jump if greater, signed) condition is emitted by SLEIGH as:

```
tmp1 = BoolNot(ZF)          // !ZF
tmp2 = Eq(OF, SF)           // OF == SF
cond = BoolAnd(tmp1, tmp2)  // JG: !ZF && (OF == SF)
CBranch(target, cond)
```

`classify_jcc_condition` (fold.rs ~line 2272) handles this via:

```rust
let left_is_not_zf = matches!(&left_def.expr,
    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));
if left_is_not_zf && right_is_sf_eq_of {
    Some((BinOpKind::SLess, true)) // JG: b < a
}
```

**The bug**: `mba_simplify` runs *before* `recover_conditions` in each fold round and transforms `BoolNot(ZF)` through the chain:

1. `BoolNot(ZF)` → `NotEq(Sub(a,b), Const(0))` via `negate_eq_op(Eq) → NotEq`
2. `NotEq(Sub(a,b), 0)` → `NotEq(a, b)` via the sub-as-cmp rule

By the time `classify_jcc_condition` sees the BoolAnd, the left operand is `NotEq(a, b)` — the `left_is_not_zf` check fails and `OF == SF` leaks into output.

---

## Design

### Fix location

`try_recover_condition` in `rsleigh-decompile/src/fold.rs`, as a special-case path added **after** the main `classify_jcc_condition` + `find_cmp_operands` path.

### Why `try_recover_condition`, not `classify_jcc_condition`

`classify_jcc_condition` only has the condition expression — it cannot validate that a `NotEq(x, y)` came from the same CMP as the `Eq(OF, SF)`. That validation requires the CMP operands from `find_cmp_operands`, which are only available in `try_recover_condition`. Doing the validation at this level prevents false matches.

### Change

After the existing `classify_jcc_condition` + `find_cmp_operands` block in `try_recover_condition`, add a special case for `BoolAnd` conditions where the main path returned `None`:

```
// Special case: post-mba_simplify JG pattern
// BoolAnd(NotEq(a,b), Eq(OF,SF)) or BoolAnd(Eq(OF,SF), NotEq(a,b))
// Validates that the NotEq operands match the CMP operands from the OF/SF chain.
```

**Algorithm:**

1. Check if `cond_id.expr` is `BoolAnd(left, right)`
2. Normalize: identify which side is the `Eq(OF/OV, SF/NG)` operand and which is the `NotEq`/`BoolNot(ZF)` operand — **check both orderings**
3. For the `Eq(OF/OV, SF/NG)` side: call `find_cmp_operands(block_idx, ssa).or_else(|| trace_cond_to_cmp(of_sf_side, ssa, 8))` to recover `(cmp_a, cmp_b)`
4. If CMP operands found: **validate** that the `NotEq(x, y)` operands resolve to `{cmp_a, cmp_b}` (order-independent, using `resolve_cmp_operand` for each)
5. If validation passes: create `BinOp(SLess, cmp_b, cmp_a)` = `cmp_b < cmp_a` = `cmp_a > cmp_b` (JG)
6. If validation fails: return `None` (do not recover — avoids false matches)

The `Eq(OF/OV, SF/NG)` check uses the same `is_of`/`is_sf` helpers already used in `classify_jcc_condition`. The `NotEq` side is accepted only when both operands are non-flag-derived.

**Both orderings:**
```rust
// Order 1: BoolAnd(NotEq(a,b), Eq(OF,SF))
// Order 2: BoolAnd(Eq(OF,SF), NotEq(a,b))   ← also handled
```

**Operand match validation** (prevents over-matching unrelated `NotEq`):
```rust
let (ra, rb) = (resolve_cmp_operand(neq_l, ssa), resolve_cmp_operand(neq_r, ssa));
let (ca, cb) = (resolve_cmp_operand(cmp_a, ssa), resolve_cmp_operand(cmp_b, ssa));
let operands_match = (ra == ca && rb == cb) || (ra == cb && rb == ca);
if !operands_match { return None; }
```

`resolve_cmp_operand` already exists in fold.rs and strips unique-space Var wrappers.

---

## Scope Boundaries

- `fold.rs` only — no changes to `printer.rs`, `ssa.rs`, `structure.rs`, `ir.rs`
- Only fires when both orderings of `BoolAnd(NotEq, Eq(OF,SF))` are present — no other Jcc patterns touched
- Does not modify `classify_jcc_condition`, `find_cmp_operands`, `is_flag_ref`, or `is_flag_derived`

---

## Testing

**Test file:** `rsleigh-decompile/tests/jg_condition_recovery.rs`

### Test 1: `jg_recovered_as_signed_greater` (unit — primary)

Encode `cmp rax, rcx; jg +3; xor rax, rax; ret`:
- `48 39 C8` (CMP rax, rcx) + `7F 03` (JG +3) + `48 31 C0` (XOR rax, rax) + `C3` (RET)
- After fold, find the single CBranch condition
- Assert it is `BinOp(SLess, rcx_var, rax_var)` — exact opcode AND exact operand order
- Assert neither operand has a varnode in `FLAG_OFFSETS` (no flag leak)
- To find `rax_var`/`rcx_var`: look for vars at register offsets 0 (RAX) and 8 (RCX)

### Test 2: `jg_commuted_boolAnd` (unit — commutation)

Same bytes but verify that if the SSA builder happens to produce `BoolAnd(Eq(OF,SF), NotEq(a,b))` (right-left order), the result is identical. Since the encoder produces a fixed ordering, construct the SSA variant directly in the test by swapping the BoolAnd operands and re-running fold, OR simply confirm the existing test implicitly exercises the SSA output order.

*Implementation note: if the SSA always produces left=BoolNot(ZF), right=Eq(OF,SF), a simpler alternative is to confirm with a second function or just document that both orderings are accepted by code inspection. Do not add dead test infrastructure.*

### Test 3: `jg_no_false_positive` (unit — negative)

Construct a CBranch condition that is `BoolAnd(NotEq(a, b), Eq(OF, SF))` where `{a, b}` does NOT match the CMP operands in the block (e.g., use different variables). After fold, assert the condition is **not** recovered to `SLess` — the BoolAnd should remain unmodified. This proves the operand-match validation is working.

Implementation: modify the raw SSA directly in the test to set a BoolAnd with mismatched operands before calling `fold_with_cc`.

### Test 4: `jg_integration_positive` (integration)

Decompile `0x14000195e` from `cb_baristas_secret_x64.exe`:
- Assert output does NOT contain `"OF == SF"` or `"SF == OF"`
- Assert output DOES contain `" > "` in a condition line (positive assertion that a signed comparison was emitted)
- Skip gracefully if binary not found

**Regression**: full `cargo test -p test-harness` must pass — 9 tests, no new failures.

---

## Implementation Order

1. Add the special-case path in `try_recover_condition` (both orderings + operand validation).
2. Write Test 1 as a failing test. Confirm it fails (non-vacuous). Fix, confirm passing.
3. Write Test 3 (negative). Confirm it passes immediately (over-match is prevented).
4. Write Test 4 (integration). Confirm it passes.
5. Run full regression suite.
