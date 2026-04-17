# Design Spec: JG Condition Recovery After mba_simplify

**Date:** 2026-04-17
**Status:** Ready for implementation

---

## Problem Statement

Decompiler output for `cb_baristas_secret_x64.exe` contains:

```c
if (local_c != 1 && OF == SF) {        // should be: if (local_c > 1)
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
```

`classify_jcc_condition` in `fold.rs` (line 2272) handles this via:

```rust
let left_is_not_zf = matches!(&left_def.expr,
    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));
if left_is_not_zf && right_is_sf_eq_of {
    Some((BinOpKind::SLess, true)) // JG: b < a
}
```

**The bug**: `mba_simplify` runs *before* `recover_conditions` in each fold round. It transforms `BoolNot(ZF)` through the chain:

1. `BoolNot(ZF)` → `NotEq(Sub(a,b), Const(0))` (via `negate_eq_op(Eq) → NotEq`)
2. `NotEq(Sub(a,b), 0)` → `NotEq(a, b)` (via the sub-as-cmp rule)

By the time `classify_jcc_condition` sees the BoolAnd, the left operand is `NotEq(a, b)`, not `BoolNot(ZF)`. The `left_is_not_zf` check fails, recovery returns `None`, and `OF == SF` leaks into the output.

---

## Design

### Fix location

`classify_jcc_condition` in `rsleigh-decompile/src/fold.rs`, the `BoolAnd` arm (approximately line 2272).

### Change

Extend `left_is_not_zf` to also accept `NotEq(non_flag_a, non_flag_b)` — because after mba_simplify, `BoolNot(ZF)` becomes `NotEq(a, b)`, which is semantically identical:

```rust
// BoolAnd(BoolNot(ZF/ZR), IntEq(OF/OV, SF/NG)) → JG/BGT → a > b = b < a
// Also handles post-mba_simplify form: BoolAnd(NotEq(a, b), Eq(OF/OV, SF/NG))
Expr::BinOp(BinOpKind::BoolAnd, left, right) => {
    let left_def = &ssa.vars[left.0 as usize];
    let right_def = &ssa.vars[right.0 as usize];

    let left_is_not_zf = matches!(&left_def.expr,
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));
    // Post-simplification: BoolNot(ZF) → NotEq(a, b) after mba_simplify
    let left_is_not_eq = matches!(&left_def.expr,
        Expr::BinOp(BinOpKind::NotEq, l, r)
        if !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa));
    let right_is_sf_eq_of = matches!(&right_def.expr,
        Expr::BinOp(BinOpKind::Eq, a, b)
            if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b)));

    if (left_is_not_zf || left_is_not_eq) && right_is_sf_eq_of {
        Some((BinOpKind::SLess, true)) // JG/BGT: a > b = b < a
    } else {
        // existing JA and fallback cases unchanged
        let left_is_not_cf = matches!(&left_def.expr,
            Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_cf(*inner));
        let right_is_not_zf = matches!(&right_def.expr,
            Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));

        if left_is_not_cf && right_is_not_zf {
            Some((BinOpKind::Less, true)) // JA/BHI: unsigned b < a
        } else if left_is_not_zf {
            Some((BinOpKind::NotEq, false))
        } else {
            None
        }
    }
}
```

No other changes are needed. `find_cmp_operands` already locates the CMP operands from the SF assignment (`SLess(result, 0)`) in the same block. `try_recover_condition` assembles the final `SLess(b, a)` = `a > b` result.

### Why `find_cmp_operands` works here

Block 9/17 contain the `CMP a, b` instruction. Its P-code writes:
- `SF = SLess(Sub(a, b), 0)` at register offset 519
- `OF = SBorrow(a, b)` at register offset 523

Both have `use_count > 0` (referenced by `Eq(OF, SF)`), so `eliminate_dead` leaves them. `find_cmp_in_block` scans backwards, finds SF at offset 519, verifies the second arg is `Const(0)`, and traces `Sub(a, b)` back to `(a, b)`.

---

## Scope Boundaries

- `fold.rs` only — no changes to `printer.rs`, `ssa.rs`, `structure.rs`, `ir.rs`
- x86 JG (signed greater-than) only — the mirrored case (Eq(OF,SF) on left) is not observed and not added (YAGNI)
- No changes to `find_cmp_operands`, `try_recover_condition`, `is_flag_ref`, or `is_flag_derived`

---

## Testing

**Unit test** (`rsleigh-decompile/tests/jg_condition_recovery.rs`):

Encode `cmp rax, rcx; jg +3; xor rax, rax; ret`:
- x86-64 bytes: `48 39 C8` (CMP rax, rcx) + `7F 03` (JG +3) + `48 31 C0` (XOR rax, rax) + `C3` (RET)
- After fold, assert the CBranch condition is `BinOp(SLess, _, _)` — no `BoolAnd`, no flag register VarIds

**Integration test**:

Decompile `0x14000195e` from `cb_baristas_secret_x64.exe`, assert output does not contain `"OF == SF"` or `"SF == OF"`.

**Regression**: full `cargo test -p test-harness` must pass — 9 tests, no new failures.

---

## Implementation Order

1. Extend the BoolAnd arm in `classify_jcc_condition`.
2. Write unit test (failing before fix, passing after).
3. Write integration test.
4. Run full regression suite.
