# Design Spec: Double-Negation Condition Simplification

**Date:** 2026-04-16  
**Status:** Ready for implementation

---

## Problem Statement

Decompiler output for `main` (0x140001e41) in `cb_baristas_secret_x64.exe` contains:

```c
if (lVar1 == 0) == 0 {
```

This should be:

```c
if (lVar1 != 0) {
```

The same pattern appears as `!(x == 0)` and `!(x != 0)` in AArch64 output. Both are double-negation forms that fold.rs does not currently simplify.

---

## Root Cause

`mba_simplify_expr` (fold.rs line 885) already handles:
- `Neg(Neg(x))` → `x`  
- `Not(Not(x))` → `x`

But it has no rules for:
- `BinOp(Eq, comparison, Const(0))` — comparing a bool result to false
- `UnaryOp(BoolNot, comparison)` — explicit boolean negation of a comparison
- `UnaryOp(BoolNot, UnaryOp(BoolNot, x))` → `x`

The `classify_jcc_condition` function (line 2050) already does `BoolNot` unwrapping for Jcc recovery, but only in the branch-condition path. Non-branch uses of comparisons (ternary expressions, assignments) go through `mba_simplify_expr` and are not simplified.

---

## Design

### One helper function

```rust
/// Negate an equality/inequality comparison operator.
/// Returns None for Less/SLess/LessEq/SLessEq — those require operand swapping
/// and are handled separately.
fn negate_eq_op(op: BinOpKind) -> Option<BinOpKind> {
    match op {
        BinOpKind::Eq    => Some(BinOpKind::NotEq),
        BinOpKind::NotEq => Some(BinOpKind::Eq),
        _ => None,
    }
}
```

Place after `combine_frame_offset` (near line 125).

### Three rules in `mba_simplify_expr` (after the `Not(Not(x))` rule at line 1000)

**Rule 1 — `BoolNot(BoolNot(x))` → `x`:**
```rust
Expr::UnaryOp(UnaryOpKind::BoolNot, inner) => {
    // BoolNot(BoolNot(x)) → x
    if let Expr::UnaryOp(UnaryOpKind::BoolNot, inner2) = &vars[inner.0 as usize].expr {
        return Some(Expr::Var(*inner2));
    }
    // BoolNot(BinOp(Eq/NotEq, a, b)) → BinOp(NotEq/Eq, a, b)
    if let Expr::BinOp(cmp_op, a, b) = vars[inner.0 as usize].expr {
        if let Some(neg_op) = negate_eq_op(cmp_op) {
            return Some(Expr::BinOp(neg_op, a, b));
        }
    }
    None
}
```

**Rule 2 — `BinOp(Eq, comparison, Const(0))` → negate comparison:**
```rust
Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) => {
    // (cmp(a, b) == 0) → neg_cmp(a, b)
    // e.g. (x == y) == 0  →  x != y
    //      (x != y) == 0  →  x == y
    if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
        if let Expr::BinOp(cmp_op, a, b) = vars[inner_id.0 as usize].expr {
            if let Some(neg_op) = negate_eq_op(cmp_op) {
                return Some(Expr::BinOp(neg_op, a, b));
            }
        }
    }
    None
}
```

**Rule 3 — `BinOp(NotEq, comparison, Const(0))` → identity (keep comparison as-is):**
```rust
Expr::BinOp(BinOpKind::NotEq, inner_id, zero_id) => {
    // (cmp(a, b) != 0) → cmp(a, b)  [comparison is already the bool result]
    if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
        if let Expr::BinOp(_, _, _) = vars[inner_id.0 as usize].expr {
            return Some(Expr::Var(inner_id));
        }
    }
    None
}
```

### Where to insert

Inside `mba_simplify_expr`, immediately after the existing `UnaryOp(Not, ...)` arm at line 1000, before the `// CDQ+IDIV simplification` comment at line 1001.

---

## Scope Boundaries

- Only `Eq` and `NotEq` negation — `Less`/`SLess`/`LessEq`/`SLessEq` require operand swapping and are deferred.
- No changes to `classify_jcc_condition` — that already handles `BoolNot` correctly for Jcc.
- No changes to `printer.rs`, `ssa.rs`, `structure.rs`, or `ir.rs`.
- `mba_simplify` runs in a 4-pass loop, so multi-level chains collapse automatically across passes.

---

## Testing

**Unit test** (`rsleigh-decompile/tests/`): encode a minimal sequence that produces `(x == 0) == 0` in SSA, run `fold_with_cc`, assert no VarDef has the pattern `BinOp(Eq, BinOp(Eq|NotEq, _, _), Const(0))` after folding.

**Integration test**: decompile `main` (0x140001e41) from `cb_baristas_secret_x64.exe`, assert output does NOT contain `== 0) == 0` or `!= 0) == 0`.

**Regression**: full `cargo test -p test-harness` must pass — 9 tests, no new failures.

---

## Implementation Order

1. Add `negate_eq_op` helper to fold.rs.
2. Add Rule 1 (`BoolNot` arm) to `mba_simplify_expr`.
3. Add Rule 2 (`Eq(..., 0)` arm) to `mba_simplify_expr`.
4. Add Rule 3 (`NotEq(..., 0)` identity arm) to `mba_simplify_expr`.
5. Write unit test + integration test.
6. Run full test suite.
