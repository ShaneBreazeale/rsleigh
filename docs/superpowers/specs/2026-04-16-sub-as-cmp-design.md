# Design Spec: Subtraction-as-Comparison Simplification

**Date:** 2026-04-16
**Status:** Ready for implementation

---

## Problem Statement

Decompiler output contains patterns like:

```c
if (iVar1 - 1) {          // should be: if (iVar1 != 1)
if (!(iVar1 - 1)) {       // should be: if (iVar1 == 1)
if (!(param_1 - 1)) {     // should be: if (param_1 == 1)
if (lVar1 - 1) {          // should be: if (lVar1 != 1)
```

These appear in `cb_baristas_secret_x64.exe` across multiple functions (8+ instances). The `Sub(a, b)` expression is used directly as a boolean condition, but should be normalized to `NotEq(a, b)` (or `Eq(a, b)` when negated), since `a - b != 0` ≡ `a != b`.

---

## Root Cause

`recover_conditions` (fold.rs line 1610) only processes CBranch conditions that are flag-derived (`is_flag_derived` returns true). A bare `Sub(a, b)` in a CBranch is not flag-derived — it comes through as raw arithmetic — so it is skipped entirely. The printer then formats it literally as `a - b`.

Three surface forms all require different fixes:

| Pattern | IR form | Root | Fix location |
|---|---|---|---|
| `if (x - 1)` | `CBranch(Sub(x,1))` | Not flag-derived | `recover_conditions` |
| `if (!(x - 1))` | `CBranch(BoolNot(Sub(x,1)))` | BoolNot rule misses Sub | `mba_simplify_expr` BoolNot arm |
| `if ((x-1) == 0)` | `CBranch(Eq(Sub(x,1), 0))` | Eq rule misses Sub | `mba_simplify_expr` Eq arm |
| `if ((x-1) != 0)` | `CBranch(NotEq(Sub(x,1), 0))` | NotEq returns Var(Sub) | `mba_simplify_expr` NotEq arm |

---

## Design

### Part 1: `recover_conditions` — bare Sub in CBranch

After the existing flag-recovery loop (line 1636), add a second pass that handles non-flag-derived bare Sub conditions:

```rust
// Pass: Sub(a, b) used bare as a CBranch condition → NotEq(a, b)
// This handles patterns like `if (x - 1)` → `if (x != 1)`.
// Only fires when the condition is not flag-derived (those are handled above)
// and not already a comparison.
let mut sub_to_cmp: Vec<(usize, VarId, VarId, VarId)> = Vec::new(); // (bi, cond_id, a, b)
for (bi, block) in ssa.blocks.iter().enumerate() {
    if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
        if is_flag_derived(*cond, ssa) { continue; }
        // Follow Var chains
        let mut resolved = *cond;
        for _ in 0..4 {
            if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr {
                resolved = next;
            } else {
                break;
            }
        }
        if let Expr::BinOp(BinOpKind::Sub, a, b) = ssa.vars[resolved.0 as usize].expr {
            sub_to_cmp.push((bi, *cond, a, b));
        }
    }
}
for (bi, cond_id, a, b) in sub_to_cmp {
    let new_var = ssa.new_var(
        ssa.vars[cond_id.0 as usize].varnode,
        Expr::BinOp(BinOpKind::NotEq, a, b),
        1,
    );
    if let SsaTerminator::CBranch { taken, fallthrough, .. } = ssa.blocks[bi].terminator {
        ssa.blocks[bi].terminator = SsaTerminator::CBranch {
            cond: new_var, taken, fallthrough,
        };
    }
}
```

The new var is created with `ssa.new_var(varnode, expr, size)` — same pattern as `try_recover_condition` at line 1830. Use `ssa.vars[cond_id.0 as usize].varnode` for the varnode and size `1` (bool):

```rust
let new_var = ssa.new_var(
    ssa.vars[cond_id.0 as usize].varnode,
    Expr::BinOp(BinOpKind::NotEq, a, b),
    1,
);
if let SsaTerminator::CBranch { taken, fallthrough, .. } = ssa.blocks[bi].terminator {
    ssa.blocks[bi].terminator = SsaTerminator::CBranch {
        cond: new_var, taken, fallthrough,
    };
}
```

### Part 2: `mba_simplify_expr` — three rule extensions

All three are extensions to existing match arms. Insert after/within the existing code at lines 1015–1063.

**BoolNot arm** (lines 1015–1025): extend to handle `BoolNot(Sub(a,b))` → `Eq(a, b)`:

```rust
Expr::UnaryOp(UnaryOpKind::BoolNot, inner) => {
    if let Expr::UnaryOp(UnaryOpKind::BoolNot, inner2) = &vars[inner.0 as usize].expr {
        return Some(Expr::Var(*inner2));
    }
    if let Expr::BinOp(cmp_op, a, b) = vars[inner.0 as usize].expr {
        if let Some(neg_op) = negate_eq_op(cmp_op) {
            return Some(Expr::BinOp(neg_op, a, b));
        }
        // BoolNot(Sub(a, b)) → Eq(a, b)  [!(a - b) means a == b]
        if cmp_op == BinOpKind::Sub {
            return Some(Expr::BinOp(BinOpKind::Eq, a, b));
        }
    }
    None
}
```

**Eq arm** (lines 1027–1044): extend to handle `Eq(Sub(a,b), 0)` → `Eq(a, b)`:

```rust
Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) => {
    if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
        let mut resolved = *inner_id;
        for _ in 0..4 {
            if let Expr::Var(next) = vars[resolved.0 as usize].expr { resolved = next; }
            else { break; }
        }
        if let Expr::BinOp(cmp_op, a, b) = vars[resolved.0 as usize].expr {
            if let Some(neg_op) = negate_eq_op(cmp_op) {
                return Some(Expr::BinOp(neg_op, a, b));
            }
            // Eq(Sub(a, b), 0) → Eq(a, b)  [a - b == 0 means a == b]
            if cmp_op == BinOpKind::Sub {
                return Some(Expr::BinOp(BinOpKind::Eq, a, b));
            }
        }
    }
    None
}
```

**NotEq arm** (lines 1047–1063): change generic `Var(resolved)` return to explicit `NotEq(a, b)` when inner is Sub:

```rust
Expr::BinOp(BinOpKind::NotEq, inner_id, zero_id) => {
    if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
        let mut resolved = *inner_id;
        for _ in 0..4 {
            if let Expr::Var(next) = vars[resolved.0 as usize].expr { resolved = next; }
            else { break; }
        }
        if let Expr::BinOp(cmp_op, a, b) = vars[resolved.0 as usize].expr {
            // NotEq(Sub(a, b), 0) → NotEq(a, b)  [a - b != 0 means a != b]
            if cmp_op == BinOpKind::Sub {
                return Some(Expr::BinOp(BinOpKind::NotEq, a, b));
            }
        }
        if let Expr::BinOp(_, _, _) = vars[resolved.0 as usize].expr {
            return Some(Expr::Var(resolved));
        }
    }
    None
}
```

---

## Scope Boundaries

- `fold.rs` only — no changes to `printer.rs`, `ssa.rs`, `structure.rs`, `ir.rs`
- Integer Sub only — float Sub (`BinOpKind::FSub`) not touched
- The Sub → NotEq rule in `recover_conditions` only fires for CBranch conditions, never for arithmetic uses of Sub
- No changes to `negate_eq_op` — Sub semantics are handled inline

---

## Testing

**Unit test** (`rsleigh-decompile/tests/sub_as_cmp.rs`):
- Encode a minimal x86-64 sequence: `mov rax, <val>; sub rax, 1; jnz label; ret` — produces `CBranch(Sub(rax, 1))`. After fold, assert no `BinOp(Sub, _, _)` remains in any CBranch condition.
- Encode `mov rax, <val>; sub rax, 1; jz label; ret` — the negated form. After fold, assert condition is `Eq`, not `Sub`.

**Integration test**: decompile one of the known functions (e.g., `0x140001806` or `0x140001a68` from `cb_baristas_secret_x64.exe`), assert output does not contain `- 1)` or `- 2)` in condition positions (i.e., no `if (x - N)`).

**Regression**: full `cargo test -p test-harness` must pass — 9 tests, no new failures.

---

## Implementation Order

1. Add Part 2 (three `mba_simplify_expr` extensions) — these are safer, no new API needed.
2. Add Part 1 (`recover_conditions` Sub pass) — check how `try_recover_condition` mutates SSA before writing.
3. Write unit tests + integration test.
4. Run full test suite.
