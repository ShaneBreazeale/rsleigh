# Design Spec: RSP-Relative Local Variable Naming

**Date:** 2026-04-16  
**Status:** Ready for implementation

---

## Problem Statement

In functions that use RSP-relative stack frames (no RBP frame pointer), local buffer
accesses appear as raw arithmetic expressions like `RSP - 8 - 45 + 1` instead of
named locals like `local_35[1]`. RBP-relative locals work correctly (`local_60`).
Example: `check2` (0x140001a68).

---

## Root Cause

Two independent gaps combine to produce the bad output.

### Gap 1 — Missing constant folding of chained frame-register arithmetic (fold.rs)

The expression `RSP - 8 - 45` is not reduced to `RSP - 53`. fold.rs does not simplify
`BinOp(Sub/Add, BinOp(Sub/Add, FRAME_REG, C1), C2)` → `BinOp(Sub/Add, FRAME_REG, C1±C2)`.
Without this, a single-level pattern match in any naming function cannot recognize
the expression as a frame-relative access.

### Gap 2 — No RSP offset extraction in printer.rs

`printer.rs` has `get_rbp_offset()` (~line 9801) that walks a Var chain and recognizes
`BinOp(Add/Sub, RBP_var, Const(N))`, returning the signed frame offset. There is no
equivalent for RSP. Both `try_stack_var_name()` (~line 9769) and `format_addr()`
(~line 9837) call only `get_rbp_offset()`, so RSP-relative pointers fall through to
raw expression rendering. (Verify exact line numbers before editing — these are approximate.)

---

## Design

### Fix 1 — Constant folding of chained frame-register arithmetic (fold.rs)

Add a fold rule that runs as part of the existing expression-folding pipeline:

```
BinOp(op2, BinOp(op1, FRAME_REG, Const(C1)), Const(C2))
  → BinOp(combined_op, FRAME_REG, Const(combined_C))
```

where `FRAME_REG` is any of RSP, RBP, x29 (AArch64 FP), or SP (ARM32), and `op1`/`op2`
are `Add` or `Sub`. The combined constant and operator follow standard signed arithmetic:

| op1  | op2  | result op | result const |
|------|------|-----------|--------------|
| Sub  | Sub  | Sub       | C1 + C2      |
| Sub  | Add  | Sub       | C1 - C2      |
| Add  | Sub  | Add or Sub| C1 - C2 (sign-select) |
| Add  | Add  | Add       | C1 + C2      |

Apply recursively so three-deep chains (`RSP - 8 - 45 + 1`) also collapse.

**Where to add:** in the `fold_expr` match arm (or equivalent recursive pass) in fold.rs,
after existing algebraic simplifications. Guard with `is_frame_reg(var)` using the
existing RSP_OFFSET / RBP_OFFSET constants.

---

### Fix 2 — Add `get_rsp_offset()` and extend naming (printer.rs)

**2a. Add `fn get_rsp_offset(id: VarId, ssa: &SsaCfg) -> Option<i64>`**

Model it on `get_rbp_offset()` (~line 9801). Walk through Var chains (Copy propagation).
Recognize the patterns produced after Fix 1:

- `BinOp(Add, RSP_var, Const(N))` → return `N` (positive = above RSP)
- `BinOp(Sub, RSP_var, Const(N))` → return `-N` (negative = local below RSP)

Use `RSP_OFFSET = 32` (already defined in printer.rs) to identify the RSP Varnode.

**2b. Update `try_stack_var_name()` (~line 9769)**

After the existing `get_rbp_offset()` call, add:

```rust
if let Some(off) = get_rsp_offset(id, ssa) {
    if off < 0 {
        return Some(format!("local_{:x}", (-off) as u64));
    }
}
```

**2c. Update `format_addr()` (~line 9837)**

After the RBP branch, add an RSP branch that calls `get_rsp_offset()` and formats
the address as `local_{:x}` (reusing the naming from 2b) so the result flows into
the same `local_XX` display path already used for RBP locals.

**2d. Extend the declaration pass**

Wherever `local_XX` variable declarations are generated from collected stack slot names
(the pass that emits `int local_c;` etc.), extend the slot-collection step to also walk
RSP-relative accesses using the same `get_rsp_offset()` function. This ensures RSP
locals appear in the declaration block with correct sizes inferred from offset gaps,
identical to RBP locals.

---

## Non-Goals

- No changes to ssa.rs or ir.rs.
- No changes to shadow-store forwarding (separate defect class, separate spec).
- ESP-relative (x86-32) is out of scope — only RSP (x86-64 omit-frame-pointer functions).
- No new IR types or Varnode changes.

---

## Testing

**Unit test** (test-harness): decode a minimal x86-64 function with `sub rsp, 0x40` prologue
and a local buffer access at `[rsp + 0x10]`. Assert that decompiler output contains
`local_30` (or appropriate offset name), not `RSP + 0x10` or chained arithmetic.

**Integration test**: decompile `check2` at `0x140001a68`. Assert output does **not**
contain the substring `RSP - 8 -` (chained raw arithmetic). Assert output does contain
`local_` variables for the buffer accesses.

**Regression**: full test suite (`cargo test -p test-harness`) must pass without new
failures, in particular the 14-point pseudocode quality audit tests.

---

## Implementation Order

1. **fold.rs** — Add chained frame-register arithmetic folding rule.
2. **printer.rs** — Add `get_rsp_offset()`.
3. **printer.rs** — Update `try_stack_var_name()` to call `get_rsp_offset()`.
4. **printer.rs** — Update `format_addr()` to call `get_rsp_offset()`.
5. **printer.rs** — Extend declaration-collection pass to include RSP-relative slots.
6. **Tests** — Add unit + integration tests as described above.
7. **Verify** — Decompile `check2`, confirm `local_XX` output, confirm no raw chained arithmetic.
