# AArch64 CSEL Ternary Recovery — Design Spec

## Problem

AArch64 conditional instructions (`CSEL`, `CSINC`, `CSETM`, `CSET`, `CNEG`) generate P-code with intra-instruction CBranch (dest in Const space, not Ram space). The CFG builder only handles Ram-space branches — Const-space branches are silently dropped. This is a **correctness bug**: the conditional skip never happens, only the "else" assignment survives.

### Example: `CSEL w8, w0, w2, lt`

P-code generated:
```
[0] IntNotEq { tmp = NG(256), OV(259) }     // lt = NG != OV
[1] CBranch { dest: Const(1), cond: tmp }    // if lt, skip next op
[2] IntZext { w8 = zext(w2) }                // else: w8 = w2
```

Current behavior: op[1] dropped, op[2] always executes → `w8 = w2` unconditionally.
Expected: `w8 = (NG != OV) ? w8_previous : zext(w2)` → after flag folding: `w8 = (a < b) ? a : b`.

### Affected Instructions

| Instruction | Semantics | P-code Pattern |
|-------------|-----------|----------------|
| `CSEL Wd, Wn, Wm, cond` | `Wd = cond ? Wn : Wm` | CBranch skips `Wd = Wm` |
| `CSINC Wd, Wn, Wm, cond` | `Wd = cond ? Wn : Wm+1` | CBranch skips `Wd = Wm+1` |
| `CSETM Wd, cond` | `Wd = cond ? -1 : 0` | CBranch skips `Wd = neg(1) * zext(cond)` |
| `CSET Wd, cond` | `Wd = cond ? 1 : 0` | CBranch skips increment |
| `CNEG Wd, Wn, cond` | `Wd = cond ? -Wn : Wn` | CBranch skips `Wd = -Wn` or `Wd = Wn` |

All use the same P-code pattern: condition compute → CBranch(Const) → skipped assignment.

### Current Decompilation (broken)

```c
// compare_signed: cmp w0,w1; csetm w8,lt; csinc w0,w8,wzr,le
long compare_signed(void) {
    param_0 = (uint)1;    // only last assignment survives
}

// clamp: cmp w0,w2; csel w8,w0,w2,lt; cmp w0,w1; csel w0,w1,w8,lt
long clamp(void) {
    while (w0 < w1) {     // garbled — conditions misinterpreted
        x8 = (uint)w2;
    }
    param_0 = (uint)w8;
}
```

## Design

### A. Add Ternary expression to IR (`ir.rs`)

Add a new `Expr` variant:

```rust
pub enum Expr {
    // ... existing variants ...
    /// Conditional select: if cond != 0, then_val, else else_val.
    /// Generated from AArch64 CSEL-family intra-instruction CBranch patterns.
    Ternary(VarId, VarId, VarId),  // (cond, then_val, else_val)
}
```

### B. Handle intra-instruction CBranch in SSA builder (`ssa.rs`)

In the instruction-grouped processing loop (same location as Zext deferral and MOVSD fix), detect the intra-instruction CBranch pattern.

When processing an instruction's ops:
1. Scan for `CBranch { dest }` where `dest.space == AddressSpaceId::Const`
2. The CBranch divides the remaining ops into "skipped" (else path) and "post-skip" ops
3. Process pre-branch ops normally to establish the condition variable
4. For the skipped ops: process them but don't update `current` — capture as "else values"
5. For each register written in the skipped ops, emit `Ternary(cond, current_value, else_value)`
6. Skip the CBranch and skipped ops in the normal processing loop

The `dest.offset` field indicates how many P-code ops to skip (relative from the CBranch). Need to verify the exact semantics by testing.

### C. Fold ternary conditions (`fold.rs`)

Extend the fold pass to simplify ternary expressions:

1. **Flag condition folding:** When the ternary condition is a flag expression like `IntNotEq(NG, OV)`, trace back to the CMP instruction's operands and replace with a comparison: `Ternary(a < b, then, else)`.

2. **Constant ternary folding:** `Ternary(const_true, a, b)` → `a`; `Ternary(const_false, a, b)` → `b`.

3. **Identity ternary elimination:** `Ternary(cond, a, a)` → `a`.

4. **Use counting:** Both branches of a ternary contribute to use_count of their operands.

### D. Print ternary expressions (`printer.rs`)

In the expression formatter, add ternary printing:

```c
(cond) ? then_val : else_val
```

With parentheses for clarity. The condition should be printed as a comparison when folded: `(param_0 < param_1) ? param_0 : param_1`.

Also add ternary to the local declaration type inference — the result type matches the then/else types.

### E. Structure pass (`structure.rs`)

Ensure `Expr::Ternary` is handled in any match expressions that enumerate `Expr` variants. It should pass through as a normal expression (it doesn't affect control flow structure).

## Files Changed

| File | Changes |
|------|---------|
| `rsleigh-decompile/src/ir.rs` | Add `Expr::Ternary(VarId, VarId, VarId)` |
| `rsleigh-decompile/src/ssa.rs` | Intra-instruction CBranch detection + ternary emission |
| `rsleigh-decompile/src/fold.rs` | Ternary use counting, flag condition folding, constant/identity simplification |
| `rsleigh-decompile/src/printer.rs` | `cond ? a : b` printing, flag leak suppression |
| `rsleigh-decompile/src/structure.rs` | Handle Ternary in exhaustive matches |
| `test-harness/` | AArch64 CSEL/CSINC/CNEG tests |

## Test Plan

- Compile `flag_test.c` with `-O1 -arch arm64` for CSEL-heavy output
- Test `compare_signed`: should show ternary with signed comparison
- Test `clamp`: should show two ternary selects, not garbled while loop
- Test `abs_val`: should show conditional negate
- All existing 9 tests must pass (no regressions)

## Non-Goals

- Full AArch64 condition simplification (e.g., `(NG != OV) && !ZR` → `a > b`) — do the common cases, defer rare compound conditions
- SIMD conditional select (FCSEL, vector select) — future work
- ARM32 conditional execution (IT blocks) — different mechanism entirely
