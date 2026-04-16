# Call-Return Binding Fix — Design Spec

**Date:** 2026-04-16
**Status:** Ready to implement

---

## Problem Statement

`strcspn(input, "\n\r")` renders as a void call. The return value is decoded and
assigned in SSA (`call_return=true` VarDef), but the binding never reaches the
`StructuredStmt::Call.out` field the printer reads. Affected path: every non-void
function call whose result is used.

The SSA call-clobber fix (`ssa.rs`) correctly emits a `Stmt::Assign(ret_var)` with
`ret_var.call_return = true` after every call. Two structural gaps prevent that
assignment from surfacing as a named binding.

---

## IR Structure Context

Two Call node kinds exist:

- `SsaTerminator::Call { target, args, fallthrough }` — block terminator; the majority
  of calls. The return-value assign lands in the fallthrough block's first stmt.
- `Stmt::Call { target, args, out: Option<VarId> }` — mid-block call (rare P-code
  Call ops). The return-value assign lands immediately after in the same block.

The printer (`printer.rs` lines 8396–8402 and 9292–9297) already handles both:
- `StructuredStmt::Call { out: Some(var) }` → emits `name = func(args);`
- `StructuredStmt::Call { out: None }` → emits `func(args);` (void)

The printer is correct. Both gaps are upstream.

---

## Fix 1 — `SsaTerminator::Call` path (`structure.rs`)

**Where:** the arm that converts a block with a `SsaTerminator::Call` terminator into
a `StructuredStmt::Call`.

**Algorithm:**

1. After resolving `target` and `args`, look up the fallthrough block.
2. Scan the start of the fallthrough block's `stmts` for the first
   `Stmt::Assign(var)` where:
   - `ssa.vars[var].call_return == true`
   - `ssa.vars[var].use_count > 0`
3. If found: pass `out = Some(var)` when constructing the `StructuredStmt::Call`.
4. Record `var` in a `consumed_call_returns: HashSet<VarId>` (block-local or passed
   through the structuring context). When the fallthrough block's stmts are later
   rendered, any `Stmt::Assign(v)` where `consumed_call_returns.contains(&v)` is
   skipped — it is already the call's `out` and emitting it again would produce a
   redundant declaration.

**Invariant:** only the first `call_return=true` stmt at the head of the fallthrough
block is consumed. Subsequent stmts (from nested calls or unrelated assigns) are
unaffected.

---

## Fix 2 — `Stmt::Call` path (`fold.rs` `propagate_call_returns`)

**Where:** `propagate_call_returns`, second-half loop, approximately lines 3147–3164.
This loop already detects the pattern `Stmt::Call` followed by `Stmt::Assign(var)`
with `call_return=true`.

**Extension:**

After the existing logic marks `call_return=true` on `var`, add:

```rust
if ssa.vars[var].use_count > 0 {
    if let Stmt::Call { ref target, ref args, .. } = stmts[call_idx] {
        stmts[call_idx] = Stmt::Call {
            target: target.clone(),
            args: args.clone(),
            out: Some(var),
        };
    }
}
```

The `Stmt::Assign` that was the source of `call_return` is now redundant; remove it
from `stmts` (or mark it dead so the dead-code pass eliminates it).

If `use_count == 0` the call result is unused — leave `out: None` (void call).

---

## Non-Goals

- Do **not** add `out: Option<VarId>` to `SsaTerminator::Call` in `ir.rs`; that
  would require touching every match arm across the codebase.
- Do **not** change the SSA builder (`ssa.rs`).
- Do **not** change the printer (`printer.rs`).
- Do **not** change how `call_return` flags are set; the existing SSA clobber logic
  is correct.

---

## Testing

**Unit test (new, `test-harness/`):**

Decode a minimal 3-instruction sequence (setup reg, CALL, mov return-reg into local),
build SSA + run fold passes + structure pass. Assert:
- `StructuredStmt::Call.out == Some(_)`
- Rendered output contains `= strcspn(` (or equivalent symbol)
- No duplicate assignment line for the same variable

**Integration test (existing binary):**

Decompile `main` (0x140001e41) from `cb_baristas_secret_x64.exe`. Assert:
- Output contains a named local variable bound to the `strcspn` return value
  (e.g., `sVar1 = strcspn(...)`)
- The call is not rendered as a void call

**Regression:**

Full suite (`cargo test -p test-harness`) must pass — 240 tests, 7200+ assertions.
The `consumed_call_returns` skip must not suppress any non-call-return assign.

---

## Implementation Order

1. **Fix 2 first** (`fold.rs`): self-contained, no struct changes, easiest to unit-test
   in isolation. Verify mid-block Call stmts gain `out` and the redundant assign is
   removed.
2. **Fix 1 second** (`structure.rs`): introduce `consumed_call_returns` set, wire
   fallthrough-block scan, verify `StructuredStmt::Call.out` is populated.
3. Add unit test, run integration test on `cb_baristas_secret_x64.exe`.
4. Run full suite; fix any regressions before merging.
