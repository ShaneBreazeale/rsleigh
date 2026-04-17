# Design Spec: String Literal False Positives in Load Addresses

**Date:** 2026-04-17  
**Status:** Ready for implementation (v2 — revised after Codex review)

---

## Problem Statement

Decompiler output for `cb_baristas_secret_x64.exe` contains:

```c
while (*(*("ȡ")) != 0) {     // should be: while (*(*(DAT_140005770)) != 0)
*("`@")                       // should be: *(DAT_140005680)
*(*("hS"))                    // should be: *(DAT_1400056d0)
*(long*)("0@")                // should be: *(long*)(DAT_1400057e0)
```

Four instances across three functions (`0x140001017`, `0x14000109a`, `0x140001154`). String literals appear as pointer-dereference addresses instead of `DAT_` globals.

**Ghidra positive control** (function `0x140001154` = `__tmainCRTStartup`):
```c
*(longlong *)_refptr___native_startup_lock
*(int *)_refptr___native_startup_state
```
No string literals — Ghidra shows named import references.

---

## Root Cause

Every 8-byte PE pointer in `.rdata` (and other read-only non-exec sections: `.pdata`, `.idata`, `.reloc`) commonly has `0x00` at byte 2, because image VAs like `0x0000000140004060` encode as `60 40 00 40 01 00 00 00`:

```
60 40 00 40 01 00 00 00   ← pointer to 0x140004060
      ^^
      null at byte 2
```

`try_read_string` finds the null at index 2 and reads 2 bytes as a UTF-8 string. The current guard in `format_const_ctx` is `s.len() < 2`, so a 2-byte result passes and is emitted as a string literal in any context — including when the Const is a Load address.

**Important:** `try_read_string` uses `String::len()` (byte count, not char count). A single 2-byte UTF-8 codepoint like `c8 a1` → `"ȡ"` has `len() == 2` and passes the guard. So `"È¡"` in terminal output is `"ȡ"` in the Rust source (encoding/display difference).

---

## Deref-Address Emission Sites

All sites that produce `*(addr)` or `*(type*)(addr)` and could route a Const address through `format_const_ctx`:

| Site | Location | Path to `format_const_ctx` |
|---|---|---|
| `format_cond_operand` non-stack Load | line ~9578 | recursive `format_cond_operand(*ptr)` → line 9628 Const arm |
| `format_cond_operand` register Load | line ~9597 | recursive `format_cond_operand(*ptr)` → line 9628 Const arm |
| `format_store_operand` Load | line ~10084 | recursive `format_store_operand(*ptr)` → line 10072 Const arm |
| `format_expr` Load | line ~10208 | `format_addr(*ptr)` → `format_var` line 10018 Const arm |

All four must be patched to eliminate the false positive class.

---

## Design

### Fix overview

**One new helper:** `format_const_ctx_load` — like `format_const_ctx` but:
- Checks `ctx.imports` / vtable **before** string resolution (load addresses are more likely named globals than string literals)
- Requires `s.len() >= 4` instead of `s.len() >= 2` for string resolution

**Four patched sites:** at each `*(addr)` construction, resolve the pointer variable to its underlying `Const` (if any) using a deep resolver, then format with `format_const_ctx_load` instead of the recursive format call.

**One shared deep resolver helper:** `resolve_to_const(id, ssa) -> Option<(u64, u32)>` — follows `Expr::Var` chains (up to 8 hops) and unwraps `Expr::UnaryOp(Zext/Sext, inner)` wrappers, returning `(val, size)` if the underlying expression is `Expr::Const`, `None` otherwise.

### New functions

**`resolve_to_const`** (place near `resolve_through_vars`):

```rust
fn resolve_to_const(mut id: VarId, ssa: &SsaCfg) -> Option<(u64, u32)> {
    for _ in 0..8 {
        let expr = &ssa.var(id).expr;
        match expr {
            Expr::Const(val, sz) => return Some((*val, *sz)),
            Expr::Var(next) => id = *next,
            Expr::UnaryOp(UnaryOpKind::Zext, inner)
            | Expr::UnaryOp(UnaryOpKind::Sext, inner) => id = *inner,
            _ => return None,
        }
    }
    None
}
```

**`format_const_ctx_load`** (place immediately after `format_const_ctx`):

```rust
fn format_const_ctx_load(val: u64, size: u32, ctx: &PrintCtx) -> String {
    // Like format_const_ctx, but for load-address context:
    // 1. Prefers named imports/vtable over string resolution (addresses are likely globals)
    // 2. Requires ≥4 bytes of string content to avoid PE pointer-table false positives
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    if size >= 4 && val > 0x200 {
        // imports and vtable names first — more reliable than string heuristics for addresses
        if let Some(name) = ctx.imports.get(&val) {
            return name.clone();
        }
        if let Some(binary) = ctx.binary {
            if let Some(vtable_name) = crate::imports::resolve_pe_vtable(val, binary) {
                return vtable_name;
            }
        }
        // String resolution only if ≥4 chars (prevents 2-byte pointer-table artifacts)
        if let Some(s) = try_read_string(val, ctx) {
            if s.len() >= 4 {
                return format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"));
            }
        }
        if let Some(ws) = try_read_wide_string(val, ctx) {
            return ws;
        }
    }
    format_const(val, size)
}
```

### Four patched sites

The same pattern at each `*(addr)` construction:

```rust
// Before (example from format_cond_operand line 9578):
let addr = format_cond_operand(*ptr, ssa, ctx, tracker);
return format!("*({})", addr);

// After:
let addr = match resolve_to_const(*ptr, ssa) {
    Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
    None => format_cond_operand(*ptr, ssa, ctx, tracker),
};
return format!("*({})", addr);
```

The four sites:
1. `format_cond_operand` non-stack Load (~line 9578) — recursive call to `format_cond_operand`
2. `format_cond_operand` register Load (~line 9597) — recursive call to `format_cond_operand`
3. `format_store_operand` Load (~line 10084) — recursive call to `format_store_operand`
4. `format_addr` fallthrough (~line 9955) — `format_var(id, ssa, ctx)` call

For site 4, the pattern is slightly different:

```rust
// format_addr fallthrough (line 9955):
// Before:
format_var(id, ssa, ctx)

// After:
match resolve_to_const(id, ssa) {
    Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
    None => format_var(id, ssa, ctx),
}
```

### Scope boundaries

- `printer.rs` only — no changes to `fold.rs`, `ssa.rs`, `structure.rs`, `ir.rs`
- `format_const_ctx` unchanged — all existing callers keep min_len=2
- `try_read_string` unchanged
- `resolve_through_vars` unchanged

---

## Testing

**Test file:** `rsleigh-decompile/tests/string_false_positive.rs`

### Test 1: `no_string_literal_as_load_address` (primary — negative)

Decompile `0x140001154` from `cb_baristas_secret_x64.exe`. Assert the output contains NO string literal used as a deref address — i.e., no `*("` or `*(type*)("` pattern anywhere:

```rust
let deref_string_lines: Vec<&str> = out.lines()
    .filter(|l| l.contains("*(\"") || (l.contains("*(") && l.contains("*)(\")")))
    .collect();
assert!(deref_string_lines.is_empty(),
    "string literal used as load address:\n{}", deref_string_lines.join("\n"));
```

This is stronger than checking 4 hardcoded strings — it catches any false positive of this class.

Skip gracefully if fixture absent.

### Test 2: `load_address_uses_dat_or_hex` (positive — not vacuous)

Same function. Assert that the output contains `DAT_` names or `0x14000...` hex in the load positions — confirming the fix replaced strings with real addresses, not empty strings:

```rust
assert!(out.contains("DAT_") || out.contains("0x1400"),
    "expected DAT_ or hex address after fix, got:\n{}", out);
```

Skip gracefully if fixture absent.

### Test 3: `real_strings_still_resolved` (positive — no regression on real strings)

Decompile `0x140001a68` which passes `"v\`cav\`\`|rarqzprQAVD>"` (19 chars, clearly ≥4) to a function call. Assert the real long string still appears as a string literal:

```rust
assert!(out.contains("\"v`cav"),
    "real string literal was suppressed by the fix:\n{}", out);
```

Skip gracefully if fixture absent.

**Regression:** `cargo test -p test-harness` must remain 9/9.

---

## Implementation Order

1. Add `resolve_to_const` and `format_const_ctx_load` to `printer.rs`
2. Write failing Test 1 — confirm it fails (false positive present)
3. Patch the four `*(addr)` sites
4. Run Test 1 — must pass. Run Tests 2 and 3.
5. Run full regression suite.
