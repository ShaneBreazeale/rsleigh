# Design Spec: String Literal False Positives in Load Addresses

**Date:** 2026-04-17
**Status:** Ready for implementation

---

## Problem Statement

Decompiler output for `cb_baristas_secret_x64.exe` contains:

```c
while (*(*("È¡")) != 0) {   // should be: while (*(*(DAT_140005770)) != 0)
*("`@")                      // should be: *(DAT_140005680)
*(*("hS"))                   // should be: *(*(DAT_1400056d0))
*(long*)("0@")               // should be: *(long*)(DAT_1400057e0)
```

Four instances across three functions (`0x140001017`, `0x14000109a`, `0x140001154`). String literals appear as pointer-dereference addresses instead of `DAT_` globals.

**Ghidra positive control** (function `0x140001154` = `__tmainCRTStartup`):
```c
*(longlong *)_refptr___native_startup_lock   // named global
*(int *)_refptr___native_startup_state       // named global
```
No string literals anywhere in the function — Ghidra recognises these as named import references.

---

## Root Cause

Every 8-byte PE pointer in `.rdata` looks like:

```
60 40 00 40 01 00 00 00   ←  0x0000000140004060
          ^^
          null at byte 2
```

`try_read_string` finds the null at index 2 and reads 2 bytes as a string. Byte 0 and 1 happen to be valid UTF-8/ASCII (e.g. `` `@ `` = `0x60 0x40`, or `ȡ`/`È¡` = `0xc8 0xa1`). The current guard in `format_const_ctx` is `s.len() < 2`, so a 2-char result passes and is emitted as a string literal.

This fires whenever a `Expr::Const` is formatted as a Load address — the Const is the pointer being dereferenced, not a char* string argument.

---

## Design

### Fix location

`rsleigh-decompile/src/printer.rs` only. No changes to `fold.rs`, `ssa.rs`, `structure.rs`, or `ir.rs`.

### Approach: Load-address formatter with min_len = 4

Add one new helper function:

```rust
fn format_const_ctx_load(val: u64, size: u32, ctx: &PrintCtx) -> String {
    // Identical to format_const_ctx but requires ≥4 chars for string resolution.
    // Prevents PE .rdata pointer-table entries (null at byte 2 of an 8-byte VA)
    // from being misread as 2-char strings when the Const is a Load address.
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    if size >= 4 && val > 0x200 {
        if let Some(s) = try_read_string(val, ctx) {
            if s.len() >= 4 {
                return format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"));
            }
        }
        if let Some(name) = ctx.imports.get(&val) { return name.clone(); }
        if let Some(binary) = ctx.binary {
            if let Some(n) = crate::imports::resolve_pe_vtable(val, binary) { return n; }
        }
        if let Some(ws) = try_read_wide_string(val, ctx) { return ws; }
    }
    format_const(val, size)
}
```

The only difference from `format_const_ctx`: the string length guard is `s.len() >= 4` instead of `s.len() >= 2`.

### Two patched call sites

Both `format_cond_operand` (line 9577) and `format_store_operand` (line 10082) produce `format!("*({})", addr)` where `addr` comes from a recursive format call. When that recursive call bottoms out at a `Const`, it uses `format_const_ctx` with min_len=2.

At each site, intercept the Const case before the recursive call:

```rust
// Before (both sites):
let addr = format_cond_operand(*ptr, ssa, ctx, tracker);   // or format_store_operand
return format!("*({})", addr);

// After:
let addr = {
    let mut pid = *ptr;
    for _ in 0..4 {
        if let Expr::Var(next) = ssa.vars[pid.0 as usize].expr { pid = next; } else { break; }
    }
    if let Expr::Const(val, sz) = ssa.vars[pid.0 as usize].expr {
        format_const_ctx_load(val, sz, ctx)
    } else {
        format_cond_operand(*ptr, ssa, ctx, tracker)   // or format_store_operand
    }
};
return format!("*({})", addr);
```

The Var-chain traversal (up to 4 hops) handles the common case where the Load's pointer is a `Var` wrapping a `Const`. If it doesn't resolve to a Const in 4 hops, the normal path handles it.

### Scope boundaries

- `format_const_ctx` unchanged — all existing callers (lines 9628, 10018, 10072, 10120) keep min_len=2
- `try_read_string` unchanged
- Only two call sites patched: `format_cond_operand` (~line 9578) and `format_store_operand` (~line 10084)
- `format_const_ctx_load` is placed immediately after `format_const_ctx` in the file

---

## Testing

**Test file:** `rsleigh-decompile/tests/string_false_positive.rs`

### Test 1: `no_string_literal_as_load_address` (primary — negative)

Decompile `0x140001154` from `cb_baristas_secret_x64.exe`. Assert output does NOT contain any of: `"È¡"`, `"hS"`, `` "`@" ``, `"0@"`.

```rust
assert!(!out.contains("\"È¡\"") && !out.contains("\"hS\"")
    && !out.contains("\"`@\"") && !out.contains("\"0@\""),
    "string false positive still present:\n{}",
    out.lines().filter(|l| l.contains('"')).collect::<Vec<_>>().join("\n"));
```

Skip gracefully if fixture binary absent.

### Test 2: `load_address_uses_dat_or_hex` (positive — regression guard)

Same function. Assert that the output contains `DAT_` or a hex address in place of the false-positive strings. The addresses `0x140005680`, `0x1400056d0`, `0x140005770`, `0x1400057e0` must appear as `DAT_` names or `0x14000...` hex literals, not as string literals.

```rust
let has_dat = out.contains("DAT_") || out.contains("0x1400056") || out.contains("0x140005");
assert!(has_dat, "expected DAT_ or hex address in load positions, got:\n{}", out);
```

Skip gracefully if fixture absent.

### Test 3: `real_strings_still_resolved` (positive — no regression on real strings)

Decompile a function that has a real string argument in `.rdata` (e.g., `0x140001a68` which passes `"v\`cav\`\`|rarqzprQAVD>"` to a function call). Assert the real long string still appears as a string literal in the output.

```rust
assert!(out.contains('"'), "real string literal was suppressed:\n{}", out);
```

Skip gracefully if fixture absent.

**Regression:** `cargo test -p test-harness` must remain 9/9.

---

## Implementation Order

1. Write failing Test 1 — confirm it fails (false positive present)
2. Add `format_const_ctx_load` to `printer.rs`
3. Patch the two Load-address call sites
4. Run Test 1 — must pass. Run Tests 2 and 3.
5. Run full regression suite.
