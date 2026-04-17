# String Literal False Positive Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop PE `.rdata` pointer-table entries from being emitted as 2-char string literals when used as Load addresses.

**Architecture:** Add `resolve_to_const` (deep Var/Zext/Sext resolver) and `format_const_ctx_load` (min_len=4, imports-first) to `printer.rs`. Patch all four `*(addr)` construction sites to use `format_const_ctx_load` when the pointer resolves to a Const.

**Tech Stack:** Rust, `rsleigh-decompile` crate, `printer.rs`.

---

## Background for the implementer

**The bug:** `format_const_ctx` calls `try_read_string(addr)`. PE `.rdata` pointer tables have `0x00` at byte 2 (e.g. `60 40 00 40 01 00 00 00`). `try_read_string` reads 2 bytes as a UTF-8 string. The guard `s.len() < 2` lets 2-byte results through, producing `*("ȡ")` etc. Note: `"È¡"` in the terminal is `"ȡ"` in Rust source — UTF-8 encoding difference.

**All four sites that must be patched** (each produces `*(addr)` and routes Load addresses through `format_const_ctx`):
1. `format_cond_operand` non-stack Load — line ~9578
2. `format_cond_operand` register Load — line ~9597
3. `format_store_operand` Load — line ~10084
4. `format_addr` fallthrough — line ~9955

**The fix pattern** at each site: resolve the pointer VarId to its underlying Const using `resolve_to_const`, and if found, format with `format_const_ctx_load` instead of the existing recursive call.

**`resolve_to_const`** follows `Expr::Var` chains (up to 8 hops) and unwraps `Expr::UnaryOp(Zext/Sext, inner)` wrappers, returning `Some((val, size))` if it reaches an `Expr::Const`, `None` otherwise. This handles: direct Const, Var(Const), Var(Var(Const)), Zext(Const), Var(Zext(Const)), etc.

**`format_const_ctx_load`** differs from `format_const_ctx` in two ways:
- Checks `ctx.imports` and vtable names **before** string resolution (load addresses are more likely named globals)
- Requires `s.len() >= 4` instead of `s.len() >= 2`

**`resolve_through_vars` in printer.rs (line ~10754) is only 1-hop** — do NOT use it for this fix; it will miss almost all cases.

**Key types and functions:**
- `VarId` — SSA variable identifier (u32 wrapper)
- `ssa.var(id)` → `&VarDef` with `.expr: Expr` and `.varnode`
- `Expr::Var(VarId)`, `Expr::Const(u64, u32)`, `Expr::UnaryOp(UnaryOpKind, VarId)`, `Expr::Load(VarId)`
- `UnaryOpKind::Zext`, `UnaryOpKind::Sext` — zero/sign extension ops
- `format_const_ctx(val, size, ctx)` — existing function, unchanged
- `format_const(val, size)` — hex/decimal fallback
- `try_read_string(val, ctx)`, `try_read_wide_string(val, ctx)` — existing, unchanged

---

## Files

- **Modify:** `rsleigh-decompile/src/printer.rs`
- **Create:** `rsleigh-decompile/tests/string_false_positive.rs`

---

### Task 1: Write failing tests

**Files:**
- Create: `rsleigh-decompile/tests/string_false_positive.rs`

- [ ] **Step 1: Create the test file**

```rust
//! Regression tests for string literal false positives in Load addresses.
//!
//! Spec: docs/superpowers/specs/2026-04-17-string-false-positive-design.md

fn decompile_func(func_va: u64, max_len: usize) -> Option<String> {
    use pcode_ir::PcodeOp;
    use rsleigh_api::{Architecture, Decoder};

    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = std::fs::read(path).ok()?;
    let pe = goblin::pe::PE::parse(&data).ok()?;
    let image_base = pe.image_base as u64;
    let rva = func_va - image_base;
    let mut file_off = None;
    for s in &pe.sections {
        let s_va = s.virtual_address as u64;
        let s_sz = s.virtual_size as u64;
        if rva >= s_va && rva < s_va + s_sz {
            file_off = Some((s.pointer_to_raw_data as u64 + (rva - s_va)) as usize);
            break;
        }
    }
    let off = file_off?;
    let func_len = max_len.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut io = 0usize;
    while io < bytes.len() {
        match dec.decode(&bytes[io..], func_va + io as u64) {
            Ok(inst) => {
                let is_ret = inst.ops.iter().any(|op| matches!(op, PcodeOp::Return { .. }));
                let l = inst.len as usize;
                insts.push((func_va + io as u64, inst));
                io += l;
                if is_ret { break; }
            }
            Err(_) => break,
        }
    }

    let out = rsleigh_decompile::decompile_with_binary(
        Architecture::X86_64,
        &insts,
        Some(&data),
        Some(std::path::Path::new(path)),
    );
    Some(out)
}

/// Primary test: no string literal may appear as a Load address in 0x140001154.
/// Catches all deref-of-string patterns: *("...") or *(type*)("...").
/// Before the fix this emits *(*("ȡ")), *("`@"), etc.
#[test]
fn no_string_literal_as_load_address() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let out = match decompile_func(0x140001154, 0x400) {
                Some(s) => s,
                None => { eprintln!("skipping: fixture not found"); return; }
            };

            // Check for any deref-of-string-literal pattern: *("...") anywhere in output
            let bad_lines: Vec<&str> = out.lines()
                .filter(|l| {
                    // *(  "  — direct deref of string
                    // *( something *)( "  — typed deref of string
                    (l.contains("*(\"") )
                    || (l.contains("*(") && l.contains("*)(\""))
                })
                .collect();
            assert!(
                bad_lines.is_empty(),
                "string literal used as load address:\n{}",
                bad_lines.join("\n")
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Positive guard: after the fix, the load positions must show DAT_ names or hex.
/// Prevents a vacuous pass where the output is just empty.
#[test]
fn load_address_uses_dat_or_hex() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let out = match decompile_func(0x140001154, 0x400) {
                Some(s) => s,
                None => { eprintln!("skipping: fixture not found"); return; }
            };
            assert!(
                out.contains("DAT_") || out.contains("0x1400"),
                "expected DAT_ or hex address in output after fix:\n{}", out
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Regression guard: real long strings (≥4 chars) in .rdata must still be resolved.
/// Function 0x140001a68 passes "v`cav``|rarqzprQAVD>" (19 chars) — must still appear.
#[test]
fn real_strings_still_resolved() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let out = match decompile_func(0x140001a68, 0x400) {
                Some(s) => s,
                None => { eprintln!("skipping: fixture not found"); return; }
            };
            assert!(
                out.contains("\"v`cav"),
                "real string literal was suppressed by the fix:\n{}", out
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}
```

- [ ] **Step 2: Run tests to confirm Test 1 fails**

```bash
cd /Users/shane/repos/rsleigh
cargo test -p rsleigh-decompile --test string_false_positive 2>&1 | tail -15
```

Expected:
```
test no_string_literal_as_load_address ... FAILED   ← must fail (bug present)
test load_address_uses_dat_or_hex ... ok or FAILED
test real_strings_still_resolved ... ok             ← must pass
```

If `no_string_literal_as_load_address` passes, the bug is not reproducible — check the binary path and function VA, or print the decompiled output to verify.

- [ ] **Step 3: Commit the failing tests**

```bash
cd /Users/shane/repos/rsleigh
git add rsleigh-decompile/tests/string_false_positive.rs
git commit -m "test: add failing string false positive tests"
```

---

### Task 2: Add `resolve_to_const` and `format_const_ctx_load` to printer.rs

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs`

- [ ] **Step 1: Add `resolve_to_const` near `resolve_through_vars` (line ~10754)**

Find `fn resolve_through_vars` (around line 10754). Insert the new function immediately before it:

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

- [ ] **Step 2: Add `format_const_ctx_load` after `format_const_ctx` (line ~10262)**

Find `fn format_const_ctx` (around line 10231) — it ends around line 10262. Insert the new function immediately after it:

```rust
fn format_const_ctx_load(val: u64, size: u32, ctx: &PrintCtx) -> String {
    // Like format_const_ctx, but for load-address context:
    // 1. Prefers named imports/vtable over string resolution
    // 2. Requires ≥4 bytes of string content to avoid PE pointer-table false positives
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    if size >= 4 && val > 0x200 {
        if let Some(name) = ctx.imports.get(&val) {
            return name.clone();
        }
        if let Some(binary) = ctx.binary {
            if let Some(vtable_name) = crate::imports::resolve_pe_vtable(val, binary) {
                return vtable_name;
            }
        }
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

- [ ] **Step 3: Build to confirm it compiles**

```bash
cd /Users/shane/repos/rsleigh
cargo build -p rsleigh-decompile 2>&1 | grep "^error"
```

Expected: no errors.

- [ ] **Step 4: Commit the two new functions**

```bash
cd /Users/shane/repos/rsleigh
git add rsleigh-decompile/src/printer.rs
git commit -m "printer: add resolve_to_const and format_const_ctx_load helpers"
```

---

### Task 3: Patch the four Load-address sites

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs`

- [ ] **Step 1: Patch site 1 — `format_cond_operand` non-stack Load (~line 9577)**

Find the comment `// Non-stack Load: dereference a pointer`. The current code is:

```rust
        // Non-stack Load: dereference a pointer (e.g., *s for string access)
        let addr = format_cond_operand(*ptr, ssa, ctx, tracker);
        return format!("*({})", addr);
```

Replace with:

```rust
        // Non-stack Load: dereference a pointer (e.g., *s for string access)
        let addr = match resolve_to_const(*ptr, ssa) {
            Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
            None => format_cond_operand(*ptr, ssa, ctx, tracker),
        };
        return format!("*({})", addr);
```

- [ ] **Step 2: Patch site 2 — `format_cond_operand` register Load (~line 9597)**

Find the block ending with `let addr = format_cond_operand(*ptr, ssa, ctx, tracker);` inside the `if vdef.varnode.space == AddressSpaceId::Register` guard (around line 9597). The current code is:

```rust
            let addr = format_cond_operand(*ptr, ssa, ctx, tracker);
            return format!("*({})", addr);
```

Replace with:

```rust
            let addr = match resolve_to_const(*ptr, ssa) {
                Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
                None => format_cond_operand(*ptr, ssa, ctx, tracker),
            };
            return format!("*({})", addr);
```

- [ ] **Step 3: Patch site 3 — `format_store_operand` Load (~line 10084)**

Find the comment `// Non-stack load (array element, struct field, etc.)`. The current code is:

```rust
            // Non-stack load (array element, struct field, etc.)
            // Show as *(addr) or resolve to array syntax
            let addr = format_store_operand(*ptr, ssa, ctx, tracker);
            return format!("*({})", addr);
```

Replace with:

```rust
            // Non-stack load (array element, struct field, etc.)
            // Show as *(addr) or resolve to array syntax
            let addr = match resolve_to_const(*ptr, ssa) {
                Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
                None => format_store_operand(*ptr, ssa, ctx, tracker),
            };
            return format!("*({})", addr);
```

- [ ] **Step 4: Patch site 4 — `format_addr` fallthrough (~line 9955)**

Find `fn format_addr`. It ends with:

```rust
    format_var(id, ssa, ctx)
}
```

Replace the final `format_var` call with:

```rust
    match resolve_to_const(id, ssa) {
        Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
        None => format_var(id, ssa, ctx),
    }
}
```

- [ ] **Step 5: Build**

```bash
cd /Users/shane/repos/rsleigh
cargo build -p rsleigh-decompile 2>&1 | grep "^error"
```

Expected: no errors. If there are unused variable warnings on `ptr` at any patch site, check the match — the variable is still used in the `None` arm so there should be none.

- [ ] **Step 6: Run all three tests**

```bash
cd /Users/shane/repos/rsleigh
cargo test -p rsleigh-decompile --test string_false_positive 2>&1 | tail -10
```

Expected:
```
test no_string_literal_as_load_address ... ok
test load_address_uses_dat_or_hex ... ok
test real_strings_still_resolved ... ok
```

If `no_string_literal_as_load_address` still fails, there is a fifth deref-address site not covered by these four patches. Print the offending lines from the decompiled output to find which format function is producing them, then apply the same `resolve_to_const` + `format_const_ctx_load` pattern to that site too.

- [ ] **Step 7: Commit**

```bash
cd /Users/shane/repos/rsleigh
git add rsleigh-decompile/src/printer.rs
git commit -m "printer: use format_const_ctx_load at all Load-address sites to fix string false positives"
```

---

### Task 4: Full regression suite

**Files:** none

- [ ] **Step 1: Run the full rsleigh-decompile test suite**

```bash
cd /Users/shane/repos/rsleigh
cargo test -p rsleigh-decompile 2>&1 | tail -20
```

Expected: all test suites pass — double_negation, rsp_local_naming, sub_as_cmp, jg_condition_recovery, string_false_positive. Zero failures.

- [ ] **Step 2: Run the full test-harness suite**

```bash
cd /Users/shane/repos/rsleigh
cargo test -p test-harness 2>&1 | tail -10
```

Expected:
```
test result: ok. 9 passed; 0 failed
```

- [ ] **Step 3: Commit if any fixes were needed**

If any regression needed a fix not covered above, commit it. If everything was clean, no additional commit needed.
