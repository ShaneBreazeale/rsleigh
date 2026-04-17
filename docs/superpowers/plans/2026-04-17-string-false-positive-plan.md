# String Literal False Positive Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop PE `.rdata` pointer-table entries from being emitted as 2-char string literals when used as Load addresses.

**Architecture:** Add `format_const_ctx_load` (min_len=4 variant of `format_const_ctx`) in `printer.rs`. Patch the two `*(addr)` construction sites in `format_cond_operand` and `format_store_operand` to use it when the Load pointer resolves to a `Const`.

**Tech Stack:** Rust, `rsleigh-decompile` crate, `printer.rs`.

---

## Background for the implementer

**The bug:** In `printer.rs`, `format_const_ctx` calls `try_read_string(addr)`. For PE `.rdata`, every 8-byte pointer has `0x00` at byte 2 (e.g. `60 40 00 40 01 00 00 00` = VA `0x140004060`). `try_read_string` reads bytes 0–1 as a 2-char string. The current guard is `s.len() < 2`, so 2-char results like `` `@ `` or `ȡ` pass through and get printed as string literals inside dereferences: `` *(("`@")) ``.

**The fix:** When a `Const` is being formatted as a Load address (the thing being dereferenced in `*(addr)`), require at least 4 printable chars before treating it as a string. This is `format_const_ctx_load`.

**Two call sites produce `*(addr)`:**
1. `format_cond_operand` around line 9577–9579
2. `format_store_operand` around line 10082–10085

At each site the pattern is:
```rust
let addr = format_cond_operand(*ptr, ssa, ctx, tracker);  // recursive call
return format!("*({})", addr);
```
When `*ptr` resolves to a `Const`, that recursive call hits `format_const_ctx` with min_len=2. The fix intercepts Const pointer values before the recursive call.

**Key functions (do not modify):**
- `try_read_string(va, ctx)` — reads bytes from the binary at a VA, returns `Option<String>`
- `format_const_ctx(val, size, ctx)` — formats a Const, tries string resolution with min_len=2
- `format_const(val, size)` — formats a Const as hex/decimal (fallback)

**Register offsets for reference:** not needed for this fix — it's pure printer logic.

---

## Files

- **Modify:** `rsleigh-decompile/src/printer.rs` — add `format_const_ctx_load`, patch two call sites
- **Create:** `rsleigh-decompile/tests/string_false_positive.rs` — 3 tests

---

### Task 1: Write failing tests

**Files:**
- Create: `rsleigh-decompile/tests/string_false_positive.rs`

- [ ] **Step 1: Create the test file**

```rust
//! Regression tests for string literal false positives in Load addresses.
//!
//! Spec: docs/superpowers/specs/2026-04-17-string-false-positive-design.md

/// Test 1: the 4 known false-positive strings must not appear in 0x140001154 output.
/// Decompile __tmainCRTStartup (0x140001154) from cb_baristas_secret_x64.exe.
/// Before the fix this emits *(*("È¡")), *("`@"), etc.
#[test]
fn no_string_literal_as_load_address() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => { eprintln!("skipping: fixture not found"); return; }
    };
    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => { eprintln!("skipping: PE parse error: {}", e); return; }
    };
    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001154;
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
    let off = match file_off {
        Some(o) => o,
        None => { eprintln!("skipping: VA not in any section"); return; }
    };
    let func_len = 0x400_usize.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            use pcode_ir::PcodeOp;
            use rsleigh_api::{Architecture, Decoder};
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
            // None of the 4 known false-positive string literals should appear
            let bad: Vec<&str> = out.lines()
                .filter(|l| {
                    l.contains("\"È¡\"") || l.contains("\"hS\"")
                        || l.contains("\"`@\"") || l.contains("\"0@\"")
                })
                .collect();
            assert!(
                bad.is_empty(),
                "string false positives still present in output:\n{}",
                bad.join("\n")
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Test 2: the load positions must show DAT_ names or hex addresses, not empty/gibberish.
/// Checks that suppressing the false-positive string doesn't produce a blank address.
#[test]
fn load_address_uses_dat_or_hex() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => { eprintln!("skipping: fixture not found"); return; }
    };
    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => { eprintln!("skipping: PE parse error: {}", e); return; }
    };
    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001154;
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
    let off = match file_off {
        Some(o) => o,
        None => { eprintln!("skipping: VA not in any section"); return; }
    };
    let func_len = 0x400_usize.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            use pcode_ir::PcodeOp;
            use rsleigh_api::{Architecture, Decoder};
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
            // The replaced addresses should appear as DAT_ names or hex constants
            let has_dat_or_hex = out.contains("DAT_") || out.contains("0x14000568")
                || out.contains("0x14000569") || out.contains("0x1400056")
                || out.contains("0x140005");
            assert!(
                has_dat_or_hex,
                "expected DAT_ or hex address in load positions after fix, got output:\n{}",
                out
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Test 3: real long strings in .rdata are still resolved as string literals.
/// Function 0x140001a68 passes a long encrypted string to a call — it must still appear.
#[test]
fn real_strings_still_resolved() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => { eprintln!("skipping: fixture not found"); return; }
    };
    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => { eprintln!("skipping: PE parse error: {}", e); return; }
    };
    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001a68;
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
    let off = match file_off {
        Some(o) => o,
        None => { eprintln!("skipping: VA not in any section"); return; }
    };
    let func_len = 0x400_usize.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            use pcode_ir::PcodeOp;
            use rsleigh_api::{Architecture, Decoder};
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
            // The long encrypted string "v`cav``|rarqzprQAVD>" (19 chars) must still appear
            assert!(
                out.contains("\"v`cav"),
                "real string literal was suppressed by the fix:\n{}",
                out
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
test no_string_literal_as_load_address ... FAILED   ← must fail (bug not fixed yet)
test load_address_uses_dat_or_hex ... ok or FAILED  ← may pass or fail
test real_strings_still_resolved ... ok             ← must pass (real strings work)
```

If `no_string_literal_as_load_address` passes instead of failing, the bug is not reproducible — check the binary path and function VA.

- [ ] **Step 3: Commit the failing tests**

```bash
cd /Users/shane/repos/rsleigh
git add rsleigh-decompile/tests/string_false_positive.rs
git commit -m "test: add failing string false positive tests"
```

---

### Task 2: Implement the fix in printer.rs

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs`

- [ ] **Step 1: Add `format_const_ctx_load` after `format_const_ctx`**

Find `fn format_const_ctx` in `printer.rs` (around line 10231). It ends around line 10262. Insert the new function immediately after it:

```rust
fn format_const_ctx_load(val: u64, size: u32, ctx: &PrintCtx) -> String {
    // Like format_const_ctx but requires ≥4 chars for string resolution.
    // Used when val is the address being dereferenced in *(val) — prevents
    // PE .rdata pointer-table entries (null at byte 2) from being misread
    // as 2-char string literals.
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    if size >= 4 && val > 0x200 {
        if let Some(s) = try_read_string(val, ctx) {
            if s.len() >= 4 {
                return format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"));
            }
        }
        if let Some(name) = ctx.imports.get(&val) {
            return name.clone();
        }
        if let Some(binary) = ctx.binary {
            if let Some(vtable_name) = crate::imports::resolve_pe_vtable(val, binary) {
                return vtable_name;
            }
        }
        if let Some(ws) = try_read_wide_string(val, ctx) {
            return ws;
        }
    }
    format_const(val, size)
}
```

- [ ] **Step 2: Patch `format_cond_operand` — the first `*(addr)` site**

Find the `// Non-stack Load` comment around line 9577. The current code is:

```rust
        // Non-stack Load: dereference a pointer (e.g., *s for string access)
        let addr = format_cond_operand(*ptr, ssa, ctx, tracker);
        return format!("*({})", addr);
```

Replace it with:

```rust
        // Non-stack Load: dereference a pointer (e.g., *s for string access)
        // For Const load addresses, use min_len=4 to avoid pointer-table bytes
        // being misread as 2-char strings.
        let addr = {
            let mut pid = *ptr;
            for _ in 0..4 {
                if let Expr::Var(next) = ssa.vars[pid.0 as usize].expr { pid = next; } else { break; }
            }
            if let Expr::Const(val, sz) = ssa.vars[pid.0 as usize].expr {
                format_const_ctx_load(val, sz, ctx)
            } else {
                format_cond_operand(*ptr, ssa, ctx, tracker)
            }
        };
        return format!("*({})", addr);
```

- [ ] **Step 3: Patch `format_store_operand` — the second `*(addr)` site**

Find the `// Non-stack load` comment around line 10082. The current code is:

```rust
            // Non-stack load (array element, struct field, etc.)
            // Show as *(addr) or resolve to array syntax
            let addr = format_store_operand(*ptr, ssa, ctx, tracker);
            return format!("*({})", addr);
```

Replace it with:

```rust
            // Non-stack load (array element, struct field, etc.)
            // For Const load addresses, use min_len=4 to avoid pointer-table bytes
            // being misread as 2-char strings.
            let addr = {
                let mut pid = *ptr;
                for _ in 0..4 {
                    if let Expr::Var(next) = ssa.vars[pid.0 as usize].expr { pid = next; } else { break; }
                }
                if let Expr::Const(val, sz) = ssa.vars[pid.0 as usize].expr {
                    format_const_ctx_load(val, sz, ctx)
                } else {
                    format_store_operand(*ptr, ssa, ctx, tracker)
                }
            };
            return format!("*({})", addr);
```

- [ ] **Step 4: Build**

```bash
cd /Users/shane/repos/rsleigh
cargo build -p rsleigh-decompile 2>&1 | grep "^error"
```

Expected: no errors.

- [ ] **Step 5: Run all three tests**

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

If `no_string_literal_as_load_address` still fails, the Const is being reached through a different path. Check the decompiled output to see what string is still present, trace the call path, and add an equivalent patch at the relevant `*(addr)` site.

- [ ] **Step 6: Commit**

```bash
cd /Users/shane/repos/rsleigh
git add rsleigh-decompile/src/printer.rs
git commit -m "printer: use min_len=4 for string resolution when Const is a Load address"
```

---

### Task 3: Full regression suite

**Files:** none (running existing tests)

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
