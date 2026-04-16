# RSP-Relative Local Variable Naming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `RSP - 8 - 45 + 1`-style raw arithmetic in decompiler output by (1) collapsing chained frame-register arithmetic in fold.rs and (2) adding RSP-relative local naming in printer.rs to match the existing RBP path.

**Architecture:** Two independent fixes. fold.rs gains a constant-folding rule that collapses `BinOp(op2, BinOp(op1, FRAME_REG, C1), C2)` → `BinOp(combined_op, FRAME_REG, combined_C)` applied during `fold_once`'s Pass 2. printer.rs gains `get_rsp_offset()` modelled on the existing `get_rbp_offset()`, wired into `try_stack_var_name()`, `format_addr()`, and the `#DECLARATIONS` scan.

**Tech Stack:** Rust stable, `rsleigh-decompile` crate, `pcode_ir::AddressSpaceId`, `rsleigh_decompile::ir::{BinOpKind, Expr, VarDef, VarId, SsaCfg}`, `rsleigh_api::{Architecture, Decoder}`, `rsleigh_decompile::decompile_with_binary`.

---

## File Structure

| File | Change |
|---|---|
| `rsleigh-decompile/src/fold.rs` | Add `combine_frame_offset()` helper + chained-frame-reg folding rule in `simplify_expr()` |
| `rsleigh-decompile/src/printer.rs` | Add `get_rsp_offset()` (~line 9818), extend `try_stack_var_name()` (~line 9768), extend `format_addr()` (~line 9837), extend `#DECLARATIONS` scan (~line 6578) |
| `rsleigh-decompile/tests/rsp_local_naming.rs` | New test file: two `#[test]` functions (fold rule unit test + integration test) |

No new IR types. No changes to `ssa.rs` or `ir.rs`.

---

## Context Reference

**fold.rs constants (top of file):**
```rust
const RSP_OFFSET: u64 = 32;   // x86-64 RSP
const ESP_OFFSET: u64 = 16;   // x86-32 ESP
```

fold.rs has no `RBP_OFFSET` constant — the value `40` is inlined in local scopes. The spec says to add the folding rule for RSP (offset 32) only, since RBP-relative frames already work through `get_rbp_offset`.

**printer.rs constants (top of file, lines 6-10):**
```rust
const RBP_OFFSET: u64 = 40;
const EBP_OFFSET: u64 = 20;
const RSP_OFFSET: u64 = 32;
const ESP_OFFSET: u64 = 32; // ESP is at same offset as RSP (lower 4 bytes)
const RIP_OFFSET: u64 = 648;
```

**`get_rbp_offset` signature (printer.rs line 9801):**
```rust
fn get_rbp_offset(id: VarId, ssa: &SsaCfg) -> Option<u64>
```
Returns the magnitude of the negative offset (e.g., `RBP - 0x30` → `Some(0x30)`).  
Uses `resolve_through_vars(id, ssa)` to chase one level of `Expr::Var` indirection.  
Recognises only `Expr::BinOp(BinOpKind::Add, base_id, off_id)` where `base` is RBP/EBP and `off_id` resolves to a large (negative-in-two's-complement) constant.

**`try_stack_var_name` (printer.rs line 9768):** calls `get_rbp_offset`, formats `var_{:x}`.  
Note: RBP locals print as `var_XX` here but are renamed to `local_XX` in the `#DECLARATIONS` pass.

**`format_addr` (printer.rs line 9837):** calls `get_rbp_offset`, formats `RBP - 0x{:x}`.  
Also falls through to a second `BinOp(Add, RBP/EBP, off_id)` check for positive offsets.

**`#DECLARATIONS` scan (printer.rs ~line 6578):** scans rendered text for `var_XX` tokens; computes offset gaps; emits `local_XX` / array declarations; renames `var_XX` → `local_XX` throughout output.

**`simplify_expr` (fold.rs line 997):** called from `fold_once` Pass 2 (line 159). Receives an owned `Expr` and a `&[VarDef]` slice — NOT a mutable reference. Returns a new `Expr`. No `ssa.new_var()` calls are possible here. ← **Important constraint**: the rule must rewrite in-place by replacing the outer expression's VarIds. Because the inner `BinOp` VarId becomes unused (use_count drops to 0) it will be eliminated by `eliminate_dead` in the same fold round.

**`SsaCfg::new_var` (ir.rs line 248):** allocates a new `VarDef` and returns its `VarId`. Used in fold.rs when a new expression node is needed that requires a `&mut SsaCfg`. Needed for the fold pass version that has `&mut ssa`.

---

## Task 1: Add chained-frame-register folding rule in fold.rs

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs` (lines ~997–1074)

### Background

`simplify_expr(expr: Expr, vars: &[VarDef]) -> Expr` takes ownership of `expr` and returns a new `Expr`. It cannot call `ssa.new_var()`. The rule must replace the outer `BinOp`'s operands in-place.

The pattern is:
```
BinOp(op2, inner_id, c2_id)
  where vars[inner_id] = BinOp(op1, frame_id, c1_id)
  where vars[frame_id].varnode.space == Register && .offset == RSP_OFFSET && .expr == Unknown
  where vars[c1_id].expr == Const(c1, sz)
  where vars[c2_id].expr == Const(c2, _)
```

Because `simplify_expr` only has `vars: &[VarDef]` (not `&mut ssa`), the result must be expressed as `BinOp(combined_op, frame_id, c1_id)` where we overwrite the constant in `c1_id` in-place. But `vars` is `&[VarDef]`, so we cannot mutate. Instead, return `Expr::BinOp(combined_op, frame_id, c2_id)` reusing one of the existing const VarIds — the caller will re-run simplify in the next round, collapsing any remaining chains. However, this would still leave `c1` orphaned (use_count decays via `eliminate_dead`).

The simplest correct approach: return a new `Expr::BinOp(combined_op, frame_id, c1_id)` but we need to store `combined_C` somewhere. Since we can't create a new VarDef in `simplify_expr`, we add the rule to the `fold_once` loop where `&mut ssa` is available — specifically, add a dedicated new pass just after Pass 2.

- [ ] **Step 1: Add `combine_frame_offset` helper at the bottom of fold.rs**

Append after the closing `}` of `mba_simplify_expr` (around line 994):

```rust
/// Combine two chained frame-register offset operations into a single (op, const) pair.
///
/// Given: `(FRAME_REG op1 C1) op2 C2`, returns `(result_op, result_const)` such that
/// `FRAME_REG result_op result_const` is numerically equivalent.
///
/// All arithmetic is signed 64-bit. The returned constant is the raw bit pattern
/// to store in a `Expr::Const` (i.e., two's-complement u64).
fn combine_frame_offset(op1: BinOpKind, c1: u64, op2: BinOpKind, c2: u64) -> (BinOpKind, u64) {
    // Treat the constants as signed i64 for arithmetic, then convert back.
    let s1 = c1 as i64;
    let s2 = c2 as i64;
    // Compute the signed offset relative to the frame register:
    //   FRAME op1 C1 means: FRAME + (if Sub { -C1 } else { C1 })
    let delta1: i64 = if matches!(op1, BinOpKind::Sub) { -s1 } else { s1 };
    let delta2: i64 = if matches!(op2, BinOpKind::Sub) { -s2 } else { s2 };
    let combined = delta1.wrapping_add(delta2);
    if combined < 0 {
        (BinOpKind::Sub, (-combined) as u64)
    } else {
        (BinOpKind::Add, combined as u64)
    }
}
```

- [ ] **Step 2: Run `cargo check -p rsleigh-decompile` — verify compiles**

```bash
cargo check -p rsleigh-decompile 2>&1 | tail -5
```
Expected: no errors.

- [ ] **Step 3: Add the folding pass in `fold_once` after Pass 2 (line ~168)**

In `fold_once`, immediately after the existing constant-folding block (after line 168, before `// MBA deobfuscation`), insert:

```rust
    // Pass 2b: Collapse chained frame-register arithmetic.
    // Pattern: (FRAME_REG op1 C1) op2 C2 → FRAME_REG combined_op combined_C
    // Only handles RSP (offset 32) since RBP frames already work via get_rbp_offset.
    for v in 0..ssa.vars.len() {
        let (op2, inner_id, c2_id) = match &ssa.vars[v].expr {
            Expr::BinOp(op, inner, c2) if matches!(op, BinOpKind::Add | BinOpKind::Sub) => {
                (*op, *inner, *c2)
            }
            _ => continue,
        };
        // c2 must be a constant
        let c2_val = match ssa.vars[c2_id.0 as usize].expr {
            Expr::Const(val, _) => val,
            _ => continue,
        };
        // inner must be (FRAME_REG op1 C1)
        let (op1, frame_id, c1_id) = match &ssa.vars[inner_id.0 as usize].expr {
            Expr::BinOp(op, frame, c1) if matches!(op, BinOpKind::Add | BinOpKind::Sub) => {
                (*op, *frame, *c1)
            }
            _ => continue,
        };
        // c1 must be a constant
        let c1_val = match ssa.vars[c1_id.0 as usize].expr {
            Expr::Const(val, _) => val,
            _ => continue,
        };
        // frame must be RSP with Expr::Unknown (initial SSA value, not a computed sub-expression)
        let frame_vdef = &ssa.vars[frame_id.0 as usize];
        if frame_vdef.varnode.space != AddressSpaceId::Register
            || frame_vdef.varnode.offset != RSP_OFFSET
            || !matches!(frame_vdef.expr, Expr::Unknown)
        {
            continue;
        }
        // Combine
        let (combined_op, combined_c) = combine_frame_offset(op1, c1_val, op2, c2_val);
        let sz = ssa.vars[c1_id.0 as usize].size;
        let new_const_id = ssa.new_var(
            ssa.vars[c1_id.0 as usize].varnode,
            Expr::Const(combined_c, sz),
            sz,
        );
        ssa.vars[v].expr = Expr::BinOp(combined_op, frame_id, new_const_id);
    }
```

- [ ] **Step 4: Run `cargo check -p rsleigh-decompile` — verify compiles**

```bash
cargo check -p rsleigh-decompile 2>&1 | tail -5
```
Expected: no errors.

- [ ] **Step 5: Commit fold.rs changes**

```bash
cd /Users/shane/repos/rsleigh
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: collapse chained RSP frame-register arithmetic (RSP-C1-C2 → RSP-combined)"
```

---

## Task 2: Write failing test for fold constant combining

**Files:**
- Create: `rsleigh-decompile/tests/rsp_local_naming.rs`

- [ ] **Step 1: Create the test file with a failing assertion**

Create `/Users/shane/repos/rsleigh/rsleigh-decompile/tests/rsp_local_naming.rs`:

```rust
//! Tests for RSP-relative local variable naming.
//!
//! Plan: docs/superpowers/plans/2026-04-16-rsp-local-naming-plan.md
//! Spec: docs/superpowers/specs/2026-04-16-rsp-local-naming-design.md

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{BinOpKind, Expr};
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn decode_x64(bytes: &[u8], base: u64) -> Vec<(u64, Instruction)> {
    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = base + off as u64;
        match dec.decode(&bytes[off..], addr) {
            Ok(inst) => {
                let l = inst.len as usize;
                let is_ret = inst.ops.iter().any(|op| matches!(op, PcodeOp::Return { .. }));
                insts.push((addr, inst));
                off += l;
                if is_ret { break; }
            }
            Err(_) => break,
        }
    }
    insts
}

/// Verify that chained RSP arithmetic is collapsed after fold.
///
/// Encodes:  sub rsp, 8      (48 83 EC 08)
///           sub rsp, 0x2d   (48 83 EC 2D)
///           ret             (C3)
///
/// After fold, no VarDef should have the expression
/// BinOp(Sub/Add, BinOp(Sub/Add, RSP_var, _), _)
/// where the innermost BinOp's left operand is the RSP Unknown var.
/// In other words, chained nesting around RSP must have been flattened.
#[test]
fn fold_collapses_chained_rsp_arithmetic() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // sub rsp, 8  ;  sub rsp, 0x2d  ;  ret
            let bytes: &[u8] = &[
                0x48, 0x83, 0xEC, 0x08,   // sub rsp, 8
                0x48, 0x83, 0xEC, 0x2D,   // sub rsp, 0x2d
                0xC3,                     // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::SysV);
            fold_with_cc(&mut ssa, CallingConv::SysV);

            // RSP is at register offset 32.
            let rsp_offset: u64 = 32;

            // Find the RSP Unknown var (the initial SSA value of RSP).
            let rsp_unknown = ssa.vars.iter().find(|v| {
                v.varnode.space == AddressSpaceId::Register
                    && v.varnode.offset == rsp_offset
                    && matches!(v.expr, Expr::Unknown)
            });
            let rsp_id = match rsp_unknown {
                Some(v) => v.id,
                None => return, // RSP Unknown may have been eliminated — no issue
            };

            // Assert no VarDef has a nested BinOp with RSP_Unknown at the inner left:
            //   BinOp(_, BinOp(_, RSP_id, _), _)
            for vdef in &ssa.vars {
                if let Expr::BinOp(_, outer_left, _) = vdef.expr {
                    let inner = &ssa.vars[outer_left.0 as usize];
                    if let Expr::BinOp(_, inner_left, _) = inner.expr {
                        assert_ne!(
                            inner_left, rsp_id,
                            "chained RSP arithmetic was NOT collapsed: VarDef #{} still has nested BinOp with RSP at inner left",
                            vdef.id.0
                        );
                    }
                }
            }
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Verify that decompiling a minimal function with an RSP-relative buffer access
/// produces `local_` variable names, not raw `RSP` arithmetic.
///
/// Encodes:
///   sub rsp, 0x40            (48 83 EC 40)
///   mov byte ptr [rsp+0x10], 0x42  (C6 44 24 10 42)
///   ret                      (C3)
///
/// The buffer write at RSP+0x10 should appear as local_30[...] or similar,
/// NOT as `RSP + 0x10` or `RSP - 0x30`.
#[test]
fn decompile_rsp_relative_access_uses_local_name() {
    use rsleigh_decompile::decompile_with_binary;
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // sub rsp, 0x40  ;  mov byte ptr [rsp+0x10], 0x42  ;  ret
            let bytes: &[u8] = &[
                0x48, 0x83, 0xEC, 0x40,         // sub rsp, 0x40
                0xC6, 0x44, 0x24, 0x10, 0x42,   // mov byte ptr [rsp+0x10], 0x42
                0xC3,                           // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let out = decompile_with_binary(
                Architecture::X86_64,
                &insts,
                None,
                None,
            );
            // Must contain a local_ name for the buffer slot.
            assert!(
                out.contains("local_"),
                "expected 'local_' variable name in output, got:\n{}",
                out
            );
            // Must NOT contain chained RSP arithmetic like "RSP - N -"
            assert!(
                !out.contains("RSP - ") || !out.contains(" - "),
                "output contains chained RSP arithmetic:\n{}",
                out
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
```

- [ ] **Step 2: Run failing test to confirm it fails before implementation**

```bash
cd /Users/shane/repos/rsleigh
cargo test -p rsleigh-decompile --test rsp_local_naming -- --nocapture 2>&1 | tail -30
```

Expected: `fold_collapses_chained_rsp_arithmetic` — FAIL or PASS (fold task may already be done); `decompile_rsp_relative_access_uses_local_name` — FAIL with "expected 'local_' variable name".

- [ ] **Step 3: Commit the failing test file**

```bash
git add rsleigh-decompile/tests/rsp_local_naming.rs
git commit -m "test(rsp-naming): add failing tests for RSP local variable naming"
```

---

## Task 3: Add `get_rsp_offset()` in printer.rs

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs` (~line 9818)

`get_rbp_offset` (line 9801) recognises only `BinOp(Add, base, off)` because P-code represents `RBP - 0x30` as `RBP + (u64)(-0x30)` (two's-complement large constant). RSP-relative locals after fold.rs fixup will be represented as `BinOp(Sub, RSP_base, Const(N))` with a small positive constant (the actual subtracted amount), which is different. The new function must recognise this pattern.

- [ ] **Step 1: Insert `get_rsp_offset` immediately after `get_rbp_offset` (line 9818)**

In `rsleigh-decompile/src/printer.rs`, after the closing `}` of `get_rbp_offset` (line 9818), before `fn get_const_val`, insert:

```rust
/// Get the signed frame offset for an RSP-relative access.
///
/// After fold.rs collapses chained arithmetic, RSP-relative locals have the form:
///   `BinOp(Sub, RSP_base, Const(N))` → returns `Some(-(N as i64))` (negative = local below RSP)
///   `BinOp(Add, RSP_base, Const(N))` → returns `Some(N as i64)` (positive = above RSP / spill area)
///
/// Returns `None` if the expression is not a single-level RSP ± constant.
fn get_rsp_offset(id: VarId, ssa: &SsaCfg) -> Option<i64> {
    let expr = resolve_through_vars(id, ssa);
    match &expr {
        Expr::BinOp(BinOpKind::Sub, base_id, off_id) => {
            let base = ssa.var(*base_id);
            if base.varnode.space == AddressSpaceId::Register
                && base.varnode.offset == RSP_OFFSET
                && matches!(base.expr, Expr::Unknown)
            {
                let c = get_const_val_expr(&ssa.var(*off_id).expr, ssa)?;
                return Some(-(c as i64));
            }
            None
        }
        Expr::BinOp(BinOpKind::Add, base_id, off_id) => {
            let base = ssa.var(*base_id);
            if base.varnode.space == AddressSpaceId::Register
                && base.varnode.offset == RSP_OFFSET
                && matches!(base.expr, Expr::Unknown)
            {
                let c = get_const_val_expr(&ssa.var(*off_id).expr, ssa)?;
                return Some(c as i64);
            }
            None
        }
        _ => None,
    }
}
```

- [ ] **Step 2: Run `cargo check -p rsleigh-decompile` — verify compiles**

```bash
cargo check -p rsleigh-decompile 2>&1 | tail -5
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add rsleigh-decompile/src/printer.rs
git commit -m "printer: add get_rsp_offset() for RSP-relative stack variable extraction"
```

---

## Task 4: Update `try_stack_var_name` to call `get_rsp_offset`

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs` (line ~9768)

Current body of `try_stack_var_name` (lines 9768–9777):
```rust
fn try_stack_var_name(addr_id: VarId, ssa: &SsaCfg) -> Option<String> {
    if let Some(offset) = get_rbp_offset(addr_id, ssa) {
        return Some(format!("var_{:x}", offset));
    }
    // x86-32: positive EBP offsets are parameters (EBP+8 = param_0, EBP+12 = param_1, ...)
    if let Some(param_name) = get_ebp_param(addr_id, ssa) {
        return Some(param_name);
    }
    None
}
```

RSP-relative locals have negative signed offset (e.g., `RSP - 0x30` → `get_rsp_offset` returns `-0x30`). We format the magnitude as `var_{:x}` to match the RBP convention, then the `#DECLARATIONS` pass renames `var_XX` → `local_XX`.

- [ ] **Step 1: Add RSP branch after the RBP branch in `try_stack_var_name`**

Replace the function body:

```rust
fn try_stack_var_name(addr_id: VarId, ssa: &SsaCfg) -> Option<String> {
    if let Some(offset) = get_rbp_offset(addr_id, ssa) {
        return Some(format!("var_{:x}", offset));
    }
    // RSP-relative locals (omit-frame-pointer functions): RSP - N → var_N
    if let Some(signed_off) = get_rsp_offset(addr_id, ssa) {
        if signed_off < 0 {
            return Some(format!("var_{:x}", (-signed_off) as u64));
        }
    }
    // x86-32: positive EBP offsets are parameters (EBP+8 = param_0, EBP+12 = param_1, ...)
    if let Some(param_name) = get_ebp_param(addr_id, ssa) {
        return Some(param_name);
    }
    None
}
```

- [ ] **Step 2: Run `cargo check -p rsleigh-decompile`**

```bash
cargo check -p rsleigh-decompile 2>&1 | tail -5
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add rsleigh-decompile/src/printer.rs
git commit -m "printer: wire get_rsp_offset into try_stack_var_name for RSP-relative locals"
```

---

## Task 5: Update `format_addr` to handle RSP-relative accesses

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs` (line ~9837)

Current `format_addr` (lines 9837–9860) starts:
```rust
fn format_addr(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    // Try stack variable first (RBP or EBP relative, negative offset = local)
    if let Some(offset) = get_rbp_offset(id, ssa) {
        return format!("RBP - 0x{:x}", offset);
    }
    // Try x86-32 parameter (positive EBP offset)
    if let Some(param) = get_ebp_param(id, ssa) {
        return param;
    }
    // ... fallthrough BinOp checks ...
    format_var(id, ssa, ctx)
}
```

For pointer-expression contexts (e.g., `*(local_30 + 1)` in array indexing), `format_addr` is the function that formats the base address. We want RSP-relative locals to format the same way as RBP locals: return the local name so the caller can apply `[index]` indexing.

- [ ] **Step 1: Add RSP branch in `format_addr` after the `get_ebp_param` branch**

Find the existing body and replace with:

```rust
fn format_addr(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    // Try stack variable first (RBP or EBP relative, negative offset = local)
    if let Some(offset) = get_rbp_offset(id, ssa) {
        return format!("RBP - 0x{:x}", offset);
    }
    // Try x86-32 parameter (positive EBP offset)
    if let Some(param) = get_ebp_param(id, ssa) {
        return param;
    }
    // RSP-relative locals (omit-frame-pointer functions)
    if let Some(signed_off) = get_rsp_offset(id, ssa) {
        if signed_off < 0 {
            return format!("var_{:x}", (-signed_off) as u64);
        }
    }

    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register
            && (base.varnode.offset == RBP_OFFSET || base.varnode.offset == EBP_OFFSET)
        {
            if let Some(val) = get_const_val(*off_id, ssa) {
                return format_rbp_offset(val);
            }
        }
    }

    format_var(id, ssa, ctx)
}
```

- [ ] **Step 2: Run `cargo check -p rsleigh-decompile`**

```bash
cargo check -p rsleigh-decompile 2>&1 | tail -5
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add rsleigh-decompile/src/printer.rs
git commit -m "printer: wire get_rsp_offset into format_addr for RSP-relative locals"
```

---

## Task 6: Extend `#DECLARATIONS` scan to collect `local_` names from RSP slots

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs` (~line 6578)

The `#DECLARATIONS` block (starting ~line 6578) already scans for `var_XX` tokens in the rendered text, computes gap-based sizes, and emits `local_XX` declarations (renaming `var_XX` → `local_XX` in the final pass).

Because `try_stack_var_name` and `format_addr` now emit `var_{:x}` for RSP locals (same as RBP locals), the existing `var_XX` scan will automatically pick them up — **no additional change needed for the declaration scan itself**.

However, there is one subtlety: the `try_stack_var_name` path produces `var_XX` (renamed to `local_XX`), but the `format_addr` RSP path also returns `var_{:x}`. Both feed into the same downstream scan. Verify this by checking the output of the test added in Task 2.

- [ ] **Step 1: Run the new tests now**

```bash
cd /Users/shane/repos/rsleigh
cargo test -p rsleigh-decompile --test rsp_local_naming -- --nocapture 2>&1
```

Expected: both tests PASS. If `decompile_rsp_relative_access_uses_local_name` still fails, read the actual output and proceed to Step 2.

- [ ] **Step 2 (conditional): If `local_` still absent, add explicit `local_` scan to `#DECLARATIONS`**

Only do this step if Step 1 shows `local_` is missing from output. The `#DECLARATIONS` block at line 6578 already scans `var_XX`. If RSP vars are being rendered as `local_XX` directly (bypassing the rename step), add a parallel scan for `local_` prefix:

In the block that collects `stack_vars` (around line 6579), after the `var_` scan closes its `}` at ~line 6610, add:

```rust
        // Also collect RSP-relative locals that may already carry the local_ prefix.
        {
            let mut search_from = 0;
            while let Some(pos) = all_text[search_from..].find("local_") {
                let abs_pos = search_from + pos;
                let before_ok = abs_pos == 0 || {
                    let b = all_text.as_bytes()[abs_pos - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                if before_ok {
                    let hex_start = abs_pos + 6; // after "local_"
                    let mut hex_end = hex_start;
                    while hex_end < all_text.len() && all_text.as_bytes()[hex_end].is_ascii_hexdigit() {
                        hex_end += 1;
                    }
                    if hex_end > hex_start {
                        let after_ok = hex_end >= all_text.len() || {
                            let b = all_text.as_bytes()[hex_end];
                            !b.is_ascii_alphanumeric() && b != b'_'
                        };
                        if after_ok {
                            let vname = format!("var_{}", &all_text[hex_start..hex_end]);
                            if !aliases.contains_key(&vname) {
                                stack_vars.insert(vname);
                            }
                        }
                    }
                }
                search_from = search_from + pos + 6;
            }
        }
```

- [ ] **Step 3: Run tests again and confirm both pass**

```bash
cargo test -p rsleigh-decompile --test rsp_local_naming -- --nocapture 2>&1
```
Expected: both PASS.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/printer.rs
git commit -m "printer: RSP-relative locals now collected in declarations pass"
```

---

## Task 7: Integration test against check2 + full suite

**Files:**
- Modify: `rsleigh-decompile/tests/rsp_local_naming.rs`

- [ ] **Step 1: Add integration test for check2**

Append to `rsleigh-decompile/tests/rsp_local_naming.rs`:

```rust
/// Integration test: decompile check2 (0x140001a68) from the baristas_secret binary.
///
/// Assert:
///   1. Output does NOT contain `RSP - ` followed by a digit (chained raw arithmetic).
///   2. Output DOES contain at least one `local_` variable.
///
/// Skips gracefully if the fixture binary is not present.
#[test]
fn check2_has_no_chained_rsp_arithmetic() {
    use rsleigh_decompile::decompile_with_binary;

    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping check2_has_no_chained_rsp_arithmetic: fixture binary not found");
            return;
        }
    };

    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: PE parse error: {}", e);
            return;
        }
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
        None => {
            eprintln!("skipping: func_va not in any section");
            return;
        }
    };
    let func_len = 0x200_usize.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            let insts = decode_x64(&bytes, func_va);
            let out = decompile_with_binary(
                Architecture::X86_64,
                &insts,
                Some(&data),
                Some(std::path::Path::new(path)),
            );

            // Must NOT contain raw chained RSP arithmetic: "RSP - N -"
            // (a minus sign followed by a hex digit, then space-dash, signals a chain)
            let has_chain = out.lines().any(|l| {
                // Match pattern "RSP - <hex> -" or "RSP - <hex><hex>... -"
                if let Some(idx) = l.find("RSP - ") {
                    let rest = &l[idx + 6..];
                    // Find next " -" after the first constant
                    rest.chars().next().map_or(false, |c| c.is_ascii_hexdigit())
                        && rest.contains(" -")
                } else {
                    false
                }
            });
            assert!(
                !has_chain,
                "check2 output still contains chained RSP arithmetic.\nSnippet:\n{}",
                out.lines()
                    .filter(|l| l.contains("RSP - "))
                    .collect::<Vec<_>>()
                    .join("\n")
            );

            // Must contain at least one local_ variable
            assert!(
                out.contains("local_"),
                "check2 output has no local_ variables:\n{}",
                out
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
```

- [ ] **Step 2: Add `goblin` to `rsleigh-decompile/Cargo.toml` if not present**

```bash
grep "goblin" /Users/shane/repos/rsleigh/rsleigh-decompile/Cargo.toml
```

If missing, add to `[dev-dependencies]`:
```toml
goblin = { version = "0.9", default-features = false, features = ["pe"] }
```

- [ ] **Step 3: Run the new test**

```bash
cd /Users/shane/repos/rsleigh
cargo test -p rsleigh-decompile --test rsp_local_naming check2_has_no_chained_rsp_arithmetic -- --nocapture 2>&1
```

Expected: PASS (or skip if binary absent).

- [ ] **Step 4: Run full decompile test suite — must be zero new failures**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -20
```

Expected: all tests pass (or same skip count as before for fixture-dependent tests).

- [ ] **Step 5: Run full test-harness suite**

```bash
cargo test -p test-harness 2>&1 | tail -30
```

Expected: all tests pass. In particular the 14-point pseudocode quality audit tests must not regress.

- [ ] **Step 6: Commit**

```bash
git add rsleigh-decompile/tests/rsp_local_naming.rs rsleigh-decompile/Cargo.toml
git commit -m "test(rsp-naming): add check2 integration test for RSP chained arithmetic fix"
```

---

## Task 8: Final verification

- [ ] **Step 1: Spot-check decompiler output for check2 directly**

```bash
cd /Users/shane/repos/rsleigh
cargo run -p rsleigh-cli -- /Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe 0x140001a68 2>&1 | head -40
```

Expected: output contains `local_XX` variable names for buffer accesses; no `RSP - 8 -` or similar chained expressions.

- [ ] **Step 2: Run the full test suite one final time**

```bash
cargo test -p test-harness 2>&1 | tail -10
```

Expected: all tests pass.

- [ ] **Step 3: Final commit (if any files changed)**

```bash
git status
# Only commit if there are uncommitted changes
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Gap 1: Constant folding of chained frame-register arithmetic in fold.rs | Task 1 |
| Gap 2: `get_rsp_offset()` function in printer.rs | Task 3 |
| `try_stack_var_name()` calls `get_rsp_offset()` | Task 4 |
| `format_addr()` calls `get_rsp_offset()` | Task 5 |
| Declaration pass picks up RSP-relative slots | Task 6 |
| Unit test: minimal function with RSP-relative access produces `local_` | Task 2 |
| Integration test: check2 no `RSP - N -` substring | Task 7 |
| Regression: full test suite passes | Task 7 step 5 |

**Type consistency check:**
- `get_rsp_offset` returns `Option<i64>` — consistent with usage in Tasks 4 and 5 (`signed_off < 0` branch)
- `get_rbp_offset` returns `Option<u64>` — not changed, existing callers unaffected
- `combine_frame_offset` takes `(BinOpKind, u64, BinOpKind, u64)` returns `(BinOpKind, u64)` — used only in Task 1 fold pass
- All `ssa.var(id)` calls use the safe accessor defined in `ir.rs:222`
- `resolve_through_vars` is `fn resolve_through_vars(id: VarId, ssa: &SsaCfg) -> Expr` — printer.rs private function, used in Tasks 3, 4, 5

**Placeholder check:** All code blocks are complete. No TBD, TODO, or "similar to" references.
