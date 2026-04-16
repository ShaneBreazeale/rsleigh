# Call-Return Binding Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every non-void function call emit `name = func(args);` in decompiled output by wiring the SSA `call_return` variable into `StructuredStmt::Call.out` for both the `SsaTerminator::Call` path (structure.rs) and the `Stmt::Call` path (fold.rs).

**Architecture:** Two targeted fixes: (1) `fold.rs propagate_call_returns` sets `Stmt::Call.out` when the next statement is a `call_return=true` VarDef; (2) `structure.rs` `SsaTerminator::Call` arms scan the fallthrough block head for the `call_return` var and pass it as `out`, then skip the redundant `Stmt::Assign` when rendering that fallthrough block. No IR type changes required — `StructuredStmt::Call.out: Option<VarId>` already exists and the printer already handles it.

**Tech Stack:** Rust 2021, `rsleigh-decompile` crate, `rsleigh-api` crate, `pcode-ir` crate, goblin for PE parsing in integration test, 32MB stack thread for x86-64 decode.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `rsleigh-decompile/tests/call_return_binding.rs` | **Create** | Regression tests: unit (mid-block `Stmt::Call.out`) and integration (`strcspn` named binding) |
| `rsleigh-decompile/src/fold.rs` lines ~3143–3167 | **Modify** | `propagate_call_returns`: track `call_idx`, set `Stmt::Call.out`, remove redundant assign |
| `rsleigh-decompile/src/structure.rs` lines ~314–407 | **Modify** | `SsaTerminator::Call` arms: scan fallthrough head for `call_return` var, pass `out`, suppress duplicate assign in `emit_block_stmts` call path |

---

## Task 1: Write the Failing Regression Test

**Files:**
- Create: `rsleigh-decompile/tests/call_return_binding.rs`

This test verifies the mid-block `Stmt::Call` path (Fix 2). After `fold_with_cc`, every `Stmt::Call` whose next statement assigns a `call_return=true` var must have `out: Some(_)`.

- [ ] **Step 1: Write the test file**

```rust
//! Regression: Stmt::Call.out must be Some(_) when the return value is used,
//! and StructuredStmt::Call.out must be Some(_) for SsaTerminator::Call.
//!
//! Spec: docs/superpowers/specs/2026-04-16-call-return-binding-design.md

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::Stmt;
use rsleigh_decompile::ssa::build_ssa_with_cc;

fn decode_x64(bytes: &[u8], base: u64) -> Vec<(u64, pcode_ir::Instruction)> {
    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let addr = base + off as u64;
        match dec.decode(&bytes[off..], addr) {
            Ok(inst) => {
                let l = inst.len as usize;
                insts.push((addr, inst));
                off += l;
            }
            Err(_) => break,
        }
    }
    insts
}

/// After fold_with_cc, any Stmt::Call whose return value is subsequently read
/// must have out: Some(_), not None.
///
/// Sequence (Win64 calling convention):
///   48 89 F9        mov rcx, rdi        ; arg setup
///   E8 10 00 00 00  call rel32 +0x10    ; call (fallthrough = next insn)
///   48 89 45 F8     mov [rbp-8], rax    ; store call result
///   C3              ret
///
/// The `mov [rbp-8], rax` reads RAX which is the call return value.
/// After propagate_call_returns, the Stmt::Call that emits this RAX
/// must carry out: Some(rax_var_id).
#[test]
fn mid_block_call_out_is_set() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: [u8; 14] = [
                0x48, 0x89, 0xF9,             // mov rcx, rdi
                0xE8, 0x10, 0x00, 0x00, 0x00, // call rel32 +0x10
                0x48, 0x89, 0x45, 0xF8,       // mov [rbp-8], rax
                0xC3,                         // ret
            ];
            let insts = decode_x64(&bytes, 0x1000);
            assert!(
                insts.len() >= 3,
                "expected >=3 instructions, got {}",
                insts.len()
            );

            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            // Find any Stmt::Call in any block.
            let call_stmts: Vec<_> = ssa.blocks.iter().flat_map(|b| &b.stmts).filter(|s| matches!(s, Stmt::Call { .. })).collect();

            // There may or may not be a mid-block Call depending on how the CFG splits.
            // If one exists, it MUST have out = Some(_) because RAX is read after it.
            for stmt in &call_stmts {
                if let Stmt::Call { out, .. } = stmt {
                    assert!(
                        out.is_some(),
                        "Stmt::Call.out must be Some(_) when return value is used; got None"
                    );
                }
            }

            // At minimum: there must be at least one block with a Call terminator
            // or a Stmt::Call — the sequence contains a call instruction.
            let has_any_call = !call_stmts.is_empty()
                || ssa.blocks.iter().any(|b| {
                    matches!(
                        &b.terminator,
                        rsleigh_decompile::ir::SsaTerminator::Call { .. }
                    )
                });
            assert!(has_any_call, "no Call found in SSA after decoding a CALL instruction");
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Integration test: decompiling the strcspn-calling function from the CTF binary
/// must produce output that binds the return value to a named variable.
///
/// Skips gracefully if the fixture binary is not present.
#[test]
fn strcspn_return_is_named() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping strcspn_return_is_named: fixture binary not found");
            return;
        }
    };

    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping strcspn_return_is_named: PE parse error: {}", e);
            return;
        }
    };

    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001e41;
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
            eprintln!("skipping strcspn_return_is_named: func VA not in any section");
            return;
        }
    };

    let func_len = 0x300_usize.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            use pcode_ir::PcodeOp;
            let mut dec = Decoder::new(Architecture::X86_64);
            let mut insts = Vec::new();
            let mut io = 0usize;
            while io < bytes.len() {
                match dec.decode(&bytes[io..], func_va + io as u64) {
                    Ok(inst) => {
                        let is_ret =
                            inst.ops.iter().any(|op| matches!(op, PcodeOp::Return { .. }));
                        let l = inst.len as usize;
                        insts.push((func_va + io as u64, inst));
                        io += l;
                        if is_ret {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            let out = rsleigh_decompile::decompile_with_binary(
                Architecture::X86_64,
                &insts,
                Some(&data),
                Some(std::path::Path::new(
                    "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe",
                )),
            );

            // The strcspn call result must be bound to a named local, not discarded.
            // Accept either: `= strcspn(` (named binding) or a named var containing
            // the return in an expression like `sVar1 = strcspn(`.
            let has_named_binding = out.lines().any(|line| {
                line.contains("= strcspn(") || line.contains("=strcspn(")
            });
            assert!(
                has_named_binding,
                "strcspn return value not bound to a named variable; output:\n{}",
                out
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
```

Save this as `/Users/shane/repos/rsleigh/rsleigh-decompile/tests/call_return_binding.rs`.

- [ ] **Step 2: Run the tests to verify they fail (or that the file compiles)**

```bash
cargo test -p rsleigh-decompile --test call_return_binding 2>&1 | head -60
```

Expected: tests compile and `mid_block_call_out_is_set` either passes trivially (no mid-block Stmt::Call found — the CALL becomes a terminator) or fails. `strcspn_return_is_named` is expected to fail with "strcspn return value not bound to a named variable" if the binary is present, or skip if absent.

Note: if `mid_block_call_out_is_set` passes because the call becomes a `SsaTerminator::Call` (not a `Stmt::Call`), that is fine — the second test (`strcspn_return_is_named`) is the primary regression gate. Keep both.

- [ ] **Step 3: Commit the failing test**

```bash
git add rsleigh-decompile/tests/call_return_binding.rs
git commit -m "test: add failing regression tests for call-return binding"
```

---

## Task 2: Fix fold.rs — Set Stmt::Call.out (Fix 2)

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs:3143–3168`

The second-half loop in `propagate_call_returns` already detects the `Stmt::Call` → `Stmt::Assign(call_return_var)` pattern and marks the var. We need to:
1. Track the index of the `Stmt::Call` while scanning.
2. After marking `call_return = true` on the var, if `use_count > 0`, rewrite the `Stmt::Call` at that index to set `out: Some(var_id)`.

- [ ] **Step 1: Read the current second-half loop (lines 3143–3168) to understand the exact borrow pattern before editing**

The current code:
```rust
// For Call statements within a block: the next RAX assignment is the return value
let stmts = &ssa.blocks[bi].stmts;
let mut after_call = false;
for i in 0..stmts.len() {
    if matches!(&stmts[i], Stmt::Call { .. }) {
        after_call = true;
        continue;
    }
    if after_call {
        if let Stmt::Assign(var_id) = &stmts[i] {
            let vdef = &ssa.vars[var_id.0 as usize];
            // Skip if already marked call_return by SSA-level clobber
            if vdef.call_return {
                after_call = false;
                continue;
            }
            if vdef.varnode.space == AddressSpaceId::Register
                && vdef.varnode.offset == RAX_OFFSET
            {
                ssa.vars[var_id.0 as usize].call_return = true;
                after_call = false;
            }
        }
    }
}
```

- [ ] **Step 2: Replace the second-half loop with the binding-aware version**

Find this exact block in `rsleigh-decompile/src/fold.rs` (around line 3143) and replace it with:

```rust
        // For Call statements within a block: the next RAX assignment is the return value
        let mut call_idx: Option<usize> = None;
        for i in 0..ssa.blocks[bi].stmts.len() {
            if matches!(&ssa.blocks[bi].stmts[i], Stmt::Call { .. }) {
                call_idx = Some(i);
                continue;
            }
            if let Some(cidx) = call_idx {
                if let Stmt::Assign(var_id) = &ssa.blocks[bi].stmts[i] {
                    let var_id = *var_id;
                    let vdef = &ssa.vars[var_id.0 as usize];
                    // Skip if already marked call_return by SSA-level clobber
                    if vdef.call_return {
                        // Already handled by SSA clobber; wire out if use_count > 0
                        let use_count = ssa.vars[var_id.0 as usize].use_count;
                        if use_count > 0 {
                            if let Stmt::Call { ref target, ref args, .. } =
                                ssa.blocks[bi].stmts[cidx].clone()
                            {
                                ssa.blocks[bi].stmts[cidx] = Stmt::Call {
                                    target,
                                    args,
                                    out: Some(var_id),
                                };
                            }
                        }
                        call_idx = None;
                        continue;
                    }
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RAX_OFFSET
                    {
                        ssa.vars[var_id.0 as usize].call_return = true;
                        let use_count = ssa.vars[var_id.0 as usize].use_count;
                        if use_count > 0 {
                            if let Stmt::Call { ref target, ref args, .. } =
                                ssa.blocks[bi].stmts[cidx].clone()
                            {
                                ssa.blocks[bi].stmts[cidx] = Stmt::Call {
                                    target,
                                    args,
                                    out: Some(var_id),
                                };
                            }
                        }
                        call_idx = None;
                    }
                } else {
                    // Non-assign stmt between call and return read — reset
                    call_idx = None;
                }
            }
        }
```

- [ ] **Step 3: Build to check compilation**

```bash
cargo build -p rsleigh-decompile 2>&1
```

Expected: builds cleanly. Fix any borrow errors (the `.clone()` on the stmt is intentional to avoid the simultaneous mutable/immutable borrow of `ssa.blocks[bi].stmts`).

- [ ] **Step 4: Run the regression test**

```bash
cargo test -p rsleigh-decompile --test call_return_binding mid_block_call_out_is_set 2>&1
```

Expected: PASS (or still passes trivially — the key test is `strcspn_return_is_named`).

- [ ] **Step 5: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: set Stmt::Call.out when call_return var is used (Fix 2)"
```

---

## Task 3: Fix structure.rs — Wire SsaTerminator::Call.out (Fix 1)

**Files:**
- Modify: `rsleigh-decompile/src/structure.rs:314–407` and `emit_block_stmts` function (~line 417)

There are **three** places where `SsaTerminator::Call` emits a `StructuredStmt::Call` with `out: None`:
1. Line ~337: do-while loop body path
2. Line ~373: is-loop-header, not-do-while path ("Not a do-while — try while pattern")
3. Line ~401: normal (non-loop) path (the `else` arm)

All three need the fallthrough-block scan. We also need `emit_block_stmts` to skip a consumed `call_return` var.

The approach:
- Write a helper `fn find_call_return_in_block(ssa: &SsaCfg, block_id: BlockId) -> Option<VarId>` that scans the block's `stmts` for the first `Stmt::Assign(v)` where `ssa.vars[v.0].call_return && ssa.vars[v.0].use_count > 0`.
- Pass a `consumed_call_returns: &mut HashSet<VarId>` through `emit_region` and `emit_block_stmts`.
- When a `SsaTerminator::Call` is emitted, call the helper on the fallthrough block, pass the result as `out`, and add the found var to `consumed_call_returns`.
- In `emit_block_stmts`, skip any `Stmt::Assign(v)` where `consumed_call_returns.contains(&v)`.

- [ ] **Step 1: Add the helper function at the top of structure.rs (after the imports)**

Add after the `use` line and before `pub fn recover_structure`:

```rust
use std::collections::HashSet;

/// Scan the first few stmts of `block_id` for the call-return variable:
/// the first `Stmt::Assign(v)` where `call_return=true` and `use_count > 0`.
/// Returns the VarId if found.
fn find_call_return_in_block(ssa: &SsaCfg, block_id: BlockId) -> Option<VarId> {
    if block_id.0 >= ssa.blocks.len() {
        return None;
    }
    for stmt in &ssa.blocks[block_id.0].stmts {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = &ssa.vars[var_id.0 as usize];
            if vdef.call_return && vdef.use_count > 0 {
                return Some(*var_id);
            }
        }
    }
    None
}
```

- [ ] **Step 2: Update `emit_block_stmts` to accept and respect `consumed_call_returns`**

Change the function signature and body from:

```rust
fn emit_block_stmts(block: &SsaBlock, out: &mut Vec<StructuredStmt>) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Assign(var_id) => {
                out.push(StructuredStmt::Assign { lhs: *var_id, rhs: *var_id });
            }
            Stmt::Store { addr, val } => {
                out.push(StructuredStmt::Store { addr: *addr, val: *val });
            }
            Stmt::Call { target, args, out: call_out } => {
                out.push(StructuredStmt::Call {
                    target: target.clone(),
                    args: args.clone(),
                    out: *call_out,
                });
            }
        }
    }
}
```

To:

```rust
fn emit_block_stmts(
    block: &SsaBlock,
    out: &mut Vec<StructuredStmt>,
    consumed: &HashSet<VarId>,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Assign(var_id) => {
                // Skip vars consumed as call-return bindings — already emitted as `out`.
                if consumed.contains(var_id) {
                    continue;
                }
                out.push(StructuredStmt::Assign { lhs: *var_id, rhs: *var_id });
            }
            Stmt::Store { addr, val } => {
                out.push(StructuredStmt::Store { addr: *addr, val: *val });
            }
            Stmt::Call { target, args, out: call_out } => {
                out.push(StructuredStmt::Call {
                    target: target.clone(),
                    args: args.clone(),
                    out: *call_out,
                });
            }
        }
    }
}
```

- [ ] **Step 3: Update `emit_region` signature to carry `consumed_call_returns`**

Change:

```rust
fn emit_region(
    ssa: &SsaCfg,
    cfg: &Cfg,
    dom: &[BlockId],
    pdom: &[BlockId],
    back_edges: &[(BlockId, BlockId)],
    start: BlockId,
    emitted: &mut Vec<bool>,
    out: &mut Vec<StructuredStmt>,
    depth: usize,
    _loop_ctx: Option<&LoopCtx>,
) {
```

To:

```rust
fn emit_region(
    ssa: &SsaCfg,
    cfg: &Cfg,
    dom: &[BlockId],
    pdom: &[BlockId],
    back_edges: &[(BlockId, BlockId)],
    start: BlockId,
    emitted: &mut Vec<bool>,
    out: &mut Vec<StructuredStmt>,
    depth: usize,
    _loop_ctx: Option<&LoopCtx>,
    consumed: &mut HashSet<VarId>,
) {
```

- [ ] **Step 4: Update the `emit_region` call in `recover_structure` to pass an empty set**

Find:
```rust
    emit_region(ssa, cfg, &dom, &pdom, &back_edges, cfg.entry,
                &mut emitted, &mut result, 0, None);
```

Replace with:
```rust
    let mut consumed: HashSet<VarId> = HashSet::new();
    emit_region(ssa, cfg, &dom, &pdom, &back_edges, cfg.entry,
                &mut emitted, &mut result, 0, None, &mut consumed);
```

- [ ] **Step 5: Update all recursive `emit_region` calls inside `emit_region` to pass `consumed`**

There are multiple recursive calls inside the `emit_region` body. Each call like:
```rust
emit_region(ssa, cfg, dom, pdom, back_edges, *fallthrough, emitted, &mut body, depth + 1, None);
```
must become:
```rust
emit_region(ssa, cfg, dom, pdom, back_edges, *fallthrough, emitted, &mut body, depth + 1, None, consumed);
```

Search the file for all occurrences of `emit_region(` inside the function body and add `, consumed` as the final argument to each. (The `recover_structure` call site was already fixed in Step 4.)

Run to find all internal call sites:
```bash
grep -n "emit_region(" /Users/shane/repos/rsleigh/rsleigh-decompile/src/structure.rs
```

Expected output shows ~5–8 call sites. Update every one that is NOT the `recover_structure` call site.

- [ ] **Step 6: Update all `emit_block_stmts` call sites to pass `consumed`**

Find all calls to `emit_block_stmts(` in structure.rs:
```bash
grep -n "emit_block_stmts(" /Users/shane/repos/rsleigh/rsleigh-decompile/src/structure.rs
```

Change each from `emit_block_stmts(block, out)` to `emit_block_stmts(block, out, consumed)`.

- [ ] **Step 7: Populate `out` and `consumed` for the three `SsaTerminator::Call` emit sites**

**Site A — Normal (non-loop) path**, currently around line 401:

Change from:
```rust
                } else {
                    out.push(StructuredStmt::Call {
                        target: target.clone(),
                        args: args.clone(),
                        out: None,
                    });
                }
```
To:
```rust
                } else {
                    let call_out = find_call_return_in_block(ssa, *fallthrough);
                    if let Some(v) = call_out {
                        consumed.insert(v);
                    }
                    out.push(StructuredStmt::Call {
                        target: target.clone(),
                        args: args.clone(),
                        out: call_out,
                    });
                }
```

**Site B — Loop-header, not-do-while path ("Not a do-while — try while pattern")**, currently around line 372–377:

Change from:
```rust
                    // Not a do-while — try while pattern
                    out.push(StructuredStmt::Call {
                        target: target.clone(),
                        args: args.clone(),
                        out: None,
                    });
```
To:
```rust
                    // Not a do-while — try while pattern
                    let call_out = find_call_return_in_block(ssa, *fallthrough);
                    if let Some(v) = call_out {
                        consumed.insert(v);
                    }
                    out.push(StructuredStmt::Call {
                        target: target.clone(),
                        args: args.clone(),
                        out: call_out,
                    });
```

**Site C — Do-while loop body path**, currently around line 337–341:

Change from:
```rust
                                    // Emit the call as part of the loop body
                                    let mut body = Vec::new();
                                    body.push(StructuredStmt::Call {
                                        target: target.clone(),
                                        args: args.clone(),
                                        out: None,
                                    });
```
To:
```rust
                                    // Emit the call as part of the loop body
                                    let mut body = Vec::new();
                                    let call_out = find_call_return_in_block(ssa, *fallthrough);
                                    if let Some(v) = call_out {
                                        consumed.insert(v);
                                    }
                                    body.push(StructuredStmt::Call {
                                        target: target.clone(),
                                        args: args.clone(),
                                        out: call_out,
                                    });
```

- [ ] **Step 8: Build to check compilation**

```bash
cargo build -p rsleigh-decompile 2>&1
```

Expected: builds cleanly. Borrow checker is satisfied because `consumed` is `&mut HashSet<VarId>` passed through all call chains, and `find_call_return_in_block` takes `&SsaCfg` (immutable).

- [ ] **Step 9: Run both new regression tests**

```bash
cargo test -p rsleigh-decompile --test call_return_binding 2>&1
```

Expected:
- `mid_block_call_out_is_set` — PASS
- `strcspn_return_is_named` — PASS (if binary present) or SKIPPED (if absent)

- [ ] **Step 10: Commit**

```bash
git add rsleigh-decompile/src/structure.rs
git commit -m "structure: wire SsaTerminator::Call fallthrough call_return var to StructuredStmt::Call.out (Fix 1)"
```

---

## Task 4: Run Full Test Suite and Fix Any Regressions

**Files:**
- Modify: any file flagged by test failures

The `consumed_call_returns` skip in `emit_block_stmts` must not suppress any `Stmt::Assign` that is not a call-return binding. The guard (`call_return=true && use_count > 0`) is narrow enough that only the one var targeted by `find_call_return_in_block` is consumed.

- [ ] **Step 1: Run the full test suite**

```bash
cargo test -p test-harness 2>&1 | tail -40
```

Expected: all 240 tests pass, 7200+ assertions green. Look for any new failures in decompiler output golden tests.

- [ ] **Step 2: If any golden test fails, inspect the diff**

If a golden test like `test_decompile_*` fails with unexpected output, it likely means a previously-void call now has a named binding (which is correct behavior). Update the golden file:

```bash
# Example: update a golden file if the new output is correct
cargo test -p test-harness -- --nocapture 2>&1 | grep "left:"
```

Compare the new output to expected. If the new output shows `sVar1 = func(...)` where previously it showed `func(...)`, that is the correct fix. Update the golden snapshot.

- [ ] **Step 3: If `consumed` suppresses a non-call-return assign, add a guard**

If any test fails because a legitimate `Stmt::Assign` was skipped, add the `call_return` guard to `find_call_return_in_block` (it already has it — check that `ssa.vars[var_id.0 as usize].call_return` is truly `true` only for call returns). The flag is only set by `propagate_call_returns` and the SSA clobber pass, so collisions are not expected.

- [ ] **Step 4: Final commit after all regressions fixed**

```bash
git add -p  # stage only regression fixes
git commit -m "fix: update golden tests for named call-return bindings"
```

---

## Self-Review

### Spec Coverage

| Spec Requirement | Task |
|---|---|
| Fix 2: `Stmt::Call.out` set when `call_return` var follows in same block | Task 2 |
| Fix 1: `SsaTerminator::Call` scans fallthrough block head for `call_return` var | Task 3 |
| `consumed_call_returns` set prevents duplicate assign emission | Task 3 Steps 2, 6, 7 |
| Only first `call_return=true` stmt at head of fallthrough consumed | Task 3 Step 1 (helper returns on first match) |
| `use_count > 0` guard — leave `out: None` for unused return | Task 2 Step 2, Task 3 Step 1 |
| No changes to `SsaTerminator::Call` in `ir.rs` | Confirmed — no IR change |
| No changes to `ssa.rs` | Confirmed — no SSA builder change |
| No changes to `printer.rs` | Confirmed — printer already correct |
| Unit test: `Stmt::Call.out == Some(_)` | Task 1 (`mid_block_call_out_is_set`) |
| Integration test: `strcspn` named binding | Task 1 (`strcspn_return_is_named`) |
| Full suite regression: 240 tests pass | Task 4 |

### Placeholder Scan

No TBD, TODO, "implement later", or placeholder text present. All code steps contain exact Rust code.

### Type Consistency

- `VarId` — used consistently as `VarId` throughout (`var_id.0 as usize` for indexing into `ssa.vars`).
- `Stmt::Call { target: CallTarget, args: Vec<VarId>, out: Option<VarId> }` — matches `ir.rs` definition exactly.
- `StructuredStmt::Call { target: CallTarget, args: Vec<VarId>, out: Option<VarId> }` — matches `ir.rs` definition exactly.
- `SsaTerminator::Call { target, args, fallthrough }` — destructured correctly in all three sites; `fallthrough: BlockId` used as `*fallthrough` to dereference.
- `find_call_return_in_block(ssa: &SsaCfg, block_id: BlockId) -> Option<VarId>` — return type consistent with `out: Option<VarId>` in both `Stmt::Call` and `StructuredStmt::Call`.
- `HashSet<VarId>` — `VarId` implements `Hash + Eq` (it wraps a `u32`, standard derives expected). Verify before building: if `VarId` does not derive `Hash + Eq`, add `#[derive(Hash, Eq, PartialEq)]` to `VarId` in `ir.rs`.
- `consumed: &mut HashSet<VarId>` — threaded through `emit_region` and `emit_block_stmts`; all call sites updated in Task 3 Steps 4–6.
