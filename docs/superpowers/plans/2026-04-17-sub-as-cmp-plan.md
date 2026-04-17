# Sub-as-Comparison Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate `if (x - 1)`, `if (!(x - 1))` and related patterns from decompiler output by adding Sub-aware simplification rules to `mba_simplify_expr` and a Sub→NotEq pass to `recover_conditions` in fold.rs.

**Architecture:** Two surgical edits to `rsleigh-decompile/src/fold.rs` only. Part 1 extends three existing match arms in `mba_simplify_expr` (~lines 1015–1063) to handle `Sub` operands. Part 2 adds a new pass inside `recover_conditions` (after line 1636) that rewrites bare `Sub(a,b)` CBranch conditions to `NotEq(a,b)`. The `mba_simplify` loop already runs after `recover_conditions` (added in the double-negation fix), so multi-level chains collapse automatically.

**Tech Stack:** Rust stable, `rsleigh-decompile` crate, `BinOpKind`, `UnaryOpKind`, `Expr`, `SsaTerminator` from `ir.rs`.

---

## File Structure

| File | Change |
|---|---|
| `rsleigh-decompile/src/fold.rs` lines 1015–1025 | Extend BoolNot arm: `BoolNot(Sub(a,b))` → `Eq(a,b)` |
| `rsleigh-decompile/src/fold.rs` lines 1027–1044 | Extend Eq arm: `Eq(Sub(a,b), 0)` → `Eq(a,b)` |
| `rsleigh-decompile/src/fold.rs` lines 1047–1063 | Extend NotEq arm: `NotEq(Sub(a,b), 0)` → `NotEq(a,b)` |
| `rsleigh-decompile/src/fold.rs` after line 1636 | New pass in `recover_conditions`: bare `Sub(a,b)` CBranch → `NotEq(a,b)` |
| `rsleigh-decompile/tests/sub_as_cmp.rs` | New test file: unit + integration tests |

---

## Task 1: Write the failing tests

**Files:**
- Create: `rsleigh-decompile/tests/sub_as_cmp.rs`

- [ ] **Step 1: Write the test file**

Create `/Users/shane/repos/rsleigh/rsleigh-decompile/tests/sub_as_cmp.rs` with this exact content:

```rust
//! Regression tests for subtraction-as-comparison simplification.
//!
//! Spec: docs/superpowers/specs/2026-04-16-sub-as-cmp-design.md

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{BinOpKind, Expr, SsaTerminator};
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

/// After fold, no CBranch condition should resolve to a bare BinOp(Sub, _, _).
/// Encodes: mov rax, rcx; sub rax, 1; test rax, rax; jnz +3; xor rax, rax; ret
/// The SUB result is tested via TEST, so ZF = (rcx - 1 == 0). After fold, the
/// CBranch condition must be a comparison (Eq or NotEq), not Sub arithmetic.
#[test]
fn sub_cond_becomes_comparison() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes: &[u8] = &[
                0x48, 0x89, 0xC8,       // mov rax, rcx
                0x48, 0x83, 0xE8, 0x01, // sub rax, 1
                0x48, 0x85, 0xC0,       // test rax, rax
                0x75, 0x03,             // jnz +3
                0x48, 0x31, 0xC0,       // xor rax, rax
                0xC3,                   // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            // Walk every CBranch condition and follow Var chains.
            // Assert that no resolved condition is a bare Sub BinOp.
            for block in &ssa.blocks {
                if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
                    let mut resolved = *cond;
                    for _ in 0..8 {
                        if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr {
                            resolved = next;
                        } else {
                            break;
                        }
                    }
                    let cond_expr = &ssa.vars[resolved.0 as usize].expr;
                    assert!(
                        !matches!(cond_expr, Expr::BinOp(BinOpKind::Sub, _, _)),
                        "CBranch condition is still a raw Sub: {:?}",
                        cond_expr
                    );
                }
            }
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Integration test: known-problematic functions must not contain `if (x - N)` patterns.
/// Checks FUN_140001017 (0x140001017) which had `if (!(iVar1 - 1))` in the audit.
/// Skips gracefully if fixture binary is absent.
#[test]
fn sub_cond_gone_in_output() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping sub_cond_gone_in_output: fixture not found");
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

    // Decompile the full binary and check that no `if (... - N)` patterns remain
    // in condition positions. We check for the literal strings produced by the printer
    // for Sub-as-condition: `- 1)` or `- 2)` at end of a condition expression.
    // These appear as `if (iVar1 - 1)` or `if (!(iVar1 - 1))` in the output.
    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x140001017;  // FUN_140001017 — known to have the pattern
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
            eprintln!("skipping: func VA not in any section");
            return;
        }
    };

    let func_len = 0x400_usize.min(data.len() - off);
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

            // Check for `if (... - 1)` and `if (!(... - 1))` patterns
            let bad_lines: Vec<&str> = out.lines()
                .filter(|l| {
                    let trimmed = l.trim();
                    (trimmed.starts_with("if (") || trimmed.starts_with("while ("))
                        && (trimmed.contains(" - 1)") || trimmed.contains(" - 2)")
                            || trimmed.contains(" - 1))") || trimmed.contains(" - 2))"))
                })
                .collect();

            assert!(
                bad_lines.is_empty(),
                "sub-as-condition patterns still present:\n{}",
                bad_lines.join("\n")
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
```

- [ ] **Step 2: Run the tests to confirm the integration test fails**

```bash
cargo test -p rsleigh-decompile --test sub_as_cmp -- --nocapture 2>&1 | tail -30
```

Expected:
- `sub_cond_becomes_comparison`: may pass or fail (acceptable)
- `sub_cond_gone_in_output`: should FAIL with sub-condition patterns listed, or skip if binary absent

- [ ] **Step 3: Commit the failing test**

```bash
git add rsleigh-decompile/tests/sub_as_cmp.rs
git commit -m "test: add failing tests for sub-as-cmp simplification"
```

---

## Task 2: Extend `mba_simplify_expr` for Sub operands (Part 2)

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs` lines 1015–1063

- [ ] **Step 1: Verify exact line numbers**

```bash
grep -n "BoolNot, inner\|BinOpKind::Eq, inner_id\|BinOpKind::NotEq, inner_id\|CDQ.IDIV" \
    /Users/shane/repos/rsleigh/rsleigh-decompile/src/fold.rs | head -10
```

Confirm:
- `UnaryOpKind::BoolNot, inner` arm starts around line 1015
- `BinOpKind::Eq, inner_id` arm starts around line 1027
- `BinOpKind::NotEq, inner_id` arm starts around line 1047
- `CDQ+IDIV` comment is around line 1064

- [ ] **Step 2: Extend the BoolNot arm**

Find this exact block:
```rust
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) => {
            if let Expr::UnaryOp(UnaryOpKind::BoolNot, inner2) = &vars[inner.0 as usize].expr {
                return Some(Expr::Var(*inner2));
            }
            if let Expr::BinOp(cmp_op, a, b) = vars[inner.0 as usize].expr {
                if let Some(neg_op) = negate_eq_op(cmp_op) {
                    return Some(Expr::BinOp(neg_op, a, b));
                }
            }
            None
        }
```

Replace with:
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

- [ ] **Step 3: Extend the Eq arm**

Find this exact block:
```rust
        // (Eq(a,b) == 0) → NotEq(a,b),  (NotEq(a,b) == 0) → Eq(a,b)
        Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                // Follow Var chains to reach the underlying BinOp
                let mut resolved = *inner_id;
                for _ in 0..4 {
                    if let Expr::Var(next) = vars[resolved.0 as usize].expr {
                        resolved = next;
                    } else {
                        break;
                    }
                }
                if let Expr::BinOp(cmp_op, a, b) = vars[resolved.0 as usize].expr {
                    if let Some(neg_op) = negate_eq_op(cmp_op) {
                        return Some(Expr::BinOp(neg_op, a, b));
                    }
                }
            }
            None
        }
```

Replace with:
```rust
        // (Eq(a,b) == 0) → NotEq(a,b),  (NotEq(a,b) == 0) → Eq(a,b)
        // (Sub(a,b) == 0) → Eq(a,b)  [a - b == 0 means a == b]
        Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                // Follow Var chains to reach the underlying BinOp
                let mut resolved = *inner_id;
                for _ in 0..4 {
                    if let Expr::Var(next) = vars[resolved.0 as usize].expr {
                        resolved = next;
                    } else {
                        break;
                    }
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

- [ ] **Step 4: Extend the NotEq arm**

Find this exact block:
```rust
        // (BinOp(a,b) != 0) → BinOp(a,b)  [identity: comparison already a bool]
        Expr::BinOp(BinOpKind::NotEq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                // Follow Var chains to reach the underlying BinOp
                let mut resolved = *inner_id;
                for _ in 0..4 {
                    if let Expr::Var(next) = vars[resolved.0 as usize].expr {
                        resolved = next;
                    } else {
                        break;
                    }
                }
                if let Expr::BinOp(_, _, _) = vars[resolved.0 as usize].expr {
                    return Some(Expr::Var(resolved));
                }
            }
            None
        }
```

Replace with:
```rust
        // (BinOp(a,b) != 0) → BinOp(a,b)  [identity: comparison already a bool]
        // (Sub(a,b) != 0) → NotEq(a,b)  [a - b != 0 means a != b]
        Expr::BinOp(BinOpKind::NotEq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                // Follow Var chains to reach the underlying BinOp
                let mut resolved = *inner_id;
                for _ in 0..4 {
                    if let Expr::Var(next) = vars[resolved.0 as usize].expr {
                        resolved = next;
                    } else {
                        break;
                    }
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

- [ ] **Step 5: Build**

```bash
cargo build -p rsleigh-decompile 2>&1 | grep "^error" | head -20
```

Expected: zero errors. Common errors and fixes:
- `use of undeclared type BinOpKind::Sub` → check the import at the top of fold.rs; `BinOpKind` is already imported
- `cannot move out of` → the `vars[resolved.0 as usize].expr` match copies values because `BinOpKind`, `VarId` are `Copy`

- [ ] **Step 6: Run the new tests**

```bash
cargo test -p rsleigh-decompile --test sub_as_cmp -- --nocapture 2>&1 | tail -20
```

- [ ] **Step 7: Run full rsleigh-decompile suite**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: simplify Sub(a,b) in boolean context to Eq/NotEq(a,b)"
```

---

## Task 3: Add Sub→NotEq pass in `recover_conditions` (Part 1)

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs` after line 1636

- [ ] **Step 1: Find the insertion point**

```bash
grep -n "to_recover\b\|// Also recover conditions inside Ternary" \
    /Users/shane/repos/rsleigh/rsleigh-decompile/src/fold.rs | head -10
```

Find the blank line between the end of `for (bi, cond_id) in to_recover { ... }` (around line 1636) and the `// Also recover conditions inside Ternary` comment (around line 1638). The new code goes in that gap.

- [ ] **Step 2: Insert the Sub→NotEq pass**

Find this exact text (the gap between the two passes):
```rust
    }

    // Also recover conditions inside Ternary expressions (from CSEL/CSINC/CNEG).
```

Replace with:
```rust
    }

    // Pass 1b: Sub(a, b) used bare as a CBranch condition → NotEq(a, b).
    // Handles patterns like `if (x - 1)` → `if (x != 1)` that are not flag-derived.
    // Only fires when the condition (after Var-chain following) is a bare Sub BinOp.
    let mut sub_cond: Vec<(usize, VarId, VarId)> = Vec::new(); // (bi, a, b)
    for (bi, block) in ssa.blocks.iter().enumerate() {
        if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
            if is_flag_derived(*cond, ssa) { continue; }
            let mut resolved = *cond;
            for _ in 0..4 {
                if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr {
                    resolved = next;
                } else {
                    break;
                }
            }
            if let Expr::BinOp(BinOpKind::Sub, a, b) = ssa.vars[resolved.0 as usize].expr {
                sub_cond.push((bi, a, b));
            }
        }
    }
    for (bi, a, b) in sub_cond {
        let cond_varnode = if let SsaTerminator::CBranch { cond, .. } = ssa.blocks[bi].terminator {
            ssa.vars[cond.0 as usize].varnode
        } else { continue; };
        let new_cond = ssa.new_var(cond_varnode, Expr::BinOp(BinOpKind::NotEq, a, b), 1);
        if let SsaTerminator::CBranch { taken, fallthrough, .. } = ssa.blocks[bi].terminator {
            ssa.blocks[bi].terminator = SsaTerminator::CBranch {
                cond: new_cond, taken, fallthrough,
            };
        }
    }

    // Also recover conditions inside Ternary expressions (from CSEL/CSINC/CNEG).
```

- [ ] **Step 3: Build**

```bash
cargo build -p rsleigh-decompile 2>&1 | grep "^error" | head -20
```

Expected: zero errors. If `ssa.new_var` has a different signature, check:
```bash
grep -n "pub fn new_var\|fn new_var" /Users/shane/repos/rsleigh/rsleigh-decompile/src/ssa.rs | head -5
```
The signature is `new_var(varnode: Varnode, expr: Expr, size: u32) -> VarId`. Pass `1` for the bool size.

- [ ] **Step 4: Run the new tests**

```bash
cargo test -p rsleigh-decompile --test sub_as_cmp -- --nocapture 2>&1 | tail -20
```

Expected: both tests pass (or integration test skips if binary absent).

- [ ] **Step 5: Run full rsleigh-decompile suite**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 6: Spot-check CLI output**

```bash
cargo run -p rsleigh-cli --release -- \
    /Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe \
    0x140001017 2>/dev/null | head -30
```

Look for: `if (!(iVar1 - 1))` should now be `if (iVar1 == 1)` (or similar).

- [ ] **Step 7: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: recover_conditions: rewrite bare Sub(a,b) CBranch conds to NotEq(a,b)"
```

---

## Task 4: Full regression suite

**Files:** No changes — verification only.

- [ ] **Step 1: Run the test-harness**

```bash
cargo test -p test-harness 2>&1 | tail -15
```

Expected: 9/9 tests pass.

- [ ] **Step 2: If decompiler_validation fails, inspect**

```bash
cargo test -p test-harness -- decompiler_validation --nocapture 2>&1 | head -60
```

If a golden assertion fails because a legitimate `x - N` subtraction was converted to a comparison (e.g., `result - offset` where the subtraction is arithmetic, not a boolean test), the guard is: only fire the Sub→NotEq rule when the result size is 1 (bool). Add this check to both Part 1 and Part 2:

```rust
// Guard: only fire for 1-byte (bool) results
if ssa.vars[resolved.0 as usize].varnode.size == 1 {
    // ... fire the rule
}
```

- [ ] **Step 3: Spot-check all known-bad functions**

```bash
cargo run -p rsleigh-cli --release -- \
    /Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe \
    0x140001017 0x14000147c 0x140001806 2>/dev/null | \
    grep -E "if \(.*- [0-9]|while \(.*- [0-9]"
```

Expected: no output (no remaining `if (x - N)` or `while (x - N)` patterns).

- [ ] **Step 4: Commit guard fix if Step 2 required it**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: guard sub-as-cmp rules to size-1 boolean expressions only"
```

Only commit if Step 2 required a guard. Otherwise skip this step.

---

## Self-Review

### Spec Coverage

| Spec requirement | Task |
|---|---|
| `BoolNot(Sub(a,b))` → `Eq(a,b)` | Task 2 Step 2 |
| `Eq(Sub(a,b), 0)` → `Eq(a,b)` | Task 2 Step 3 |
| `NotEq(Sub(a,b), 0)` → `NotEq(a,b)` | Task 2 Step 4 |
| Bare `Sub(a,b)` CBranch → `NotEq(a,b)` | Task 3 Step 2 |
| Unit test: no Sub in CBranch conditions after fold | Task 1 |
| Integration test: no `if (x - N)` in function output | Task 1 |
| Full regression: 9/9 test-harness pass | Task 4 |
| `fold.rs` only — no other files changed | All tasks |

### Placeholder Scan

No TBD, TODO, or vague steps — all code is explicit.

### Type Consistency

- `BinOpKind::Sub` — used in `==` comparisons against `cmp_op: BinOpKind` (which is `Copy + PartialEq`). Correct.
- `Expr::BinOp(BinOpKind::NotEq, a, b)` / `Expr::BinOp(BinOpKind::Eq, a, b)` — `a` and `b` are `VarId` (Copy), extracted from `vars[resolved.0 as usize].expr`. Same type as every other `Expr::BinOp` construction in `mba_simplify_expr`.
- `ssa.new_var(varnode, expr, 1)` — returns `VarId`, same as `try_recover_condition` at line 1830. Third arg is size in bytes; `1` = bool.
