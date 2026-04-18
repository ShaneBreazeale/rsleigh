# Double-Negation Condition Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate `(x == 0) == 0` and `!(x == 0)` patterns from decompiler output by adding three simplification rules to `mba_simplify_expr` in fold.rs.

**Architecture:** Two surgical edits to one file — (1) a helper `negate_eq_op` added near `combine_frame_offset` (~line 129), and (2) three new match arms in `mba_simplify_expr` inserted after the existing `Not(Not(x))` arm at line 1000. The `mba_simplify` loop already runs 4 passes, so multi-level chains collapse automatically. No other files change.

**Tech Stack:** Rust stable, `rsleigh-decompile` crate, `BinOpKind`, `UnaryOpKind`, `Expr` from `ir.rs`.

---

## File Structure

| File | Change |
|---|---|
| `rsleigh-decompile/src/fold.rs` line ~143 | Add `fn negate_eq_op` helper |
| `rsleigh-decompile/src/fold.rs` lines 1000–1001 | Insert 3 new match arms in `mba_simplify_expr` |
| `rsleigh-decompile/tests/double_negation.rs` | New test file: unit + integration tests |

---

## Task 1: Write the failing tests

**Files:**
- Create: `rsleigh-decompile/tests/double_negation.rs`

- [ ] **Step 1: Write the test file**

Create `/Users/shane/repos/rsleigh/rsleigh-decompile/tests/double_negation.rs` with this exact content:

```rust
//! Regression tests for double-negation condition simplification.
//!
//! Spec: docs/superpowers/specs/2026-04-16-double-negation-condition-design.md

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::{fold_with_cc, CallingConv};
use rsleigh_decompile::ir::{BinOpKind, Expr};
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

/// After fold, no VarDef should have the pattern BinOp(Eq, BinOp(Eq|NotEq, _, _), Const(0)).
/// This is the `(x == 0) == 0` / `(x != 0) == 0` pattern.
#[test]
fn double_negation_eq_zero_eliminated() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // xor rax, rax     — rax = 0
            // cmp rax, 0       — sets ZF
            // sete al          — al = (rax == 0) ? 1 : 0
            // cmp al, 0        — (al == 0) — double-negation
            // sete cl          — cl = (al == 0) ? 1 : 0
            // ret
            let bytes: &[u8] = &[
                0x48, 0x31, 0xC0,       // xor rax, rax
                0x48, 0x83, 0xF8, 0x00, // cmp rax, 0
                0x0F, 0x94, 0xC0,       // sete al
                0x80, 0xF8, 0x00,       // cmp al, 0
                0x0F, 0x94, 0xC1,       // sete cl
                0xC3,                   // ret
            ];
            let insts = decode_x64(bytes, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            for vdef in &ssa.vars {
                if let Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) = vdef.expr {
                    // zero_id must be Const(0)
                    if matches!(ssa.vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                        // inner must NOT itself be a comparison (Eq or NotEq)
                        let inner_expr = &ssa.vars[inner_id.0 as usize].expr;
                        assert!(
                            !matches!(inner_expr,
                                Expr::BinOp(BinOpKind::Eq, _, _)
                                | Expr::BinOp(BinOpKind::NotEq, _, _)
                            ),
                            "double-negation NOT eliminated: BinOp(Eq, {:?}, Const(0)) remains",
                            inner_expr
                        );
                    }
                }
            }
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}

/// Integration test: main (0x140001e41) must not contain `== 0) == 0` in output.
/// Skips gracefully if fixture binary is absent.
#[test]
fn main_func_no_double_negation_in_output() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skipping main_func_no_double_negation_in_output: fixture not found");
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
            eprintln!("skipping: func VA not in any section");
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

            assert!(
                !out.contains("== 0) == 0") && !out.contains("!= 0) == 0"),
                "double-negation still present in main output:\n{}",
                out.lines()
                    .filter(|l| l.contains("== 0"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        })
        .expect("thread spawn failed");
    handle.join().expect("test thread panicked");
}
```

- [ ] **Step 2: Run the tests to confirm they fail (or compile)**

```bash
cargo test -p rsleigh-decompile --test double_negation -- --nocapture 2>&1 | tail -20
```

Expected: `double_negation_eq_zero_eliminated` may pass or fail depending on the byte sequence. `main_func_no_double_negation_in_output` should FAIL with "double-negation still present" if binary is present, or skip.

- [ ] **Step 3: Commit the failing test**

```bash
git add rsleigh-decompile/tests/double_negation.rs
git commit -m "test: add failing tests for double-negation condition simplification"
```

---

## Task 2: Add `negate_eq_op` helper and the three simplification rules

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs`

### Step 1: Read the insertion points

```bash
grep -n "fn combine_frame_offset\|UnaryOpKind::Not, inner\|CDQ.IDIV" /Users/shane/repos/rsleigh/rsleigh-decompile/src/fold.rs | head -10
```

Verify:
- `fn combine_frame_offset` is around line 129
- `Expr::UnaryOp(UnaryOpKind::Not, inner)` arm ends around line 1000
- `// CDQ+IDIV simplification` comment is around line 1001

- [ ] **Step 2: Add `negate_eq_op` after `combine_frame_offset`**

Read the closing `}` of `combine_frame_offset` (around line 143). Insert immediately after it:

```rust
/// Return the logical negation of an equality/inequality operator.
/// Only handles Eq↔NotEq. Returns None for Less/SLess/etc. (those need operand swapping).
fn negate_eq_op(op: BinOpKind) -> Option<BinOpKind> {
    match op {
        BinOpKind::Eq    => Some(BinOpKind::NotEq),
        BinOpKind::NotEq => Some(BinOpKind::Eq),
        _ => None,
    }
}
```

- [ ] **Step 3: Add three rules to `mba_simplify_expr` after the `Not(Not(x))` arm**

Find the block ending at line 1000:
```rust
        Expr::UnaryOp(UnaryOpKind::Not, inner) => {
            if let Expr::UnaryOp(UnaryOpKind::Not, inner2) = &vars[inner.0 as usize].expr {
                return Some(Expr::Var(*inner2));
            }
            None
        }
        // CDQ+IDIV simplification: ...
```

Insert between the closing `}` of the `Not` arm and the `// CDQ+IDIV` comment:

```rust
        // BoolNot(BoolNot(x)) → x
        // BoolNot(Eq(a, b))   → NotEq(a, b)
        // BoolNot(NotEq(a, b)) → Eq(a, b)
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
        // (Eq(a,b) == 0) → NotEq(a,b),  (NotEq(a,b) == 0) → Eq(a,b)
        Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                if let Expr::BinOp(cmp_op, a, b) = vars[inner_id.0 as usize].expr {
                    if let Some(neg_op) = negate_eq_op(cmp_op) {
                        return Some(Expr::BinOp(neg_op, a, b));
                    }
                }
            }
            None
        }
        // (Eq(a,b) != 0) → Eq(a,b),  (NotEq(a,b) != 0) → NotEq(a,b)  [identity: already a bool]
        Expr::BinOp(BinOpKind::NotEq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                if matches!(vars[inner_id.0 as usize].expr,
                    Expr::BinOp(BinOpKind::Eq, _, _) | Expr::BinOp(BinOpKind::NotEq, _, _)
                ) {
                    return Some(Expr::Var(inner_id));
                }
            }
            None
        }
```

**Important:** The `Expr::BinOp(BinOpKind::Eq, ...)` arm you are adding must come BEFORE any existing `Expr::BinOp(BinOpKind::Eq, ...)` arm in the same match. Check with:

```bash
grep -n "BinOpKind::Eq\b" /Users/shane/repos/rsleigh/rsleigh-decompile/src/fold.rs | head -20
```

If there is already a `Expr::BinOp(BinOpKind::Eq, ...)` arm in `mba_simplify_expr`, you must merge the new `== 0` check into that existing arm rather than adding a duplicate arm.

- [ ] **Step 4: Build**

```bash
cargo build -p rsleigh-decompile 2>&1 | grep "^error" | head -20
```

Expected: no errors. If you get "unreachable pattern" for `BinOpKind::Eq`, it means a prior arm already matches — merge the `== 0` check into that arm.

- [ ] **Step 5: Run the regression tests**

```bash
cargo test -p rsleigh-decompile --test double_negation -- --nocapture 2>&1 | tail -20
```

Expected: both tests pass (or integration test skips if binary absent).

- [ ] **Step 6: Run the full rsleigh-decompile suite**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: simplify double-negation conditions (BoolNot/Eq-zero elimination)"
```

---

## Task 3: Full regression suite

**Files:**
- No changes — verification only

- [ ] **Step 1: Run the test-harness**

```bash
cargo test -p test-harness 2>&1 | tail -15
```

Expected: 9/9 tests pass. The `decompiler_validation` test must not regress — in particular `reverse_string` (contains `strlen`) and `main` (contains printf string literals) are the sensitive ones.

- [ ] **Step 2: If decompiler_validation fails, inspect the diff**

```bash
cargo test -p test-harness -- decompiler_validation --nocapture 2>&1 | head -60
```

If a golden assertion fails because an expression was over-simplified (e.g., a legitimate `== 0` removed), add a guard: the `Eq(inner, 0)` rule should only fire when `inner` is itself a size-1 (boolean) expression — check `vars[inner_id.0 as usize].size == 1` before simplifying.

- [ ] **Step 3: Spot-check main output directly**

```bash
cargo run -p rsleigh-cli --release -- \
    /Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe \
    0x140001e41 2>&1 | head -30
```

Confirm the double-negation is gone from the `if` condition.

- [ ] **Step 4: Commit if any golden fixes were needed**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: guard double-negation rule to size-1 boolean expressions only"
```

Only commit if Step 2 required a fix. Otherwise skip.

---

## Self-Review

### Spec Coverage

| Spec requirement | Task |
|---|---|
| `negate_eq_op` helper | Task 2 Step 2 |
| Rule 1: `BoolNot(BoolNot(x))` → `x` | Task 2 Step 3 |
| Rule 1: `BoolNot(Eq(a,b))` → `NotEq(a,b)` | Task 2 Step 3 |
| Rule 2: `Eq(comparison, Const(0))` → negate | Task 2 Step 3 |
| Rule 3: `NotEq(comparison, Const(0))` → identity | Task 2 Step 3 |
| Unit test: no `BinOp(Eq, BinOp(Eq,_,_), Const(0))` after fold | Task 1 |
| Integration test: main output no `== 0) == 0` | Task 1 |
| Full suite regression | Task 3 |

### Placeholder scan

No TBD, TODO, or vague steps — all code is explicit.

### Type consistency

- `negate_eq_op(op: BinOpKind) -> Option<BinOpKind>` — used as `negate_eq_op(cmp_op)` in Tasks 2 and the test checks `BinOpKind::Eq` / `BinOpKind::NotEq`.
- `Expr::BinOp(neg_op, a, b)` — `a` and `b` are `VarId`, same type as the inner `BinOp` operands looked up from `vars[inner_id.0 as usize].expr`.
- `Expr::Var(inner_id)` — `inner_id` is `VarId`, consistent with all other `Expr::Var` returns in `mba_simplify_expr`.
