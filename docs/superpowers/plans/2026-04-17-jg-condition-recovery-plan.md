# JG Condition Recovery Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `OF == SF` leaking into decompiler output by recovering the post-`mba_simplify` JG pattern `BoolAnd(NotEq(a,b), Eq(OF,SF))` as a signed greater-than comparison.

**Architecture:** Add a special-case path at the end of `try_recover_condition` in `fold.rs` that handles the `BoolAnd(NotEq, Eq(OF,SF))` shape (both orderings), validates that the `NotEq` operands match the CMP operands recovered from the OF/SF side, and emits `SLess(cmp_right, cmp_left)` = `a > b`.

**Tech Stack:** Rust, `rsleigh-decompile` crate, x86-64 P-code SSA.

---

## Background for the implementer

**The bug:** In x86, the JG (jump if greater, signed) condition is SLEIGH-encoded as `BoolAnd(BoolNot(ZF), Eq(OF,SF))`. The existing `classify_jcc_condition` recognizes this pattern. But `mba_simplify` runs *before* `recover_conditions` each fold round and rewrites `BoolNot(ZF)` → `NotEq(a,b)` (via the BoolNot→negate_eq chain + sub-as-cmp rule). By the time `classify_jcc_condition` sees the BoolAnd, the left operand is `NotEq(a,b)`, not `BoolNot(ZF)`, and the recognizer fails.

**The fix location:** `try_recover_condition` in `rsleigh-decompile/src/fold.rs` (currently lines 1844–1902). Add code after the existing fallback comparison checks (before the final `return None`) that:
1. Detects `BoolAnd(NotEq(x,y), Eq(OF,SF))` or its mirror
2. Validates `{x,y}` matches `{cmp_left, cmp_right}` (already in scope at that point)
3. Emits `SLess(cmp_right, cmp_left)` — that's JG: `cmp_left > cmp_right`

**Key existing functions in fold.rs (do not modify these):**
- `is_flag_ref(id, offset, ssa)` — checks if a VarId is at a flag register offset (one level of Var indirection). OF=523, SF=519, OV(ARM64)=259, NG(ARM64)=256, etc.
- `is_flag_derived(id, ssa)` — recursively checks if any sub-expression uses a flag register
- `resolve_cmp_operand(id, ssa)` — strips unique-space Var wrappers to get the underlying register var
- `find_cmp_operands(block_idx, ssa)` / `trace_cond_to_cmp(id, ssa, depth)` — find (cmp_left, cmp_right) from the block's SF/ZF/CF assignments

**`cmp_left` / `cmp_right` are already in scope** at the insertion point — they come from `let (cmp_left, cmp_right) = cmp_result?;` at line 1870. The `?` early-returns if no CMP is found, so your code is only reached when operands are available.

**Borrow safety pattern:** Extract all VarId values from `ssa.vars[...].expr` via `if let ... = &ssa.vars[x.0 as usize].expr { /* copy VarIds */ }` blocks. These immutable borrows are released after each block. Then call `ssa.new_var(varnode, ...)` for the single mutable borrow at the end.

**Register offsets:** x86-64: RAX=0, RCX=8, RDX=16. OF=523, SF=519, ZF=518, CF=512. These are byte offsets in the Ghidra register file.

---

## Files

- **Modify:** `rsleigh-decompile/src/fold.rs` — insert ~50 lines before the final `None` in `try_recover_condition`
- **Create:** `rsleigh-decompile/tests/jg_condition_recovery.rs` — 3 tests

---

### Task 1: Write failing tests

**Files:**
- Create: `rsleigh-decompile/tests/jg_condition_recovery.rs`

- [ ] **Step 1: Write the test file**

```rust
//! Regression tests for JG condition recovery after mba_simplify.
//!
//! Spec: docs/superpowers/specs/2026-04-17-jg-condition-recovery-design.md

use pcode_ir::AddressSpaceId;
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
            Ok(inst) => { let l = inst.len as usize; insts.push((addr, inst)); off += l; }
            Err(_) => break,
        }
    }
    insts
}

// cmp rax, rcx; jg +3; xor rax, rax; ret
const JG_BYTES: &[u8] = &[
    0x48, 0x39, 0xC8, // CMP rax, rcx  (rax - rcx; sets ZF, SF, OF, CF)
    0x7F, 0x03,       // JG +3         (jump if rax > rcx signed)
    0x48, 0x31, 0xC0, // XOR rax, rax
    0xC3,             // RET
];

/// After fold, the CBranch condition for a JG instruction must be SLess(rcx, rax),
/// meaning "rcx < rax" i.e. "rax > rcx" (signed). Exact opcode AND operand order checked.
/// This test fails before the fix because BoolNot(ZF) gets rewritten to NotEq(a,b)
/// by mba_simplify before recover_conditions runs, breaking the existing JG recognizer.
#[test]
fn jg_recovered_as_signed_greater() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let insts = decode_x64(JG_BYTES, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);
            fold_with_cc(&mut ssa, CallingConv::Win64);

            // Find the CBranch condition
            let cond_id = ssa.blocks.iter()
                .find_map(|b| if let SsaTerminator::CBranch { cond, .. } = b.terminator { Some(cond) } else { None })
                .expect("no CBranch block after fold");

            // Resolve through Var chains (up to 8 hops) to get the expression
            let mut resolved = cond_id;
            for _ in 0..8 {
                if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr { resolved = next; } else { break; }
            }
            let cond_expr = &ssa.vars[resolved.0 as usize].expr;

            // Must be SLess, not BoolAnd or anything flag-involving
            let (sl, sr) = match cond_expr {
                Expr::BinOp(BinOpKind::SLess, l, r) => (*l, *r),
                other => panic!("expected SLess, got {:?}", other),
            };

            // Resolve operands through Var/Unique chains to get register vars
            let resolve = |mut id| {
                for _ in 0..8 {
                    let v = &ssa.vars[id.0 as usize];
                    match v.expr {
                        Expr::Var(next) => id = next,
                        _ => break,
                    }
                    if v.varnode.space == AddressSpaceId::Register { break; }
                }
                id
            };
            let left_var = resolve(sl);
            let right_var = resolve(sr);
            let left_off = ssa.vars[left_var.0 as usize].varnode.offset;
            let right_off = ssa.vars[right_var.0 as usize].varnode.offset;

            // CMP rax, rcx → JG means rax > rcx → SLess(rcx, rax)
            // RAX is at register offset 0, RCX is at register offset 8
            assert_eq!(left_off, 8,  "SLess left operand must be RCX (offset 8), got offset {}", left_off);
            assert_eq!(right_off, 0, "SLess right operand must be RAX (offset 0), got offset {}", right_off);

            // Neither operand should be a flag register
            const FLAG_OFFSETS: &[u64] = &[512, 513, 514, 518, 519, 521, 523];
            assert!(!FLAG_OFFSETS.contains(&left_off),  "left operand is a flag register");
            assert!(!FLAG_OFFSETS.contains(&right_off), "right operand is a flag register");
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Validates the operand-match guard: a BoolAnd(NotEq(0,1), Eq(OF,SF)) where the NotEq
/// operands do NOT match the CMP operands must NOT be recovered as a signed comparison.
/// This proves the validation logic is actually present and working.
#[test]
fn jg_no_false_positive() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let insts = decode_x64(JG_BYTES, 0x1000);
            let cfg = build_cfg(&insts);
            let mut ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);

            // Before fold: the CBranch has BoolAnd(BoolNot(ZF), Eq(OF,SF)).
            // We replace it with BoolAnd(NotEq(Const(0), Const(1)), Eq(OF,SF)) —
            // operands 0 and 1 do not match rax/rcx, so the validator must reject it.
            let cbranch_block = ssa.blocks.iter()
                .position(|b| matches!(b.terminator, SsaTerminator::CBranch { .. }))
                .expect("no CBranch");

            // Extract Eq(OF,SF) from the right side of the BoolAnd, and terminator fields
            let (eq_of_sf_id, taken, fallthrough) = {
                if let SsaTerminator::CBranch { cond, taken, fallthrough } = ssa.blocks[cbranch_block].terminator {
                    let eq_id = if let Expr::BinOp(BinOpKind::BoolAnd, _l, r) = ssa.vars[cond.0 as usize].expr {
                        r
                    } else { panic!("expected BoolAnd before fold, got {:?}", ssa.vars[cond.0 as usize].expr) };
                    (eq_id, taken, fallthrough)
                } else { panic!("expected CBranch") }
            };
            let template_varnode = ssa.vars[eq_of_sf_id.0 as usize].varnode;

            // Build NotEq(Const(0), Const(1)) — operands that will NOT match rax/rcx
            let c0 = ssa.new_var(template_varnode, Expr::Const(0, 8), 8);
            let c1 = ssa.new_var(template_varnode, Expr::Const(1, 8), 8);
            let mismatched_neq = ssa.new_var(template_varnode, Expr::BinOp(BinOpKind::NotEq, c0, c1), 1);
            let mismatched_cond = ssa.new_var(template_varnode, Expr::BinOp(BinOpKind::BoolAnd, mismatched_neq, eq_of_sf_id), 1);
            ssa.blocks[cbranch_block].terminator = SsaTerminator::CBranch { cond: mismatched_cond, taken, fallthrough };

            // Fold: the mismatched condition must NOT be recovered to SLess
            fold_with_cc(&mut ssa, CallingConv::Win64);

            if let SsaTerminator::CBranch { cond, .. } = &ssa.blocks[cbranch_block].terminator {
                let mut resolved = *cond;
                for _ in 0..8 {
                    if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr { resolved = next; } else { break; }
                }
                assert!(
                    !matches!(ssa.vars[resolved.0 as usize].expr, Expr::BinOp(BinOpKind::SLess, _, _)),
                    "false positive: NotEq(0,1) was incorrectly recovered as SLess: {:?}",
                    ssa.vars[resolved.0 as usize].expr,
                );
            }
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Integration: function 0x14000195e must not contain "OF == SF" or "SF == OF"
/// in output, and must contain " > " in at least one condition line.
/// Skips gracefully if the fixture binary is absent.
#[test]
fn jg_integration_positive() {
    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => { eprintln!("skipping jg_integration_positive: fixture not found"); return; }
    };
    let pe = match goblin::pe::PE::parse(&data) {
        Ok(p) => p,
        Err(e) => { eprintln!("skipping: PE parse error: {}", e); return; }
    };

    let image_base = pe.image_base as u64;
    let func_va: u64 = 0x14000195e;
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

            // Negative: no flag register names in conditions
            assert!(
                !out.contains("OF == SF") && !out.contains("SF == OF"),
                "flag registers still leak into output:\n{}",
                out.lines().filter(|l| l.contains("OF") || l.contains("SF")).collect::<Vec<_>>().join("\n")
            );

            // Positive: a signed > comparison was emitted somewhere
            let has_gt = out.lines().any(|l| {
                let t = l.trim();
                (t.starts_with("if (") || t.starts_with("while (") || t.starts_with("} else if ("))
                    && t.contains(" > ")
            });
            assert!(has_gt, "no signed > comparison found in output:\n{}", out);
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}
```

- [ ] **Step 2: Run the tests to confirm Test 1 fails, others pass**

```bash
cargo test -p rsleigh-decompile --test jg_condition_recovery 2>&1 | tail -20
```

Expected:
```
test jg_recovered_as_signed_greater ... FAILED   ← must fail (proves non-vacuous)
test jg_no_false_positive ... ok                 ← must pass  (no false positive yet)
test jg_integration_positive ... FAILED          ← expected to fail too
```

If `jg_recovered_as_signed_greater` passes, the test is vacuous — check that `JG_BYTES` actually decodes to a JG instruction by adding a `dbg!(insts)` print.

- [ ] **Step 3: Commit the failing tests**

```bash
git add rsleigh-decompile/tests/jg_condition_recovery.rs
git commit -m "test: add failing JG condition recovery tests"
```

---

### Task 2: Implement the fix in try_recover_condition

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs` (lines ~1895–1902, before `None`)

- [ ] **Step 1: Locate the insertion point**

Open `rsleigh-decompile/src/fold.rs`. Find `fn try_recover_condition` (around line 1844). The function ends with:

```rust
    if let Expr::BinOp(kind, l, r) = &vdef.expr {
        if is_comparison(*kind) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
            return Some(cond_id);
        }
    }

    None
}
```

Insert the new code **between** the last `if let Expr::BinOp` block and the final `None`.

- [ ] **Step 2: Insert the special-case path**

The full insertion (replace the trailing `None` and closing brace with the block below, then add `None` and the brace back after):

```rust
    // Special case: post-mba_simplify JG pattern.
    // mba_simplify rewrites BoolNot(ZF) → NotEq(cmp_a, cmp_b) before recover_conditions.
    // Handle BoolAnd(NotEq(a,b), Eq(OF/OV,SF/NG)) and its mirror — both orderings.
    // Validates that NotEq operands match cmp_left/cmp_right to prevent false positives.
    {
        let ba_parts = if let Expr::BinOp(BinOpKind::BoolAnd, l, r) = &ssa.vars[cond_id.0 as usize].expr {
            Some((*l, *r))
        } else { None };

        if let Some((ba_left, ba_right)) = ba_parts {
            // Check if a VarId's expression is Eq(OF/OV, SF/NG) for any arch
            let is_of_sf_eq = |id: VarId| -> bool {
                if let Expr::BinOp(BinOpKind::Eq, a, b) = &ssa.vars[id.0 as usize].expr {
                    let a_of = is_flag_ref(*a,523,ssa)||is_flag_ref(*a,259,ssa)||is_flag_ref(*a,262,ssa)||is_flag_ref(*a,99,ssa);
                    let a_sf = is_flag_ref(*a,519,ssa)||is_flag_ref(*a,256,ssa)||is_flag_ref(*a,263,ssa)||is_flag_ref(*a,96,ssa);
                    let b_of = is_flag_ref(*b,523,ssa)||is_flag_ref(*b,259,ssa)||is_flag_ref(*b,262,ssa)||is_flag_ref(*b,99,ssa);
                    let b_sf = is_flag_ref(*b,519,ssa)||is_flag_ref(*b,256,ssa)||is_flag_ref(*b,263,ssa)||is_flag_ref(*b,96,ssa);
                    (a_of && b_sf) || (a_sf && b_of)
                } else { false }
            };
            // Check if a VarId's expression is NotEq(non-flag, non-flag); return operands
            let non_flag_neq = |id: VarId| -> Option<(VarId, VarId)> {
                if let Expr::BinOp(BinOpKind::NotEq, l, r) = &ssa.vars[id.0 as usize].expr {
                    if !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
                        return Some((*l, *r));
                    }
                }
                None
            };

            // Normalize: find which side is Eq(OF,SF) and which is NotEq(a,b)
            let neq_pair = if is_of_sf_eq(ba_right) {
                non_flag_neq(ba_left)
            } else if is_of_sf_eq(ba_left) {
                non_flag_neq(ba_right)
            } else {
                None
            };

            if let Some((neq_l, neq_r)) = neq_pair {
                // Validate: NotEq operands must resolve to the same vars as CMP operands
                let ra = resolve_cmp_operand(neq_l, ssa);
                let rb = resolve_cmp_operand(neq_r, ssa);
                let ca = resolve_cmp_operand(cmp_left, ssa);
                let cb = resolve_cmp_operand(cmp_right, ssa);
                if (ra == ca && rb == cb) || (ra == cb && rb == ca) {
                    let varnode = ssa.vars[cond_id.0 as usize].varnode;
                    let new_var = ssa.new_var(
                        varnode,
                        Expr::BinOp(BinOpKind::SLess, cmp_right, cmp_left),
                        1,
                    );
                    return Some(new_var);
                }
            }
        }
    }

    None
}
```

**Important borrow note:** The closures `is_of_sf_eq` and `non_flag_neq` capture `ssa` by shared reference. They must go out of scope before `ssa.new_var` (mutable borrow). Since both closures are defined and used entirely within the inner `if let Some((ba_left, ba_right))` block, and `ssa.new_var` is called after the `if let Some((neq_l, neq_r))` check — after the closures are dropped — this is borrow-safe.

If the compiler complains about simultaneous borrows, replace the closure bodies with inline expressions (no closures):

```rust
// Inline version for is_of_sf_eq(ba_right):
let r_is_of_sf = if let Expr::BinOp(BinOpKind::Eq, a, b) = &ssa.vars[ba_right.0 as usize].expr {
    (is_flag_ref(*a,523,ssa)||is_flag_ref(*a,259,ssa)||is_flag_ref(*a,262,ssa)||is_flag_ref(*a,99,ssa))
    && (is_flag_ref(*b,519,ssa)||is_flag_ref(*b,256,ssa)||is_flag_ref(*b,263,ssa)||is_flag_ref(*b,96,ssa))
    || (is_flag_ref(*a,519,ssa)||is_flag_ref(*a,256,ssa)||is_flag_ref(*a,263,ssa)||is_flag_ref(*a,96,ssa))
    && (is_flag_ref(*b,523,ssa)||is_flag_ref(*b,259,ssa)||is_flag_ref(*b,262,ssa)||is_flag_ref(*b,99,ssa))
} else { false };
// ... similar for l_is_of_sf, then derive neq_pair manually
```

- [ ] **Step 3: Build to check it compiles**

```bash
cargo build -p rsleigh-decompile 2>&1 | grep -E "^error"
```

Expected: no errors. If borrow errors appear, use the inline version from Step 2.

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rsleigh-decompile --test jg_condition_recovery 2>&1 | tail -20
```

Expected:
```
test jg_recovered_as_signed_greater ... ok
test jg_no_false_positive ... ok
test jg_integration_positive ... ok
```

- [ ] **Step 5: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: recover post-mba_simplify JG condition BoolAnd(NotEq,Eq(OF,SF)) with operand validation"
```

---

### Task 3: Full regression suite

**Files:** none (just running existing tests)

- [ ] **Step 1: Run the full rsleigh-decompile test suite**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -20
```

Expected: all test suites pass — double_negation (2), rsp_local_naming (3), sub_as_cmp (2), jg_condition_recovery (3).

- [ ] **Step 2: Run the full test-harness suite**

```bash
cargo test -p test-harness 2>&1 | tail -15
```

Expected:
```
test result: ok. 9 passed; 0 failed
```

- [ ] **Step 3: Commit if any fixes were needed**

If any test needed a fix not covered above, commit it. If everything was already clean, no additional commit needed.
