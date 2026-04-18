# Float/XMM Type Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make float-heavy x86-64 functions decompile with correct parameter types, return types, and clean expressions — closing the biggest readability gap vs Ghidra.

**Architecture:** Fix at the SSA/fold level rather than text post-processing. Five changes: (A) float varnode size normalization in SSA builder, (B) MOVSD zero-clobber fix in SSA builder, (C) XMM self-XOR folding in SSA builder, (D) float parameter + return recognition in fold pass, (E) float call arg collection + printer updates.

**Tech Stack:** Rust, rsleigh-decompile crate (ssa.rs, fold.rs, printer.rs), test-harness crate.

**Key constants:** XMM0=offset 4608, XMM1=4672, XMM2=4736, ..., XMM7=5056 (stride 64). All size 16 in SLEIGH register space.

**Test binary:** `/tmp/float_test` compiled from `test-harness/examples/float_test.c` with `cc -O2 -arch x86_64`.

**Spec:** `docs/superpowers/specs/2026-04-15-float-xmm-type-recovery-design.md`

---

### Task 1: Create test binary and baseline golden test

**Files:**
- Create: `test-harness/examples/float_test.c`
- Modify: `test-harness/src/main.rs` (add test)

This task establishes the test infrastructure. We compile a float-heavy C file and write a test that asserts the decompiler output contains expected patterns. The test will FAIL initially — that's intentional (TDD).

- [ ] **Step 1: Create the C test source**

Create `test-harness/examples/float_test.c`:

```c
#include <stdio.h>
#include <math.h>

double dot_product(double *a, double *b, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

float lerp(float a, float b, float t) {
    return a + t * (b - a);
}

int main() {
    double a[] = {1.0, 2.0, 3.0};
    double b[] = {4.0, 5.0, 6.0};
    double result = dot_product(a, b, 3);
    printf("dot product: %f\n", result);

    float x = lerp(1.0f, 5.0f, 0.5f);
    printf("lerp: %f\n", (double)x);

    double y = sin(3.14159) + cos(1.0);
    printf("trig: %f\n", y);
    return 0;
}
```

- [ ] **Step 2: Compile the test binary**

Run: `cc -O2 -o test-harness/examples/float_test test-harness/examples/float_test.c -lm -arch x86_64`

If on Apple Silicon without x86_64 toolchain, use: `cc -O2 -o test-harness/examples/float_test test-harness/examples/float_test.c -lm` (will be native AArch64 — adjust test expectations accordingly). The x86-64 binary is preferred since that's where XMM registers exist.

- [ ] **Step 3: Write the float decompilation test**

Add to `test-harness/src/main.rs`, in the test module, a new test function. Find the existing test pattern — tests use `rsleigh_api::Decoder` and `rsleigh_decompile::decompile_function` or similar. The test should:

1. Load the compiled `float_test` binary
2. Decompile the `lerp` function
3. Assert the output contains `float` (return type or param type)
4. Assert the output does NOT contain `void lerp(void)` (the current broken output)
5. Assert the output contains `fparam` or `param` (float params recognized)

Look at existing decompiler tests in `test-harness/src/main.rs` for the exact API pattern — there are ~240 tests, so copy the pattern from one that decompiles a real binary. The test should call `decompile_with_binary` or whatever the existing tests use.

If tests use raw bytes and `Decoder::decode()` rather than full binary decompilation, write a simpler P-code level test instead:

```rust
#[test]
fn test_float_lerp_params() {
    // SUBSS XMM1, XMM0 | MULSS XMM1, XMM2 | ADDSS XMM0, XMM1 | RET
    // These are the core ops of lerp(float a, float b, float t)
    let bytes: Vec<u8> = vec![
        0x55,                               // PUSH RBP
        0x48, 0x89, 0xE5,                   // MOV RBP, RSP
        0xF3, 0x0F, 0x5C, 0xC8,             // SUBSS XMM1, XMM0
        0xF3, 0x0F, 0x59, 0xCA,             // MULSS XMM1, XMM2
        0xF3, 0x0F, 0x58, 0xC1,             // ADDSS XMM0, XMM1
        0x5D,                               // POP RBP
        0xC3,                               // RET
    ];
    // Decompile and check output contains float types
    // (exact decompilation API call depends on existing test patterns)
    let output = decompile_bytes_x86_64(&bytes, "lerp");
    assert!(output.contains("float"), "expected float type in output: {}", output);
    assert!(!output.contains("void lerp(void)"), "should not be void: {}", output);
}
```

Adapt the decompilation call to match whatever helper the existing tests use.

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p test-harness test_float_lerp_params -- --nocapture 2>&1 | tail -20`

Expected: FAIL — the test should fail because `lerp` currently decompiles as `void lerp(void)` with raw XMM register names and no float types.

- [ ] **Step 5: Commit**

```bash
git add test-harness/examples/float_test.c test-harness/src/main.rs
git commit -m "test: add failing float/XMM decompilation test for lerp"
```

---

### Task 2: Float varnode size normalization in SSA builder

**Files:**
- Modify: `rsleigh-decompile/src/ssa.rs:164-186` (the main op-processing loop)

**Problem:** `FloatSub { out: XMM1(size:16), left: tmp(size:4), right: tmp(size:4) }` — the SSA builder creates a 16-byte VarDef for a 4-byte float result because it uses `out_vn.size` (16) from the SLEIGH P-code.

**Fix:** After calling `build_expr()`, if the expression is a float binary/unary op, override the size to match the operand size.

- [ ] **Step 1: Add helper to detect float expression operand size**

In `rsleigh-decompile/src/ssa.rs`, add a function after `build_expr` (around line 580):

```rust
/// For float ops, return the semantic operand size (4=float, 8=double).
/// SSE scalar instructions write to full 16-byte XMM registers but the
/// meaningful result is only the low 4 or 8 bytes.
fn float_semantic_size(expr: &Expr, vars: &[VarDef]) -> Option<u32> {
    match expr {
        Expr::BinOp(kind, left, right) => {
            use BinOpKind::*;
            match kind {
                FloatAdd | FloatSub | FloatMult | FloatDiv => {
                    // Use operand size — both should match (4 for SS, 8 for SD)
                    let ls = vars[left.0 as usize].size;
                    let rs = vars[right.0 as usize].size;
                    Some(ls.min(rs))
                }
                _ => None,
            }
        }
        Expr::UnaryOp(kind, input) => {
            use UnaryOpKind::*;
            match kind {
                FloatNeg | FloatAbs | FloatSqrt | FloatCeil
                | FloatFloor | FloatRound => {
                    Some(vars[input.0 as usize].size)
                }
                Int2Float => {
                    // Result is float — input is int. Use 4 (float) as default
                    // unless input is 8 bytes, in which case result is double.
                    let is = vars[input.0 as usize].size;
                    Some(if is >= 8 { 8 } else { 4 })
                }
                Float2Float => {
                    // Precision conversion — output size differs from input.
                    // We can't know the target precision from the expression alone.
                    // Return None and let the output varnode size stand.
                    None
                }
                _ => None,
            }
        }
        _ => None,
    }
}
```

- [ ] **Step 2: Apply size normalization in the op-processing loop**

In `rsleigh-decompile/src/ssa.rs`, find the block at lines ~180-185 where vars are created from non-Load ops:

```rust
                                } else {
                                    build_expr(&mut ssa, &mut current, op)
                                };
                                let var_id = ssa.new_var(out_vn, expr, out_vn.size);
                                current.insert(out_vn, var_id);
                                stmts.push(Stmt::Assign(var_id));
```

Change the `new_var` call to use the semantic float size when applicable:

```rust
                                } else {
                                    build_expr(&mut ssa, &mut current, op)
                                };
                                // Float ops: use semantic operand size instead of
                                // the 16-byte XMM output varnode size.
                                let effective_size = float_semantic_size(&expr, &ssa.vars)
                                    .unwrap_or(out_vn.size);
                                let var_id = ssa.new_var(out_vn, expr, effective_size);
                                current.insert(out_vn, var_id);
                                stmts.push(Stmt::Assign(var_id));
```

- [ ] **Step 3: Run existing tests**

Run: `cargo test -p test-harness 2>&1 | tail -5`

Expected: All 240 existing tests PASS. The size normalization only affects vars created from float P-code ops writing to 16-byte XMM registers, which don't appear in integer-only test cases.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/ssa.rs
git commit -m "fix: normalize float varnode size to operand size (16→4/8)"
```

---

### Task 3: MOVSD zero-clobber fix in SSA builder

**Files:**
- Modify: `rsleigh-decompile/src/ssa.rs:96-195` (instruction grouping loop)

**Problem:** `MOVSD XMM1, [mem]` generates:
```
Load  { out: XMM1(off:4672, sz:16), ptr: addr }
Copy  { out: XMM1(off:4672, sz:16), input: Const(0, sz:8) }
```
The Copy zeros the upper 8 bytes but SSA sees it overwriting the Load result, producing `0 * expr` noise.

**Fix:** Within the instruction-grouped op processing (same loop as Zext deferral), detect and drop the zero-copy.

- [ ] **Step 1: Add MOVSD zero-clobber detection**

In `rsleigh-decompile/src/ssa.rs`, inside the instruction-grouped loop (after the Zext deferral detection at ~line 114), add detection for the MOVSD pattern. Insert before the `// Process remaining ops normally` comment at line 142:

```rust
                // Detect MOVSD zero-clobber pattern:
                // Load { out: XMM(off>=4608, sz:16) } followed by
                // Copy { out: same_XMM, input: Const(0) }
                // The Copy zeros upper bytes — drop it to preserve the Load result.
                let mut skip_zero_copy: HashSet<usize> = HashSet::new();
                for (i, op) in inst_ops.iter().enumerate() {
                    if let PcodeOp::Load { out, .. } = op {
                        if out.space == AddressSpaceId::Register
                            && out.offset >= 4608
                            && out.size == 16
                        {
                            // Check if next op is Copy of 0 to same register
                            if i + 1 < inst_ops.len() {
                                if let PcodeOp::Copy { out: copy_out, input } = inst_ops[i + 1] {
                                    if copy_out.space == out.space
                                        && copy_out.offset == out.offset
                                        && input.space == AddressSpaceId::Const
                                        && input.offset == 0
                                    {
                                        skip_zero_copy.insert(i + 1);
                                    }
                                }
                            }
                        }
                    }
                }
```

- [ ] **Step 2: Skip the zero-copy ops during processing**

In the same file, in the `// Process remaining ops normally` loop at line 143, add a skip check. Change:

```rust
                for op in &inst_ops {
                    // Skip ops we already handled as deferred Zext
                    if let PcodeOp::IntZext { out, input } = op {
                        if deferred_zext.iter().any(|(vn, _)| vn == out) {
                            continue;
                        }
                    }
```

To:

```rust
                for (op_idx, op) in inst_ops.iter().enumerate() {
                    // Skip MOVSD zero-clobber Copy ops
                    if skip_zero_copy.contains(&op_idx) {
                        continue;
                    }
                    // Skip ops we already handled as deferred Zext
                    if let PcodeOp::IntZext { out, input } = op {
                        if deferred_zext.iter().any(|(vn, _)| vn == out) {
                            continue;
                        }
                    }
```

Note: the existing loop uses `for op in &inst_ops` — change to `for (op_idx, op) in inst_ops.iter().enumerate()`.

- [ ] **Step 3: Run existing tests**

Run: `cargo test -p test-harness 2>&1 | tail -5`

Expected: All existing tests PASS. MOVSD only occurs in float code paths.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/ssa.rs
git commit -m "fix: drop MOVSD zero-clobber Copy that overwrites XMM Load result"
```

---

### Task 4: XMM self-XOR → zero folding in SSA builder

**Files:**
- Modify: `rsleigh-decompile/src/ssa.rs:523` (IntXor in build_expr)

**Problem:** `XORPD XMM0, XMM0` (float zero-init idiom) generates `IntXor` of the same register, which flows through as a complex expression. Currently handled by fragile text-level pattern matching.

**Fix:** In `build_expr`, when `IntXor` has both inputs resolving to the same VarId, fold to `Expr::Const(0)`.

- [ ] **Step 1: Fold self-XOR to zero constant**

In `rsleigh-decompile/src/ssa.rs`, change line 523:

```rust
        PcodeOp::IntXor { left, right, .. } => bin!(Xor, left, right),
```

To:

```rust
        PcodeOp::IntXor { left, right, out, .. } => {
            // XOR reg, reg → 0 (common zero-init idiom, especially XORPS/XORPD)
            if left.space == right.space
                && left.offset == right.offset
                && left.size == right.size
                && left.space == AddressSpaceId::Register
            {
                Expr::Const(0, out.size)
            } else {
                bin!(Xor, left, right)
            }
        }
```

Note: `PcodeOp::IntXor` has fields `{ out, left, right }`. Check the exact field names in `pcode-ir/src/lib.rs` — they may be `out`, `left`, `right`. The key is comparing the input varnodes (not resolved VarIds) since self-XOR means the *same register* appears on both sides of the instruction.

- [ ] **Step 2: Run existing tests**

Run: `cargo test -p test-harness 2>&1 | tail -5`

Expected: All existing tests PASS. Self-XOR of GPRs (`XOR EAX, EAX`) also folds to 0, which is correct — it's a common zero idiom for integer registers too.

- [ ] **Step 3: Commit**

```bash
git add rsleigh-decompile/src/ssa.rs
git commit -m "fix: fold self-XOR to zero constant (XORPS/XORPD/XOR reg,reg)"
```

---

### Task 5: Float parameter recognition in fold pass

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs:17-31` (constants and thread-locals)
- Modify: `rsleigh-decompile/src/fold.rs:47-55` (fold_with_cc)
- Modify: `rsleigh-decompile/src/fold.rs:2898-2968` (name_parameters)

**Problem:** `name_parameters()` only scans for integer arg registers (RDI, RSI, etc). Float params in XMM0-XMM7 are invisible, so `lerp(float, float, float)` becomes `lerp(void)`.

- [ ] **Step 1: Add float arg register constants and thread-local**

In `rsleigh-decompile/src/fold.rs`, after line 21 (WIN64_ARG_REGS), add:

```rust
/// x86-64 SysV ABI float argument register offsets (XMM0-XMM7).
const SYSV_FLOAT_ARG_REGS: &[u64] = &[4608, 4672, 4736, 4800, 4864, 4928, 4992, 5056];

/// Windows x64 ABI float argument register offsets (XMM0-XMM3).
const WIN64_FLOAT_ARG_REGS: &[u64] = &[4608, 4672, 4736, 4800];
```

After the existing `ARG_REG_OFFSETS_TLS` thread-local (line 26), add:

```rust
std::thread_local! {
    static FLOAT_ARG_REG_OFFSETS_TLS: std::cell::RefCell<&'static [u64]> = const { std::cell::RefCell::new(SYSV_FLOAT_ARG_REGS) };
}

fn float_arg_reg_offsets() -> &'static [u64] {
    FLOAT_ARG_REG_OFFSETS_TLS.with(|r| *r.borrow())
}
```

- [ ] **Step 2: Set float arg regs in fold_with_cc**

In `rsleigh-decompile/src/fold.rs`, in `fold_with_cc()` after the existing `ARG_REG_OFFSETS_TLS.with(...)` block (around line 49-55), add:

```rust
    FLOAT_ARG_REG_OFFSETS_TLS.with(|r| {
        *r.borrow_mut() = match cc {
            CallingConv::SysV => SYSV_FLOAT_ARG_REGS,
            CallingConv::Win64 => WIN64_FLOAT_ARG_REGS,
            CallingConv::Cdecl32 => &[],
        };
    });
```

- [ ] **Step 3: Extend name_parameters to recognize XMM float params**

In `rsleigh-decompile/src/fold.rs`, at the end of `name_parameters()` (after the x86-32 Pass 3, around line 3050), add a new pass for float params:

```rust
    // Pass 4: Float parameters from XMM registers (x86-64 SysV / Win64).
    // Float args are passed in XMM0-XMM7 (SysV) or XMM0-XMM3 (Win64).
    let float_offsets = float_arg_reg_offsets();
    if !float_offsets.is_empty() {
        let mut fparam_idx = 0u32;
        let mut fnamed_offsets = std::collections::HashSet::new();

        // Scan entry block for XMM register vars with Unknown expr
        let stmts: Vec<Stmt> = ssa.blocks[entry].stmts.clone();
        for stmt in &stmts {
            if let Stmt::Assign(var_id) = stmt {
                let vdef = &ssa.vars[var_id.0 as usize];
                if let Expr::Unknown = &vdef.expr {
                    if vdef.varnode.space == AddressSpaceId::Register
                        && float_offsets.contains(&vdef.varnode.offset)
                        && !fnamed_offsets.contains(&vdef.varnode.offset)
                    {
                        ssa.vars[var_id.0 as usize].param_name = Some(format!("fparam_{}", fparam_idx));
                        ssa.vars[var_id.0 as usize].inferred_type = InferredType::Float;
                        fnamed_offsets.insert(vdef.varnode.offset);
                        fparam_idx += 1;
                    }
                }
            }
        }

        // Fallback: scan all vars for XMM reads with no prior def (optimized code)
        if fparam_idx == 0 {
            for &offset in float_offsets.iter() {
                for v in 0..ssa.vars.len() {
                    let vdef = &ssa.vars[v];
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == offset
                        && vdef.param_name.is_none()
                    {
                        if matches!(&vdef.expr, Expr::Unknown | Expr::Phi(_)) {
                            ssa.vars[v].param_name = Some(format!("fparam_{}", fparam_idx));
                            ssa.vars[v].inferred_type = InferredType::Float;
                            fnamed_offsets.insert(offset);
                            fparam_idx += 1;
                            break;
                        }
                    }
                }
            }
        }
    }
```

- [ ] **Step 4: Run existing tests**

Run: `cargo test -p test-harness 2>&1 | tail -5`

Expected: All existing tests PASS. Float param naming only fires when XMM registers appear as Unknown/Phi vars, which doesn't happen in non-float test cases.

- [ ] **Step 5: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "feat: recognize XMM float parameters (SysV XMM0-7, Win64 XMM0-3)"
```

---

### Task 6: Float return value detection in fold pass

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs:1949-2077` (detect_return_values, find_ret_reg_in_block)

**Problem:** `detect_return_values()` only checks RAX (offset 0) or ARM32 r0 (offset 32). Functions returning float/double use XMM0 (offset 4608).

- [ ] **Step 1: Add XMM0 return detection to detect_return_values**

In `rsleigh-decompile/src/fold.rs`, in `detect_return_values()`, after all existing strategies (after the Strategy 4 block, around line 2053), add:

```rust
        // Strategy 5: Float return — check XMM0 (offset 4608) for functions with float ops.
        if found.is_none() {
            let has_float_ops = ssa.vars.iter().any(|v| matches!(&v.expr,
                Expr::BinOp(BinOpKind::FloatAdd | BinOpKind::FloatSub
                    | BinOpKind::FloatMult | BinOpKind::FloatDiv, _, _)
                | Expr::UnaryOp(UnaryOpKind::FloatNeg | UnaryOpKind::FloatAbs
                    | UnaryOpKind::FloatSqrt | UnaryOpKind::Int2Float
                    | UnaryOpKind::Float2Float, _)
            ));
            if has_float_ops {
                const XMM0_OFFSET: u64 = 4608;
                // Search this block
                found = find_float_ret_in_block(&ssa.blocks[bi].stmts, &ssa.vars, XMM0_OFFSET);
                // Search predecessors if not found
                if found.is_none() {
                    for pred_bi in 0..ssa.blocks.len() {
                        if pred_bi == bi { continue; }
                        let flows_to_bi = match &ssa.blocks[pred_bi].terminator {
                            SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) => b.0 == bi,
                            SsaTerminator::CBranch { taken, fallthrough, .. } => taken.0 == bi || fallthrough.0 == bi,
                            SsaTerminator::Call { fallthrough, .. } => fallthrough.0 == bi,
                            _ => false,
                        };
                        if !flows_to_bi { continue; }
                        found = find_float_ret_in_block(&ssa.blocks[pred_bi].stmts, &ssa.vars, XMM0_OFFSET);
                        if found.is_some() { break; }
                    }
                }
            }
        }
```

- [ ] **Step 2: Add find_float_ret_in_block helper**

After `find_ret_reg_in_block` (around line 2077), add:

```rust
/// Search a block's statements backwards for an assignment to a float return register.
fn find_float_ret_in_block(stmts: &[Stmt], vars: &[VarDef], float_ret_offset: u64) -> Option<VarId> {
    for stmt in stmts.iter().rev() {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = &vars[var_id.0 as usize];
            if vdef.varnode.space == AddressSpaceId::Register
                && vdef.varnode.offset == float_ret_offset
            {
                return Some(*var_id);
            }
        }
    }
    None
}
```

- [ ] **Step 3: Run existing tests**

Run: `cargo test -p test-harness 2>&1 | tail -5`

Expected: All existing tests PASS. Strategy 5 only fires when earlier strategies fail AND the function has float ops, so it won't change behavior for existing non-float tests.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "feat: detect float return values via XMM0 in functions with float ops"
```

---

### Task 7: Float call argument collection

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs:2154-2190` (collect_reg_args_from_block)

**Problem:** `collect_reg_args_from_block()` only collects integer arg registers before calls. XMM register writes that set up float arguments are ignored, so float args to calls are lost.

- [ ] **Step 1: Extend collect_reg_args_from_block to collect float args**

In `rsleigh-decompile/src/fold.rs`, at the end of `collect_reg_args_from_block`, before the final sort/return (around line 2186), add float arg collection:

```rust
    // Also collect float arguments from XMM registers
    let float_offsets = float_arg_reg_offsets();
    if !float_offsets.is_empty() {
        let mut float_args: Vec<(u64, VarId)> = Vec::new();
        for j in (0..up_to).rev() {
            if let Stmt::Assign(var_id) = &stmts[j] {
                let vdef = safe_var(vars, *var_id);
                if vdef.varnode.space == AddressSpaceId::Register
                    && float_offsets.contains(&vdef.varnode.offset)
                {
                    if !float_args.iter().any(|(off, _)| *off == vdef.varnode.offset) {
                        float_args.push((vdef.varnode.offset, *var_id));
                    }
                }
            }
            if matches!(&stmts[j], Stmt::Call { .. }) { break; }
        }
        // Append float args after integer args, sorted by XMM register order
        float_args.sort_by_key(|(off, _)| {
            float_offsets.iter().position(|o| o == off).unwrap_or(99)
        });
        args.extend(float_args);
    }
```

- [ ] **Step 2: Run existing tests**

Run: `cargo test -p test-harness 2>&1 | tail -5`

Expected: All existing tests PASS. Float arg collection only fires when XMM register writes are found before calls.

- [ ] **Step 3: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "feat: collect XMM float arguments before function calls"
```

---

### Task 8: Printer updates for float signatures and declarations

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs:7666-7681` (param sorting in generate_function_signature)
- Modify: `rsleigh-decompile/src/printer.rs:6600-6615` (local variable declarations)

**Problem:** The printer's param sort uses `strip_prefix("param_")` which won't handle `fparam_` names. Also, local variable declarations don't account for float-typed variables.

- [ ] **Step 1: Fix param sorting to handle fparam_ prefix**

In `rsleigh-decompile/src/printer.rs`, in `generate_function_signature()`, update the sort at line ~7677:

```rust
    params.sort_by(|a, b| {
        let idx_a = a.0.strip_prefix("param_")
            .or_else(|| a.0.strip_prefix("fparam_"))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(999);
        let idx_b = b.0.strip_prefix("param_")
            .or_else(|| b.0.strip_prefix("fparam_"))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(999);
        // Sort integer params before float params, then by index
        let is_float_a = a.0.starts_with("fparam_");
        let is_float_b = b.0.starts_with("fparam_");
        is_float_a.cmp(&is_float_b).then(idx_a.cmp(&idx_b)).then(a.0.cmp(&b.0))
    });
```

This sorts integer params first (`param_0, param_1, ...`) then float params (`fparam_0, fparam_1, ...`), matching the ABI argument order convention where integer and float args are in separate register files.

- [ ] **Step 2: Ensure float-typed vars get correct local declaration types**

In `rsleigh-decompile/src/printer.rs`, find the local variable declaration section (search for `fVar` or `dVar` in the declaration generation). The existing code at ~line 6608-6612 maps variable name prefixes to types:

```rust
                } else if name.starts_with("fVar") {
                    "float"
                } else if name.starts_with("dVar") {
                    "double"
```

This already handles the naming. However, we also need to ensure that variables created from float ops (which now have correct sizes from Task 2) get the `dVar`/`fVar` naming. Check the auto-naming logic — look for where `dVar` names are assigned. The existing XMM register mapping at line ~6398 maps `("XMM0", "d"), ("XMM1", "d"), ...` which produces `dVar` names. With the size normalization from Task 2, these should now correctly size as `double dVar1;` (8-byte) or `float fVar1;` (4-byte).

Verify this works by reading the auto-naming code path. If float-sized (4-byte) XMM vars don't get `fVar` prefix, they'll get `dVar` which is for `double`. Check if a separate mapping or check is needed for size=4 XMM vars to get `fVar` prefix instead.

If needed, add a size-based override in the auto-naming section:

```rust
// XMM register with float-sized (4-byte) result → fVar prefix
if name.starts_with("dVar") && vdef.size == 4 && vdef.inferred_type == InferredType::Float {
    // Rename to fVar
    name = name.replace("dVar", "fVar");
}
```

- [ ] **Step 3: Run existing tests**

Run: `cargo test -p test-harness 2>&1 | tail -5`

Expected: All existing tests PASS.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/printer.rs
git commit -m "fix: printer handles fparam_ sorting and float local declarations"
```

---

### Task 9: Integration test — verify float_test decompilation

**Files:**
- Modify: `test-harness/src/main.rs` (update or verify the test from Task 1)

This task validates the full pipeline end-to-end on the `lerp` function.

- [ ] **Step 1: Run the float test from Task 1**

Run: `cargo test -p test-harness test_float_lerp_params -- --nocapture 2>&1 | tail -20`

Expected: PASS — `lerp` should now show float params and float return type.

- [ ] **Step 2: Manually check lerp decompilation**

Run: `cargo run -p rsleigh-cli --release -- /tmp/float_test lerp 2>/dev/null`

Expected output should look approximately like:

```c
float lerp(float fparam_0, float fparam_1, float fparam_2) {
    return fparam_0 + fparam_2 * (fparam_1 - fparam_0);
}
```

The exact expression may vary depending on folding order, but the key requirements are:
- Return type is `float` (not `void`)
- Parameters show `float fparam_0`, `float fparam_1`, `float fparam_2`
- No raw `XMM0`/`XMM1`/`XMM2` register names in the body
- The expression involves subtraction, multiplication, and addition

- [ ] **Step 3: Check dot_product decompilation**

Run: `cargo run -p rsleigh-cli --release -- /tmp/float_test dot_product 2>/dev/null`

Expected improvements:
- No `0 * expr` noise (MOVSD zero-clobber fixed)
- `double` return type or at least not `int`
- Cleaner loop body

This one is more complex (loop-unrolled by -O2) so don't expect perfect output, but the `0 *` artifacts should be gone.

- [ ] **Step 4: Update test assertions if needed**

Based on the actual output, tighten the test assertions in `test-harness/src/main.rs`. Add checks for:
- `output.contains("float")` — float type appears somewhere
- `!output.contains("void lerp(void)")` — not the broken signature
- `!output.contains("0 *")` — no zero-multiply noise (if testing dot_product)

- [ ] **Step 5: Run full test suite**

Run: `cargo test -p test-harness 2>&1 | tail -10`

Expected: All tests PASS including the new float test.

- [ ] **Step 6: Commit**

```bash
git add test-harness/src/main.rs
git commit -m "test: verify float/XMM type recovery on lerp and dot_product"
```

---

### Task 10: Run full regression suite and fix any breakage

**Files:**
- Potentially modify: any file touched in Tasks 2-8

This is the safety net task. The changes in Tasks 2-8 affect core SSA and fold paths. While each task ran tests incrementally, this task does a thorough validation.

- [ ] **Step 1: Run full test suite**

Run: `make test 2>&1 | tail -30`

This runs the full pipeline: generate slaspecs → build → test. Expected: all 240+ tests pass.

- [ ] **Step 2: Test on a real-world binary**

If test binaries exist in `test-harness/` (check with `ls test-harness/test_bin/`), pick one and decompile it:

Run: `cargo run -p rsleigh-cli --release -- test-harness/test_bin/<some_binary> --all 2>/dev/null | head -100`

Verify no panics and output looks reasonable — especially that non-float functions are unchanged.

- [ ] **Step 3: Fix any regressions**

If any existing tests fail:
- Check if the failure is in a float-related test (expected — may need assertion updates)
- Check if the failure is in a non-float test (unexpected — investigate the SSA change)
- The most likely regression is from Task 4 (self-XOR folding) affecting `XOR EAX, EAX` patterns. Verify that `XOR EAX, EAX` → `Const(0)` is still correct for integer zero-init.

- [ ] **Step 4: Commit any fixes**

```bash
git add -u
git commit -m "fix: address regressions from float/XMM type recovery"
```

(Only if there were regressions to fix. Skip if all tests passed.)
