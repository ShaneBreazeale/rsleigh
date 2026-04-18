# Float/XMM Type Recovery — Design Spec

## Problem

Float-heavy functions decompile poorly. `lerp(float a, float b, float t)` produces:

```c
void lerp(void) {
    return (XMM1 - XMM0) * XMM2;
}
```

Expected:

```c
float lerp(float fparam_0, float fparam_1, float fparam_2) {
    return fparam_0 + fparam_2 * (fparam_1 - fparam_0);
}
```

The P-code layer is correct — SLEIGH generates `FloatSub`, `FloatMult`, `FloatAdd` ops. The problem is in the decompiler pipeline (SSA builder, fold pass, printer).

## Root Causes

### 1. No XMM float parameter recognition

`SYSV_ARG_REGS` in `fold.rs` only contains integer register offsets (RDI=56, RSI=48, RDX=16, RCX=8, R8=128, R9=136). Per SysV ABI, float/double params are passed in XMM0-XMM7. `name_parameters()` never sees XMM registers, so all float params are invisible.

XMM register offsets: XMM0=4608, XMM1=4672, XMM2=4736, XMM3=4800, XMM4=4864, XMM5=4928, XMM6=4992, XMM7=5056. Stride is 64 bytes (16-byte register + padding in SLEIGH layout).

### 2. No XMM0 return value detection

`detect_return_values()` and `find_ret_reg_in_block()` only check RAX (offset 0) or ARM32 r0 (offset 32). SysV returns float/double in XMM0 (offset 4608). Functions with float returns show as `void`.

### 3. 16-byte output varnode for 4/8-byte float ops

SLEIGH's P-code for `SUBSS XMM1, XMM0` produces:

```
Subpiece { out: unique(size:4), input: XMM1(size:16), lsb: 0 }
Subpiece { out: unique(size:4), input: XMM0(size:16), lsb: 0 }
FloatSub  { out: XMM1(size:16), left: unique(size:4), right: unique(size:4) }
```

The FloatSub operands are 4 bytes (float) but the output is 16 bytes (full XMM1). The SSA builder creates a 16-byte VarDef for a semantically 4-byte float result. This confuses sizing, type display, and local declarations.

### 4. MOVSD zero-clobber overwrites loads

`MOVSD XMM1, [mem]` generates:

```
Load { out: XMM1(size:16), ptr: addr }
Copy { out: XMM1(size:16), input: Const(0, size:8) }
```

The Copy zeros the upper 8 bytes of XMM1 but the SSA builder sees it as overwriting the Load result entirely. This produces `0 * expr` noise in `dot_product`.

### 5. XORPD self-XOR noise

`XORPD XMM0, XMM0` (float zero-init idiom) generates 6 P-code ops with IntXor on both halves. Currently handled by fragile text-level pattern matching in the printer. Should be folded at SSA level.

## Design

### A. Float parameter recognition (`fold.rs`)

Add float arg register constants:

```rust
const SYSV_FLOAT_ARG_REGS: &[u64] = &[4608, 4672, 4736, 4800, 4864, 4928, 4992, 5056];
const WIN64_FLOAT_ARG_REGS: &[u64] = &[4608, 4672, 4736, 4800]; // XMM0-XMM3
```

Add a thread-local for float arg regs (parallel to `ARG_REG_OFFSETS_TLS`):

```rust
std::thread_local! {
    static FLOAT_ARG_REG_OFFSETS_TLS: std::cell::RefCell<&'static [u64]> = const { std::cell::RefCell::new(SYSV_FLOAT_ARG_REGS) };
}
```

Set in `fold_with_cc()` based on calling convention.

Extend `name_parameters()`:
- After naming integer params, scan entry block for XMM register vars with `Expr::Unknown` or `Expr::Phi` that match float arg reg offsets.
- Name them `fparam_0`, `fparam_1`, etc. (separate numbering from integer params).
- Set `inferred_type = InferredType::Float` on these vars.
- Pass 2 fallback: scan all vars for float arg reg reads with no prior definition, same as existing integer param Pass 2.

### B. Float return value detection (`fold.rs`)

Extend `detect_return_values()`:
- After failing to find RAX/r0 return value, check if the function contains any float ops (FloatAdd/Sub/Mult/Div in any VarDef's expr).
- If so, search return blocks for XMM0 (offset 4608) assignments using a new `find_float_ret_in_block()`.
- Also handle: the return value may be the result of a FloatAdd/FloatMult that writes to XMM0's offset.

Extend `find_ret_reg_in_block()` signature or add `find_float_ret_in_block()` that searches for offset 4608.

### C. Float varnode size normalization (`ssa.rs`)

In the SSA builder's `lift_pcode_op` (or equivalent), when processing `FloatAdd/FloatSub/FloatMult/FloatDiv`:
- If the output varnode has size 16 (full XMM) but both operands have size 4 or 8, create the output VarDef with `size` equal to the operand size.
- Keep the varnode offset the same (still XMM0's offset 4608) — only the size changes.
- This ensures `InferredType::Float` + size 4 → `"float"`, size 8 → `"double"` in the printer.

Also apply to unary float ops: `FloatNeg`, `FloatAbs`, `FloatSqrt`, `FloatCeil`, `FloatFloor`, `FloatRound`, `Int2Float`, `Float2Float`.

For float comparisons (`FloatEq`, `FloatLess`, etc.), the output is already 1-byte bool — no change needed.

### D. MOVSD zero-clobber fix (`ssa.rs`)

Use the existing instruction-address grouping mechanism (same as Zext deferral). When processing ops at the same instruction address:
- Detect pattern: `Load { out: XMM_reg }` followed by `Copy { out: same_XMM_reg, input: Const(0) }`.
- XMM_reg identified by offset >= 4608 and size 16.
- Drop the Copy from the op sequence before SSA lifting.

This is the same architectural pattern as the sub-register Zext deferral already in `ssa.rs`.

### E. XMM self-XOR → 0.0 (`ssa.rs`)

During SSA construction, when processing `IntXor` where both inputs reference the same register offset at the same instruction address:
- Fold to `Expr::Const(0)` instead of `Expr::BinOp(Xor, left, right)`.
- Set `inferred_type = InferredType::Float` if the register is an XMM register (offset >= 4608).

### F. Printer updates (`printer.rs`)

- Float-typed local declarations: when a VarDef has `InferredType::Float`, declare as `float varN;` or `double varN;` based on size.
- Float params in function signature: `float fparam_0` instead of `int fparam_0`.
- Float return type: if the detected return value has `InferredType::Float`, emit `float` or `double` return type.
- Constant `0` from XMM self-XOR: display as `0.0` when in float context.

### G. Float call argument collection (`fold.rs`)

Extend `collect_reg_args_from_block()` to also collect XMM register writes before calls. Float args should be appended after integer args in the args list, matching ABI ordering. When a function's signature is known (from signature DB), use it to determine which XMM registers are float args.

## Files Changed

| File | Changes |
|------|---------|
| `rsleigh-decompile/src/fold.rs` | Float arg regs, `name_parameters()`, `detect_return_values()`, `collect_reg_args_from_block()` |
| `rsleigh-decompile/src/ssa.rs` | Float varnode size normalization, MOVSD zero-clobber fix, self-XOR folding |
| `rsleigh-decompile/src/printer.rs` | Float local declarations, float signature types, `0.0` display |
| `test-harness/` | Golden tests for float functions (lerp, dot_product) |

## Test Plan

- Compile `float_test.c` with `-O2` for x86-64
- Verify `lerp` decompiles with float params, float return, clean expression
- Verify `dot_product` decompiles without `0 *` noise, with double accumulator
- Run full test suite (`cargo test -p test-harness`) — no regressions in 240 existing tests
- Test on real-world binaries with float code (if available in test corpus)

## Non-Goals

- SIMD/vector operations (packed float, shuffles, broadcasts) — future work
- x87 FPU (ST0-ST7) — legacy, lower priority
- Float constant formatting (hex → decimal) — Phase 3 polish
- AArch64 NEON float recovery — separate follow-up (different register layout)
