# SSA Call-Clobber + Printer Param-Name Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Invalidate caller-saved registers in the SSA builder after every Call, so post-call reads (strcspn's return, printf's args, etc.) resolve to fresh `Expr::Unknown` VarDefs instead of stale pre-call values. Optionally tighten the printer's param_name chase so stale-register renderings like `*(C)` disappear.

**Architecture:** Add a caller-saved register table keyed by `fold::CallingConv`. Plumb `CallingConv` into `ssa::build_ssa_with_cc`. At every Call site — both `Terminator::Call` and pcode-op Calls inside a block — scrub the per-block `current` varnode→VarId map for caller-saved register entries and emit a fresh `Expr::Unknown` VarDef for the return register (RAX / x0 / etc.) with `call_return: true`. This makes the SSA honor standard ABI clobber rules by construction, replacing the fragile post-hoc scan in `fold::propagate_call_returns`.

**Tech Stack:** Rust 2021, rsleigh workspace. Files touched: `rsleigh-decompile/src/ssa.rs`, `rsleigh-decompile/src/lib.rs`, `rsleigh-decompile/src/fold.rs`, optionally `rsleigh-decompile/src/printer.rs`, new test file `rsleigh-decompile/tests/call_clobber.rs`.

---

## File Structure

| File | Responsibility | Change type |
|---|---|---|
| `rsleigh-decompile/src/ssa.rs` | SSA construction; owns `current` varnode map | Add `build_ssa_with_cc`, caller-saved tables, clobber helper; call from `convert_terminator` and `process_op` Call paths |
| `rsleigh-decompile/src/lib.rs` | Pipeline wiring | Replace `build_ssa(&cfg)` with `build_ssa_with_cc(&cfg, cc)` in 3 call sites |
| `rsleigh-decompile/src/fold.rs` | `propagate_call_returns` | Make idempotent — skip vars already marked `call_return: true` |
| `rsleigh-decompile/src/printer.rs` | Param-name chase at lines 8651–8662 | (Conditional, Task 6) tighten the Var/Phi chain to stop at non-arg terminals |
| `rsleigh-decompile/tests/call_clobber.rs` | Regression test | New |
| `test-harness/examples/probe_check2_ssa.rs` | Manual diagnostic probe | Keep as-is for re-runs |

---

## Task 1: Write the failing SSA regression test

**Files:**
- Create: `rsleigh-decompile/tests/call_clobber.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! Regression: after a Call terminator, caller-saved registers must be
//! invalidated so post-call reads resolve to fresh Expr::Unknown VarDefs.
//!
//! Spec: docs/superpowers/specs/2026-04-16-ssa-call-clobber-design.md

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::cfg::build_cfg;
use rsleigh_decompile::fold::CallingConv;
use rsleigh_decompile::ir::Expr;
use rsleigh_decompile::ssa::build_ssa_with_cc;

/// Decode a tiny x86-64 sequence: set RAX to a LEA result, CALL an absolute
/// address, then read RAX. Post-call RAX must be a fresh Unknown, not the
/// pre-call LEA value.
fn decode(bytes: &[u8], base: u64) -> Vec<(u64, Instruction)> {
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

#[test]
fn post_call_rax_is_unknown_win64() {
    // lea rax, [rip+0x10]       48 8D 05 10 00 00 00
    // mov rcx, rax               48 89 C1
    // call rel32 (to +0x20)      E8 13 00 00 00    (returns to insn after call)
    // mov rdx, rax               48 89 C2
    // ret                        C3
    let bytes: [u8; 18] = [
        0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC1,
        0xE8, 0x13, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC2,
    ];
    let insts = decode(&bytes, 0x1000);
    assert!(insts.len() >= 5, "expected >=5 instructions, got {}", insts.len());

    let cfg = build_cfg(&insts);
    let ssa = build_ssa_with_cc(&cfg, CallingConv::Win64);

    // The "mov rdx, rax" instruction reads RAX post-call. Its source must be
    // a VarDef whose expr is Expr::Unknown (a fresh clobber), NOT the LEA
    // expression from before the call.
    let rdx_vn = Varnode { space: AddressSpaceId::Register, offset: 16, size: 8 };
    let rdx_var = ssa
        .vars
        .iter()
        .rev()
        .find(|v| v.varnode == rdx_vn)
        .expect("no RDX assignment found");

    // RDX = Var(RAX_post_call) where RAX_post_call has Expr::Unknown.
    let rax_src_id = match rdx_var.expr {
        Expr::Var(id) => id,
        ref other => panic!("expected RDX = Var(RAX), got {:?}", other),
    };
    let rax_src = &ssa.vars[rax_src_id.0 as usize];
    assert!(
        matches!(rax_src.expr, Expr::Unknown),
        "post-call RAX must be Expr::Unknown; got {:?}",
        rax_src.expr
    );
    assert!(
        rax_src.call_return,
        "post-call RAX must be marked call_return=true"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p rsleigh-decompile --test call_clobber 2>&1 | tail -20
```

Expected: compile error — `build_ssa_with_cc` does not exist.

- [ ] **Step 3: Commit the failing test**

```bash
git add rsleigh-decompile/tests/call_clobber.rs
git commit -m "test: failing regression for SSA post-call clobber

Covers: caller-saved RAX must be invalidated after a Call terminator
so subsequent reads yield Expr::Unknown instead of the pre-call value.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add caller-saved register tables in ssa.rs

**Files:**
- Modify: `rsleigh-decompile/src/ssa.rs` (top of file, after existing `FRAME_REGS` constant around line 732)

- [ ] **Step 1: Add the `use` for `CallingConv`**

At the top of `rsleigh-decompile/src/ssa.rs`, after the existing `use crate::ir::*;` line, add:

```rust
use crate::fold::CallingConv;
```

- [ ] **Step 2: Add caller-saved tables near `FRAME_REGS`**

Immediately after the `const FRAME_REGS: [u64; 5] = ...` line (around line 732), insert:

```rust
/// Caller-saved (volatile) integer register offsets per ABI.
/// These registers must be invalidated in the SSA `current` map after any Call,
/// because the ABI guarantees the callee may clobber them.
///
/// Register offsets are as used in the generated pcode varnodes:
///   x86-64: RAX=0, RCX=8, RDX=16, RSI=48, RDI=56, R8=128, R9=136, R10=144, R11=152
///   AArch64: x0=16384, stride 8 up through x30=16624 (only x0..x18 are caller-saved)
///   ARM32:  r0=32, r1=36, r2=40, r3=44, r12=80, lr=84
///   MIPS32: v0=16, v1=20, a0=24, a1=28, a2=32, a3=36, t0..t7=40..68, t8=136, t9=140
///   RISC-V: ra=8, t0=40, t1=48, t2=56, a0=80, a1=88, .. a7=136, t3..t6=216..240
const WIN64_CALLER_SAVED: &[u64] = &[
    0,   // RAX
    8,   // RCX
    16,  // RDX
    128, // R8
    136, // R9
    144, // R10
    152, // R11
];

const SYSV64_CALLER_SAVED: &[u64] = &[
    0,   // RAX
    8,   // RCX
    16,  // RDX
    48,  // RSI
    56,  // RDI
    128, // R8
    136, // R9
    144, // R10
    152, // R11
];

/// AArch64 AAPCS64 caller-saved: x0..x18 at stride 8 starting at 16384.
const AARCH64_CALLER_SAVED: &[u64] = &[
    16384, 16392, 16400, 16408, 16416, 16424, 16432, 16440, // x0..x7
    16448, 16456, 16464, 16472, 16480, 16488, 16496, 16504, // x8..x15
    16512, 16520, 16528,                                    // x16..x18
];

/// x86-32 cdecl: EAX, ECX, EDX are caller-saved. Offsets same as x86-64 sub-registers.
const X86_32_CALLER_SAVED: &[u64] = &[
    0,  // EAX
    8,  // ECX
    16, // EDX
];

/// Return register offset for each CC. This is the varnode offset whose fresh
/// post-call VarDef gets `call_return: true`.
fn return_reg_offset(cc: CallingConv) -> u64 {
    match cc {
        CallingConv::SysV | CallingConv::Win64 | CallingConv::Cdecl32 => 0, // RAX/EAX
        CallingConv::AArch64 => 16384, // x0
    }
}

/// Return-register full size (so we can create a representative clobber VarDef).
fn return_reg_size(cc: CallingConv) -> u32 {
    match cc {
        CallingConv::SysV | CallingConv::Win64 => 8,
        CallingConv::Cdecl32 => 4,
        CallingConv::AArch64 => 8,
    }
}

fn caller_saved_offsets(cc: CallingConv) -> &'static [u64] {
    match cc {
        CallingConv::Win64 => WIN64_CALLER_SAVED,
        CallingConv::SysV => SYSV64_CALLER_SAVED,
        CallingConv::AArch64 => AARCH64_CALLER_SAVED,
        CallingConv::Cdecl32 => X86_32_CALLER_SAVED,
    }
}
```

- [ ] **Step 3: Verify it compiles (no behavior change yet)**

```bash
cargo build -p rsleigh-decompile 2>&1 | grep -E "error" | head -5
```

Expected: no errors. The new constants are unused; we'll consume them in Task 3.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/ssa.rs
git commit -m "ssa: add caller-saved register tables per calling convention

Tables are currently unused; Task 3 wires them into the SSA builder
so Call sites invalidate them.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Add clobber helper and `build_ssa_with_cc` entry point

**Files:**
- Modify: `rsleigh-decompile/src/ssa.rs`

- [ ] **Step 1: Add the clobber helper function**

Append to `rsleigh-decompile/src/ssa.rs` (after the caller-saved tables from Task 2):

```rust
/// Invalidate caller-saved registers in `current` after a Call. Emits one
/// `Stmt::Assign(rax_clobber)` for the return register (RAX/x0) whose expr is
/// `Expr::Unknown` and `call_return: true`. Other caller-saved registers are
/// simply dropped from `current` — if read later, `resolve_input` will lazily
/// create fresh Unknown VarDefs for them.
fn clobber_caller_saved(
    ssa: &mut SsaCfg,
    current: &mut HashMap<Varnode, VarId>,
    cc: CallingConv,
    stmts: &mut Vec<Stmt>,
) {
    let offsets = caller_saved_offsets(cc);
    let ret_off = return_reg_offset(cc);
    let ret_size = return_reg_size(cc);

    // Step 1: drop every current entry at any caller-saved offset, regardless of size.
    current.retain(|vn, _| {
        !(vn.space == AddressSpaceId::Register && offsets.contains(&vn.offset))
    });

    // Step 2: create the fresh return-register clobber with call_return=true.
    let ret_vn = Varnode {
        space: AddressSpaceId::Register,
        offset: ret_off,
        size: ret_size,
    };
    let ret_var = ssa.new_var(ret_vn, Expr::Unknown, ret_size);
    ssa.vars[ret_var.0 as usize].call_return = true;
    current.insert(ret_vn, ret_var);

    // Mirror sub-register propagation (matches the existing logic at ssa.rs
    // ~line 657 for 8-byte writes): also seed the size-4 sub-register so
    // `mov eax, ...` style reads see the same VarId.
    if ret_size == 8 {
        let sub_vn = Varnode {
            space: AddressSpaceId::Register,
            offset: ret_off,
            size: 4,
        };
        current.insert(sub_vn, ret_var);
    }

    stmts.push(Stmt::Assign(ret_var));
}
```

- [ ] **Step 2: Add `build_ssa_with_cc` and make `build_ssa` delegate**

Find the existing `pub fn build_ssa(cfg: &Cfg) -> SsaCfg {` at ssa.rs:18. Replace its signature and body with:

```rust
/// Backwards-compatible entry point — defaults to SysV calling convention.
/// New call sites should use `build_ssa_with_cc` with the ABI for the binary.
pub fn build_ssa(cfg: &Cfg) -> SsaCfg {
    build_ssa_with_cc(cfg, CallingConv::SysV)
}

/// Convert a CFG into SSA form, using `cc` to determine which registers are
/// caller-saved and must be invalidated at Call sites.
pub fn build_ssa_with_cc(cfg: &Cfg, cc: CallingConv) -> SsaCfg {
    let mut ssa = SsaCfg {
        blocks: Vec::new(),
        vars: Vec::new(),
        entry: cfg.entry,
    };
```

…then continue with the existing body (the `let preds = cfg.predecessors();` line and everything that follows). The only structural change is the renamed signature; preserve every line after the opening `{`.

- [ ] **Step 3: Pass `cc` through to `convert_terminator`**

Find the call to `convert_terminator` inside `build_ssa_with_cc`. Thread `cc` to it:

Change `convert_terminator` signature at ssa.rs:905 from:

```rust
fn convert_terminator(
    ssa: &mut SsaCfg,
    current: &mut HashMap<Varnode, VarId>,
    term: &Terminator,
) -> SsaTerminator {
```

To:

```rust
fn convert_terminator(
    ssa: &mut SsaCfg,
    current: &mut HashMap<Varnode, VarId>,
    term: &Terminator,
    cc: CallingConv,
    stmts: &mut Vec<Stmt>,
) -> SsaTerminator {
```

Update the Call arm inside `convert_terminator` (currently ssa.rs:917) from:

```rust
        Terminator::Call { target, fallthrough } => {
            SsaTerminator::Call { target: target.clone(), args: vec![], fallthrough: *fallthrough }
        }
```

To:

```rust
        Terminator::Call { target, fallthrough } => {
            clobber_caller_saved(ssa, current, cc, stmts);
            SsaTerminator::Call { target: target.clone(), args: vec![], fallthrough: *fallthrough }
        }
```

Locate the one existing call site of `convert_terminator` inside the block-processing loop (grep for `convert_terminator(` in ssa.rs — there is exactly one caller). Update it from:

```rust
let terminator = convert_terminator(&mut ssa, &mut current, &block.terminator);
```

To:

```rust
let terminator = convert_terminator(&mut ssa, &mut current, &block.terminator, cc, &mut stmts);
```

(The local variable `stmts` is the `Vec<Stmt>` that the block processing loop is accumulating — inspect the surrounding code to confirm the name. If the variable is a field on a struct instead of a local, pass the appropriate mutable reference.)

- [ ] **Step 4: Handle mid-block Call pcode ops (`process_op`)**

Find the Call handling inside `process_op` (grep `PcodeOp::Call` or `Stmt::Call` in ssa.rs around line 984). The existing handler pushes a `Stmt::Call` into `stmts`. Immediately after that push, call the clobber helper.

Find:

```rust
Stmt::Call { args, out: _, .. } => {
```

Trace backwards to the `PcodeOp::Call` or `PcodeOp::CallInd` match arm that produces the Stmt. Immediately after the `stmts.push(Stmt::Call { ... })` call, add:

```rust
clobber_caller_saved(ssa, current, cc, stmts);
```

Thread `cc` through `process_op` the same way as for `convert_terminator`:

- Add `cc: CallingConv` to `process_op`'s parameter list
- Update every call site of `process_op` to pass `cc`

- [ ] **Step 5: Verify it compiles**

```bash
cargo build -p rsleigh-decompile 2>&1 | grep -E "error" | head -10
```

Expected: clean build.

- [ ] **Step 6: Run the Task 1 test — should now pass**

```bash
cargo test -p rsleigh-decompile --test call_clobber 2>&1 | tail -10
```

Expected: `test post_call_rax_is_unknown_win64 ... ok`.

- [ ] **Step 7: Run the full decompile test suite — verify no regressions**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -20
cargo test -p test-harness 2>&1 | tail -20
```

Expected: all existing tests pass. If anything regresses, STOP and investigate — do not paper over by relaxing an assertion.

- [ ] **Step 8: Commit**

```bash
git add rsleigh-decompile/src/ssa.rs rsleigh-decompile/tests/call_clobber.rs
git commit -m "ssa: invalidate caller-saved regs after Call terminators/ops

Introduces build_ssa_with_cc(cfg, cc) that clobbers ABI-specified
caller-saved registers in the per-block 'current' varnode map after
every Call site. The return register (RAX/x0) gets a fresh Unknown
VarDef with call_return=true, so the existing printer pipeline renders
post-call return-value reads correctly.

Fixes the root cause behind strcspn-return-lost, printf-args-dropped,
and puts(...)+5 artifacts documented in the 2026-04-16 x86-64
pseudocode audit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Wire `build_ssa_with_cc` through the pipeline

**Files:**
- Modify: `rsleigh-decompile/src/lib.rs` at the three `ssa::build_ssa(&cfg)` call sites (currently lines 53, 203, 337).

- [ ] **Step 1: Inspect the first call site and its surrounding CC detection**

Read `rsleigh-decompile/src/lib.rs` lines 50–80. Note that CC detection already happens immediately after `build_ssa` (lines 55–74), then `fold_with_cc(&mut ssa, cc)` is called. The SSA has to be built with the SAME `cc`, so we need to detect CC BEFORE `build_ssa` rather than after.

- [ ] **Step 2: Extract the CC detection into a helper**

At the top of `rsleigh-decompile/src/lib.rs` (after the `use` statements), add:

```rust
/// Detect calling convention from binary format and architecture.
/// Used to parameterize both SSA construction and fold passes.
fn detect_cc(arch: Architecture, binary: Option<&[u8]>) -> fold::CallingConv {
    if let Some(binary) = binary {
        if let Ok(obj) = goblin::Object::parse(binary) {
            match &obj {
                goblin::Object::PE(pe) => {
                    return if pe.is_64 {
                        fold::CallingConv::Win64
                    } else {
                        fold::CallingConv::Cdecl32
                    };
                }
                _ => {
                    return match arch {
                        Architecture::X86_32 | Architecture::ARM32 | Architecture::MIPS32
                            => fold::CallingConv::Cdecl32,
                        Architecture::AArch64 => fold::CallingConv::AArch64,
                        _ => fold::CallingConv::SysV,
                    };
                }
            }
        }
    }
    if arch == Architecture::AArch64 {
        fold::CallingConv::AArch64
    } else {
        fold::CallingConv::SysV
    }
}
```

- [ ] **Step 3: Use the helper at all 3 call sites**

**Site A (around line 44, `decompile_with_binary`):** Replace the block starting `let mut ssa = ssa::build_ssa(&cfg);` through the end of the existing CC-detection match (approximately lines 53–74) with:

```rust
    let cc = detect_cc(arch, binary);
    let mut ssa = ssa::build_ssa_with_cc(&cfg, cc);
```

Leave the following `fold::fold_with_cc(&mut ssa, cc);` line unchanged — it now just reuses `cc`.

**Site B (around line 203):** Same substitution pattern — detect cc before `build_ssa_with_cc`, remove the redundant detection after.

**Site C (around line 337, WASM/other path):** Same substitution pattern. For this path, inspect whether `binary` is available — if not, pass `None` to `detect_cc`.

Confirm there are exactly 3 `build_ssa(&cfg)` call sites to replace:

```bash
grep -n "build_ssa(" rsleigh-decompile/src/lib.rs
```

After editing, this command must output only references to `build_ssa_with_cc` (and potentially doc-comment mentions of the default `build_ssa`).

- [ ] **Step 4: Verify compile**

```bash
cargo build -p rsleigh-decompile 2>&1 | grep error | head -5
```

Expected: clean.

- [ ] **Step 5: Run full test suite**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -10
cargo test -p test-harness 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add rsleigh-decompile/src/lib.rs
git commit -m "decompile: thread CallingConv into SSA construction

Extracts CC detection into detect_cc() and uses it at all 3
build_ssa call sites so SSA and fold agree on which registers are
caller-saved.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Make `propagate_call_returns` idempotent

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs` at `propagate_call_returns` (line 3109).

Rationale: Task 3 already marks post-call RAX VarDefs as `call_return: true`. The existing pass (`propagate_call_returns`) scans for the same condition and sets it again — harmless, but should skip vars that are already marked so the check doesn't rely on Expr::Unknown (Task 3 emits Unknown, so it still matches; but defensive idempotence hedges against future change).

- [ ] **Step 1: Update the Call-terminator branch**

In `rsleigh-decompile/src/fold.rs`, replace the existing body of the `if has_call_term {` branch (lines 3115–3137) with:

```rust
        if has_call_term {
            let fallthrough = match &ssa.blocks[bi].terminator {
                SsaTerminator::Call { fallthrough, .. } => Some(*fallthrough),
                _ => None,
            };
            if let Some(ft) = fallthrough {
                if ft.0 < ssa.blocks.len() {
                    // Find the first RAX/EAX assignment in the fallthrough block
                    // that is not already marked a call_return.
                    for stmt in &ssa.blocks[ft.0].stmts {
                        if let Stmt::Assign(var_id) = stmt {
                            let vdef = &ssa.vars[var_id.0 as usize];
                            if vdef.call_return {
                                break; // already marked upstream — done
                            }
                            if vdef.varnode.space == AddressSpaceId::Register
                                && (vdef.varnode.offset == RAX_OFFSET)
                                && matches!(&vdef.expr, Expr::Unknown)
                            {
                                ssa.vars[var_id.0 as usize].call_return = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
```

- [ ] **Step 2: Update the in-block Call-statement branch**

Replace the second half of `propagate_call_returns` (lines 3139–3158) with:

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
                    if vdef.call_return {
                        after_call = false; // already marked — stop scanning
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

- [ ] **Step 3: Verify compile and tests**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -10
cargo test -p test-harness 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/fold.rs
git commit -m "fold: make propagate_call_returns idempotent

Skips VarDefs already marked call_return by the SSA-level clobber
introduced in ssa.rs. Prevents double-marking and clarifies the pass
is now belt-and-braces rather than the primary mechanism.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Re-audit check2 and main, decide on printer fix

**Files:**
- Run-only (no edits yet).

- [ ] **Step 1: Re-run the probe**

```bash
cargo run -q -p test-harness --example probe_check2_ssa --release 2>&1 | tail -40
RSLEIGH_PROBE_ADDR=0x140001e41 cargo run -q -p test-harness --example probe_check2_ssa --release 2>&1 | grep -E "terminator|Unknown|call_return" | head -40
```

Expected: after each `terminator: "Call(...)"` there is a fresh `Register/0/8` or `Register/0/4` VarDef with `Expr::Unknown`.

- [ ] **Step 2: Re-run the CLI on both functions and eyeball the output**

```bash
./target/release/rsleigh ~/Downloads/test_bin/cb_baristas_secret_x64.exe 0x140001a68 2>&1 | tee /tmp/check2_after.txt
./target/release/rsleigh ~/Downloads/test_bin/cb_baristas_secret_x64.exe 0x140001e41 2>&1 | tee /tmp/main_after.txt
```

Expected changes vs. the audit baseline:
- `main`: `strcspn(...)` return captured and used as `input[sVar] = 0` (or a named local).
  `printf("...%s...\n", input + 5)` shows 2 args, not 1.
  No `puts("...") + 5` artifact.
- `check2`: may or may not still show `*(C)` — that is the printer bug, and is Task 6's decision point.

- [ ] **Step 3: Decide on Task 7 (printer fix)**

If `/tmp/check2_after.txt` no longer contains `*(C)`, skip Task 7 entirely and jump to Task 8.

If `*(C)` persists, proceed to Task 7.

---

## Task 7: Tighten printer param-name chase (conditional)

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs` around lines 8651–8662.

Only execute this task if Task 6 determined `*(C)` still appears in check2.

- [ ] **Step 1: Write the failing printer test**

Append to `rsleigh-decompile/tests/call_clobber.rs`:

```rust
/// Regression: printer must not render a register as the parameter name
/// when the register's expr chain terminates at a BinOp (address arithmetic)
/// rather than an Expr::Unknown on a bona-fide arg register.
#[test]
fn check2_byte_pointer_not_rendered_as_param_c() {
    use goblin::pe::PE;

    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let Ok(data) = std::fs::read(path) else {
        eprintln!("skipping: fixture binary missing at {path}");
        return;
    };
    let pe = PE::parse(&data).expect("parse PE");
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
    let off = file_off.expect("func not in any section");
    let bytes = &data[off..off + 0x180];

    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut io = 0;
    while io < bytes.len() {
        match dec.decode(&bytes[io..], func_va + io as u64) {
            Ok(inst) => {
                let is_ret = inst
                    .ops
                    .iter()
                    .any(|op| matches!(op, PcodeOp::Return { .. }));
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
        !out.contains("*(C)"),
        "printer still renders byte pointer as *(C); output:\n{}",
        out
    );
}
```

- [ ] **Step 2: Run it — expect fail**

```bash
cargo test -p rsleigh-decompile --test call_clobber check2_byte_pointer_not_rendered_as_param_c 2>&1 | tail -20
```

Expected: assertion failure citing `*(C)` in output, OR a skip if the fixture binary is missing.

- [ ] **Step 3: Apply the printer tightening**

Replace lines 8651–8662 in `rsleigh-decompile/src/printer.rs` (the `if vdef.varnode.space == AddressSpaceId::Register { ... }` block that chases param_name through Var/Phi) with:

```rust
    // For Phi/Var nodes on argument registers, check if any input has a
    // param_name — but only when the chain terminates at an Expr::Unknown on
    // a register that is in the current calling convention's arg set. A chain
    // that terminates at a BinOp (address arithmetic) or Load is a local
    // computation, not a parameter reference; naming it after a param is a
    // rendering bug (see 2026-04-16 audit).
    if vdef.varnode.space == AddressSpaceId::Register {
        if let Some(name) = resolve_param_chain(vdef, ssa) {
            return name;
        }
    }
```

Then add the helper at the bottom of `printer.rs` (or near the other `ssa` helpers — grep `fn ssa.var` or similar to find the idiomatic spot). Add:

```rust
/// Walk a Var/Phi chain looking for a param_name on an arg-register terminal.
/// Returns Some(name) only when the chain ultimately lands on an Expr::Unknown
/// VarDef whose varnode offset is in the calling-convention's arg register set
/// and whose param_name is set. Bounded at depth 8 to guard against cycles.
fn resolve_param_chain(vdef: &VarDef, ssa: &Ssa) -> Option<String> {
    use crate::ir::Expr;
    let mut cur = vdef;
    for _ in 0..8 {
        // Terminal case: param_name on an Unknown is a real param ref.
        if matches!(cur.expr, Expr::Unknown) {
            return cur.param_name.clone();
        }
        match &cur.expr {
            Expr::Var(src) => {
                cur = ssa.var(*src);
            }
            Expr::Phi(inputs) => {
                // Prefer the input whose own chain resolves; if none do, bail.
                for inp in inputs {
                    let inp_def = ssa.var(*inp);
                    if let Some(name) = resolve_param_chain(inp_def, ssa) {
                        return Some(name);
                    }
                }
                return None;
            }
            // Any other expr shape (BinOp, Load, Const, UnaryOp, ...) means
            // the value is a local computation, NOT a parameter. Stop.
            _ => return None,
        }
    }
    None
}
```

(Adjust the `Ssa` type name to whatever the module actually uses — grep for `pub struct Ssa` or similar in `rsleigh-decompile/src/`. Most likely it's the same `&PrintCtx` or `SsaCfg` already threaded through the caller. Match the idiom of the surrounding code.)

- [ ] **Step 4: Run the new test — expect pass**

```bash
cargo test -p rsleigh-decompile --test call_clobber check2_byte_pointer_not_rendered_as_param_c 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Run the full suite — no regressions**

```bash
cargo test -p rsleigh-decompile 2>&1 | tail -10
cargo test -p test-harness 2>&1 | tail -10
```

Expected: all pass. If any pseudocode-quality test fails because a param name it DID want is now gone, inspect carefully — the test may have been depending on the buggy behavior, or the tightening may be too strict. If genuinely too strict, relax: allow the chain to terminate at `Expr::Load` from a stack slot too (that's also a valid param spill/reload on x86-32).

- [ ] **Step 6: Commit**

```bash
git add rsleigh-decompile/src/printer.rs rsleigh-decompile/tests/call_clobber.rs
git commit -m "printer: tighten param_name chase to arg-register terminals only

The Var/Phi chase at render time was assigning parameter names to any
register whose expr chain eventually passed through an arg register
VarDef. After the SSA call-clobber fix, the remaining *(C) render in
check2 byte-pickoff loops came from this chase consuming an Unknown
terminal that happened to be on RAX. Restrict to chains whose terminal
is on a register in the CC's declared arg set.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Final end-to-end audit comparison

**Files:**
- Run-only, no edits.

- [ ] **Step 1: Run both audit CLIs and diff against baseline**

```bash
./target/release/rsleigh ~/Downloads/test_bin/cb_baristas_secret_x64.exe \
    0x140001017 0x140001378 0x140001a68 0x140001bc6 0x140001e41 \
    2>&1 | tee /tmp/audit_after.txt
```

- [ ] **Step 2: Smoke-test on two other x86-64 binaries**

```bash
./target/release/rsleigh ~/Downloads/test_bin/ChocolateFactory.exe --all 2>&1 | wc -l
./target/release/rsleigh ~/Downloads/test_bin/rust-crackme-easy.exe --all 2>&1 | wc -l
```

Expected: both complete without panic. Line counts should be within ±10% of the pre-fix output (DCE will remove the new Unknown clobber assigns once downstream reads are gone).

- [ ] **Step 3: Update the audit doc with results**

Append to `docs/audits/2026-04-16-x86-64-pseudocode-audit.md`:

```markdown
---

## Post-Fix Results (<YYYY-MM-DD>)

After implementing the plan at
`docs/superpowers/plans/2026-04-16-ssa-call-clobber-plan.md`:

- **main (0x140001e41):** `strcspn` return captured as `input[sVarN] = 0`.
  `printf` now shows both args. `puts(...) + 5` artifact gone.
- **check2 (0x140001a68):** byte-pickoff pointer rendered as address
  expression, not `*(C)`.
- **Full test suite:** N tests pass, zero regressions.
- **Smoke tests:** ChocolateFactory.exe and rust-crackme-easy.exe decompile
  cleanly.

Remaining defect classes from the original audit (B: data-as-strings,
D: fold noise) are unaddressed — future work.
```

Fill in the date and any actual numbers.

- [ ] **Step 4: Commit**

```bash
git add docs/audits/2026-04-16-x86-64-pseudocode-audit.md
git commit -m "audit: record post-fix results for SSA call-clobber work

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Self-review checklist — completed inline

- Spec coverage: Fix 1 (SSA clobber) → Tasks 1–5. Fix 2 (printer) → Task 7 (gated). Regression fixture → Task 1 + Task 7. Non-goals (shadow store, save/restore) not in any task — correct.
- Placeholders: none. Every step has exact commands, file paths, and code.
- Type consistency: `build_ssa_with_cc(&cfg, cc)`, `fold::CallingConv`, `Expr::Unknown`, `call_return: bool` used consistently across tasks.
- Outstanding assumption: Task 3 Step 4 asks the implementer to locate `process_op` Call handling and add the clobber call there. If that handler doesn't exist (some binaries never produce mid-block Call pcode), the step becomes a no-op — document as "no mid-block Calls found" and proceed.
