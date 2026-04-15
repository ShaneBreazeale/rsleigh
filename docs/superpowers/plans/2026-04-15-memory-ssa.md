# Memory SSA — Stack Slot Store/Load Forwarding (Revised)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Resolve `Load([RBP+N])` expressions to the stored value across basic block boundaries, enabling proper expression tracing for stack-spilled variables in loops and multi-block functions.

**Architecture:** Two-phase approach. Phase 1 builds SSA normally, keeping cross-block Loads opaque and collecting per-block stack store summaries. Phase 2 runs after register Phi insertion: computes memory entry/exit maps to a fixed point via worklist, inserts memory Phis at join points where predecessor values disagree, then rewrites opaque Loads to the resolved values.

**Tech Stack:** Pure Rust, modifies `rsleigh-decompile/src/ssa.rs` only.

**Review feedback incorporated from:** GPT-5.2 Codex review (2026-04-15)

---

## Key Design Decisions (from review)

1. **Slot key**: `(base_reg_offset: u64, displacement: i64, size: u32)` — not just `i64` offset. Prevents conflating 4-byte and 8-byte accesses at the same offset, and distinguishes RBP-relative from SP-relative.

2. **Separate entry/exit maps**: `block_entry_stack` (includes Phis) and `block_exit_stack` (transfer of entry through block's stores). Never overwrite exit state with entry Phis.

3. **Fixed-point worklist**: Phase 2 computes entry/exit maps iteratively until convergence, handling nested loops and cyclic CFGs correctly.

4. **Missing = Unknown**: If a predecessor doesn't have a value for a slot, treat it as Unknown. Only forward when ALL predecessors agree or a Phi covers all paths. "Fail closed" — leave as `Expr::Load` when uncertain.

5. **Unknown stores kill tracking**: A Store to an unresolved address conservatively invalidates all tracked stack slots in that block's exit state.

---

## Tasks

### Task 1: Define SlotKey and refactor stack tracking

Replace `HashMap<i64, VarId>` with `HashMap<SlotKey, VarId>` throughout.

**Files:** `rsleigh-decompile/src/ssa.rs`

### Task 2: Phase 1 — Collect per-block stack store summaries

During SSA construction, keep cross-block Loads opaque. Record intra-block store→load forwarding and per-block exit stack state.

### Task 3: Phase 2a — Fixed-point memory entry/exit computation

After register Phi insertion, compute `block_entry_stack` and `block_exit_stack` to convergence using a worklist. Insert memory Phis at join points.

### Task 4: Phase 2b — Rewrite opaque Loads

Walk all blocks, replace `Expr::Load(ptr)` with `Expr::Var(resolved)` using the computed entry maps.

### Task 5: Edge cases — size checks, unknown stores, missing predecessors

### Task 6: Test and verify quality improvements
