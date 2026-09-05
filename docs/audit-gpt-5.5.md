# rsleigh Engineering Audit — GPT-5.5

> Historical engineering audit. Findings and counts describe the audited
> revision, not the current CLI contract. Start at the [documentation hub](README.md)
> for current usage and support guidance.

## 1. Executive Summary

- **Strong:** This is a serious systems project with real SLEIGH ingestion, generated Rust decoders, multi-arch P-code emission, a real CLI/API split, extensive regression tests, and honest README caveats.
- **Fragile:** The SLEIGH/compiler path still has correctness landmines: constructor priority bugs, context-dependent lift values replaced with zero, table export hacks, silent fallbacks, and many `todo!/unwrap!/panic!` paths.
- **Missing:** A proper Ghidra oracle harness, semantic P-code differential testing, robust context modeling in lifted P-code, principled SSA/memory modeling, and credible type/calling-convention recovery beyond heuristics.
- **Most likely wrong output:** Return values, stack parameters, indirect calls, conditional branches, loops, context-sensitive register selection, table exports, flag-derived conditions, and printer post-processed pseudocode.
- **Immediate attention:** Fix SLEIGH matching priority, stop emitting zero for context-dependent lift values, add diagnostics for fallback paths, remove branch-target snapping, and build strict Ghidra P-code comparison tests.

## 2. Architecture Map

### `.slaspec` Preprocessing / Parsing

- **Files/modules:** `src/preprocessor/*`, `src/syntax/*`
- **Main structures:** preprocessor `Token`, syntax-level definitions and table/constructor ASTs
- **Inputs:** Ghidra `.slaspec` / `.sinc` text
- **Outputs:** syntax AST for defines, tables, patterns, displays, p-code blocks
- **Correctness assumptions:** tokenization and macro expansion match enough of Ghidra SLEIGH for bundled specs
- **Failure modes:** incomplete escape handling, parser panics on empty inputs, permissive syntax acceptance, `todo!` on uncommon constructs

### Semantic Compilation

- **Files/modules:** `src/semantic/*`, especially `src/semantic/inner/*`
- **Main structures:** `Sleigh`, `Table`, `Constructor`, `Pattern`, `Execution`, `FieldSize`, exports
- **Inputs:** syntax AST
- **Outputs:** solved semantic `Sleigh` object with tables, constructors, token fields, spaces, varnodes
- **Correctness assumptions:** table export types can be unified per table, pattern lengths can be solved, pattern containment ordering approximates SLEIGH priority
- **Failure modes:** wrong constructor ordering, unresolved or mis-sized exports, recursive table panics, context-dependent exports collapsed incorrectly

### Decoder Generation

- **Files/modules:** `src/codegen/*`, `rsleigh-generate/src/main.rs`
- **Main structures:** `Disassembler`, `TableEnum`, `ConstructorStruct`, generated crates under `generated/*`
- **Inputs:** semantic `Sleigh`
- **Outputs:** Rust parser/display/lift code split into generated crates
- **Correctness assumptions:** generated prefilters and constructor parsers agree; split/non-split emit identical behavior
- **Failure modes:** optional table unwrap panics, missing stored fields for lift, context reads omitted, priority bug creates plausible wrong decode

### Instruction Decode

- **Files/modules:** `rsleigh-api/src/lib.rs`, generated `*_root` crates
- **Main structures:** `Decoder`, generated `ContextMemory`, `GlobalSet`, `Instruction`
- **Inputs:** bytes + virtual address + architecture
- **Outputs:** `Instruction { len, disassembly, ops }`
- **Correctness assumptions:** architecture default context is sufficient; per-instruction context resets are valid for supported use cases
- **Failure modes:** mode/context mistakes, address truncation on 32-bit arch wrappers, unknown bytes silently stop CLI function decoding

### P-code Emission

- **Files/modules:** `src/codegen/builder/disassembler/constructor/execution.rs`, `pcode-ir/src/lib.rs`
- **Main structures:** `PcodeOp`, `Varnode`, `AddressSpaceId`
- **Inputs:** decoded constructor + execution template
- **Outputs:** emitted P-code operations
- **Correctness assumptions:** simplified address spaces are enough; table export handling captures Ghidra semantics
- **Failure modes:** context values become zero, dynamic token fallback becomes zero, `New/CPool` become zero, bitrange/subpiece precision loss, missing `PIECE` semantics

### IR Normalization

- **Files/modules:** `pcode-ir/src/lib.rs`
- **Main structures:** peephole optimizer over `Vec<PcodeOp>`
- **Inputs:** raw generated P-code
- **Outputs:** optimized P-code
- **Correctness assumptions:** local unique-varnode substitutions are semantics-preserving
- **Failure modes:** optimizer changes branch/data dependencies, underflow in masks, dead-code elimination removing side effects through incomplete read/write modeling

### CFG Construction

- **Files/modules:** `rsleigh-decompile/src/cfg.rs`
- **Main structures:** `Cfg`, `BasicBlock`, `Terminator`
- **Inputs:** instruction list with P-code
- **Outputs:** basic blocks and edges
- **Correctness assumptions:** last P-code op is the instruction-level terminator; direct branch targets are RAM constants
- **Failure modes:** branch-target snapping hides bad lift targets; indirect branches unresolved; jump-table/switch edges incomplete; calls and fallthroughs conflated

### SSA / Value Tracking

- **Files/modules:** `rsleigh-decompile/src/ssa.rs`
- **Main structures:** `SsaCfg`, `VarDef`, `Expr`, stack `SlotKey`
- **Inputs:** CFG
- **Outputs:** SSA-ish value graph
- **Correctness assumptions:** fixed iteration count converges enough; register varnodes identify state; stack slots can be keyed by frame register + displacement + size
- **Failure modes:** use-def gaps, stale register values, partial-register approximation, stack aliasing gaps, cross-block memory misresolution

### Decompiler Passes

- **Files/modules:** `rsleigh-decompile/src/fold.rs`, `structure.rs`, `printer.rs`
- **Main structures:** typed `Expr`, `StructuredStmt`, print context and register tracker
- **Inputs:** SSA CFG
- **Outputs:** C-like pseudocode
- **Correctness assumptions:** pattern recognizers and text rewrites preserve semantics
- **Failure modes:** return/parameter false positives, wrong structuring, lost side effects, text-level cleanup deleting meaningful statements

### CLI/API Entry Points

- **Files/modules:** `rsleigh-api/src/lib.rs`, `rsleigh-cli/src/main.rs`, `rsleigh-decompile/src/lib.rs`
- **Main structures:** `Decoder`, `decompile_with_binary`, CLI function discovery/decode loops
- **Inputs:** binaries, raw blobs, function addresses
- **Outputs:** disassembly, P-code JSON, SSA JSON, pseudocode, analysis metadata
- **Correctness assumptions:** function boundaries are known or discoverable; decode failures indicate function end
- **Failure modes:** skipped panics, truncated function bodies, wrong symbol/segment mapping, heuristic function discovery over/under-discovery

### Test Infrastructure

- **Files/modules:** `test-harness/src/main.rs`, `rsleigh-decompile/tests/*`, `rsleigh-cli/tests/*`, `scripts/*`
- **Main structures:** golden P-code tests, bug regression tests, fixtures, scripts
- **Inputs:** synthetic bytes, compiled C fixtures, real fixtures
- **Outputs:** assertions over decode/P-code/pseudocode
- **Correctness assumptions:** curated cases represent core behavior
- **Failure modes:** contains/mnemonic-only assertions, shallow oracle coverage, snapshot-like pseudocode tests that bless wrong semantics

## 3. Correctness Audit

### SLEIGH / `.slaspec` Support

- **Negative constant bug:** `Number::try_from(i128)` returns `Number::Positive` for negative values at `src/lib.rs:145`. This can corrupt signed constants before codegen.
- **Constructor priority bug:** `pattern_len_b` uses `constructor_a` instead of `constructor_b` at `src/semantic/inner/table/mod.rs:64`. Overlapping patterns may decode as the wrong constructor.
- **Pattern conflict handling is incomplete:** matching order only uses containment; conflict detection is explicitly TODO at `src/semantic/inner/table/mod.rs:339`.
- **Table export model is underpowered:** comments in `src/semantic/inner/table/mod.rs:20` acknowledge tables can export different types depending on context. That is not a rare detail for real SLEIGH semantics.
- **Empty pattern panic:** `src/syntax/block/pattern.rs:176` uses `input.first().unwrap()`.
- **Unimplemented pattern/codegen cases:** table return verification, OR-pattern implicit field production, direct table production in OR patterns, ellipsis variants.
- **Endian/bitrange risk:** bit ranges are lowered to byte-oriented `Subpiece` in places, which loses sub-byte precision.
- **Macro/preprocessor gaps:** string escapes and conditional define behavior have TODOs; this is less urgent for bundled specs but matters for arbitrary specs.

### Decoder Generation

- **Generated parser structure is reasonable:** table-level byte/context prefilters are emitted before constructor parser calls in `src/codegen/builder/disassembler/table.rs`.
- **But priority bug undermines it:** prefilters are only as correct as `matcher_order`.
- **Optional table lift can panic:** optional tables are lifted via `.as_ref().unwrap()` in `src/codegen/builder/disassembler/constructor/execution.rs:281`.
- **Dynamic value fallback emits zero:** missing dynamic token field resolves to `0u64` at `src/codegen/builder/disassembler/constructor/execution.rs:132`.
- **Context-dependent dynamic values emit zero:** `dynamic_value_expr` returns `0u64` for context at `src/codegen/builder/disassembler/constructor/execution.rs:137`.
- **Context `ExprValue` emits zero:** `ExprValue::Context` lowers to constant zero at `src/codegen/builder/disassembler/constructor/execution.rs:1106`.
- **Branch target calculation has hacks:** table-reference branches scan prior ops for constants and otherwise return constant zero. That can produce valid-looking but wrong control flow.
- **Register bank modeling is simplified:** dynamic varnode attach uses first varnode size and default offset zero for misses. That should be a diagnostic, not a silent decode.

### P-code IR

- **Operation coverage is partial:** `PcodeOp` covers many integer/float ops but lacks explicit `PIECE`, memory barriers, and richer address-space modeling.
- **Address spaces are collapsed:** only `Register`, `Ram`, `Unique`, `Const`; named SLEIGH spaces collapse into RAM or register.
- **Optimizer mask bug:** `u64::MAX >> (64 - out.size * 8)` at `pcode-ir/src/lib.rs:198` can underflow or shift incorrectly for wide varnodes.
- **`Subpiece` semantics are weakened later:** SSA maps `Subpiece lsb=0` to `Expr::Var`, losing truncation semantics at `rsleigh-decompile/src/ssa.rs:1059`.
- **Unique-space identity is local and offset-based:** subtable remapping is a pragmatic scheme but fragile under nested/larger generated templates.
- **Memory state is not represented:** `LOAD/STORE` effects only matter later through stack heuristics; global memory/aliasing is opaque.

### Decompiler

- **Stack variable recovery:** stack tracking is useful but keyed by frame register/displacement/size. It misses aliasing, dynamic stack adjustments, overlapping stores, red zones, shadow space, variable-sized allocas.
- **Parameter detection:** register args are inferred from last writes before calls; x86-32 args are backward-scanned ESP stores. This misses stdcall cleanup, thiscall/fastcall variants, mixed push/register conventions, and varargs edge cases.
- **Return detection:** return recovery scans current state, predecessor blocks, and multi-hop paths. It can choose stale values. README already identifies use-def linking failure as top priority.
- **Calling convention inference:** binary-format based; no per-function prototype or callsite convention inference.
- **Control-flow structuring:** structure recovery is custom pattern matching over dominators/postdominators. It can misstructure irreducible graphs, exception edges, nested loops, and jump-table switches.
- **Loop recovery:** while/do-while is heuristic; for-loop recovery appears printer/postprocess-heavy rather than CFG-native.
- **Switch recovery:** primarily if-else chain collapse; direct jump-table edge recovery is not robust enough to claim general switch support.
- **Expression simplification:** impressive set of targeted folds, but high risk because correctness depends on use-def quality and many arch-specific flag patterns.
- **Aliasing/pointer handling:** pointer type inference is shallow. Loads from unknown memory are not linked through alias classes.
- **Struct-field recovery:** heuristic field naming can look convincing without actual type evidence.
- **Global variable recovery:** printer names addresses as `DAT_*`, but memory SSA does not model globals semantically.
- **Flag register modeling:** handled with targeted offsets and condition recognizers; fragile across architectures/modes.
- **Printer danger:** `rsleigh-decompile/src/printer.rs` performs extensive text-level post-processing. This is the biggest “pretty but wrong” surface because semantic decisions happen after formatting.

## 4. Test Coverage Audit

### Well Covered

- Common instruction smoke tests across several architectures.
- x86-64 P-code golden-ish checks for many basic instructions.
- Panic-freedom fuzzing of random bytes.
- Regression tests for recent decompiler and CLI bugs.
- API contract tests for Spectra-style usage.

### Under-tested

- Constructor priority and overlapping SLEIGH patterns.
- Context-variable dependent decode/lift.
- Table exports, especially mixed value/reference/register exports.
- Exact P-code parity against Ghidra.
- Exact branch target parity.
- ABI-specific call/return behavior.
- Memory-space identity and non-RAM spaces.
- Switch/jump-table CFG recovery.
- Struct/array recovery with ground truth.

### Missing Immediate Tests

1. **`number_try_from_i128_negative_preserves_sign`**
   - Fixture: direct unit test
   - Expected: `Number::Negative(5)` for `-5i128`
   - Why: signed constants are foundational
   - Location: `src/lib.rs` tests or `tests/number.rs`

2. **`overlapping_constructor_priority_specific_wins`**
   - Fixture: minimal synthetic SLEIGH with general and specific constructors
   - Expected: specific constructor is selected
   - Why: catches `pattern_len_b` bug
   - Location: parser/compiler integration test

3. **`context_value_lift_not_zero`**
   - Fixture: SLEIGH/architecture instruction whose p-code reads context
   - Expected: Ghidra-equivalent nonzero context value
   - Why: current lift emits zero
   - Location: `test-harness/tests/ghidra_oracle.rs`

4. **`x86_partial_register_preserve`**
   - Bytes: `b8 78 56 34 12 b0 01 c3`
   - Expected: return `0x12345601`, not `1`
   - Why: current AL-to-parent zext approximation can be wrong
   - Location: `rsleigh-decompile/tests/partial_register.rs`

5. **`x86_ret_imm16_stdcall_cleanup`**
   - Bytes: `c2 10 00`
   - Expected: return plus callee stack cleanup metadata/behavior
   - Why: stdcall/RET imm16 matters for PE32
   - Location: `test-harness/src/main.rs` plus decompiler ABI test

6. **`x86_simm8_backward_branch_ghidra_parity`**
   - Fixture: short loop with negative rel8 branch
   - Expected: exact target equals Ghidra
   - Why: branch snapping currently hides target bugs
   - Location: Ghidra oracle tests

7. **`cdecl_vs_stdcall_callsite_args`**
   - Fixture: PE32 compiled with cdecl and stdcall functions
   - Expected: different stack cleanup behavior
   - Why: avoids wrong parameter recovery
   - Location: `rsleigh-decompile/tests/calling_convention.rs`

8. **`indirect_iat_call_resolved`**
   - Fixture: `mov edi, [IAT]; call edi`
   - Expected: resolved imported callee or explicit indirect call
   - Why: README lists this as a limitation
   - Location: CLI integration fixture

9. **`pic_switch_jump_table_cfg`**
   - Fixture: compiled C switch under PIE
   - Expected: CFG includes jump-table edges and switch cases
   - Why: switch output can otherwise be plausible but wrong
   - Location: Ghidra CFG oracle tests

10. **`stack_local_overlapping_store_sizes`**
    - Fixture: stores to `[rbp-8]` as qword then `[rbp-4]` as dword
    - Expected: no conflation as same variable
    - Why: stack SlotKey includes size but aliasing is unresolved
    - Location: SSA memory tests

## 5. Ghidra Reference Strategy

### Headless Run

Use Ghidra headless:

```bash
analyzeHeadless /tmp/rsleigh-ghidra proj \
  -import fixture.bin \
  -processor x86:LE:64:default \
  -scriptPath scripts \
  -postScript ExportRsleighOracle.java out.json
```

### Export Artifacts

- Instruction bytes, addresses, lengths, mnemonic, operands.
- Raw P-code per instruction: opcode, output varnode, input varnodes, space names, offsets, sizes.
- Function boundaries and symbols.
- CFG blocks and edges.
- Calls, returns, direct/indirect branch targets.
- HighFunction facts: params, locals, stack variables, return storage, simplified ops.
- Decompiled pseudocode as non-strict reference.

### Comparison Approach

- **Strict:** instruction length, raw P-code opcode sequence, varnode spaces/sizes, direct targets, function entry addresses for symbol-known fixtures.
- **Normalized strict:** unique temp IDs remapped by first definition order; register names canonicalized by offset/size.
- **Fuzzy:** disassembly spelling, pseudocode text, local variable names, typedef names.
- **Semantic:** return presence, call target, argument count, CFG edge set, stack slot read/write equivalence, branch condition dependency equivalence.

### Harness Design

```text
test-harness/fixtures/oracle/
  x86_64/
    ret_imm16.bin
    ret_imm16.ghidra.json
  aarch64/
    csel.bin
    csel.ghidra.json
scripts/
  ExportRsleighOracle.java
  ghidra-export-oracle.sh
test-harness/tests/
  ghidra_oracle.rs
```

Suggested schema:

```json
{
  "arch": "x86_64",
  "binary_sha256": "...",
  "functions": [
    {
      "entry": 4096,
      "blocks": [{ "start": 4096, "end": 4112, "succs": [4112] }],
      "instructions": [
        {
          "addr": 4096,
          "bytes": "4889d8",
          "len": 3,
          "disasm": "MOV RAX,RBX",
          "pcode": [
            { "op": "COPY", "out": {"space":"register","offset":0,"size":8}, "inputs": [] }
          ]
        }
      ]
    }
  ]
}
```

### CI Feasibility

- Commit small exported JSON fixtures.
- Run Rust-side comparison in normal CI.
- Run Ghidra export regeneration in nightly/manual CI because Ghidra install is heavy.
- Keep divergence reports as artifacts.

## 6. Security and Robustness Audit

- Parser/compiler has many `unwrap`, `expect`, `panic`, and `todo` paths. Treat `.slaspec` as trusted until this changes.
- CLI catches decoder panics and skips bytes. That is useful UX but dangerous for correctness auditing.
- Integer overflow/shift risks exist in bit masks and address arithmetic.
- Recursive patterns/table solving can panic or blow up.
- Generated decoder size can create compile-time and memory pressure.
- `safe_var` sentinel prevents crashes but hides corrupted SSA state.
- File/path handling appears normal, but CLI has many unwraps in JSON rendering and binary optional-header access.
- No hardening claim should be made for service use on adversarial inputs.

### Fuzz Targets

- `.slaspec` preprocessing and syntax parsing.
- Semantic solver on generated/structured SLEIGH fragments.
- Per-architecture byte decoding.
- P-code optimizer over random well-typed ops.
- CFG/SSA/fold/printer over random valid P-code functions.
- Binary loader/function discovery over ELF/PE/Mach-O fragments.
- Pseudocode renderer over random SSA graphs.

## 7. Performance Audit

### Likely Bottlenecks

- SLEIGH compilation and generated Rust compile time.
- Linear constructor matching in generated parse functions.
- Subtable lift/cache work and unique remapping.
- SSA fixed-point passes cloning maps.
- Memory SSA over larger CFGs.
- Printer post-processing with repeated line scans.
- Whole-binary `--all` with two-pass type propagation.

### Benchmarks To Add

- Decode instructions/second by architecture.
- Functions decompiled/second by binary.
- Peak RSS for `--all`.
- Generated decoder compile time by architecture.
- P-code ops/instruction distribution.
- SSA vars/function distribution.
- Printer post-process ms per 1K output lines.
- Large binary scaling curve.

Correctness should come first. Do not optimize branch snapping, text rewriting, or silent fallbacks; remove or constrain them.

## 8. Prioritized Roadmap

### P0 — Correctness Blockers

1. **Fix constructor priority**
   - **Why:** Wrong instruction decode poisons everything downstream.
   - **Files:** `src/semantic/inner/table/mod.rs`
   - **Approach:** Fix `pattern_len_b`; add conflict diagnostics and overlapping-constructor tests.
   - **Test plan:** synthetic SLEIGH and selected Ghidra parity cases.
   - **Risk:** Medium; may expose generated decoder divergences.
   - **Effort:** S

2. **Eliminate context-zero lift fallbacks**
   - **Why:** Context-dependent instructions can lift wrong while looking valid.
   - **Files:** `src/codegen/builder/disassembler/constructor/execution.rs`, constructor struct generation
   - **Approach:** collect context reads used by execution, store decoded context values in constructor structs, use them in `lift`.
   - **Test plan:** Ghidra parity for context-sensitive instructions.
   - **Risk:** High; generated code shape changes.
   - **Effort:** M/L

3. **Add strict Ghidra P-code oracle tests**
   - **Why:** Current tests prove regression stability, not semantic compatibility.
   - **Files:** `scripts/*`, `test-harness/tests/*`
   - **Approach:** export raw P-code JSON, normalize temps, compare strict facts.
   - **Test plan:** initial 20 instructions per arch, expand over time.
   - **Risk:** Low; reveals bugs.
   - **Effort:** L

4. **Make silent fallbacks visible**
   - **Why:** `0` defaults and sentinel vars create plausible wrong output.
   - **Files:** `execution.rs`, `ir.rs`, `printer.rs`
   - **Approach:** diagnostic channel plus debug assertions; visible unknown markers in release.
   - **Test plan:** tests assert diagnostics on unsupported constructs.
   - **Risk:** Medium; output changes.
   - **Effort:** M

5. **Remove default branch target snapping**
   - **Why:** It masks decoder/lifter bugs as structured pseudocode.
   - **Files:** `rsleigh-decompile/src/cfg.rs`
   - **Approach:** strict mode by default; lenient mode only for UI if needed.
   - **Test plan:** target parity with Ghidra; tests for bad target diagnostics.
   - **Risk:** High; current tests may depend on leniency.
   - **Effort:** S

### P1 — High-value Improvements

1. **Correct partial-register modeling**
   - **Why:** Current zext approximation is wrong for many x86 sequences.
   - **Files:** `rsleigh-decompile/src/ssa.rs`, `rsleigh-decompile/src/ir.rs`
   - **Approach:** model parent merge as `(old & !mask) | zext(new)` or add explicit piece expression.
   - **Test plan:** `mov eax, imm; mov al, imm; ret`.
   - **Risk:** Medium.
   - **Effort:** M

2. **ABI and call convention model**
   - **Why:** Parameter and return recovery depend on ABI.
   - **Files:** `fold.rs`, `ssa.rs`, CLI binary-format detection
   - **Approach:** explicit ABI descriptors: arg locations, return locations, caller/callee cleanup, shadow space, varargs.
   - **Test plan:** cdecl/stdcall/fastcall/thiscall fixtures.
   - **Risk:** Medium/high.
   - **Effort:** L

3. **Memory model beyond stack**
   - **Why:** Pointer/global correctness requires alias reasoning.
   - **Files:** `ssa.rs`, `fold.rs`
   - **Approach:** add memory SSA per space/alias class; keep conservative unknown writes.
   - **Test plan:** global store/load, pointer alias, struct pointer fixtures.
   - **Risk:** High.
   - **Effort:** XL

4. **Return value validation against callsites**
   - **Why:** Current return recovery can infer stale values.
   - **Files:** `fold.rs`, `lib.rs`
   - **Approach:** distinguish explicitly assigned return registers from inherited params/stale clobbers.
   - **Test plan:** void functions that leave EAX/RAX nonzero; recursive factorial.
   - **Risk:** Medium.
   - **Effort:** M

### P2 — Architecture Cleanup

1. **Move semantic rewrites out of printer text passes**
   - **Why:** Text rewrites are brittle and can delete semantics.
   - **Files:** `printer.rs`, `fold.rs`, `structure.rs`
   - **Approach:** introduce semantic cleanup passes over SSA/StructuredStmt.
   - **Test plan:** preserve current regressions while comparing structured output.
   - **Risk:** High.
   - **Effort:** XL

2. **Stable vs experimental API split**
   - **Why:** README documents experimental features but API does not enforce stability boundaries.
   - **Files:** `rsleigh-api`, `rsleigh-cli`
   - **Approach:** stable decode/decompile core; experimental analysis behind feature flags or namespace.
   - **Test plan:** API compatibility tests.
   - **Risk:** Low/medium.
   - **Effort:** M

3. **Generated decoder diagnostics**
   - **Why:** Need traceability from wrong P-code to constructor/source span.
   - **Files:** codegen table/constructor modules
   - **Approach:** optional decoded constructor ID, source span, table path in `Instruction` metadata.
   - **Test plan:** debug output includes constructor span.
   - **Risk:** Low.
   - **Effort:** M

### P3 — Nice-to-have

1. **Broader FID/signature databases**
   - **Why:** Improves UX but not core correctness.
   - **Files:** `rsleigh-fid`, signatures modules
   - **Effort:** M

2. **More syscall/hash variants**
   - **Why:** Useful malware triage annotations.
   - **Files:** `syscall_table.rs`, `peb_walk.rs`
   - **Effort:** S/M

3. **Performance tuning of generated dispatch**
   - **Why:** Good throughput after correctness stabilizes.
   - **Files:** codegen table dispatch
   - **Effort:** L

## 9. Concrete Patch Suggestions

### Patch 1 — Fix Negative `i128` Conversion

- **Bug:** `Number::try_from(-5i128)` returns `Number::Positive(5)`.
- **File/function:** `src/lib.rs`, `impl TryFrom<i128> for Number`
- **Smallest good fix:**

```rust
impl TryFrom<i128> for Number {
    type Error = TryFromIntError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        if value.is_negative() {
            let value = i64::try_from(value)?;
            Ok(Number::Negative(value.unsigned_abs()))
        } else {
            u64::try_from(value).map(Number::Positive)
        }
    }
}
```

- **Test:** `number_try_from_i128_negative_preserves_sign`
- **Before:** fails by returning positive
- **After:** returns `Number::Negative(5)`

### Patch 2 — Fix Constructor Ordering Length

- **Bug:** `pattern_len_b` reads from constructor A.
- **File/function:** `src/semantic/inner/table/mod.rs`, `is_first_then`
- **Smallest good fix:**

```rust
let pattern_len_a = constructor_a.pattern.bits_produced();
let pattern_len_b = constructor_b.pattern.bits_produced();
```

- **Test:** `overlapping_constructor_priority_specific_wins`
- **Before:** general/specific ordering can be wrong
- **After:** matching order respects actual pattern lengths

### Patch 3 — Stop Context Values Lowering To Zero

- **Bug:** context values used by execution lower to `0`.
- **Files/functions:**
  - `src/codegen/builder/disassembler/constructor/execution.rs::dynamic_value_expr`
  - `src/codegen/builder/disassembler/constructor/execution.rs::lower_value`
  - constructor field generation in `constructor/mod.rs`
- **Smallest good fix:**
  - Add collection of execution context references.
  - Add corresponding fields to `ConstructorStruct`.
  - Populate them during `parse` from `context_instance`.
  - Emit `self.ctx_<name>` in `lift`.
- **Pseudocode:**

```rust
// generated struct
pub struct SomeCtor {
    pub ctx_mode: u64,
    // existing fields...
}

// generated parse
let ctx_mode = context_instance.read_mode();
Some((pattern_len, Self { ctx_mode, ... }))

// generated lift
pcode_ir::Varnode::constant(self.ctx_mode, size)
```

- **Test:** context-sensitive fixture compared to Ghidra raw P-code.

### Patch 4 — Guard Wide Mask In P-code Optimizer

- **Bug:** `IntAnd` all-ones mask expression can underflow or shift wrongly when `out.size > 8`.
- **File/function:** `pcode-ir/src/lib.rs::optimize_once`
- **Smallest good fix:**

```rust
fn all_ones_mask(size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    if bits >= 64 {
        u64::MAX
    } else {
        u64::MAX >> (64 - bits)
    }
}
```

Use:

```rust
&& right.offset == all_ones_mask(out.size)
```

- **Test:** `optimize_intand_all_ones_wide_size_no_panic`

### Patch 5 — Replace Branch Snapping With Strict Diagnostics

- **Bug:** CFG snaps branch targets to nearby instructions, hiding lift bugs.
- **File/function:** `rsleigh-decompile/src/cfg.rs::build_cfg`
- **Smallest good fix:**
  - Remove nearest-neighbor snap from default path.
  - If direct target is not in `leader_to_block`, emit unresolved/indirect terminator or diagnostic.
  - Optionally add `build_cfg_lenient` for CLI display.
- **Pseudocode:**

```rust
let target = dest.offset;
match leader_to_block.get(&target) {
    Some(&bid) => Terminator::Branch(bid),
    None => Terminator::Indirect(*dest),
}
```

- **Test:** fixture with known Ghidra branch target; strict comparison fails on wrong target instead of snapping.

## 10. Final Verdict

- This repo is currently closest to **4. early decompiler**, with pieces of **5. credible decompiler foundation** in architecture and testing discipline.
- Honest README claim today: **pure-Rust SLEIGH-driven multi-arch decoder/lifter with an experimental decompiler and useful malware-analysis heuristics.**
- Avoid claiming: **Ghidra-compatible decompiler**, **reliable decompilation**, **semantically equivalent P-code**, or **production-safe untrusted analysis** until oracle validation exists.
- What would impress serious reverse-engineering/systems people:
  - Public Ghidra differential reports.
  - Exact P-code parity on broad instruction corpora.
  - Explicit known-divergence tracking.
  - Minimal silent fallbacks.
  - ABI-specific tests.
  - Less printer-level semantic rewriting.
  - Clear diagnostics from pseudocode back to constructor/source P-code.
