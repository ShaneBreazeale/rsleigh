# CLAUDE.md — rsleigh

## What

Unified Rust workspace: parses Ghidra `.slaspec` → generates instruction decoder
+ P-code emitter → decompiles P-code to C pseudocode. Zero C++ deps.
Wired into Spectra as native analysis backend.

Supported: x86-64, x86-32, AArch64, ARM32, MIPS32, RISC-V 64, WASM.
Binary formats: ELF, PE, Mach-O, WASM, raw.

See `docs/architectures.md`, `docs/features.md`, `docs/decompiler-passes.md`.
Testing: `docs/TESTING.md`. SEH: `docs/pe64-seh-pipeline.md`.

## Build

```bash
make test                           # generate + build + test
cargo run -p rsleigh-generate       # parse slaspecs (~30s)
cargo test -p test-harness          # compile + run all tests
```

Rust 2021 stable, make.

## CLI (`rsleigh-cli`)

```bash
rsleigh <binary>                       # list functions
rsleigh <binary> <func> [func2..]      # decompile (name or 0xAddr)
rsleigh <binary> --all                 # decompile all (two-pass type prop)
rsleigh <binary> --disasm <func>       # disassembly + P-code
rsleigh <binary> --sigs extra.json     # additional signatures
rsleigh <binary> --fid file.fidb       # additional FID database (repeatable)
rsleigh <binary> --no-fid-auto         # disable bundled glibc/musl/libstdc++ DBs
rsleigh <binary> --pcode-json <func>   # raw P-code (debug)
rsleigh <binary> --ssa-json <func>     # post-fold SSA (debug)
rsleigh <binary> --json                # JSON
rsleigh <binary> --search <query>      # find by string/pattern
rsleigh <binary> --search --api <name> # find by API call
rsleigh <binary> --search --const <hex># find by constant
rsleigh <binary> --summary             # one-line per function
rsleigh <binary> --xrefs <func>        # callers + callees
rsleigh <binary> --yara                # generate YARA
rsleigh <binary> --diff <binary2>      # side-by-side diff
rsleigh <binary> --taint <func>        # taint analysis
rsleigh <binary> --vulnscan            # 27 vuln patterns
rsleigh <binary> --callgraph           # JSON + behavioral tags
rsleigh <binary> --classes [--json]    # C++ hierarchies
rsleigh <binary> --compact             # -24% size
rsleigh <binary> --brief                # calls + cflow only, -35%
rsleigh <binary> --min-complexity N    # skip trivial funcs
rsleigh --raw <arch> <binary>          # raw firmware blob
```

## Layout

```
src/                  parser + SLEIGH codegen
pcode-ir/             P-code types + peephole (no_std)
rsleigh-api/          Decoder API + reg name resolution
rsleigh-decompile/    5-pass decompiler (cfg → ssa → fold → structure → print)
rsleigh-fid/          Function ID: body fingerprinting + bundled .fidb
rsleigh-cli/          CLI
rsleigh-generate/     slaspec → generated crate source
generated/            output crates (/out/ gitignored)
test-harness/         golden + stress + fuzz + differential
slaspec/              Ghidra .slaspec (Apache 2.0)
scripts/              Ghidra/Qt sig extraction, FID DB build
docs/                 detail docs (architectures, features, passes, SEH, testing)
```

## Pipeline

```
.slaspec → parser → codegen → generated crates → compile
bytes + addr → Decoder::decode() → Instruction { disasm, ops: Vec<PcodeOp> }
              → decompile_with_binary() → CFG → SSA → fold → structure → C
```

## Load-bearing gotchas

### Codegen (`src/codegen/builder/disassembler/constructor/execution.rs`)

- Subtable cache: `lift()` once per subtable, results cached
- Unique offset scheme: parent uses `(num_fields*2+2)*0x10000` to avoid subtable-export collision
- `dynamic_value_expr()` resolves aliased token fields by bit position (r32/r64 share bits 0-2)
- Signed displacements: cast signed token fields (simm8, simm16) to signed type before i128 widen
- Const-space refs: `export *[const]:4 simm8` → `Varnode::constant()` (no Load)
- MixOperations: mixed AND/OR pattern blocks default to AND (VFP/NEON)
- Optional table lift: OR-pattern subtables lifted via `.as_ref().unwrap()`

### Decompiler

See `docs/decompiler-passes.md` for full pass list. Hotspots:

- **printer.rs post_process is multi-pass.** Lines not present at entry can be synthesized mid-pipeline (e.g. `sp = (((sp - 8) - 12) - 0x10);` appears AFTER `mult_addr → sp` rename ~line 2243). Strips needing final form must run inside ARM32 retain block (before rename, match `mult_addr = (`) OR at very end before `*out = result`.
- **STACKSTR pointer-write guard:** stack-string merge skips lines starting `*(` — those are global pointer-table writes like `*(uint64_t*)(DAT_00602948) = "gone";`.
- **Thunk misdetection guard:** "empty body → `return target(); // thunk`" requires (a) zero body lines AND (b) no Call stmt/terminator anywhere AND (c) branch target address NOT in `ssa.blocks`. `Branch(BlockId)` always in-graph — self-loops previously emitted `return func_<self_addr>(); // thunk`.
- **Deterministic Phi creation:** varnodes sorted `(space, offset, size)` before iteration. HashMap order previously made repeated runs non-deterministic, surfaced as differing ternary arms.

### Signatures + discovery

- **`SigType` variant touches 3 match sites.** `c_str()` + `to_inferred()` in `rsleigh-decompile/src/signatures.rs`, `sigtype_to_cast()` in `rsleigh-decompile/src/printer.rs`. Missing third = non-exhaustive-match compile error.
- **248 Python C API sigs** in `signatures_python.rs`. Variants: `PyObjectPtr`, `ConstPyObjectPtr`, `PyObjectPtrPtr`, `PyTypeObjectPtr`, `PyFrameObjectPtr`, `PySsizeT`, `PyHashT`, `PyCFunction`, `PyRichCmpOp`.
- **PyMethodDef scanner** in `rsleigh-cli/src/main.rs::scan_pymethoddef` ALWAYS runs for PE64 (not gated on empty symbols). Validates: name→ASCII ident, meth→.text range, flags<0x1000, doc→NULL/printable. Scans by section characteristics (works with obfuscated section names like PyVMProtect `.424um`).
- **`segs` in `discover_pe_functions` is executable-only.** Data scans need separate `all_segs` over readable sections.
- **Underscore filter** hides `_dl_*`, `__do_global*`, `__libc_*`, `__pthread_*`, `_GLOBAL__sub_I_`, plus `_init`/`_fini`/`_start`/`_DYNAMIC`/`_GLOBAL_OFFSET_TABLE_`. NOT blanket `_`-prefix — Python methods start with `_`.

### SEH pipeline (`rsleigh-decompile/src/seh_static.rs`)

PE64 only. Needs `iced-x86` in `rsleigh-decompile/Cargo.toml`. Full walkthrough in `docs/pe64-seh-pipeline.md`.

Key entry points:
- `parse_pe64_seh(image)` — `.pdata` + UNWIND_INFO, handles `UNW_FLAG_CHAININFO` + undocumented low-bit chain trick
- `read_scope_table(image, va)` — MSVC `_C_specific_handler`/`__except_handler4` scope records
- `scope_table_addresses(image)` — BFS depth 8, surfaces filter + `__except` blocks unreachable from CALL
- `analyse_handler(image, va)` → `HandlerAnalysis` (flags: redirects_rip, skips_rip, calls_wpm, calls_vprotect, uses_rep_movs)
- `extract_handler_patches(image, va)` — CF-aware abstract interp over `RegVal` (Top|Imm|Addr). Handles `mov [tracked+disp]`, `rep movsb/d/q`, indirect jumps + jump tables (stride 8, MSVC i32-rel stride 4)
- `smc_fixpoint(image, max_iters, discover_fn)` — extract→apply→re-discover, hard cap 16 iters

Fixture: `test-harness/fixtures/crackmev3.pyd` (PyVMProtect v4).

## `.opt/` convention

- `.opt/ideas.md` — parked follow-ups (e.g. nested-ternary 3+ way merges)
- `.opt/failed.md` — aborted fix attempts (per /fix-leaker 3-attempt cap)
- `.opt/campaigns/<slug>.md` — opt-in campaign mode, bounded regression arc with hypothesis+budget+horizon declared upfront; auto-revert if miss at horizon

## macOS gotchas

- Apple `c++filt` strips leading `_` by default → use `c++filt -n` for Itanium `_Z...`
- No `timeout` cmd → `gtimeout` (brew coreutils) or Bash `run_in_background`
- `pip3` aliased to `uv` → `uv pip install --system` or venv
- `cargo test -p test-harness` pre-existing stack overflow in unit tests; iterate via `cargo test -p rsleigh-decompile --release`
- **rtk caches aggressively.** If `cargo build` reports `0 crates compiled` when clearly changed → use `/opt/homebrew/bin/cargo` directly + `cargo clean -p <crate>`
- **`test-harness/examples/*.rs` includes stale files.** `probe_check2_ssa` has pre-existing non-exhaustive match on `Expr::UserOp`. Use `cargo test -p <crate> --release --lib` to skip examples
- `.DS_Store` sneaks into initial commits → `.gitignore` first

## Debugging fold/structure

- Temp `eprintln!("[tag] ...")` in fold.rs/structure.rs → run target func → inspect → remove
- `--ssa-json <addr>` for post-fold state without instrumentation
- Gate new SSA passes on `CallingConv::*` or arch when target-specific
- **`/fix-leaker` single-shot protocol:** failing regression test FIRST, commit test+fix together. 3-attempt cap. Log aborts to `.opt/failed.md`. Do not move goalposts mid-arc.
- **Bench noise band:** composite score has ~0.2 spread across repeat runs (sample 50 non-deterministic). Treat <1% composite movement on single-shot as noise; real regressions >1% or show twice.

## Known limitations

- `ExprValue::Context` returns 0 (unused by x86/ARM/RISC-V)
- `ExprNew` / `ExprCPool` return 0 (JVM/WASM only)
- Some reg values not traced to defining expr (`iVar1 * factorial(n-1)` instead of `n * factorial(n-1)`)
- Type inference: basic + Win32 typedef + interprocedural two-pass + heuristic field names; no constraint-based
- MBA: SiMBA handles 1-4 var linear; non-linear + 5+ var need synthesis (egg catches some)
- Some loop conditions not recovered (`while (OF == SF)`)
- x86-32 sequential TEST/JNZ sometimes nests wrong
- Register-indirect calls (`CALL EDI` from earlier IAT load) not resolved
- ARM32 VFP/NEON: decode OK, FP reg values not fully traced through folding

## License

Apache 2.0
