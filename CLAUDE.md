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
make test                           # generate + debug test-harness (may stack-overflow on some hosts)
cargo run -p rsleigh-generate       # parse slaspecs (~30s)
cargo test --release -p test-harness             # CI-style regression suite
cargo test --release -p rsleigh-decompile --lib  # decompiler unit tests / fast inner loop
```

Rust 2021 stable, make.

## CLI (`rsleigh-cli` lib + `rsleigh` bin)

Install: `cargo install rsleigh` (root crate's bin re-exports `rsleigh_cli::entrypoint`).
Workspace also keeps `cargo install --path rsleigh-cli` working — same binary name `rsleigh`.


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
rsleigh <binary> --imphash             # Mandiant imphash for PE
rsleigh <binary> --hashes              # sha256, md5, imphash, size
rsleigh <binary> --ioc [--json]        # IOC extraction (URLs/IPs/paths/registry/mutexes/secrets); see docs/cli-triage.md
rsleigh <binary> --xor-strings [--json] # brute single-byte XOR string recovery
rsleigh <binary> --sigcheck [--json]   # Authenticode signer/issuer/timestamp/chain; see docs/cli-triage.md
rsleigh <binary> --resources [--dump DIR] [--json]  # PE resource walk + extraction; see docs/cli-triage.md
rsleigh <binary> --callgraph           # JSON + behavioral tags
rsleigh <binary> --classes [--json]    # C++ hierarchies
rsleigh <binary> --compact             # -24% size
rsleigh <binary> --brief                # calls + cflow only, -35%
rsleigh <binary> --min-complexity N    # skip trivial funcs
rsleigh <binary> --annotate-crypto     # rewrite crypto consts to symbolic names
rsleigh <binary> --vm-dispatch <addr>  # extract VM dispatcher metadata
rsleigh <binary> --vm-classify-handlers <addrs>  # opcode handler classifier
rsleigh <binary> --tag-dispatch <addrs>          # CMP r8/JZ chain extractor
rsleigh <binary> --summarise-handlers <addrs>    # IAT-API + stack-pop signature
rsleigh <binary> --vm-bytecode <bc_va>:<size> --vm-handlers <path.json>  # VM bytecode disasm
rsleigh <binary> --seh-fixpoint        # SEH-driven SMC patch fixpoint
rsleigh <binary> --raw <arch>          # raw firmware blob
```

## Layout

```
src/                  parser + SLEIGH codegen (root `rsleigh` crate; also re-exposes CLI bin via src/bin/rsleigh.rs → rsleigh_cli::entrypoint)
pcode-ir/             P-code types + peephole (no_std)
rsleigh-api/          Decoder API + reg name resolution
rsleigh-decompile/    5-pass decompiler (cfg → ssa → fold → structure → print)
rsleigh-fid/          Function ID: body fingerprinting + bundled .fidb
rsleigh-cli/          CLI — split into lib.rs (pub mod cli, wasm; pub use cli::entrypoint) + thin main.rs shim
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
- **PyMethodDef scanner** in `rsleigh-cli/src/cli.rs::scan_pymethoddef` ALWAYS runs for PE64 (not gated on empty symbols). Validates: name→ASCII ident, meth→.text range, flags<0x1000, doc→NULL/printable. Scans by section characteristics (works with obfuscated section names like PyVMProtect `.424um`).
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
- `tls_callback_addresses(image)` — walks `IMAGE_TLS_DIRECTORY64.AddressOfCallBacks` (data dir 9), NULL-terminated VA array, cap 64
- `extract_patches_at_candidates(image, vas)` — generic patch scan over arbitrary VAs with `(target_va, bytes)` dedup
- `extract_all_patches_extended(image, extra)` — SEH + TLS + caller VAs merged
- `smc_fixpoint(image, max_iters, discover_fn)` — uses extended scan; extract→apply→re-discover, hard cap 16 iters

Fixture: `test-harness/fixtures/crackmev3.pyd` (PyVMProtect v4).

### PE64 annotators (`rsleigh-decompile/src/{syscall_table,peb_walk}.rs`)

- **`syscall_table.rs`** — Win11 24H2 x64 ntdll syscall numbers (~120 entries). Numbers shift across Windows builds; treat results as hint with version qualifier. `resolve_x64_syscall(num)` returns `Option<&'static str>`. Wired into printer void-stmt UserOp render; only fires when arch == X86_64 AND `func_id == 5` (syscall pcodeop).
- **`peb_walk.rs`** — ROR13 API hash resolver. `ror13_api(name)` and `ror13_module_api(module, name)` for both unqualified + Metasploit-style block_api UTF-16 forms. `LazyLock<HashMap>` reverse-index, ~130 seeds. `looks_like_hash(v)` filters out small offsets / masks / page sizes — false-positive surface ~1 in 2^32. Annotation appears via `format_const` wrapper; wraps every `Const` render so the comment shows up in any context (mov, cmp, conditional, return).
- **Annotation falsifying**: ROR13 algorithm has multiple published variants (uppercase pre-folding, UTF-16 module prefix, custom seed). The shipped algo doesn't necessarily match Metasploit's documented `0x0726774C` for `LoadLibraryA` — different shellcode strains use different ROR13 variants. Tests assert determinism + uniqueness, NOT match against external reference. Add new hash variants by adding new `ror13_*` entry-point fn + extending `HASH_INDEX` initializer.

## `.opt/` convention

- `.opt/ideas.md` — parked follow-ups (e.g. nested-ternary 3+ way merges)
- `.opt/failed.md` — aborted fix attempts (per /fix-leaker 3-attempt cap)
- `.opt/campaigns/<slug>.md` — opt-in campaign mode, bounded regression arc with hypothesis+budget+horizon declared upfront; auto-revert if miss at horizon

## macOS gotchas

- Apple `c++filt` strips leading `_` by default → use `c++filt -n` for Itanium `_Z...`
- No `timeout` cmd → `gtimeout` (brew coreutils) or Bash `run_in_background`
- `pip3` aliased to `uv` → `uv pip install --system` or venv
- `cargo test -p test-harness` has a pre-existing stack overflow in some debug test runs; use `cargo test --release -p test-harness` for CI parity, and iterate via `cargo test --release -p rsleigh-decompile --lib`
- **rtk caches aggressively.** If `cargo build` reports `0 crates compiled` when clearly changed → use `/opt/homebrew/bin/cargo` directly + `cargo clean -p <crate>`
- Use `cargo test -p <crate> --release --lib` when you explicitly want to skip example builds.
- `.DS_Store` sneaks into initial commits → `.gitignore` first

## Debugging fold/structure

- Temp `eprintln!("[tag] ...")` in fold.rs/structure.rs → run target func → inspect → remove
- `--ssa-json <addr>` for post-fold state without instrumentation
- Gate new SSA passes on `CallingConv::*` or arch when target-specific
- **`/fix-leaker` single-shot protocol:** failing regression test FIRST, commit test+fix together. 3-attempt cap. Log aborts to `.opt/failed.md`. Do not move goalposts mid-arc.
- **Bench noise band:** composite score has ~0.2 spread across repeat runs (sample 50 non-deterministic). Treat <1% composite movement on single-shot as noise; real regressions >1% or show twice.

## Known limitations

- Context reads used by generated lift code are captured at decode time; keep regression coverage around context-dependent operands.
- `ExprNew` / `ExprCPool` return 0 (JVM/WASM only)
- Some reg values not traced to defining expr (`iVar1 * factorial(n-1)` instead of `n * factorial(n-1)`)
- Type inference: basic + Win32 typedef + interprocedural two-pass + heuristic field names; no constraint-based
- MBA: SiMBA handles 1-4 var linear; non-linear + 5+ var need synthesis (egg catches some)
- Some loop conditions not recovered (`while (OF == SF)`)
- x86-32 sequential TEST/JNZ sometimes nests wrong
- Register-indirect calls across non-trivial CFG (e.g. multi-path conv. through a phi merge) still not resolved; same-function linear cases including cross-block IAT-into-reg now handled (resolve_callind_via_all_ops)
- ARM32 VFP/NEON: decode OK, FP reg values not fully traced through folding

## SMT backend (`--features smt`)

- Build: `CPATH=$(brew --prefix z3)/include LIBRARY_PATH=$(brew --prefix z3)/lib cargo build --release --features smt -p rsleigh-cli`
- Calibration harness: `python3 scripts/smt-calibrate.py test-harness/fixtures/smt/calibration` — 12-fixture corpus, 100% TP/TN target
- Modes: `--smt-explore <fn>` (single fn), `--smt-explore-all` (sweep, only Reachable), `--smt-candidates [<fn>]` (NDJSON dump for LLM, dedup+score+top-N+per-fn-cap), `--smt-diag` (per-binary aggregate stats)
- AX6000 router corpus: `/tmp/ax6000_ubi/ubi_out/431909977/rootfs_ubifs/usr/{bin,sbin}/{tdpServer,miniupnpd,dnsmasq,dropbear,avahi-daemon}`. Sweep baseline: 288 hits dnsmasq, 0 elsewhere
- Real-CVE corpus under `test-harness/fixtures/smt/calibration/<entry>/{<binary>,EXPECTED.json}`. Harness verdicts: TP / TN / FP / FN / FOUND-but-unproven
- `MAX_PATHS_PER_FN = 8192` truncates `collect_paths_with_summaries` output per-function (prevents 96k+ path explosion on parser-heavy fns)
- Lazy summary build: whole-binary `--smt-candidates` seeds with libc-source/sink-touching funcs, closure walks BOTH directions (forward for TaintedStore-eligible callees, reverse for inter-proc propagation callers)
- `--smt-candidates <fn>` per-fn scope ~30× faster than whole-binary on dnsmasq-class binaries; recommended

## Container builds (CVE corpus)

- `colima start --cpu 4 --memory 4 --disk 20` (after `brew install colima docker`); `colima stop` to free RAM
- **Colima quirk**: only `$HOME/...` mounts auto-pass into containers; `/tmp/...` mounts appear empty inside. Stage under `~/cve-build/{cache,scripts,out}`
- busybox-1.21.0 needs `ubuntu:18.04` image (debian:bookworm's glibc 2.36 removed `stime`, breaks rdate/date applets). Disable `CONFIG_INETD` (needs `rpc/rpc.h`)
- dropbear-2016.74: build with bare `make` (default target multibinary), NOT `make dropbear` (libtomcrypt include-path bug). Configure with `--disable-zlib` if no zlib1g-dev
- dnsmasq pre-2.70 removed from upstream archive — use 2.71 as proxy or Debian snapshot

## Symbol-table gotcha

- `symbols: Vec<(u64, String)>` can contain duplicate-address entries with empty names (call-graph discovery placeholders). `iter().find(|(a,_)| ..)` may return the empty-name placeholder before the real symbol. Prefer non-empty: `.filter(...).find(|(_,n)| !n.is_empty()).or_else(|| .find(...))`

## SMT feat branch state

- Master HEAD has v0..v21 merged. Branches alive: `feat/smt-backend`, `v18-real-cve-corpus`, `v19-v21-followups`
- v22+ filed in `.opt/failed.md`: FilePipe-write SinkKind (dropbear x11setauth FN), PathTraversal SinkKind (busybox mdev FN), pointer-arith OOB SinkKind (dnsmasq extract_name FN), LAVA-M docker pipeline

## ARM raw-mode discovery (post 9455a60)

- `--raw arm32`: prologue-validation pass culls BL-pattern false positives (~78% on real fw). ARM BLX(imm) now scanned for ARM→Thumb calls.
- Thumb LSB convention: address with `|1` = Thumb mode; even = ARM. `--disasm 0x26acd1` switches to Thumb.
- Arg order matters: `rsleigh <binary> --raw arm32 --disasm ...` (binary FIRST, --raw is a flag).
- Thumb-2 decompile still produces garbled output for high-density code (e.g. Sony BIONZ X firmware). Discovery + xref reliable; decompile lags.
- New helper `parse_object_lenient` retries with `parse_attribute_certificates: false` for carved PEs with cert-table past EOF.

## Python 3.14 quirks (macOS)

- `telnetlib` removed; roll your own via socket+select (see a7r2-sdk `tools/flash_camera.py`).
- `distutils` removed; some legacy packages (keystone-engine) need `setuptools` shim.
- `uv pip install --system --break-system-packages` to override PEP 668 guard.

## License

Apache 2.0
