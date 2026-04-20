# rsleigh Roadmap

Tracks in-flight and planned work. For shipped features, see `CLAUDE.md`
"Key Features". For test coverage, see `docs/TESTING.md`.

---

## Ghidra parity gap (PLM aarch64 baseline)

Current status on 50-function random sample of `plm-control-app.elf`:

| Metric | rsleigh | Ghidra |
|---|---|---|
| Avg lines per function | 21 | 27 |
| `lVar` leaks per 100 lines | 37 | ~0 |
| `DAT_` leaks per 100 lines | 5 | ~0 |
| `field_N` anon struct fields per 100 lines | 20 | ~0 |
| Unresolved direct call `func_X` per 100 lines | 10 | <5 |

rsleigh matches or beats Ghidra on function discovery count (4531 vs
4357) and leads on 15/21 binaries in the comparison corpus. Remaining
gap is concentrated in type recovery + control-flow shape.

---

## Active areas

### P0 — Control flow structure recovery
- **Parallel `if` collapsed to nested.** Diamond CFGs where both
  branches post-dominate the same join block currently emit nested
  form instead of sibling ifs. Root cause in `structure::emit_region`
  post-dominator picking. Needs test corpus of 10+ hand-labelled
  ARM64 functions before touching.
- **do-while vs while misclassification.** Back-edge post-test funcs
  (common in STL iterator loops) print as `while (cond) { ... return; }`
  with impossible mid-loop return. Fix in back-edge detection phase
  of structure recovery.
- **Dead-code reachability after return.** Basic-block flattener
  occasionally emits statements after an unconditional return inside
  a nested branch.

### P1 — Type recovery
- **Pointer propagation through callee-saved x19-x28.** Type inference
  almost never flags x19-x28 as Pointer even when only used via `->` /
  `*()`. Need explicit propagation: if a register-varnode use has
  InferredType::Pointer for the address of any Load/Store keyed off it,
  mark all versions of that register in the register-SSA chain.
- **Struct field naming.** `param_1->field_8` vs Ghidra's `param_1[1]`
  or `param_1->next`. Current heuristic struct-field namer only handles
  linked-list patterns. Expand to cover Qt `d_ptr` pattern, ref-counted
  object headers, common STL container headers.
- **Return-type inference.** Still guesses `long` for functions that
  take a pointer and return it unmodified (`this` return). Add
  "parameter-through" detection to the return-inference pass.

### P2 — Decoder / semantic
- **ExprValue::Context returns 0.** Used by some slaspecs for
  context-sensitive instruction semantics. Currently unused by
  x86/ARM/RISC-V but blocks PowerPC/SH-4 if we ever add them.
- **ExprNew / ExprCPool return 0.** JVM bytecode + WASM module
  instantiation. Not a real blocker.
- **ARM32 VFP/NEON float register propagation.** Instructions decode
  correctly (vmul.f64, vldr, vmov) but float register values don't
  thread through fold's expression inliner. Need float-specific
  handling in propagate_register_constants.

### P3 — Function ID database
- **Mask tuning for cross-compile match.** Current Qt5Core round-trip
  is 99% matched / 0% false-positive on same-binary lookup. Cross-compile
  (different gcc version / optlevel) unmeasured. Need labelled corpus
  of identical source + varied toolchains to tune x86 ModR/M + AArch64
  per-class masks.
- **Bundle Windows ntdll/kernel32.** Microsoft doesn't ship stable
  function bodies; lib authors rely on PDB symbols. Need PDB-backed
  match path (already partially wired via pdb_info.rs) before FID is
  useful on PE targets.
- **ARM32 / MIPS / RISC-V bundled DBs.** Today only x86_64 + aarch64
  ship. Add when we find a high-demand target (e.g. MIPS router
  firmware, ARM32 IoT).
- **Match telemetry in `--verbose` mode.** Print renamed count +
  examples when FID matches fire, so users can see which of 13,612
  signatures hit.
- **Auto-discover .fidb files in $HOME/.config/rsleigh/fid/.** Lets
  users drop Qt / OpenSSL / libcurl blobs without CLI flags.

### P4 — Analysis features
- **Indirect call resolution beyond MIPS.** Currently resolved via
  GP-relative GOT tracing on MIPS (77% resolved). Apply the same
  pattern on AArch64 (ADRP+LDR+BLR) and x86-64 (CALL [rip+off]).
- **Stack-buffer size recovery.** Array-sizing works from offset gaps
  but stops at the first pointer-to-stack-slot use. Extend to handle
  aliased stack pointers (`lea` / `add sp, N`).
- **Exception-aware dataflow.** `.eh_frame` try regions are annotated
  as comments; SSA fold doesn't treat catch handlers as alternate
  successors, so variables written in the try body are assumed live at
  the catch. Add virtual edges.

### P5 — Ecosystem
- **Spectra integration tests for FID.** `rsleigh-api::identify()` not
  exposed yet — Spectra still relies on symbol-table lookup. Surface
  via optional `ident: bool` flag on the Decoder API.
- **VSCode extension.** Decompile on hover, inline struct field rename,
  jump-to-xref. Protocol already supported via rsleigh-cli JSON mode.
- **Docker reproducible-builds.** `scripts/build-fid-dbs.sh` pulls from
  Debian/Alpine mirrors; pin via SHA256 plus provenance manifest so
  CI can re-verify the checked-in .fidb blobs match upstream.

---

## Recently shipped (current session)

- Qt5 signature database (23,274 entries extracted from bundled .so files)
- rsleigh-fid crate end-to-end (scaffold → CLI → match helper)
- Glibc / musl / libstdc++ bundled FID blobs (6 files, 287KB, 13,612 entries)
- AArch64 AAPCS64 x1-x7 + v0-v7 param recovery
- Stack-canary XOR epilogue elision (post-rename)
- ADRP page-address prologue leak strip (2 passes)
- `close` / GOT import name-collision fix (page-aligned skip)
- `InferredType::Pointer` → `void *` typing
- `lVar → puVar` rename when type=Pointer
- Callee-saved register prologue spill elision
- R_*_GLOB_DAT reloc parsing for `__stack_chk_guard` + vtable names

---

## Out of scope

- Windows PDB symbol server integration (complex licensing + network)
- Debugger integration (gdb / lldb) — use existing Spectra pipeline
- Interactive REPL — CLI is scripting-first by design
- JIT / dynamic code support — purely static analysis tool
