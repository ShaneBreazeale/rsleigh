# x86-64 Pseudocode Audit — rsleigh vs. Ghidra

**Date:** 2026-04-16
**Binary under test:** `cb_baristas_secret_x64.exe` (PE64 CTF, 82 KB, MinGW+MSVC CRT)
**Ghidra version:** 11.3.1 (headless, default analysis)
**rsleigh commit:** `8bf8f0c` (master)

Five functions decompiled in both tools and diffed: `check_managed_app` (0x140001378),
`check2` (0x140001a68), `check3` (0x140001bc6), `main` (0x140001e41), and CRT init stub
(0x140001017). Full raw output saved in `target/audit/` when re-running.

---

## Defect classes observed

### A. Control flow / condition recovery
- `if (fgets(...) == 0 == 0)` — double-zero comparison from unfolded `(X == 0) == 0`.
- `if (!(local_60 == 0) == 0)` — unfolded double negation.
- `for (var_4 = 0;  <= 3; var_4++)` — condition LHS dropped. Pre-header init-var was
  renamed (`var_4` → `i` then back) but the condition was not re-substituted.
- `check_managed_app` missing else branches and terminal returns; the structure pass
  collapses else-bool-false arms and loses the final `return`.
- `B = A >> iVar2` inside `check3` loop — induction variable is not threaded through
  the body; the byte-pack store into `ab[i]` is missing entirely.

### B. Global data addresses rendered as string literals
- `*(long*)("Ô ")`, `*(long*)("È¡")`, `*(*(GS_OFFSET + 0x40001000) + 8)` — addresses
  in `.data`/`.bss` that the printer probed for string-likelihood and matched on
  arbitrary printable bytes. Ghidra shows `_refptr___ImageBase`,
  `_refptr___mingw_initltsdrot_force`, `DAT_14000a020`, etc.
- No IAT thunk / refptr resolution at print time: Ghidra resolves `__imp_` thunks to
  their target symbol; rsleigh prints the raw address.

### C. Stack-argument and shadow-store tracking (Windows x64)
- `printf(" FLAG: CODEBREW{%s}\n\n")` — variadic arg dropped. Ghidra:
  `printf("  FLAG: CODEBREW{%s}\n\n", input + 5)`.
- `strcspn` return value never reaches its use site (`input[sVar4] = 0`). Ghidra binds
  it; rsleigh discards and emits a dead `strcspn` call.
- `validate(input)` call is lost entirely from `main`. Ghidra recovers it.
- `check2`/`check3` byte-pickoff: `*(C) << 24` where `C` is the register param name —
  the actual pointer was spilled to `[RSP+0x20]` shadow-store and memory SSA doesn't
  forward it back out.
- Raw `RSP - 8 - 45`, `-96 + RBP + lVar1`, `-16 + RBP + lVar1` leak into final output.

### D. Expression folding noise
- Duplicate casts: `(uint)(uint)(uint8_t)`, `(uint)(uint8_t)(uint8_t)`.
- `puts(...) + 5` — pointer-math against a `void`-returning call, from arg register
  reuse after the call.
- `param_0 = 2; __p__fmode(2); *(uint32_t*)(lVar1) = *param_0;` — params reassigned
  to constants then deref'd, from lost SSA identity.
- `*(*(DAT_140005780)) == 1` — triple dereference where a single refptr read would do.

---

## Root-cause hypotheses

| Defect class | Hypothesized root cause | Evidence |
|---|---|---|
| A. Double-neg, for-loop LHS | Fold pass lacks idempotent canonicalization `(X==0)==0 → X!=0` and for-init rename doesn't rewrite the condition AST | Every affected function shows both in the same pass |
| B. Data-as-strings | `looks_like_string()` probe lacks section-readonly gate and NUL-termination requirement | Address space of false-positives sits in `.data`/`.bss`, not `.rdata` |
| C. Shadow store | Memory SSA treats `[RSP+8..0x20]` as ordinary stack; doesn't alias to formal params; doesn't forward stores across intermediate calls | All symptoms cluster on MSVC-compiled PE64 with `mov [rsp+N], reg` prologs |
| D. Noise | Partial folds not re-run at `#FINAL_PASS`; reassignment-to-param cases slip past type-refresh | One-shot fold leaves the artifacts that a second pass would catch |

---

## Impact ranking

Ordered by user-visible semantic impact (highest first):

1. **C. Shadow-store / arg tracking** — produces missing args and dropped calls. Whole
   function bodies become semantically wrong, not just ugly.
2. **A. Condition / loop recovery** — breaks readability of every branch-heavy function.
3. **B. Global-data strings** — visually jarring but usually not semantically misleading.
4. **D. Fold noise** — cosmetic; Ghidra also has some of this.

Implementation cost runs the other way (B easiest, C hardest).

---

## Not in scope for this audit

- ObjC / Swift / C++ specific printers (tested elsewhere)
- ARM32, AArch64, MIPS, RISC-V output (separate audits)
- Struct recovery quality (separate — already at 30-struct / 1,861-field baseline)
- Function discovery (rsleigh already leads 15-6 here)

---

## Reproduction

```bash
# rsleigh
./target/release/rsleigh ~/Downloads/test_bin/cb_baristas_secret_x64.exe \
    0x140001017 0x140001378 0x140001a68 0x140001bc6 0x140001e41

# Ghidra (script at /tmp/DecompFunc.py)
mkdir -p /tmp/ghidra_proj_brew
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj_brew proj \
    -import ~/Downloads/test_bin/cb_baristas_secret_x64.exe \
    -postScript /tmp/DecompFunc.py -deleteProject
```

---

## Post-Fix Results (2026-04-16)

After implementing `docs/superpowers/plans/2026-04-16-ssa-call-clobber-plan.md`
(SSA call-clobber + printer param-name fix):

### main (0x140001e41)

Improvements observed:
- `puts(...) + 5` noise expression is **gone** — the `+ 5` pointer-math artifact from
  caller-saved register reuse after the `puts` call has been eliminated by the
  call-clobber pass invalidating the register correctly.
- `printf` now emits as `fprintf(...)` with recognizable format string `" FLAG: CODEBREW{%s}\n\n"`.

Still broken (unaddressed defect classes):
- `strcspn` return value still not captured: `strcspn(/*s*/ local_60, ...)` appears as a
  void call; the `*(uint8_t*)(-96 + lVar1) = 0` assignment uses `lVar1` (unresolved) instead
  of `input[sVar]`. Root cause: RAX post-`strcspn` is clobbered correctly but the memory SSA
  does not yet forward the stack-spilled result.
- `if (0 == 0 == 0)` — double-zero condition from `fgets` return still unfolded (class A).
- `if (!(0 == 0) == 0)` — double negation still present (class A).
- `func_140001c54(buf)` — validate call present but `buf` not resolved to `input` (class C).
- `fprintf` args garbled: `fprintf(" FLAG: CODEBREW{%s}\n\n", /*format*/ puts(...), ...)`
  shows `puts` inlined as the format arg — shadow-store for variadic args still missing (class C).

### check2 (0x140001a68)

- `*(C)` **is gone** — the printer param-name fix correctly stops renaming pointer dereferences
  to single-letter register names. The byte-pickoff expressions now show `*lVar1`, `*lVar2`
  (unresolved temporaries) instead of the misleading `*(C)` form.
- The underlying shadow-store issue (class C) remains: `RSP - 8 - 45 + 7` raw stack addresses
  still appear because memory SSA does not forward the `[RSP+0x20]` shadow-store back to the
  parameter. No regression here versus baseline.
- `func_140001806(...)` decode call shows the obfuscated-string arg correctly with 4 arguments.

### Full test suite

0 rsleigh-decompile unit tests (doctests only, 1 ignored), 9 test-harness tests pass (0 regressions).

### Smoke tests

ChocolateFactory.exe: 10 functions decompile cleanly, 216 lines, no panic.
rust-crackme-easy.exe: 10 functions decompile cleanly, 392 lines, no panic.
(Note: `--all` on 603-function / 487-function binaries times out in CI; per-function decoding confirmed clean.)

### Remaining defect classes (unaddressed — future work)

- B: Global data addresses rendered as string literals (`.data`/`.bss` addresses hit `looks_like_string()`)
- A: Control flow / double-neg / loop condition recovery (`(X==0)==0` not canonicalized to `X!=0`)
- D: Fold noise (duplicate casts `(uint)(uint)(uint8_t)`, redundant expressions from one-shot fold)
- C: Shadow-store / variadic arg tracking — `[RSP+8..0x20]` not aliased to formal params across calls
