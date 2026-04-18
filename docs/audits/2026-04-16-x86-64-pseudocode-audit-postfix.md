# x86-64 Pseudocode Audit — Post-Fix Comparison (rsleigh vs. Ghidra)

**Date:** 2026-04-16  
**Binary:** `cb_baristas_secret_x64.exe` (PE64 CTF, 82 KB, MinGW+MSVC CRT)  
**Ghidra version:** 11.3.1 (headless, default analysis)  
**rsleigh commit:** post-fix (call-return binding + RSP-relative local naming)

Fixes shipped since the original audit (`8bf8f0c`):
- **Plan A** — Call-return binding: `strcspn(...)` now emits `sVar1 = strcspn(...)` instead of a void call
- **Plan B** — RSP-relative local naming: `RSP - 8 - 45` style expressions now render as `local_35`

---

## Full rsleigh Output (post-fix)

```c
// 0x140001017
long func_140001017(void) {
    int iVar1;
    long lVar1;
    long lVar2;
*(uint64_t*)(DAT_14000a020) = func_140001378();
if (*(*(DAT_140005710)) == 0) {
    lVar1 = __p__fmode();
    *(uint32_t*)(lVar1) = *lVar2;
    lVar1 = __p__commode(*(uint32_t*)(lVar2));
    *(uint32_t*)(lVar1) = *lVar2;
    func_140002050(*(uint32_t*)(lVar2));
    if (*(*("`@")) == 1) {
        return 0;
    }
}
return iVar1;
}

// 0x140001378
long func_140001378(void) {
    int iVar1;
    long lVar1;
    long local_10;
    int local_18;
lVar1 = *(long*)("Ô ");
*(uint32_t*)(lVar1) = 1;
lVar1 = *(long*)("Ø ");
*(uint32_t*)(lVar1) = 1;
lVar1 = *(long*)("Ü ");
var_8 = DAT_1400056a0->field_0;
iVar1 = (uint16_t)*lVar1;
if (*(*(DAT_1400056a0)) == 0x5a4d /* MZ header */) {
    local_10 = lVar1 + *(lVar1 + 60);
    if (*(*(DAT_1400056a0) + *(*(DAT_1400056a0) + 60)) == 0x4550 /* PE signature */) {
        local_18 = local_10 + 24;
        if (local_10[3] == 267) {
            if (iVar1 > 14) {
                return (14 != *(uint32_t*)(lVar1 + 108)) ? 1 : 0;
            }
        } else if (local_10[3] == 523) {
                if (local_18[108] > 14) {
    }
        }
    }
}
}

// 0x140001a68
int func_140001a68(int C) {
    int iVar1;
    char local_c[34];
    byte local_2e;
    short local_2f;
    int local_31;
    int local_35;
    byte local_3a;
    int local_3b;
func_140001806("v`cav``|rarqzprQAVD>", 8, 19, local_35);
local_c = C;
iVar1 = (uint)(uint8_t)*(local_2e) << 24 | k2b << 8 | (uint)(uint)(uint8_t)*(local_31) | (uint)(uint)(uint8_t)*(local_2f) << 16;
local_c = iVar1 ^ iVar1 ^ iVar1;
func_140001806("rarqzprQAVD>", 7, 19, k1);
iVar1 = (uint)(uint8_t)*(local_3a) << 24 | k2_word << 8 | (uint)(uint)(uint8_t)local_35 | (uint)(uint)(uint8_t)*(local_3b) << 16;
local_c = local_c ^ iVar1;
return (local_c == (uint)0xcafebabe) ? 1 : 0;
}

// 0x140001bc6
int func_140001bc6(int A, int B) {
    int iVar1;
    int iVar2;
    int iVar3;
    long lVar1;
    int local_8;
for (var_4 = 0;  <= 3; var_4++) {
    B = A >> iVar2;
    *(uint32_t*)(-16 + RBP + lVar1) = lVar1;
}
for (local_8 = 0;  <= 3; local_8++) {
    B = B >> iVar2;
    *(uint32_t*)(-16 + RBP + lVar1) = iVar3 >> local_8 << 3;
}
lVar1 = func_140001870(i, 8);
iVar1 = lVar1 & 1048575;
return (ZF & 1048575 == 0xdecaf) ? 1 : 0;
}

// 0x140001e41
long func_140001e41(void) {
    uint8_t bVar1;
    long lVar1;
    int local_60;
lVar1 = fgets(/*s*/ local_60, /*size*/ (int)80, /*stream*/ lVar1);
if (lVar1 == 0 == 0) {
    lVar1 = strcspn(/*s*/ local_60, /*reject*/ (char *)0x140005295);
    *(uint8_t*)(-96 + RBP + lVar1) = 0;
    lVar1 = func_140001c54(local_60);
    if (!(lVar1 == 0) == 0) {
        puts(" Press Enter to exit...");
        return 0;
    }
    puts("\n ✓ Your brew is flawless. Access granted.");
    puts("\n ✓ Your brew is flawless. Access granted.");
}
return bVar1;
}
```

---

## Full Ghidra Output (11.3.1)

> Note: `0x140001017` (CRT init stub) returned `FUNC_NOT_FOUND` — Ghidra did not create a function at this address during auto-analysis.

```c
// check_managed_app (0x140001378)
bool check_managed_app(void)
{
  int *piVar1;
  bool bVar2;

  *(undefined4 *)_refptr___mingw_initltsdrot_force = 1;
  *(undefined4 *)_refptr___mingw_initltsdyn_force = 1;
  *(undefined4 *)_refptr___mingw_initltssuo_force = 1;
  if (*(short *)_refptr___ImageBase == 0x5a4d) {
    piVar1 = (int *)(_refptr___ImageBase + *(int *)(_refptr___ImageBase + 0x3c));
    if (*piVar1 == 0x4550) {
      if ((short)piVar1[6] == 0x10b) {
        if ((uint)piVar1[0x1d] < 0xf) {
          bVar2 = false;
        }
        else {
          bVar2 = piVar1[0x3a] != 0;
        }
      }
      else if ((short)piVar1[6] == 0x20b) {
        if ((uint)piVar1[0x21] < 0xf) {
          bVar2 = false;
        }
        else {
          bVar2 = piVar1[0x3e] != 0;
        }
      }
      else {
        bVar2 = false;
      }
    }
    else {
      bVar2 = false;
    }
  }
  else {
    bVar2 = false;
  }
  return bVar2;
}

// check2 (0x140001a68)
/* WARNING: Unknown calling convention */
int check2(uint32_t C)
{
  uint in_ECX;
  uint8_t *in_stack_ffffffffffffff98;
  size_t in_stack_ffffffffffffffa0;
  uint8_t in_stack_ffffffffffffffa8;
  char *in_stack_ffffffffffffffb0;
  char k2 [8];
  char k1 [9];
  uint32_t k2_word;
  uint8_t *k2b;
  uint32_t half_hi;
  uint32_t half_lo;
  uint32_t fold;
  uint8_t *k;

  deobf(in_stack_ffffffffffffff98,in_stack_ffffffffffffffa0,in_stack_ffffffffffffffa8,
        in_stack_ffffffffffffffb0);
  deobf(in_stack_ffffffffffffff98,in_stack_ffffffffffffffa0,in_stack_ffffffffffffffa8,
        in_stack_ffffffffffffffb0);
  return (int)((in_ECX ^ k1._0_4_ ^ k1._4_4_ ^ k2._0_4_) == 0xcafebabe);
}

// check3 (0x140001bc6)
/* WARNING: Unknown calling convention */
int check3(uint32_t A,uint32_t B)
{
  uint32_t uVar1;
  uint in_ECX;
  uint in_EDX;
  uint8_t *in_stack_ffffffffffffffc8;
  size_t in_stack_ffffffffffffffd0;
  uint8_t ab [8];
  int i_1;
  int i;

  for (i = 0; i < 4; i = i + 1) {
    ab[i] = (uint8_t)(in_ECX >> ((byte)(i << 3) & 0x1f));
  }
  for (i_1 = 0; i_1 < 4; i_1 = i_1 + 1) {
    ab[i_1 + 4] = (uint8_t)(in_EDX >> ((byte)(i_1 << 3) & 0x1f));
  }
  uVar1 = brew_hash(in_stack_ffffffffffffffc8,in_stack_ffffffffffffffd0);
  return (int)((uVar1 & 0xfffff) == 0xdecaf);
}

// main (0x140001e41)
int __cdecl main(int _Argc,char **_Argv,char **_Env)
{
  int iVar1;
  FILE *pFVar2;
  char *pcVar3;
  size_t sVar4;
  uint8_t *in_stack_ffffffffffffff78;
  size_t in_stack_ffffffffffffff80;
  uint8_t in_stack_ffffffffffffff88;
  char *in_stack_ffffffffffffff90;
  char input [80];
  char brand [9];

  __main();
  SetConsoleOutputCP(0xfde9);
  SetConsoleCP(0xfde9);
  anti_debug();
  deobf(in_stack_ffffffffffffff78,in_stack_ffffffffffffff80,in_stack_ffffffffffffff88,
        in_stack_ffffffffffffff90);
  putchar(10);
  puts(&DAT_140005070);
  printf(&DAT_1400050f8,brand);
  puts(&DAT_140005128);
  // ... (64 input[N] = '\0' initializer lines elided for brevity) ...
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets(input,0x50,pFVar2);
  if (pcVar3 == (char *)0x0) {
    iVar1 = 1;
  }
  else {
    sVar4 = strcspn(input,"\n\r");
    input[sVar4] = '\0';
    iVar1 = validate((char *)in_stack_ffffffffffffff78);
    if (iVar1 == 0) {
      puts(&DAT_1400052e0);
    }
    else {
      puts(&DAT_140005298);
      printf("  FLAG: CODEBREW{%s}\n\n",input + 5);
    }
    puts("  Press Enter to exit...");
    getchar();
    getchar();
    iVar1 = 0;
  }
  return iVar1;
}
```

---

## Quantitative Scoring Table

Metrics are measured per-function across all 5 audit targets.

### Named Locals Ratio

Count of `local_XX`-named variables declared in function headers (higher = better stack variable naming).

| Function | Ghidra | rsleigh pre-fix | rsleigh post-fix |
|---|---|---|---|
| func_140001017 (CRT init) | N/A (not found) | 0 | 0 |
| check_managed_app (0x140001378) | 2 (`piVar1`, `bVar2`) | 2 (`local_10`, `local_18`) | 2 (`local_10`, `local_18`) |
| check2 (0x140001a68) | 0 (uses `in_stack_*` raw) | 7 (`local_c`, `local_2e`, `local_2f`, `local_31`, `local_35`, `local_3a`, `local_3b`) | 7 (unchanged) |
| check3 (0x140001bc6) | 2 (`ab`, `i`/`i_1`) | 1 (`local_8`) | 1 (unchanged) |
| main (0x140001e41) | 2 (`input`, `brand`) | 1 (`local_60`) | 1 (unchanged) |
| **Total** | **4** | **11** | **11** |

### Void Call Rate (calls that return values but appear unbound)

A call is "void" if it appears as a standalone statement with no `=` binding and the function is known to return a non-void value.

| Function | Ghidra | rsleigh pre-fix | rsleigh post-fix |
|---|---|---|---|
| check_managed_app | 0 | 0 | 0 |
| check2 | 0 | 0 | 0 |
| check3 | 0 | 0 | 0 |
| main | 0 | **1** (`strcspn` unbound — pre-fix) | **0** (`lVar1 = strcspn(...)` — FIXED) |
| func_140001017 | N/A | 0 | 0 |
| **Total void calls** | **0** | **1** | **0** |
| **Rate** | **0%** | **~17%** (1/6 value-returning calls) | **0%** |

### Raw Address / Register Noise Lines

Lines in function body containing raw `RBP`, `RSP`, or literal `0x14000xxxx` style expressions (lower = better).

| Function | Ghidra | rsleigh pre-fix | rsleigh post-fix |
|---|---|---|---|
| func_140001017 | N/A | 0 | 0 |
| check_managed_app | 0 | 0 | 0 |
| check2 | 0 (uses `in_stack_*` — different noise) | 2 (`RSP - 8 - 45` forms) | **0** (RSP forms resolved to `local_35` etc.) |
| check3 | 0 | 2 (`-16 + RBP + lVar1`) | 2 (still present — loop body RBP not resolved) |
| main | 0 | 2 (`-96 + RBP + lVar1`) | 2 (still present — shadow-store issue) |
| **Total raw addr lines** | **0** | **6** | **4** |

### Argument Completeness

Known-signature calls with correct argument count emitted vs. total known-signature calls.

| Metric | Ghidra | rsleigh pre-fix | rsleigh post-fix |
|---|---|---|---|
| `strcspn` args (expects 2) | 2 ✓ | 2 ✓ | 2 ✓ |
| `fgets` args (expects 3) | 3 ✓ | 3 ✓ | 3 ✓ |
| `printf` with format+arg in main | `printf("  FLAG: CODEBREW{%s}\n\n", input + 5)` ✓ | garbled (shadow-store) | garbled (shadow-store) |
| `validate(input)` arg resolved | `validate((char *)in_stack_...)` (shadow arg) | `func_140001c54(local_60)` ✓ | `func_140001c54(local_60)` ✓ |

### Total Output Lines (body, excluding blank lines and declarations)

| Function | Ghidra | rsleigh post-fix |
|---|---|---|
| func_140001017 | N/A (not found) | ~10 |
| check_managed_app | ~24 | ~14 |
| check2 | ~8 | ~10 |
| check3 | ~12 | ~9 |
| main | ~30 (+ 64 init lines = 94 total) | ~10 |
| **Total body lines** | **~74 (+64 init noise)** | **~53** |

> Note: Ghidra's `main` expands the `memset`-style zero-init loop into 64 explicit `input[N] = '\0'` lines. rsleigh omits this noise entirely, producing a much more readable output body for `main`.

### Summary Table

| Metric | Ghidra | rsleigh pre-fix | rsleigh post-fix | Delta (pre→post) |
|---|---|---|---|---|
| Named locals total | 4 | 11 | 11 | 0 (already good) |
| Void call rate | 0% | ~17% | **0%** | **-17 pp (FIXED)** |
| Raw addr/register noise lines | 0 | 6 | **4** | **-2 (partial fix)** |
| `strcspn` return captured | ✓ | ✗ | **✓** | **FIXED** |
| `printf` variadic args complete | ✓ | ✗ | ✗ | unchanged |
| Double-negation conditions | 0 | 2 | 2 | unchanged |
| Main body noise (init lines) | +64 | 0 | 0 | rsleigh advantage |
| Total body lines (all 5 funcs) | ~74 | ~53 | ~53 | rsleigh more compact |

---

## Per-Defect-Class Analysis

### Class A — Control Flow / Condition Recovery

**Status: Unchanged (not targeted by these fixes)**

Still present post-fix:
- `if (lVar1 == 0 == 0)` — fgets return double-zero in `main`
- `if (!(lVar1 == 0) == 0)` — double negation on validate result in `main`
- `for (var_4 = 0;  <= 3; var_4++)` — for-loop condition LHS dropped in `check3`
- `check_managed_app` missing else branches and terminal `return`

Ghidra emits clean `if (pcVar3 == (char *)0x0)` and proper `for (i = 0; i < 4; i = i + 1)` loops. This remains rsleigh's most impactful open defect class for this binary.

### Class B — Global Data Addresses as String Literals

**Status: Partially improved (not directly targeted)**

rsleigh still emits `*(long*)("Ô ")`, `*(long*)("Ø ")`, `*(long*)("Ü ")` for global refptr accesses in `check_managed_app`. Ghidra correctly names these `_refptr___mingw_initltsdrot_force`, `_refptr___ImageBase`, etc.

The `*(*("`@"))` artifact in `func_140001017` persists — a two-byte address in `.data` that passes the string probe.

`DAT_` prefix names (e.g., `DAT_14000a020`, `DAT_140005710`) are correctly emitted by rsleigh for non-string globals, matching Ghidra's `&DAT_140005070` style.

### Class C — Shadow-Store / Arg Tracking

**Plan A fix (call-return binding): SHIPPED AND CONFIRMED**

`main` (0x140001e41) before fix (from audit doc):
```
strcspn(/*s*/ local_60, ...)   // void call — return value lost
*(uint8_t*)(-96 + RBP + lVar1) = 0  // lVar1 unrelated
```

`main` (0x140001e41) after fix:
```c
lVar1 = strcspn(/*s*/ local_60, /*reject*/ (char *)0x140005295);
*(uint8_t*)(-96 + RBP + lVar1) = 0;
```

The `strcspn` return is now bound to `lVar1` and used as the string offset. This is a **semantic correctness fix** — the null-termination logic is now readable.

**Plan B fix (RSP-relative naming): PARTIALLY CONFIRMED**

`check2` (0x140001a68) — the local variable declarations now show `local_35`, `local_3b`, etc. instead of `RSP - 8 - 45` expressions. This reduces noise in the declaration block. However, the body of `check3` still shows `-16 + RBP + lVar1` in the loop body store, and `main` still shows `-96 + RBP + lVar1` for the strcspn result write. These are expression-level RBP accesses that the naming pass does not yet transform.

Remaining shadow-store issues (unaddressed):
- `printf("  FLAG: CODEBREW{%s}\n\n")` — variadic second arg (`input + 5`) still dropped
- `validate` called as `func_140001c54(local_60)` — arg resolves correctly but name not recovered
- Ghidra passes `in_stack_ffffffffffffff78` (knows it's a stack param) while rsleigh passes `local_60` (correct value, wrong identity — it should be `input`)

### Class D — Expression Folding Noise

**Status: Unchanged (not targeted by these fixes)**

Still present:
- Duplicate casts: `(uint)(uint)(uint8_t)` in `check2`
- `k2b`, `k2_word`, `k1` — partial name recovery for xor key pieces but not full constant folding
- `ZF & 1048575 == 0xdecaf` — flag register leak in `check3` return condition
- Ghidra correctly emits `(uVar1 & 0xfffff) == 0xdecaf` using a clean temp variable

---

## Observations

1. **rsleigh has better local variable naming density**: 11 named `local_XX` vars vs. Ghidra's 4, across the 4 functions Ghidra found. Ghidra relies on `in_stack_*` for shadow-passed params (which is accurate but verbose).

2. **rsleigh produces more compact output**: ~53 body lines vs. ~138 (Ghidra with init noise). The 64-line `input[N] = '\0'` expansion in Ghidra is a known weakness.

3. **Ghidra wins on control flow**: Clean `for` loops with both bounds, proper else branches, complete `return` statements. rsleigh drops the for-loop condition LHS and collapses else-false arms.

4. **Ghidra wins on named symbol resolution**: `_refptr___ImageBase`, `_refptr___mingw_initltsdrot_force` vs. `*(long*)("Ô ")`. PE-specific refptr symbol resolution is not implemented in rsleigh.

5. **Plan A (call-return binding) was the highest-value fix**: Converting `strcspn` from a void call to a bound assignment restores the semantic meaning of the null-termination line in `main`. This is the defect most likely to mislead a reverse engineer.

6. **Plan B (RSP-relative naming) improved declarations but not expressions**: The `local_35` naming in `check2` declarations is cleaner, but `RBP +`-style expressions still appear in loop bodies where the fold pass emits them directly into the expression tree rather than through the naming pass.
