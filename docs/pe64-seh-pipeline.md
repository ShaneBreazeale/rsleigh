# PE64 SEH Static Analysis Pipeline

rsleigh includes a Windows structured-exception-handling (SEH) analysis
layer that models at static-analysis time what the OS exception dispatcher
does at runtime.  The pipeline is the backbone of static unpacking for
SEH-SMC-based obfuscators (PyVMProtect, Themida-like schemes, custom
exception-driven packers) and also improves ordinary function discovery
on any MSVC-built PE64 binary.

No dynamic execution, no Windows VM, no debugger.  Pure data-flow over
the PE image plus `.pdata`.

## Pipeline stages

```
     PE64 bytes
        │
        ▼
 ┌───────────────────┐
 │ parse .pdata      │  RUNTIME_FUNCTION entries
 │  + UNWIND_INFO    │  → handler VAs, scope_table VAs,
 │  + CHAININFO +    │    UNW_FLAG_{EH,UH,CHAIN}INFO
 │   chain-low-bit   │
 └─────┬─────────────┘
       │   SehRecord {func_begin, func_end, handler, scope_table, ...}
       ▼
 ┌───────────────────┐        ┌───────────────────┐
 │ handler body      │        │ SCOPE_TABLE       │
 │ analyser          │        │ parser            │
 │ (iced-x86,        │        │ {begin,end,       │
 │  control-flow     │        │  handler/filter,  │
 │  aware)           │        │  jump_target}     │
 └─────┬─────────────┘        └─────┬─────────────┘
       │                            │
       ▼                            ▼
 HandlerAnalysis                ScopeRecord list
 {redirects_rip,                    │
  skips_rip, calls_wpm,             │  nested recursion
  calls_vprotect,                   │  up to depth 8
  uses_rep_movs,                    │
  resumption_va, …}                 │
       │                            │
       └──────┬─────────────────────┘
              ▼
     ┌────────────────────┐
     │ patch extractor    │  worklist abstract interpreter:
     │ (control-flow      │    tracks RegVal lattice
     │  aware)            │    (Top | Imm(u64) | Addr(u64))
     └────────┬───────────┘
              ▼
     ImagePatch {target_va, bytes, handler_va}
              │
              ▼
     ┌────────────────────┐
     │ apply_patches to   │  mutates a cloned copy of the image
     │ working image      │  in place; OOB ignored
     └────────┬───────────┘
              ▼
     ┌────────────────────┐
     │ smc_fixpoint       │  re-extract + re-apply + re-discover
     │ (caller-supplied   │  until no new patch and no new
     │  discovery oracle) │  function appears, or max_iters
     └────────────────────┘
```

Public API lives at `rsleigh_decompile::seh_static`.  The CLI exposes the
full-discovery fixpoint as `rsleigh <bin> --seh-fixpoint`.

## Feature / target matrix

The table below lists which pipeline features benefit which target
categories.  "Yes" means the stage is exercised and surfaces useful data;
"—" means the stage is inert for that target (not a regression, just no
new signal).

| Pipeline stage | Python C-ext (.pyd/.so) | MSVC C/C++ PE64 | SEH-SMC packer | Non-Windows |
| --- | :---: | :---: | :---: | :---: |
| PyMethodDef scanner              | **Yes** | —       | —       | —       |
| Python C API signature pack      | **Yes** | — (unless linking python3xx) | **Yes** (PyVMProtect class) | **Yes** (Python ext on ELF) |
| MSVC push-reg prologue           | **Yes** | **Yes** | **Yes** | —       |
| Underscore-filter relaxation     | **Yes** | **Yes** | **Yes** | **Yes** |
| SEH handler enumeration (.pdata) | **Yes** | **Yes** | **Yes** | —       |
| Handler-body classifier          | —       | — (rarely SMC) | **Yes** | —       |
| SCOPE_TABLE parser               | **Yes** (MSVC-linked) | **Yes** | **Yes** | —       |
| Nested scope-table BFS           | **Yes** | **Yes** | **Yes** | —       |
| Chained-entry low-bit encoding   | —       | Rare    | Possible | —       |
| Control-flow-aware patch interp  | —       | — (no SMC) | **Yes** | —       |
| Patch extractor + apply          | —       | —       | **Yes** | —       |
| `smc_fixpoint`                   | —       | —       | **Yes** | —       |

## Worked examples

Numbers from commodity hardware, cold cache.

### crackmev3.pyd — PyVMProtect v4 sample

Before the pipeline landed:

```
1 functions:
  0x1800150f0  PyInit_crackmev3
```

After:

```
68 functions
  (+ 7 exports via underscore-filter relaxation)
  (+ 1 via PyMethodDef: _ttokwy5gsm @ 0x180014cf0)
  (+ 6 unique SEH handlers)
  (+ 54 scope-table filter / resume blocks)
```

SEH fixpoint: **1 iteration, 0 patches, converged.**
v4 does not use SEH-driven SMC; the v1 baseline is locked into a test to
catch any future false-positive patch emission.

### clang-apply-replacements.exe — real LLVM tool

Previously-captured bench set Ghidra total at **4045** functions.
rsleigh now discovers **4570** — Ghidra +525.

```
3509 SEH records
8 unique handler addresses      (C_specific_handler and friends)
19 scope-table addrs surfaced   (all __try filter / resume blocks)
```

One handler flagged as making IAT calls to `RtlUnwindEx` (the MSVC
personality function) — exactly what is expected of a legitimate
exception path.  No SMC candidates.

### pydevd_cython.cp39-win_amd64.pyd — debugpy Cython extension

Shipped inside the VS Code Python extension (`debugpy._vendored.pydevd`).
Representative of Cython-compiled Python C extensions in production:
thousands of registered methods per module, autogenerated pickling
protocol methods (`__reduce_cython__`, `__setstate_cython__`) per
user-defined class, and extensive Python C API usage.

Before the pipeline:

```
1 functions:
  0x1800466f0  PyInit_pydevd_cython
```

After:

```
64 functions, including:
  0x180009c60  set_suspend
  0x180009eb0  do_wait_suspend
  0x18000a100  trace_exception
  0x18000b8f0  handle_user_exception
  0x18002dff0  trace_dispatch_and_unhandled_exceptions
  0x18002ee20  get_trace_dispatch_func
  0x180027410  get_method_object
  ... (25+ PyMethodDef entries, 9 SEH surface entries,
        plus prologue / vtable / CALL discovery)
```

Decomp of those methods shows typed Python C API calls
(`PyDict_New()`, `PyErr_Occurred()`), resolved IAT references to
runtime type objects (`PyExc_SystemError`, `PyMethod_Type`,
`PyUnicode_Type`), and Cython debug strings (e.g. the method name
`"handle_user_exception"` embedded as a rodata literal for
exception messages).

### NumPy 2.4.4 core extensions — production scientific library

Tested against the `win_amd64` wheel:

| Binary | Size | Total | Named (real) |
| --- | ---: | ---: | ---: |
| `_multiarray_umath.pyd`  | 3.7 MB  |  361 |  **347** |
| `_simd.pyd`              | 832 KB  | 1628 | **1619** |
| `_generator.pyd`         | 585 KB  |  109 |  **100** |
| `mtrand.pyd`             | 489 KB  |   85 |   **76** |
| `_pocketfft_umath.pyd`   | 276 KB  |   10 |    1 |
| **total**                | 5.8 MB  | **2193** | **2143** |

"Named" here means a symbolic Python method or attribute name (e.g.
`ndarray.shape`, `ndarray.tolist`, `ndarray.__array_interface__`,
SIMD-per-dtype kernels) rather than an anonymous `FUN_xxxxx`.

Without the PyMethodDef scanner these five binaries would list one
function each (`PyInit_*`).  With it, 2143 real names become
available for direct decomp, cross-referencing, and symbol-aware
function-signature propagation.

The `_multiarray_umath.pyd` sample in particular covers the bulk of
the user-visible `numpy.ndarray` surface — `ndim`, `shape`, `dtype`,
`real`, `imag`, `T`, `flat`, `tolist`, `item`, `tobytes`, `astype`,
`byteswap`, `copy`, `resize`, `__array__`, `__array_wrap__`,
`__sizeof__`, `__array_interface__`, `__array_struct__`,
`__array_priority__`, `device`, …

### 7za.exe — 7-Zip CLI

```
6438 functions discovered
5077 SEH records (mostly unwind-only — compression code is almost
      entirely try/finally-free)
2 unique handler addresses
3 scope-table addrs surfaced
```

## Known limitations (v2)

1. **Indirect branches** in handler bodies terminate the interpreter on
   that path.  Jump-table dispatch inside a handler hides downstream SMC.
2. **WriteProcessMemory / VirtualProtect** call sites are flagged but not
   evaluated — arguments are not symbolically propagated back to source
   bytes.
3. **RtlAddFunctionTable** / dynamic handler registration is not
   modelled.  Handlers installed at runtime do not appear in `.pdata`
   and thus miss the enumeration.
4. **DispatcherContext** (R9) field reads (`ControlPc` at +0, `TargetIp`
   at +0x20) are not currently tracked; obfuscators that fetch the real
   fault address from R9 rather than the ExceptionRecord bypass the
   `reads_exception_info` signal.

This list describes the v2 baseline; subsequent code includes partial indirect
branch resolution, concrete-source WriteProcessMemory extraction, and
DispatcherContext read classification.

Source-controlled [synthetic SEH-SMC fixtures](../test-harness/fixtures/seh-smc/FIXTURE.md)
now cover direct writes and a resolved indirect branch with exact expected
patches. They provide a reproducible positive baseline; an independently authored
SEH-SMC sample is still needed to guide broader v3 work.
