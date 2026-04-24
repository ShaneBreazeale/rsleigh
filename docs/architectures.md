# Architecture support

End-to-end working for 7 architectures:

| Architecture | Notes |
|---|---|
| x86-64 | full |
| x86-32 | SSE/AVX, PE32 import resolution |
| AArch64 | NEON + SVE |
| ARM32 | ARMv7 + Thumb + VFP/NEON floats |
| MIPS32 | FPU + DSP + MIPS16 + microMIPS |
| RISC-V 64 | F/D/B/K/P/Q/V/C |
| WebAssembly | WASM module decompilation |

Binary formats: ELF (32/64), PE (32/64), Mach-O (64), WASM, raw.

PE machine auto-detection: x86-64 (0x8664), ARM64 (0xAA64), i386 (0x014C).

## Function discovery

Symbol tables → recursive CALL descent → exhaustive CALL target scan
(E8/BL) → `.pdata` exception dirs (PE64 x86-64 + ARM64) →
`LC_FUNCTION_STARTS` (Mach-O) → `__objc_stubs` + `__stubs` →
prologue scanning (x86-32/64, AArch64 STP+SUB+ADRP) →
JMP thunk (FF 25 / E9) → vtable pointer scan (.rdata) →
`.rdata` function pointer refs → ARM32 BL/Thumb BL.

Stripped ELF (12 methods): `.eh_frame` FDE unwinding → RTTI vtable →
indirect call target resolution → prologue match → CALL enumeration →
`.init_array`/`.fini_array` → PLT stubs → xref.
MIPS: JAL/BAL + endian-aware. MIPS PIC: GP-relative GOT tracing.
