# Architecture support

Support is reported by pipeline stage. A SLEIGH rule being present, or an
instruction decoding successfully, does **not** imply that its P-code is
complete or that the decompiler reconstructs useful C.

Legend: **tested** = covered by repository regression/oracle tests;
**partial** = useful but known gaps remain; **direct** = a non-SLEIGH frontend;
**n/a** = that stage does not apply.

| ISA / mode | Decode | Lift to P-code | Function discovery | Decompile | Important limits |
|---|---|---|---|---|---|
| x86-64 | tested | tested | tested | tested | Broadest coverage. Ghidra parity is fixture-based, not yet exhaustive. |
| x86-32 protected mode | tested | tested | tested | partial | PE32 imports work; calling-convention and legacy-mode recovery remain less mature than x86-64. |
| AArch64 | tested | tested | tested | tested | Scalar instructions have the strongest coverage. NEON/SVE decode coverage is broader than decompiler type/vector recovery. |
| ARM32 ARM mode | tested | tested | tested | partial | Integer/control-flow paths are usable; VFP/NEON value and type recovery remain incomplete. |
| ARM32 Thumb / Thumb-2 | tested | partial | tested | partial | Cortex-M discovery is supported. High-density Thumb-2 and mode-changing flows still lag ARM-mode lifting/decompilation. |
| MIPS32 big-endian | tested | partial | tested | partial | JAL/BAL and PIC/GOT discovery are covered. FPU/DSP/MIPS16/microMIPS rules may decode without equivalent SSA/printer coverage. |
| RISC-V RV64GC | tested | partial | partial | partial | Base integer and common compressed flows are usable. F/D/B/K/P/Q/V/C presence in the spec is not a decompiler-completeness claim. |
| WebAssembly | direct | n/a | direct | partial | Uses the dedicated WASM parser/reconstructor rather than the SLEIGH/P-code pipeline. |

The strict oracle suite under `test-harness/fixtures/oracle` compares instruction
length plus normalized P-code opcode, varnode space, offset, and size against
Ghidra. Its committed corpus is intentionally visible and finite; architecture
labels above must not be read as whole-ISA parity claims.

Binary containers currently accepted by the CLI include ELF (32/64), PE
(32/64), Mach-O (64), WASM, and raw images. Container support is separate from
the ISA-stage matrix above.

## Native dependency queries

Semantic slices apply to parsed PE/ELF/Mach-O inputs. Support below is for
scalar integer/pointer dependencies; it does not extend the ISA coverage above.

| Dependency | x86-64 / x86-32 | AArch64 / ARM32 | MIPS32 / RISC-V |
|---|---|---|---|
| Native scalar return selection | Supported | Supported | Supported |
| ABI call-argument selection and helper argument binding | Supported for documented conventions | Supported for documented conventions | Unsupported; reported explicitly |
| Exact stack/global store-to-load forwarding | Supported | Supported | Unsupported; loads remain boundaries |

Unknown aliases, unknown calls, unsupported effects, recursion, and exhausted
budgets remain explicit boundaries. Resolved indirect calls retain heuristic
confidence. See [selector details](agent-workflow.md#bounded-backward-ssa-query)
and the [six-architecture evaluation](agent-re-evaluation.md#final-six-architecture-comparison).

## Function discovery

The discovery pipeline combines symbol tables, recursive direct-call descent,
call-target scans, platform unwind/function metadata, prologue scans, thunks,
vtable/function-pointer references, and ISA-specific branch patterns.

- PE64: `.pdata` exception directories for x86-64 and ARM64.
- Mach-O: `LC_FUNCTION_STARTS`, Objective-C stubs, and symbol stubs.
- Stripped ELF: `.eh_frame` FDEs, RTTI/vtables, indirect targets,
  `.init_array`/`.fini_array`, PLT stubs, and cross-references.
- ARM32: ARM and Thumb BL discovery, including raw-firmware scans.
- MIPS32: endian-aware JAL/BAL plus GP-relative GOT tracing for PIC code.

Discovery success means the tool found a plausible function boundary. It does
not upgrade that ISA's lift or decompile status.

## Agent preflight

Before interpreting output, record four independent facts: container, ISA/mode,
endianness where applicable, and image base. Do not infer later-stage support
from a successful decode.

1. Read `file.arch`, `file.format`, `file.imagebase`, `warnings`, and `trust`
   from `--agent-brief` for parsed PE, ELF, or Mach-O inputs.
2. For raw images, supply `--raw ARCH --base ADDR` on every invocation. Treat
   both values as analyst-provided assumptions until independently verified.
3. Check this table at the stage used by the claim. A `tested` decode does not
   make partial lifting or decompilation authoritative.
4. If a function card reports unresolved indirect calls or truncation, include
   that gap in the assessment; absence of a direct xref is not absence of a
   runtime edge.

When the required cell is `partial`, prefer instruction bytes and disassembly,
then P-code if coherent. Mark pseudocode-only conclusions `provisional`. When
the input mode or base is unknown, mark the conclusion `unsupported` rather
than guessing.

## CLI frontend coverage

The ISA matrix describes pipeline capabilities; CLI modes also depend on the
input frontend. Parsed PE/ELF/Mach-O support the native agent brief, index,
function cards, and JSON inspection paths. Raw firmware and WASM do not
implement those contracts.

Raw function selection currently renders pseudocode even when `--disasm` is
present. Raw `--xrefs` is ARM32-only. Raw MIPS discovery's endianness heuristic
does not establish matching little-endian lift support. WASM lists functions
and reconstructs a selected name or `func_N` through its dedicated frontend.
See [raw/WASM command guidance](cli-reference.md#raw-firmware-and-webassembly)
for examples and alternatives for instruction evidence.
