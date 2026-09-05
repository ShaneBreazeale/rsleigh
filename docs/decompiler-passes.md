# Decompiler passes

5-pass pipeline: CFG → SSA → fold → structure recovery → C printer.
Sources under `rsleigh-decompile/src/`. This is an implementation reference;
start with the [agent workflow](agent-workflow.md) and [CLI guide](cli-reference.md)
for tool use. Internal passes and IR are experimental; verify behavior against
the source revision being used.

## SSA builder (ssa.rs)

- Iterative dataflow, max 4 passes for loop headers + merges
- Multi-pred blocks inherit from first processed pred; re-process on exit-var change
- Phi insertion at join points from converged exit maps
- Deterministic Phi creation: varnodes sorted `(space, offset, size)` so Phi VarId allocation stable across runs
- Sub-register Zext deferral: `IntZext(EAX→RAX)` preceding addr calc that reads RAX in same instruction → defer Zext write
- Sub-register write propagation both directions (parent↔child blend)
- Forward-edge predecessor priority prevents back-edge contamination
- ESP_OFFSET = 32 (not 16=EDX)
- Parameter naming before constant propagation
- Memory SSA two-phase: intra-block forwarding + fixed-point worklist with memory Phi; SlotKey=(base_reg, disp, size)

## CFG builder (cfg.rs)

- CallInd resolution: `CALL [IAT_addr]` trace Load source → Direct
- x86-32 CALL/RET boilerplate stripping (ret addr push, stack pop)

## Fold passes (fold.rs)

Algebraic simplification, single-use temp inlining, copy prop, dead flag elim (x86 CF/ZF/SF/OF at 0x200-0x206; ARM64 NG/ZR/CY/OV; ARM32 flags at offsets 96-99).

- Condition recovery: compound Jcc → comparisons
- ARM32 condition recovery: flag offsets 96/97/98/99 → CMP operand trace
- Phi → Ternary at 2-way merges (`rewrite_conditional_phi_to_ternary`, after fold + sig prop). 3+ way compound merges skipped
- Collapses `Phi(x,x)` / `Ternary(c,x,x)` via VarId/varnode equivalence
- x86 DF ABI-default seed: DF=0 on entry (SysV/Win64/Cdecl32/GoAmd64). REP STOSB/MOVSB expansion reads DF — without seed, `(uint8_t)DF` leaks
- Call arg collection runs BEFORE fold (prevents DCE of arg regs). x86-64 SysV, Win64 (auto-detect from PE), x86-32 cdecl/thiscall
- Division-by-const → `x / 7`, modulo via `x - (x/D)*D` → `x % D`
- CDQ+IDIV: `Or(Lsl(Zext(sign),32),Zext(val))/Sext(div)` → `val / div`
- Unnecessary cast removal when both operands share type
- Redundant assignment folding: `x0=X; x0=Y+x0` → `x0=Y+X`
- ADD-zero suppression
- Format string leak fix (param alias preservation)
- Extra variadic arg trimming (count format specifiers)
- Call return over-inlining prevention
- Loop body preservation (back-edge writes protected from DCE)
- Type inference 3-phase (seed → forward → backward)
- Signature-based type propagation (38K+ sigs, `display_type` typedefs)
- Interprocedural types (two-pass)
- Backward Load propagation
- MBA deobfuscation 3-phase: pattern-based, SiMBA Möbius inversion over {1,a,b,a&b,...} from 2^N evaluations (1-4 vars), equality saturation via egg crate (40+ rules, 50ms/10K nodes). 1-var probe set includes u64::MAX, 0xAAAA..., 0x0123456789ABCDEF — small-probe-only sets mis-fold masked exprs like `(x & 0xFF00FF00FF00FF00) >> 8` to Const(0)
- Return type recovery: multi-hop EAX/RAX search (3 hops), call-site inference, two-pass
- x86-32 stack param: `Load(EBP+8)` = param value (not deref)
- Taint analysis, string decryption, crypto detection (20+ patterns)

## Printer (printer.rs)

- Ghidra-style: typed signatures, local var decls, auto-named registers
- RegTracker for per-block copy elision
- Call return inlining
- Stack alias chain: var_c → var_8 → param_0; save/restore elision
- Import resolution: ELF PLT/GOT (CET bnd jmp), Mach-O indirect, PE IAT
- Manual PE import fallback (malformed dirs, Stuxnet)
- ELF32 PIE: GOT-relative strings, `__x86.get_pc_thunk` hiding
- String literals: RO section detection, wide (UTF-16LE `L"..."`), C++ demangle, Swift demangle
- DWARF param names (gimli, DWARF4/5, macOS dSYM auto-discovery)
- PDB parsing for PE
- Signature DB (38K+): `/* param_name */` annotations, Win32 typedefs (HANDLE/HKEY/HWND/DWORD/REGSAM/LSTATUS/LRESULT/WPARAM/LPARAM), interprocedural propagation, cross-function struct propagation
- Ghidra-style local decls with array sizing from offset gaps
- MSVC CRT wrapper recognition (`__acrt_iob_func`+`__stdio_common_vfprintf` → `printf`)
- ObjC bracket syntax (`objc_msgSend$setText:` → `[self setText:arg]`)
- MSVC C++ demangling for `cout <<`, `cin >>`, etc.
- C++ wrapper inlining (chained `<<` supported)
- Global data naming (`*(0x4326f4)` → `DAT_004326f4`)
- ARM64 prologue/epilogue elision (callee-saved, FP/LR, sp[], ObjC/Swift ARC, overflow checks, flag leaks)
- ARM32 cleanup (flag writes, r0-r15 rename, carry artifacts)
- Arch-aware reg auto-naming (x86-32 ESI/EDI→iVar, ARM64 x19-x28→lVar, x86-64 XMM→dVar, param regs→lVar)
- Heuristic struct field naming (`head->field_8` → `head->next`)
- Named expression substitution (`arr[low+high/2]` → `arr[mid]`)
- Loop counter naming (iVar1 → i/j/k)
- For-loop init recovery
- Pointer deref simplification
- x86-64 RBP/RSP → local_XX
- Control flow: for, do-while (back-edge post-test), switch/case, else-if
- MSVC RTTI chain: vtable → COL → TypeDescriptor → CHD → BaseClassArray
- GCC RTTI: `_ZTV`/`_ZTI` parsing, template demangling, multi-level inheritance
- Malware: Win32 constant annotation, suspicious API flag (24 APIs), stack cookie detect, dynamic resolve

## Annotators (printer-time, x86-64 PE)

- **Syscall annotation:** statement-level UserOp render path in `printer.rs` — when `func_id == 5` (x86 `syscall` pcodeop) and arch is X86_64, calls `resolve_syscall_number_from_block(stmts, cur_idx, ssa)` which walks back ≤8 stmts in the same block looking for the most recent Register(offset=0) Const write. If found, looks up `crate::syscall_table::resolve_x64_syscall(num)` and emits trailing `// syscall 0xNN -> likely NtXxx (Win11 24H2)` or `// syscall 0xNN (unresolved)`. Non-Const RAX write before syscall stops look-back (indirect gadget).
- **ROR13 hash annotation:** `format_const(val, size)` wraps inner formatting; when `size ∈ {4, 8}` AND `val <= u32::MAX` AND `peb_walk::looks_like_hash` AND `peb_walk::resolve_ror13_hash` matches → appends `/* ROR13("ApiName") */` inline. Annotation fires on any rendered constant — works in `mov eax, HASH`, `cmp eax, HASH`, conditionals, etc.

## Peephole (pcode-ir/src/lib.rs)

Identity Subpiece elim, copy chain forwarding, DCE (batch collect + reverse remove), overwrite elim, output sinking, redundant IntAnd collapse.
