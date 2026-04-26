# Feature catalog

Implementation under `rsleigh-decompile/` + `rsleigh-cli/`. See `docs/decompiler-passes.md` for pipeline internals.

## Analysis

- String decryption (XOR/ADD/SUB loops)
- Crypto detection: AES S-box, DES tables, RC4 KSA, SHA constants, CRC32, custom XOR (20+ patterns)
- **Custom-VM packer recon (PyVMProtect/Themida/Stantinko-style):** auto-recon pipeline running on every PE64 binary —
  - `vm_fingerprint` — family detection via section-name / .fptable shape
  - `jmp_rax_trampoline` — JMP `<reg>` gadget enumeration (1- or 2-byte)
  - `xor_vtable` — XOR-encoded dispatcher site detection (`MOV [vtable]; MOV [key]; XOR; MOV [r+i*8]; CALL [iat]`)
  - `vm_dispatch_extract` — recovers data slots + trampoline IAT slot + opcode mask candidate (`--vm-dispatch <addr>`)
  - `vm_handler_classify` — variable-length opcode handler classification (`--vm-classify-handlers <addrs>`)
  - `tag_dispatch` — `CMP r8, imm; JZ/JNZ` chain extractor for type-tag dispatch (`--tag-dispatch <addrs>`)
  - `handler_summary` — IAT-API + stack-pop signature per handler (`--summarise-handlers <addrs>`)
  - `vm_bytecode_disasm` — disassembles VM bytecode given handler-table JSON (`--vm-bytecode <bc_va>:<size> --vm-handlers <path.json>`)
  - `api_resolver` — ROR13 / DJB2 / DJB2a / FNV-1 hash-resolver classifier
  - `peb_walk_detect` — GS:[0x60] PEB / Ldr / BeingDebugged / NtGlobalFlag probe sites
  - `antidebug_timing` — RDTSC / RDPMC / RDTSCP probe-pair detection
  - `scratch_leak` — alloc + write + return-Py_None heuristic (PyVMProtect const-pool leak vector)
  - `sha256_func_detect` — H0 + K constant density region detection
  - `crypto_constants` — inline-constant catalogue with `/* algorithm role */` annotations
- **`--annotate-crypto`:** rewrite raw hex literals + `DAT_<hex>` labels in decompile output to stable symbolic names (`KNUTH_9E3779B9`, `PCG_045D9F3B`, `SHA_256_6A09E667`). Pointer DATs without crypto match left untouched.
- **x64 syscall annotation:** `syscall_table.rs` — block-local 8-stmt look-back from each `syscall()` UserOp finds the most-recent EAX/RAX const write; matches against Win11 24H2 ntdll table (~120 entries) and emits `// syscall 0xNN -> likely NtXxx (Win11 24H2)`. Resolves Windows direct-syscall gadget (`mov eax, IMM; syscall`) common in shellcode, Donut, Cobalt Strike, SysWhispers.
- **PEB-walk ROR13 hash resolver:** `peb_walk.rs` — ~130 curated APIs across kernel32/ntdll/ws2_32/advapi32/wininet/user32. `LazyLock` reverse-index with both unqualified (`ror13_api`) and Metasploit `block_api` UTF-16 module-prefixed (`ror13_module_api`) forms. `format_const` adds `/* ROR13("Foo") */` annotation when 4/8-byte const matches known hash and `looks_like_hash` entropy filter passes (high+low halves nonzero, ≥0x01000000). Zero false positives on real fixtures.
- **Non-SEH SMC discovery:** `seh_static.rs::tls_callback_addresses` walks `IMAGE_TLS_DIRECTORY64.AddressOfCallBacks` (data dir 9), bounded NULL-terminated VA array (cap 64). `extract_patches_at_candidates` generalises handler-style patch extraction over arbitrary VAs with `(target_va, bytes)` dedup. `extract_all_patches_extended` merges SEH + TLS + caller-supplied; `smc_fixpoint` uses it so TLS-callback-hidden unpack stubs enter fixpoint loop.
- Taint tracking (`--taint`): user inputs (recv/read/fgets) → sinks (exec/system/SQL)
- Vulnerability scanner (`--vulnscan`, 27 patterns): buffer overflow, format string, UAF, int overflow, cmd injection, path traversal. Color-coded HIGH/MED/LOW.
- Call graph (`--callgraph`): JSON + behavioral tags (network_io, crypto, process_injection) + reverse caller map
- YARA generation (`--yara`)
- Diff decompilation (`--diff`)

## Output

- Compact (`--compact`, -24%), brief (`--brief`, -35%), `--min-complexity N`
- `--brief --min-complexity 5` = -40% tokens for LLM workflows
- `--summary` (one-line per func), `--xrefs`, `--search` by string/API/const
- Raw firmware (`--raw <arch>`)

## Triage

Constant-time string + structure scans for first-pass IR / malware
triage. Independent of the decoder pipeline. Full reference, JSON
schemas, and recommended workflow in
[`docs/cli-triage.md`](cli-triage.md).

- `--ioc [--json]` — URLs, IPv4, domains, paths, registry keys,
  mutexes, secret-like strings. `.NET` assembly identities and
  printf-style format strings filtered out.
- `--sigcheck [--json]` — Authenticode signer / issuer / signing
  time / counter-signature / full chain. Hand-rolled DER walk; no
  ASN.1 dependency.
- `--resources [--dump DIR] [--json]` — PE resource directory walk
  with magic-byte type sniffing (PE, MSI, CAB, PNG, JPEG). `--dump`
  extracts every blob to `<DIR>/<TYPE>_<id>_<lang>.bin` for nested
  triage (run `rsleigh` again on each extracted payload).

## C++

- CppClass/VirtualMethod/ClassField structs
- MSVC RTTI: COL → TypeDescriptor → CHD → BaseClassArray (multi-level inheritance)
- GCC RTTI: `_ZTV` + `_ZTI` with template demangling (`std::vector<int, std::allocator<int>>`)
- Field inference from decompiled output (offset gaps, typed API args)
- `--classes` + `--classes --json`
- Cross-function struct propagation (two-pass)

## Swift ARM64

Mangled symbol demangle (classes/methods/properties/init/deinit/metadata). ARC noise elision (swift_retain/release/bridgeObjectRetain/Release). Runtime call elision (swift_beginAccess, swift_allocObject). Overflow check + flag leak cleanup.

## Function ID (rsleigh-fid)

Ghidra-FID-style body fingerprinting in pure Rust. xxh3 full + callee-aware specific hash over operand-masked instruction bytes. Per-arch mask tables (x86 opcode+ModR/M keep; fixed-width class masks for AArch64/ARM32/MIPS/RISC-V).

Bundled 287KB, 13,612 entries: glibc 2.36, libstdc++ 12.2, musl 1.2.5 (x86_64 + aarch64). Auto-loaded by target arch.

- `rsleigh-fid-gen`: builds .fidb from ELF/Mach-O/PE/.a
- `identify()`: C++ ABI ctor/dtor variants accepted (C1/C2/C3, D0/D1/D2 share bodies by spec)
- `scripts/build-fid-dbs.sh`: reproducible distro-pkg fetch + SHA256-pinned MANIFEST
- Qt5 sigs: 23,274 entries in `rsleigh-decompile/data/qt_signatures.tsv.gz`. `scripts/extract-qt-sigs.py` walks libQt5 dynsyms via `c++filt -n`

## AArch64 AAPCS64

x0-x7 (int) + v0-v7 (float/SIMD = s/d/q variants) all map to `param_N`/`fparam_N` with typed signatures.

## Import resolution

R_*_GLOB_DAT walked: R_X86_64_GLOB_DAT=6, R_AARCH64_GLOB_DAT=1025, R_ARM_GLOB_DAT=21. Data symbols (`__stack_chk_guard`, vtable ptrs, QObject::staticMetaObject) resolve to names.

Stack-canary recognition: text-level pattern strips `RET = A ^ B;` XOR + adjacent reload + dead stores. Works without ADRP-resolved `__stack_chk_guard`.

## Pseudocode quality (14-point audit)

CDQ+IDIV simpl, Zext deferral, array base validation, call return tracking, format string preservation, variadic arg trim, return-fold protection, AArch64 stack/prologue elision, 6-arch return type inference, heuristic struct field naming, cast removal, assignment folding, ADD-zero suppression, register auto-naming, for-loop init recovery, loop counter naming, named expression substitution.

## Spectra integration

`rsleigh-api` + `rsleigh-decompile`. Settings toggle native vs Ghidra. Functions: symbol + recursive + prologue. Views: disasm/pcode/code with syntax highlighting. 32MB stack threads (x86 pattern recursion depth). Analysis API: `FunctionMeta`, `VulnFinding`, `CallGraphEntry` (serde::Serialize).

## Ghidra comparison

Current score: rsleigh 15 — Ghidra 6 on 21 PE/Mach-O/ELF/ARM32 binaries.

Install paths (bench-compare.sh auto-detects):
- `~/tools/ghidra_11.4.3_PUBLIC/` ← Jython OK
- `~/tools/ghidra_12.0.4_PUBLIC/` ← needs PyGhidra

```bash
export JAVA_HOME=$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
export GHIDRA_HOME=~/tools/ghidra_11.4.3_PUBLIC
```

Headless:
```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj proj \
  -import <binary> -postScript /tmp/CountFunctions.py -deleteProject
```

Bench:
```bash
scripts/bench-compare.sh <binary> [--sample N]
scripts/bench-score.py --binary X --rsleigh Y --ghidra cached.json --sample 50 --out DIR
```

Composite score weights: discovery 25, cflow_similarity 25, leak_parity 20, line_parity 15 (elision-aware), empty_rate 15. `line_parity` full credit when rsleigh has fewer lines AND fewer leaks.
