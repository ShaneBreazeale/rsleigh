# Test Suite

rsleigh has a multi-layer test suite spanning unit tests, integration tests, real-binary validation, fuzz testing, and Spectra backend integration tests.

**Total: 226 tests across 2 projects, ~6,800+ assertions, 0 failures.**

```
rsleigh test-harness ........  8 tests  (~6,000 assertions)
spectra native backend ......  10 tests
spectra lib unit tests ...... 157 tests
spectra integration tests ...  16 tests
spectra triage tests ........  35 tests
                              --------
                              226 tests
```

---

## Running Tests

```bash
# rsleigh — full suite (recommended)
make test                                    # generate + build + all tests

# rsleigh — test-harness only (fast, no codegen)
cargo test -p test-harness

# spectra — native backend integration tests
cd ../spectra/src-tauri && cargo test --test native_backend_tests

# spectra — all tests
cd ../spectra/src-tauri && cargo test

# benchmarks
python3 scripts/benchmark.py                 # function count vs Ghidra baselines
```

---

## Layer 1: Golden P-code Tests (`test-harness`)

**Test:** `x86_64_golden`

Validates that specific x86-64 instruction byte sequences produce the exact expected P-code operations. Each test encodes known instruction bytes, decodes them, and asserts on:

- Instruction length (bytes consumed)
- Disassembly text
- P-code operation types and varnode values
- Register offsets and sizes

Coverage: MOV, ADD, PUSH, POP, RET, Jcc, JMP, CALL, CMP, SUB, XOR, NOP, LEA, MOV mem, MOV imm, MOVSXD, MOVZX, IMUL, TEST, SHL/SHR/SAR, CMOV, SETCC, CDQ, REP MOVSB, XCHG, NOT, NEG, INC/DEC, BSF/BSR, BT, POPCNT, LZCNT, conditional set instructions, SSE/AVX moves, multi-byte prefixes, sign/zero extension edge cases, and more.

~770 assertions covering correct P-code emission for the x86-64 instruction set.

---

## Layer 2: Edge Case / Robustness Tests

**Test:** `truncated_and_garbage_input`

Validates that all 5 architecture decoders (x86-64, AArch64, ARM32, MIPS32, RISC-V) handle pathological input without panicking:

- Empty byte arrays
- Truncated instructions (1-byte fragments)
- Byte sequences of `0xFF` (all ones)
- Random single bytes (0x00 through 0xFF)
- 5,000 random multi-byte fuzz sequences

This test runs random byte sequences through both the decoder and the decompiler, asserting zero panics across all architectures.

---

## Layer 3: Decompiler Validation

**Test:** `decompiler_validation`

Compiles a C source file with known functions (`add`, `factorial`, `reverse_string`, `main`), then decompiles the resulting binary and validates:

- Function signatures are generated
- Return statements are present
- String literals are recovered from read-only sections
- Function calls are resolved (printf, strcpy, strlen)
- Parameter annotations appear at call sites (`/* format */`, `/* ptr */`)
- DWARF debug info is parsed (macOS dSYM auto-discovery)

Uses the host `cc` compiler; skips gracefully on systems without a C toolchain.

---

## Layer 4: Spectra API Contract Tests

**Tests:** `spectra_decoder_api`, `spectra_decompile_api`, `spectra_analysis_api`, `spectra_multi_arch_decode`

These verify the rsleigh API surface that Spectra depends on:

### Decoder API (`spectra_decoder_api`)
- `Decoder::new()` for all 6 architectures (X86_64, X86_32, AArch64, ARM32, MIPS32, RiscV64)
- `decode()` produces correct disassembly and P-code for known instruction bytes
- `CALL` instruction produces `PcodeOp::Call` (Spectra uses this for recursive descent)
- `addr_size()` returns 4 or 8 per architecture
- Empty/invalid input returns `Err` without panic

### Decompile API (`spectra_decompile_api`)
- `decompile()` from raw instruction tuples produces valid C-like output
- `decompile_with_binary()` with compiled Mach-O produces output with function signatures, return statements, and braces
- Empty instruction list doesn't panic

### Analysis API (`spectra_analysis_api`)
- `extract_function_meta()` extracts calls, strings, behavioral tags, complexity from pseudocode
- `scan_vulns()` detects strcpy/gets/system as HIGH/CRIT severity findings
- Safe code produces zero HIGH/CRIT findings
- `FunctionMeta`, `VulnFinding`, `CallGraphEntry` all implement `serde::Serialize` (Spectra uses JSON transport)

### Multi-Architecture (`spectra_multi_arch_decode`)
- Decode + decompile a minimal function on all 6 architectures
- Each produces non-empty output without panic

---

## Layer 5: Spectra Native Backend Integration

**Location:** `spectra/src-tauri/tests/native_backend_tests.rs`

These test the exact code paths Spectra uses when `analysis_backend = rsleigh`:

### Decoder Integration
- **`native_decoder_x86_64_sequence`** — Decode a full x86-64 function (push/mov/add/pop/ret), verify instruction lengths, disassembly, P-code ops, and return detection. Tests the `decode_range` loop pattern Spectra uses.
- **`native_decoder_aarch64_function`** — Decode STP/MOV/ADD/LDP/RET AArch64 sequence, verify 4-byte fixed instruction length.
- **`native_decoder_mips32_big_endian`** — Decode MIPS32 big-endian prologue (addiu sp/sw ra/jr ra/nop).

### Decompilation
- **`native_decompile_x86_64_function`** — Decompile from raw bytes, verify function body structure.
- **`native_decompile_with_real_binary`** — Full Spectra flow: compile C → parse Mach-O → symbol lookup → VA-to-file-offset mapping → decode until RET → `decompile_with_binary()` → verify output contains return statements.

### Analysis Pipeline
- **`native_analysis_metadata_extraction`** — `extract_function_meta()` on pseudocode with strcpy/printf/strlen calls. Verify call list, string extraction, behavioral tags, JSON serialization.
- **`native_analysis_vulnscan`** — `scan_vulns()` on code with recv/sprintf/system/gets. Verify HIGH/CRIT severity count, JSON serialization.

### P-code Frontend Contract
- **`pcode_json_round_trip`** — Decode x86-64 instruction, format each P-code op as JSON with address/seq/mnemonic/inputs fields. Validates the frontend contract for Spectra's P-code view.

### Function Discovery
- **`native_function_discovery_macho`** — Compile C with foo/bar/main call chain → extract Mach-O symbols → recursive descent via P-code `Call` ops → verify CALL targets are discovered. Tests Spectra's `open_binary()` function discovery flow.

### End-to-End Pipeline
- **`native_end_to_end_pipeline`** — Full pipeline: compile C with -g → discover functions from symbols → decode each → decompile with binary+DWARF → extract metadata → vulnscan → serialize to JSON. Tests every stage of Spectra's native analysis backend.

---

## Layer 6: Benchmarks

`scripts/benchmark.py` runs rsleigh on all binaries in the test corpus and compares function discovery counts against Ghidra baselines:

| Category | Binaries |
|----------|----------|
| PE x86-64 | main.exe, 4RMMaster.exe, ChocolateFactory.exe, crackme_shroud.exe, etc. |
| PE x86-32 | TRYCRACKME.EXE, FLRSCRNSVR.SCR, masoncrackmev2.exe |
| ELF x86-64 | elf-Linux-x64-bash (stripped, 1,242 functions) |
| Mach-O | Compiled test binaries |

**Current score: rsleigh 15 — Ghidra 6** on function discovery across 21 compared binaries.

---

## Real-World Binary Validation

Validated against external binary corpora (not in CI, manual testing):

### MIPS32 (darkerego/mips-binaries)
13 binaries tested: busybox (stripped, 5,405 functions), bash, nmap, openssl, tor, curl, wget, tcpdump, lua, htop, netcat, socat, dnsmasq. Mix of statically/dynamically linked, stripped/unstripped, big-endian.

### AArch64 (polaco1782/linux-static-binaries)
13 binaries tested: tor (10,021 functions), openssl, curl, wget, bash, busybox, tcpdump, dnsmasq, socat, htop, netcat, objdump, readelf. All statically linked and stripped.

---

## CI Pipeline

3 parallel GitHub Actions jobs:

1. **test** — Generate slaspecs → build all generated crates → golden P-code tests → decompiler unit tests → CLI release build
2. **clippy** — Lint core crates (rsleigh-api, rsleigh-decompile, pcode-ir)
3. **check** — Fast compile check on pcode-ir (no_std, zero deps)

```
make test-all    # full pipeline
make check       # quick compile check
make release     # optimized CLI build
make benchmark   # function count regression check
```
