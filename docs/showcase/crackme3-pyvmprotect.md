# Showcase: crackme3 PyVMProtect — full static lift

**Result:** `CTF{pyvm_r0cks}` — recovered end-to-end via static analysis with rsleigh, no runtime debugger, no JVM Ghidra.

A reddit-shared "PyVMProtect" PE64 Python C-extension (`crackmev3.pyd`) packing a 53-opcode custom VM, direct syscalls, JIT string decryption, and anti-debug. Solved by lifting the entire decryption + dispatch chain to readable pseudocode and reimplementing each layer in Python.

## Sample

- PE64 DLL, x86-64, base `0x180000000`, links python311
- 7 custom-named sections; 3 PRNG seed blobs (`.aelgv` / `.hqykf` / `.mjgey`, 8 bytes each)
- Real entry: `_ttokwy5gsm @ 0x180014cf0`, registered via `PyMethodDef @ 0x180051a80`
- VM interpreter at `0x180013c30` (961 instructions); dispatch table at `[0x180053128]` = 34 Python C API slots

rsleigh's `PyMethodDef` scanner ran for PE64 unconditionally and surfaced the real entry despite obfuscated section names — same scanner described in `CLAUDE.md`.

## Pipeline reversed (all layers)

1. **String decryptor** — PCG-style algorithm at `0x1800075c0`. Reversed 209 strings using keys `seed_13c=0xf057ba48`, `seed_7ec=0xd520bcc1` derived by an init chain. Tables: length `@0x18004a6a0`, offset `@0x180049960`, ciphertext `@0x180049b10`. All 209 strings turned out to be anti-debug + API names — no flag.
2. **Init chain** — 117 polymorphic handler functions (`0x180001320..0x180007190`) chain-called from `PyInit`, each passing `EAX → ECX`. Pure computation over `.424um` VM register slots. rsleigh pseudocode made these readable enough to emulate end-to-end with Unicorn.
3. **Bytecode decryptor** — `0x180` bytes at `0x18004a970` → two PCG-keystream XOR passes (mults `0x45d9f3b` / `0x27d4eb2d`, adds `0x27d4eb2d` / `0x165667b1`) → `zlib.decompress(_, wbits=15)` → 534-byte VM bytecode blob.
4. **Sbox + handler table** — emulated `0x180013670` to snapshot `sbox_B` (256 bytes), `handler_tbl` (256 × qword pointers, 58 unique handlers), Fisher-Yates `perm`. Decode formula: `raw_opcode → handler = handler_tbl[sbox_B[raw_opcode]]`.
5. **Opcode classification** — all 58 handlers classified into Python-style ops: `LOAD_GLOBAL`, `COMPARE_OP`, `POP_JUMP_IF_FALSE`, `LOAD_ATTR`, `CALL_FN`, `BUILD_TUPLE`, `FORMAT_VALUE`, `BINARY_SUBSCR`, `FOR_ITER`, etc.
6. **Aux blob decrypt + per-entry VARINT decode** — flag is 15 chars stored as individual VARINT (LEB128) integer constants at entries 1–15 of a 29-entry aux blob `[0x180053838]`. Each entry's first byte is type tag `0xb1` (VARINT), decrypted via offset-seeded PCG.

## Decoy + hash internals

- `_guard_verify @ 0x18000b890` — LCG-XOR troll. Decodes 37 bytes at `0x18004a5b0` with `key = (key*7+0xd) & 0xff, seed=0xfa` to: `"gg you just reversed a troll function"`.
- FNV-1a variant at `0x18000b7f0` (`offset=0x53474d43`, `ROR25 + *0x1000193`) — used by `_guard_verify` for internal block hashing, not the flag check.

## What rsleigh did well

- `--annotate-crypto` rewrote PCG / Knuth / SHA-256 constants to symbolic names directly in pseudocode, making the two PCG keystream stages immediately recognizable.
- `--vm-classify-handlers` + `--summarise-handlers` did the per-opcode triage (size class, IAT-API used, stack-pop signature) on the 58-handler table.
- `--vm-bytecode <bc_va>:<size> --vm-handlers handlers.json` replayed the bytecode against the classified handler set after the sbox snapshot.
- PE64 SEH/TLS static patch discovery surfaced the SMC patches up front so the disassembly matched runtime memory without a debugger.
- ROR13 / DJB2 / DJB2a hash-resolver classifier (`peb_walk.rs`) immediately identified the API-hash imports, including the pyVMProtect-style PEB walk.

## Where pure static lift stalled (and how it was finished)

`_ttokwy5gsm` runs the actual Python bytecode through the 34-slot dispatch table. Bytecode metadata at `0x18004a5e0` (23 entries of `(u32 bc_offset, u32 hash)`) indexes a 533-byte serialized blob that resembles CPython `co_code` / `co_lnotab` / `co_consts`. Pure Unicorn replay crashed deep in CRT/Python (`~0x18002327b`) because mocked Python C API was incomplete. Resolution: snapshot at `0x180013be6` (right after `sbox_B` fill, before epilogue clobbers the stack), then reimplement the per-entry decoder in Python. Captured artifacts:

- `sbox_B`: 256 bytes, 255/256 nonzero
- `handler_tbl`: 256 × qword pointers, 58 unique handlers (matches the claimed 53-opcode VM, plus shared dispatch tails)
- `perm`: 256-byte Fisher-Yates permutation
- `xor_key = 0` in this snapshot (handlers stay readable; `0x1800074e9` chain populates the real key in production runs)

## Reproduction artifacts

Reusable for similar PyVMProtect samples (v3-class):

- `emu_vm.py` — Unicorn harness for VM setup emulation
- `decrypt_bc2.py` — bytecode PCG + zlib unpack
- `decrypt_aux.py` — aux blob PCG + zlib unpack
- `decode_entries.py` — per-entry decoder with VARINT + tag dispatch

## Takeaway

A 53-opcode custom VM + multi-layer PCG + zlib + per-entry VARINT pipeline came out as readable pseudocode + classifier metadata in one tool — without a Ghidra JVM, IDA license, or live debugger. rsleigh's strongest path is exactly this: dump everything to text, annotate the crypto, classify the handlers, then finish in Python.

> **Same author shipped a v5 ("The Wall") using DJB2a instead of ROR13.** rsleigh's `peb_walk.rs` now ships `djb2a()` and resolves 25/36 init-time hashes — work in progress.
