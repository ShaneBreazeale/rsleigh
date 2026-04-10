# rsleigh

Compiles Ghidra's SLEIGH architecture specs (`.slaspec`) into native Rust decoders that turn raw bytes into P-code IR, then decompiles that P-code into C-like pseudocode. No JVM, no C++, just `cargo build`.

This is the disassembly and decompilation backend for [Spectra](https://github.com/ShaneBreazeale/spectra) — it replaces the Ghidra JVM daemon entirely.

## Quick start

```bash
make test   # generate all archs + build + run tests
```

Or step by step:

```bash
cargo run -p rsleigh-generate          # parse slaspecs, emit generated Rust (~30s)
cargo test -p test-harness             # compile generated crates + run tests
```

## Decode + decompile

```rust
use rsleigh_api::{Decoder, Architecture};

let mut dec = Decoder::new(Architecture::X86_64);
let inst = dec.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();
println!("{} ({} bytes)", inst.disassembly, inst.len);
// MOV RAX,RBX (3 bytes)

// Decompile with string literals, imports, and DWARF debug info
let binary = std::fs::read("my_binary").unwrap();
let instructions: Vec<(u64, _)> = /* decode a function's bytes */;
let pseudocode = rsleigh_decompile::decompile_with_binary(
    Architecture::X86_64, &instructions, Some(&binary),
    Some(Path::new("my_binary")));  // enables dSYM lookup on macOS
```

## Decompiler output

Given real compiled C functions (see `test-harness/fixtures/compare_test.c`):

```c
int add(int a, int b) { return a + b; }
int factorial(int n) { if (n <= 1) return 1; return n * factorial(n - 1); }
int sum_array(int* arr, int len) {
    int total = 0;
    for (int i = 0; i < len; i++) total += arr[i];
    return total;
}
int string_length(const char* s) {
    int len = 0; while (*s) { len++; s++; } return len;
}
int manhattan_distance(Point* a, Point* b) {
    int dx = a->x - b->x, dy = a->y - b->y;
    if (dx < 0) dx = -dx; if (dy < 0) dy = -dy;
    return dx + dy;
}
int binary_search(int* arr, int len, int target) { /* ... */ }
int main() {
    printf("add(3,4) = %d\n", add(3, 4));
    printf("factorial(6) = %d\n", factorial(6));
    /* ... 8 more printf calls with function results ... */
    return 0;
}
```

rsleigh produces (with DWARF debug info), compared against Ghidra 12:

```
// add() — matches Ghidra
return a + b;

// factorial() — cleaner than Ghidra (no temp variable)
if (n > 1) {
    return n * factorial(n - 1);
} else {
    return 1;
}

// sum_array() — loop body with correct variable resolution
total = 0;
i = 0;
while (len > i) {
    total = arr[i] + total;
    i = i + 1;
}

// string_length() — correct loop variables
len = 0;
while (EAX != 0) {
    len = len + 1;
    s = s + 1;
}

// manhattan_distance() — struct field access
EAX = (a->field4) - b->field4;
dx = 0 - dx;
dy = 0 - dy;
return dx + dy;

// list_sum() — linked list traversal
sum = 0;
while (head != 0) {
    sum = *(head) + sum;
    head = head->field8;
}

// binary_search() — complex control flow
lo = 0;
hi = len - 1;
while (hi >= lo) {
    mid = lo + EAX;
    if (EAX != target) {
        EAX = arr[mid];
        if (target <= EAX) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    } else {
        return mid;
    }
}

// main() — correct import resolution + string literals
printf("add(3,4) = %d\n", add(3, 4));
printf("factorial(6) = %d\n", factorial(6));
printf("sum = %d\n", sum_array(nums, 5));
printf("strlen = %d\n", string_length("hello world"));
printf("manhattan = %d\n", manhattan_distance(a, b));
printf("day = %s\n", day_name(3));
printf("search(23) = %d\n", binary_search(sorted, 0xa, 0x17));
return 0;
```

The decompiler pipeline: P-code -> CFG -> SSA -> expression folding -> structure recovery -> C printer.

What it does:
- Prologue/epilogue elimination (push/pop/leave/ret hidden)
- Stack variable naming (`var_8` instead of `*(RBP - 0x8)`)
- Parameter detection from ABI registers, with DWARF name recovery (`param_0` -> `a`)
- DWARF local variable recovery (`var_10` -> `i`, `var_c` -> `len`)
- Struct field access detection (`ptr[4]` -> `ptr->field4`)
- Condition recovery (x86 flag patterns -> comparisons, ARM64 NG/ZR/OV -> comparisons)
- Condition canonicalization (`1 < n` -> `n > 1`)
- While loop negation (exit conditions properly inverted)
- Loop body variable resolution (registers traced to underlying stack vars through SSA)
- If/else and while loop recovery from CFG back-edges and dominators
- Call return value inlining (`printf("...", add(3, 4))`)
- Function argument display (`factorial(5)` not `factorial()`)
- Return value inference for non-void functions
- Import name resolution via Mach-O indirect symbol table (`printf`, `strlen`)
- `__chk` suffix stripping (`__strcpy_chk` -> `strcpy`)
- String literal detection (`0x100000624` -> `"hello world"`)
- Array access syntax with scaling (`*(uint8_t*)(base + idx * 4)` -> `base[idx]`)
- Dead code elimination (unused flag writes, register shuffling)
- Stack canary preamble/epilogue detection and removal
- Save/restore elision (register spills across calls hidden)
- Register copy tracking and inlining at print time
- Sequential register assignment chaining (`ECX = len - 1; ECX = ECX - i` -> `ECX = (len - 1) - i`)
- Swap pattern detection (`str[i] = str[j]; str[j] = AL` -> `str[j] = str[i]`)
- IDIV dividend noise removal (`EDX << 0x20 | X` -> `X`)
- Constant propagation for loop-invariant register values

## Architectures

| Arch | Constructors | Notes |
|------|-------------|-------|
| x86-64 | 5700+ | Full instruction set, 8 parallel compile batches |
| AArch64 | 3500+ | NEON + SVE, 4 batches |
| ARM32 | 1200+ | ARMv7 + Thumb |
| MIPS32 | 900+ | Big-endian, FPU + DSP + MIPS16 + microMIPS |
| RISC-V 64 | 500+ | RV64GC + F/D/B/K/P/Q/V/C extensions |

## Crates

```
rsleigh/
  src/                    # SLEIGH parser + Rust codegen library
  pcode-ir/               # PcodeOp, Varnode types + peephole optimizer (no_std, zero deps)
  rsleigh-api/            # Decoder API — decode bytes into instructions + P-code
  rsleigh-decompile/      # Decompiler — P-code to C-like pseudocode (5-pass pipeline)
  rsleigh-generate/       # CLI: parse .slaspec files, write generated crate source
  generated/              # Output crates (gitignored /out/ dirs, regenerated from slaspecs)
  test-harness/           # Golden tests, corpus validation, fuzz tests, decompiler validation
  slaspec/                # Ghidra .slaspec files (Apache 2.0)
```

## Tests

9 test categories, ~6000 total assertions:

- **Golden P-code tests** — 145 exact assertions across all 5 architectures (x86: 43, ARM64: 24, ARM32: 21, RISC-V: 21, MIPS: 21). Verify decode length, disassembly text, and P-code op semantics.
- **Stress tests** — boundary value probes: sign-extension at every bit width (8/12/16/20/32), `i8::MIN` overflow, backward branch targets, REX prefix edge cases, SIB addressing, 64-bit immediates.
- **Functional tests** — 14 multi-instruction sequence tests: function prologues/epilogues, stack locals with sign-extended displacements, call conventions, compare-and-branch, loops, array access, RIP-relative data, sign-extend chains, ADRP+ADD pairs, conditional select.
- **Bug probes** — ~55 semantic correctness checks: all 16 x86 Jcc branch targets, IDIV quotient+remainder, MUL widening to RDX:RAX, MOVZX/MOVSX load sizes, LEA vs MOV distinction, ARM64 LDR size variants (1/2/4/8 byte), ADDS flag setting.
- **Compiled code patterns** — stack canary (FS:[0x28]), stack alignment (AND RSP,-16), indirect calls/jumps, switch tables, SETcc, REP MOVSB, LOCK XADD, SSE2 ADDSD/MOVSD, SYSCALL, PLT/GOT sequences, TBZ/TBNZ, CSET/CSINC, post-index loads, memory barriers, thread pointer reads.
- **Ghidra differential fixtures** — ~300 instructions compared against Ghidra's P-code output
- **Ghidra decompiler comparison** — 11 functions (add, factorial, sum_array, string_length, manhattan_distance, day_name, list_sum, binary_search, apply, main) decompiled side-by-side with Ghidra 12 (`cargo run -p test-harness --example compare`)
- **Corpus validation** — 278 real instructions across all architectures, decode without panic
- **Fuzz tests** — 5000 random byte sequences (empty, truncated, garbage), zero panics
- **Decompiler validation** — compiles C source with `-g`, decompiles with rsleigh, asserts string literals, import names, DWARF parameter names, conditions, function calls, return values

## Spectra integration

rsleigh is wired into Spectra as the native analysis backend. In Settings > Analysis, select "Native (rsleigh)" to use it instead of Ghidra. Functions are discovered from symbol tables + recursive descent, disassembly and P-code views are live, and clicking a function shows decompiled pseudocode with syntax highlighting.

## License

Apache 2.0. The bundled `.slaspec` files are from Ghidra (also Apache 2.0).
