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

### Compiled C functions (with DWARF debug info, vs Ghidra 12)

```
// add() — matches Ghidra
return a + b;

// factorial() — cleaner than Ghidra (no temp variable)
if (n > 1) {
    return n * factorial(n - 1);
} else {
    return 1;
}

// sum_array() — near-Ghidra quality
while (len > i) {
    total = arr[i] + total;
    i = i + 1;
}
return total;

// string_length() — pointer dereference in condition
while (*(s) != 0) {
    len = len + 1;
    s = s + 1;
}
return len;

// main() — correct imports, string literals, return
printf("add(3,4) = %d\n", add(3, 4));
printf("factorial(6) = %d\n", factorial(6));
printf("sum = %d\n", sum_array(nums, 5));
printf("strlen = %d\n", string_length("hello world"));
printf("manhattan = %d\n", manhattan_distance(a, b));
printf("day = %s\n", day_name(3));
printf("search(23) = %d\n", binary_search(sorted, 10, 23));
return 0;
```

### Real CTF binaries (stripped ELF, no source)

Tested against 16+ binaries from CSAW Red 2020, Nightmare, UTCTF, and picoCTF:

```
// CSAW warmup — buffer overflow + win function (immediately visible)
write(1, "-Warm Up-\n", 10);
write(1, "WOW:", 4);
sprintf(buf, "%p\n", easy);      // leaks easy() address
write(1, buf, 9);
gets(buf);                        // overflow here
// easy():
system("cat flag.txt");

// CSAW worstcodeever play() — heap menu (full string + function resolution)
while (var_c <= 49) {
    puts("What would you like to do?");
    puts("	1. Add a friend");
    puts("	2. Remove a friend");
    puts("	3. Display a friend");
    puts("	4. Edit a friend");
    printf("> ");
    __isoc99_scanf("%d", buf);
    if (var_10 != 1) {
        if (var_10 != 2) {
            if (var_10 != 3) {
                if (var_10 == 4) { edit_friend(); }
            } else { display(); }
        } else { remove_friend(); }
    } else { add_friend(); }
}

// CSAW concrete_trap — multi-stage CTF (PIE binary, all strings resolved)
init();
puts("Welcome to my intricate trap, where all who are not me shall fail.");
stage1();
if (0 == 0) {
    fail();
    puts("I am slightly convinced you are me. Proceed.");
    stage2();
    ...
    puts("Amazing");
    give_flag();
}

// Integer exploitation puzzle
if (0x1064deadbeef4601 * *(param_0[8]) == 0xd1038d2e07b42569) {
    system("/bin/sh");
}

// Bad seed CTF — predictable PRNG
time(0);
srand(0);                         // seed is always 0!
rand();
puts("Welcome to the number guessing game!");
if (var_10 != var_c) {
    puts("Sorry. Try again, wrong guess!");
} else {
    puts("You won. Guess was right! Here's your flag:");
    giveFlag();
}
```

### -O2 optimized code

```
// CMOV conditional select (branchless max/abs)
if (EDI > ESI) { return EDI; }
return ESI;

if (EDI > 0) { return EDI; }
return -EDI;

// GCD with recovered loop condition (from TEST + JNE flags)
while (EAX % EDX != 0) {
    EDX = EAX;
    EAX = EAX / ECX;
}

// Constant folding in main (compiler inlined everything)
printf("add(3,4) = %d\n", 7);
printf("factorial(6) = %d\n", 720);
```

The decompiler pipeline: P-code -> CFG -> SSA -> expression folding -> structure recovery -> C printer.

What it does:
- Prologue/epilogue elimination (push/pop/leave/ret hidden)
- Stack variable naming (`var_8` instead of `*(RBP - 0x8)`)
- Parameter detection from ABI registers, with DWARF name recovery (`param_0` -> `a`)
- DWARF local variable recovery (`var_10` -> `i`, `var_c` -> `len`)
- DWARF struct field names (`ptr->field4` -> `ptr->y`, `head->field8` -> `head->next`)
- Deep SSA condition operand resolution (`EAX != 0` -> `*(s) != 0` through Load chains)
- Condition recovery from eliminated flags (traces SSA tree when DCE removes flag writes)
- Condition recovery (x86 flag patterns including SBORROW, JLE, JBE -> readable comparisons)
- IntNeg condition tracing (`NEG x; CMOVS` -> `if (x > 0)` instead of `if (SF)`)
- TEST same-register recovery (`TEST EDX,EDX; JNE` -> `EDX != 0` not `EDX != EDX`)
- Recursive BoolNot unwrapping (`!(a < b)` -> `a >= b`, CMOV conditions)
- Condition canonicalization (`1 < n` -> `n > 1`)
- While loop negation (exit conditions properly inverted)
- Self-loop body recovery (-O2 tight loops: block branches to itself)
- CMOV/CSEL expansion with else-branch inference (branchless max/min/abs)
- Loop body variable resolution (registers traced to underlying stack vars through SSA)
- If/else and while loop recovery from CFG back-edges and dominators
- Call return value inlining (`printf("...", add(3, 4))`)
- Function argument display (`factorial(5)` not `factorial()`)
- Return value inference (prefers local accumulators over parameters)
- Import name resolution: Mach-O indirect symbol table, ELF PLT/GOT stubs
- ELF global variable resolution (`friend_list`, `f_index`, `stdout` from .symtab)
- C++ symbol demangling (`_ZStlsISt11char_traitsIcEE...` -> `cout_write`)
- `@@GLIBC` version suffix stripping from ELF symbols
- PIE binary string resolution (low addresses resolved via .rodata sections)
- Division-by-constant recognition (`x * 0x92492493` -> `x / 7`)
- `__chk` suffix stripping (`__strcpy_chk` -> `strcpy`)
- String literal detection with UTF-8 support (`0x100000624` -> `"hello world"`)
- Empty string literal support (`puts("")` not `puts(0x401440)`)
- Array access syntax with scaling (`*(uint8_t*)(base + idx * 4)` -> `base[idx]`)
- Array index canonicalization (`RDX[friend_type]` -> `friend_type[RDX]`)
- Dead code elimination (unused flag writes, IDIV remainder, register shuffling)
- Stack canary detection and removal (Mach-O `___stack_chk_guard`, ELF `FS_OFFSET`)
- setvbuf init boilerplate collapse (stdout/stdin/stderr -> single comment)
- `__TMC_END__` -> `stdout` normalization
- `*(stdout)` / `*(stdin)` simplification in call arguments
- Nested void call unwinding (`fgets(puts("msg"), 64, stdin)` -> separate statements)
- Phi node removal from output (SSA artifacts stripped)
- Save/restore elision (register spills across calls hidden)
- Register copy tracking and inlining at print time
- Sequential register assignment chaining (`ECX = len - 1; ECX = ECX - i` -> `ECX = (len - 1) - i`)
- Cross-block expression folding (`EAX = -EDI; if (...) {...} return EAX` -> `return -EDI`)
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
- **CTF binary validation** — 16+ real CTF binaries from CSAW Red, Nightmare, UTCTF decompiled successfully (buffer overflows, heap menus, integer exploitation, bad seeds, C++ reversing)
- **Corpus validation** — 278 real instructions across all architectures, decode without panic
- **Fuzz tests** — 5000 random byte sequences (empty, truncated, garbage), zero panics
- **Decompiler validation** — compiles C source with `-g`, decompiles with rsleigh, asserts string literals, import names, DWARF parameter names, conditions, function calls, return values

## Spectra integration

rsleigh is wired into Spectra as the native analysis backend. In Settings > Analysis, select "Native (rsleigh)" to use it instead of Ghidra. Functions are discovered from symbol tables + recursive descent, disassembly and P-code views are live, and clicking a function shows decompiled pseudocode with syntax highlighting.

## License

Apache 2.0. The bundled `.slaspec` files are from Ghidra (also Apache 2.0).
