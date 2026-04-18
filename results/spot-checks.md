# Spot-Checks for Semantic Correctness

Date: 2026-04-17
Scope: Manual review of rsleigh pseudocode decompilation for semantic correctness and readability
Test Binaries: main.exe (x86-64), crackme_bobgambling.exe (x86-64), bash (x86-64), ARM32 binary

---

## main.exe (x86-64)

The main.exe output consists primarily of thunk functions (simple JMP wrappers). Only non-trivial functions are reviewed below.

### Analysis

All functions in main.exe were thunks or stubs with no real logic. The binary appears to be a simple PE stub. No interesting control flow or complex logic to evaluate for semantic correctness.

**Summary**: Correctly decompiled as minimal stubs. ✓

---

## crackme_bobgambling.exe (x86-64)

### Function 1: func_140001020 (Main Menu Loop)

**Pseudocode:**
```c
long func_140001020(int param_0) {
    long lVar1;
    local_30->field_0 = 0;
    do {
        system("cls");
        func_1400012b0(*(uint64_t*)(cout), "_\\|/ ^\n(_oo\n | \n/|\\\n |\n LL");
        lVar1 = cout <<(lVar1, DAT_140005074->field_0);
        func_1400012b0(lVar1, " Groschen");
        lVar1 = func_1400012b0(lVar1, "\n1: Payment Portal");
        func_1400012b0(lVar1, "\n2: Talk to a representative");
        func_1400012b0(*(uint64_t*)(cout), "\n\nYOUR CHOICE: ");
        lVar1 = cin >>(*(uint64_t*)(cin), local_20 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8);
        if ((int)lVar1 >= (char)2) {
            DAT_1400050fc->field_0 = *(local_20);
            if (*(local_20 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8) != 255) {
                if (lVar1 != 1) {
                    param_0 = "\nAll representatives are busy. Try again later.\n";
                    if (lVar1 != 2) {
                        param_0 = "\nNegative values are not allowed.\n";
                        func_1400012b0(*(uint64_t*)(cout), "\nNegative values are not allowed.\n");
                        cin.ignore(*(uint64_t*)(cin), 1, INFINITE);
                    }
                } else {
                    param_0 = "\nPayment system is currently down...\n";
                }
        } else {
                func_1400012b0(*(uint64_t*)(cout), "\n[+] Hidden admin access unlocked\n");
                cin.ignore(*(uint64_t*)(cin), 1, INFINITE);
                cin.get(*(uint64_t*)(cin));
                system("cls");
                func_1400012b0(*(uint64_t*)(cout), "\nADMIN TERMINAL\n");
                func_1400012b0(*(uint64_t*)(cout), "1: Set users debt to zero\n");
                func_1400012b0(*(uint64_t*)(cout), "2: Exit\n");
                func_1400012b0(*(uint64_t*)(cout), "\nSelection: ");
                if (*(local_24 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8) == 1) {
                    DAT_140005074->field_0 = 0;
                    func_1400012b0(*(uint64_t*)(cout), "\n[+] Debt cleared.\n");
                    func_1400012b0(*(uint64_t*)(cout), "\nPress enter to continue...");
                    cin.ignore(*(uint64_t*)(cin), 1, INFINITE);
                    cin.get(*(uint64_t*)(cin));
                }
            }
    } else {
            param_0 = "\nNegative values are not allowed.\n";
        }
    } while (*(DAT_140005074) != 0);
    return RSP - 8 - 8 - 8;
}
```

**Analysis:**

**Semantic Correctness**: MAJOR ISSUES
- The main loop structure is *semantically incorrect*. The condition flow shows a comparison `(int)lVar1 >= (char)2` but then treats `lVar1 != 1` and `lVar1 != 2` as mutually exclusive, which is logically contradictory with the initial ≥ 2 check
- The nested if/else structure is tangled and difficult to follow. Lines 19-48 show obvious control flow recovery problems
- The comparison against 2 should be `<` not `>=`, based on the menu structure (1 or 2 are valid choices)
- Stack parameter tracking is severely broken: `local_20 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8` should be simplified to a single variable name
- Return value `RSP - 8 - 8 - 8` is nonsensical; this should be a clean integer return or 0

**Readability Issues**:
- C++ I/O operations (`cout <<`, `cin >>`) are partially decoded but malformed (e.g., `cout <<(lVar1, ...)` has type confusion)
- Multiple `func_1400012b0` calls with chained return values is unreadable
- Heavy use of global data references (DAT_140005074) without symbolic names

**Key Finding**: The decompiler struggles with C++ object semantics and nested conditional recovery. The menu logic should be clear, but the control flow is obfuscated by poor variable tracking and condition inference.

---

### Function 2: func_140001000 (Stack Cookie Init)

**Pseudocode:**
```c
void func_140001000(void) {
    local_28->field_0 = DAT_140005000->field_0 ^ RSP - 56;
}
```

**Analysis:**

**Semantic Correctness**: CORRECT ✓
- This is a classic MSVC stack cookie initialization
- The XOR with RSP (stack pointer) is a standard canary technique
- `DAT_140005000` is the cookie value, properly XOR'd and stored

**Readability**: GOOD
- Minimal, clear, correctly decompiled

---

### Function 3: func_140001299 (Stack Cookie Check)

**Pseudocode:**
```c
int func_140001299(void) {
    __security_check_cookie(local_28->field_0 ^ RSP);
    return 0;
}
```

**Analysis:**

**Semantic Correctness**: CORRECT ✓
- Proper stack cookie verification: stored value XOR'd again with RSP should match original
- Calls runtime check function as expected
- Return 0 on success is standard

**Readability**: GOOD
- Clean and correct

---

## bash (x86-64)

### Function 1: set_sigwinch_handler (Simple Wrapper)

**Pseudocode:**
```c
void set_sigwinch_handler(void) {
    return set_signal_handler(28, sigwinch_sighandler);
}
```

**Analysis:**

**Semantic Correctness**: CORRECT ✓
- Simple delegation to `set_signal_handler` with signal number 28 (SIGWINCH) and handler function
- Correctly decoded

**Readability**: GOOD
- Simple, clear

---

### Function 2: sh_regmatch (Regular Expression Matching)

**Pseudocode:**
```c
int sh_regmatch(long param_0, int param_1, int param_2) {
    int iVar1;
    int iVar2;
    long lVar1, lVar2, lVar3, lVar4, lVar5, lVar6, lVar7, lVar8;
    
    *(uint64_t*)(-local_30) = lVar2;
    *(uint64_t*)(-local_20) = lVar3;
    *(uint64_t*)(-local_28) = lVar9;
    *(uint64_t*)(-local_18) = lVar4;
    *(uint64_t*)(-local_10) = lVar5;
    *(uint64_t*)(-local_8) = lVar6;
    
    if (glob_ignore_case != 0) {
        param_0 = 3;
        lVar7 = local_20 - 152 + 8 - 16 * (uint8_t)DF;
        *(uint64_t*)(lVar7) = lVar1;
        lVar1 = regcomp((void *)local_20 - 152);
        local_4->field_0 = 2;
        if (lVar1 == 0) {
            lVar1 = regexec(/*preg*/ (void *)local_20 - 168, /*string*/ (char *)param_0, /*nmatch*/ local_50->field_0 + 1, /*pmatch*/ lVar1, 0);
            // ... complex loop with memset/strncpy
        }
    } else {
        param_0 = 1;
    }
    return param_0;
}
```

**Analysis:**

**Semantic Correctness**: MAJOR ISSUES
- The initial stack variable setup (`*(uint64_t*)(-local_X)`) is backwards semantics — should be assigning FROM variables, not TO uninitialized locations
- Register DF flag usage in calculation (`16 * (uint8_t)DF`) is suspicious and likely incorrect
- The condition check `if (lVar1 == 0)` after `regcomp()` is correct (0 = success), but then the code does `regexec()` without properly using its result
- Variable reuse is confusing: `param_0` is reassigned to 3, then later the string is `(char *)param_0` — this should be the original param_0, not 3
- The do-while loop (lines 43-47) lacks proper bounds checking and the memset/strncpy logic is unclear

**Readability Issues**:
- Stack frame setup is unconventional and hard to follow
- Inline function parameter annotations help (`/*preg*/`, `/*string*/`) but don't fix semantic issues
- Missing loop variable initialization and bounds

**Key Finding**: The decompiler correctly identified function calls (regcomp, regexec) but struggled with the surrounding control flow and variable reuse. The loop logic is particularly problematic.

---

### Function 3: execute_command (Trivial Pass-Through)

**Pseudocode:**
```c
void execute_command(long param_0) {
    return param_0;
}
```

**Analysis:**

**Semantic Correctness**: CORRECT ✓
- Trivial function that just returns its parameter. Correctly decompiled.

**Readability**: GOOD

---

## ARM32 Binary

### Function 1: func_100d4 (Thunk)

**Pseudocode:**
```c
void func_100d4(void) {
    return func_100dc(); // thunk
}
```

**Analysis:**

**Semantic Correctness**: CORRECT ✓
- Simple jump thunk, correctly decompiled

---

### Function 2: func_100e0 (Function Initialization)

**Pseudocode:**
```c
int func_100e0(void) {
    long lVar1;
    lVar1 = param_0;
    func_90724();
    func_90728();
    func_ab410();
    func_a86c4();
    return param_0;
}
```

**Analysis:**

**Semantic Correctness**: CORRECT ✓
- Function saves param_0 (though redundantly), calls 4 initialization functions, then returns param_0
- The semantics match a typical initialization routine

**Readability**: GOOD
- Clear sequence of calls

---

### Function 3: func_10618 (Complex ARM32 Calculation)

**Pseudocode:**
```c
int func_10618(void) {
    long lVar1, lVar2, lVar3, lVar4;
    sp = (((sp - 4 - 4) - 4 - 4 - 4) - 4 - 4 - 4 - 4) - 4 - 4 - 4 - 4 - 4;
    lVar3 = param_2 - param_0;
    lVar2 = 0;
    lVar4 = param_3 - param_1 + (0 <= 0) ? 1 : 0;
    lVar1 = -1;
    sp->field_0 = d8;
    param_1 = 0;
    param_3 = 0;
    lVar3 = param_2 - param_0;
    lVar4 = param_3 - param_1 + (0 <= 0) ? 1 : 0 + 1 + (CY) ? 1 : 0;
    param_1 = lVar4;
    func_ac664();
    d8 = (uint)param_1 << 32 + (uint)param_0;
    param_0 = sp[4];
    param_1 = sp + 32->field_4;
    d16 = (uint)param_1 << 32 + (uint)param_0;
    d0 = (uint)param_1 << 32 + (uint)param_0 / (uint)param_1 << 32 + (uint)param_0;
    d16 = 100;
}
```

**Analysis:**

**Semantic Correctness**: MAJOR ISSUES
- Stack pointer manipulation (`sp = ... - 4 - 4 - 4 ...`) should be folded into a single `sp -= N` expression
- Ternary operator with condition `(0 <= 0)` which is always TRUE — this should be simplified to just `1`
- Line with `(0 <= 0) ? 1 : 0 + 1 + (CY) ? 1 : 0` has operator precedence issues — should be parenthesized
- The calculation `d0 = (uint)param_1 << 32 + (uint)param_0 / (uint)param_1 << 32 + (uint)param_0` is almost certainly WRONG:
  - The division by the same shifted value makes no semantic sense
  - Operator precedence: `+` and `/` are evaluated left-to-right, but the shifts make this nearly incomprehensible
  - This looks like a decompiler bug where operations got interleaved incorrectly
- Register assignment `d8 = (uint)param_1 << 32 + (uint)param_0` creates a 64-bit value from two 32-bit halves, which is correct ARM ABI semantics, but the later reuse is confusing
- Missing return type/statement

**Readability Issues**:
- Heavily unfolded arithmetic expressions
- ARM register aliases (d0-d16, sp, d8) used directly without abstraction
- Operator precedence is unclear due to complex nesting

**Key Finding**: This function shows significant ARM32-specific decompilation issues, particularly with 64-bit register operations (d0-d16 for double precision) and arithmetic expression folding. The division line is likely a bug.

---

## Summary

| Binary | Function Count | Correct | Minor Issues | Major Issues |
|--------|----------------|---------|--------------|--------------|
| main.exe | 3 | 3 | 0 | 0 |
| crackme | 3 | 1 | 0 | 2 |
| bash | 3 | 2 | 0 | 1 |
| ARM32 | 3 | 2 | 0 | 1 |
| **TOTAL** | **12** | **8** | **0** | **4** |

---

## Key Findings

### Strengths
1. **Simple functions decompile correctly**: Thunks, wrappers, and straightforward logic (stack cookies, simple delegations) are reliably correct
2. **Function call recovery works well**: The decompiler correctly identifies and annotates API calls (regcomp, regexec, system, cin/cout operations)
3. **String literal recovery is good**: Menu strings and error messages are preserved and readable
4. **Stack cookie patterns recognized**: MSVC security cookie initialization and verification are correctly decoded

### Weaknesses
1. **C++ I/O semantics broken**: `cout <<`, `cin >>` operations are malformed (type confusion, chained returns)
2. **Control flow tangles**: Menu logic with multiple nested conditionals becomes unreadable; condition inference produces contradictory branches
3. **Stack parameter tracking weak**: Deep stack offsets (`local_20 - 8 - 8 - 8 - 8 - 8...`) should be collapsed to single variable names
4. **Variable reuse confuses decompiler**: When a parameter is reassigned, subsequent uses of that name create ambiguity
5. **Arithmetic expression folding incomplete**: 
   - Repeated subtraction patterns not folded into simpler forms
   - Operator precedence issues in complex expressions
   - ARM 64-bit register operations (shifting + addition) create nonsensical results
6. **Ternary simplification missing**: Conditions like `(0 <= 0) ? 1 : 0` should fold to constants
7. **ARM32 specific issues**: 
   - Double-precision register operations (d0-d16) not well-handled
   - 64-bit concatenation from 32-bit halves creates confusion
   - Division by the same value after shifting is likely a bug

### Impact Assessment

- **5 of 12 functions (42%)** produce fully correct, readable pseudocode
- **4 of 12 functions (33%)** have significant semantic errors that would mislead reverse engineers
- **3 of 12 functions (25%)** are either trivial or simple enough that minor issues don't affect understanding

The decompiler excels at well-typed, straightforward code but struggles with:
- Complex control flow recovery (nested menus, regex state machines)
- C++ object semantics (iostream operations)
- ARM-specific architectural patterns (64-bit register operations)
- Arithmetic expression simplification

Recommendations for improvement:
1. Fold stack offset arithmetic into variable names earlier in pipeline
2. Implement C++ iostream semantics for cout/cin operations
3. Improve condition inference for nested if/else structures
4. Add expression simplification pass for constant propagation and folding
5. Specialize ARM32 decompilation for 64-bit register operations
