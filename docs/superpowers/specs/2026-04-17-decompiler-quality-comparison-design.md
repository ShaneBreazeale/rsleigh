---
name: rsleigh vs Ghidra Decompiler Quality Comparison
description: Focused comparison of feature coverage and correctness across key binaries
type: specification
---

# rsleigh vs Ghidra Decompiler Quality Comparison

## Objective

Measure rsleigh decompiler feature coverage and correctness against Ghidra 11.3.1 as reference, focusing on:
- Feature recovery (string literals, variable naming, function signatures, control flow)
- Semantic correctness of pseudocode output
- Architecture-specific quality (x86-64, x86-32, ARM)

## Test Binaries

Selected for variety in architecture, complexity, and real-world/CTF representativeness:

| Binary | Arch | Format | Size | Type | Notes |
|--------|------|--------|------|------|-------|
| elf-Linux-x64-bash | x86-64 | ELF | 905 KB | Real-world | GNU bash, complex, many functions |
| main.exe | x86-64 | PE | 657 KB | Application | Moderate complexity, PE imports |
| crackme_bobgambling.exe | x86-32 | PE | 13 KB | CTF/Crackme | Small, intentionally obfuscated |
| arm-binaries/* | ARM32/ARM64 | ELF/Mach-O | varies | Mixed | Representative ARM sample |

## Measurement Framework

### Feature Coverage Checklist

For each decompiled function, score presence/quality of:

| Feature | Scoring | Notes |
|---------|---------|-------|
| String literals | Present / Partial / Missing | Correctness of recovered strings |
| Variable names | Named / Generic (param_N, lVar) / None | Meaningful vs auto-generated |
| Function signature | Correct / Partial / Wrong | Parameters, return type, calling convention |
| Control flow recovery | if/while/do-while/switch recovered | Loop types, branch nesting |
| Type inference | Correct types / Partial / No types | int, ptr, struct, etc. |
| Register/stack elimination | Clean output / Some noise / Lots of noise | Readability after post-processing |
| API/import names | Recovered / Stubbed / Missing | External function references |

### Correctness Assessment

**Semantic equivalence check** (manual spot-check on 2-3 functions per binary):
- Does rsleigh pseudocode represent the same computation as Ghidra?
- Are there logic errors, off-by-one bugs, or flow control mistakes in either?
- Can the pseudocode be mentally executed to match the binary behavior?

**Scoring:** Correct / Minor differences (cosmetic, naming) / Major differences (logic, flow) / Crash/failure

## Process

### Step 1: Extract Functions

For each binary:
- Identify all discovered functions (symbol table + heuristics)
- Select 5-10 functions based on:
  - Complexity (small, medium, complex)
  - Diversity (loops, conditionals, calls, string ops)
  - Manual review potential (non-trivial, analyzable in isolation)

### Step 2: Decompile with Both Tools

**rsleigh:**
```bash
rsleigh <binary> <func1> <func2> ... > rsleigh_output.txt
```

**Ghidra 11.3.1:**
```bash
export GHIDRA_HOME=~/ghidra_install/ghidra_11.3.1_PUBLIC
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj proj \
  -import <binary> -postScript ExportDecompile.py -deleteProject
```

### Step 3: Feature Scoring

Create a comparison matrix for each binary:
- Column per function
- Row per feature from checklist
- Cell: rsleigh score / Ghidra score

Example:
```
Function        | func_add | func_strlen | func_memcpy
Strings         | ✓ 2/2   | ✓ 1/1      | ✓ 3/3
Var names       | ✓ Good  | ✓ Good     | ⚠ Partial
Control flow    | ✓ if    | ✓ while    | ✓ switch
Type inference  | ✓ Yes   | ✓ Yes      | ⚠ Partial
Readability     | ✓ Good  | ✓ Good     | ⚠ Some noise
```

### Step 4: Spot-Check Correctness

For 2-3 interesting functions per binary (one simple, one complex):
- Display side-by-side pseudocode
- Manually trace execution through both outputs
- Flag any logic discrepancies
- Note cosmetic differences (naming, formatting)

### Step 5: Summarize Findings

Per-binary report:
- Feature coverage matrix
- Spot-check results (correct/minor/major)
- Notable wins (rsleigh beats Ghidra)
- Notable losses (Ghidra beats rsleigh)
- Architecture-specific observations

Final summary:
- Overall feature coverage by architecture (x86-64, x86-32, ARM)
- Patterns of failure/success
- Actionable recommendations (low-hanging fruit for improvement)

## Output Format

**Markdown report** (`results/decompiler_comparison_2026-04-17.md`):
- Per-binary summary table
- Full feature matrix
- Side-by-side pseudocode snippets for 1-2 spot-checks
- Consolidated findings and recommendations

## Success Criteria

- [ ] All 4 binaries decompile without crashing
- [ ] Feature matrices completed for all selected functions
- [ ] 2-3 spot-checks per binary reviewed for semantic correctness
- [ ] Report identifies ≥3 clear patterns (wins/losses/edge cases)
- [ ] Recommendations are actionable (feature/bug fix, not vague)

## Tools & Dependencies

- rsleigh CLI (built from workspace)
- Ghidra 11.3.1 (already installed at ~/ghidra_install/)
- Comparison script (to be created, or manual side-by-side review)
- Python/shell for batching decompilation across binaries

## Known Limitations

- Decompiled pseudocode is inherently lossy; perfect equivalence impossible
- Ghidra output may contain bugs too (not infallible reference)
- Manual spot-checks are subjective; focus on clear logic errors
- Some binaries may be stripped/obfuscated, reducing feature recovery for both tools
