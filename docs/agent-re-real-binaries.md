# Real-binary agent workflow validation

This release smoke check exercises shipped programs beyond the hand-encoded
[18-task corpus](agent-re-evaluation.md). It checks selected questions and
artifact consistency; it is not an exhaustive semantic or vulnerability audit.
Targets are read as data and are not executed.

The v0.5.0 preparation run used CLI SHA-256
`9c7576fe3797e0102ffc6d6143048a206c258bf629bb9f32d3818db46ef0eda1`.
[Raw outputs, commands, hashes, and the smoke runner](../test-harness/fixtures/agent-re/results/release-real-binaries.json.gz)
are retained as a compressed JSON artifact.

All five queries preserved their outcomes across uncached, cold-cache, and
warm-cache runs. Four slices had identical selection, dependency graphs, and
evidence; the unsupported selector retained its explicit failure. Every warm
query did zero decode/SSA work. Five node origins resolved to typed operations
matching separate P-code dumps. This is internal decoder consistency; the
macOS return instructions were additionally checked with `otool`.

## Targets and questions

| Target | Selected question | Observed outcome |
|---|---|---|
| macOS `true`, x86-64 Mach-O slice | What does the entry function return? | Constant zero, matching `xor eax,eax` before return |
| macOS `false`, x86-64 Mach-O slice | What does the entry function return? | Constant one, matching `mov eax,1` before return |
| BusyBox 1.21, AArch64 ELF | Where does `xmalloc`'s return value come from? | Allocation call evidence with an explicit unresolved external target |
| BusyBox 1.21, AArch64 ELF | Where does the allocation size at `xmalloc`'s call originate? | Explicit `unsupported_root`: argument zero was not recovered |
| BusyBox 1.21, AArch64 ELF | Where does `safe_read`'s result come from? | Read-call/loop dependencies with explicit unresolved boundaries |

BusyBox is the existing fixture under
`test-harness/fixtures/smt/calibration/busybox_1_21/`. macOS utilities come from
the validation host and are not redistributed. Their constant-return
instructions are also inspected with the platform disassembler, `otool`.

## Reproduce the workflow

Build the current source and generate decoders first. On macOS, extract a thin
slice from the universal system binary; native parsing currently rejects the
universal wrapper:

```bash
xcrun lipo /usr/bin/true -thin x86_64 -output /tmp/rsleigh-true-x86_64
rsleigh /tmp/rsleigh-true-x86_64
xcrun otool -tvV /tmp/rsleigh-true-x86_64
```

Select the actual function address from that binary's map. For each query,
compare uncached output with an empty cache, then a warm query that permits no
new decode/SSA work:

```bash
rsleigh FILE --ssa-slice FUNCTION --return
rsleigh FILE --ssa-slice FUNCTION --return --analysis-cache CACHE_DIR
rsleigh FILE --ssa-slice FUNCTION --return --analysis-cache CACHE_DIR \
  --max-decode-instructions 0 --max-ssa-work 0
rsleigh FILE FUNCTION --card --pcode --json
```

Use a separate cache directory for each input/build and record the binary and
tool hashes. Compare `selection`, `slice`, and `evidence`, including snapshot
identities, across all three states. Every warm function should report a cache
hit and zero decode/SSA work. Each emitted node origin must resolve to matching
typed raw evidence in its function snapshot. Preserve partial statuses and
unresolved boundaries; do not reinterpret them as successful value recovery.

## Observed limits

The macOS universal wrapper is unsupported; extracting the x86-64 slice makes
these utilities analyzable. `xmalloc` and `safe_read` stop at allocation/read
call targets that are not discovered function entries. The allocation-size
selector reports `unsupported_root` rather than recovering the incoming
argument. This is a remaining argument-recovery gap, even though AArch64
argument selection works on supported recovered roots in the deterministic
corpus. These outcomes are preserved across cache states.

Only the two macOS constant-return questions have independently inspected
instruction-level answers here. BusyBox outcomes check conservative failure
reporting and artifact consistency; they do not prove the missing call or
argument semantics. Timing is a local smoke measurement, not a benchmark.
