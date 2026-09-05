# Synthetic PE64 SEH-SMC fixtures

These original, repository-licensed fixtures exercise real `.pdata` / unwind
metadata and a language-specific exception handler that changes executable bytes.
They are synthetic regression cases, not independently authored packer samples.
The two 3 KiB executables are committed inputs so Rust tests need no Windows tools.

From the repository root:

```sh
bash test-harness/fixtures/seh-smc/build.sh
cargo test -p rsleigh-decompile --test seh_smc_fixture
```

Building requires Clang with the Windows x64 COFF target and `lld-link` on PATH;
`CLANG` and `LLD_LINK` can override their locations. No Windows SDK, CRT, import
libraries, or network downloads are needed. Intermediate files stay in ignored
`build/`. The linker timestamp is zero and the image base is fixed at
`0x140000000`. Rebuilds with the same toolchain should be byte-identical; other
toolchain versions can change the layout. Tests locate targets by exports rather
than fixed file offsets.

The checked-in binaries were built with Apple Clang 17.0.0
(`clang-1700.6.4.2`) and LLD 22.1.1.

| Variant | Handler behavior | Expected patch |
| --- | --- | --- |
| `direct.exe` | RIP-relative byte store | `payload + 1`: `00` → `2a` |
| `indirect.exe` | `lea rax, target; jmp rax`, then the same store | `payload + 1`: `00` → `2a` |

Both execute `UD2` inside `protected_fault`. Its statically registered handler
accepts `STATUS_ILLEGAL_INSTRUCTION`, patches the writable executable `.smc`
section, advances `CONTEXT.Rip` by two, and returns
`ExceptionContinueExecution` (the language-handler enum value 0, not the
`__except` filter constant). Execution resumes at a serializing `CPUID`, then
calls `payload`: `b8 00 00 00 00 c3` becomes `b8 2a 00 00 00 c3`.
The entry point returns the payload result as the process exit code.
Stack allocations and the saved RBX have matching unwind directives.

The indirect variant includes an unreachable `ret` after `jmp rax`, so a
linear scanner cannot accidentally recover the patch by falling through.

The integration tests exercise the production parser, extractor, patch applier,
and fixpoint. They require exactly one patch, compare the entire resulting image,
and require convergence in two iterations. No new functions are expected here.

## Windows runtime verification

On Windows x64, run from the repository root in PowerShell:

```powershell
& ./test-harness/fixtures/seh-smc/verify-windows.ps1
```

Each original executable must exit with code **42** within ten seconds. The CI
Windows job runs this check against the committed binaries. Static integration
tests have passed on macOS; Windows execution has not been verified locally.
Passing the static tests alone does not establish runtime correctness.

This baseline does not cover API-mediated writes, dynamic registration,
DispatcherContext value propagation, encrypted payloads, or new function
discovery. Add separate fixtures for those behaviors instead of making these
cases more complex.

Handler ABI and unwind metadata reference:
[Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64).
