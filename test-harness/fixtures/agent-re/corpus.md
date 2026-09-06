# Native RE corpus ground truth

All fixtures are original hand-encoded programs under Apache-2.0, the repository
license. [corpus.rs](corpus.rs) generates the complete inputs deterministically;
[seed.asm](seed.asm) and [seed.rs](seed.rs) describe the original PE fixture, and
[traversal.rs](traversal.rs) describes the memory/helper fixture. No downloaded
binaries, assembler, compiler, solver, or model service is required.

ELF inputs contain a native-class header, executable section/segment, and
explicit function symbols. MIPS uses big-endian ELF32, ARM uses little-endian
ELF32 in ARM mode, and the other ELF targets use little-endian ELF64. x86-64
inter-function padding is NOP. Inputs are inspection fixtures, not host programs
that the evaluator executes. All addresses below are virtual addresses.

| Task | Architecture / input | Expected answer | Instruction evidence |
|---|---|---|---|
| return-seven | x86-32 / seed.exe | Return 7 | `401000: mov eax,7` |
| first-call-arg-zero | x86-32 / seed.exe | Argument 0 is 11 | `401022: push 11`; call at 401024 |
| first-call-arg-one | x86-32 / seed.exe | Argument 1 is 22 | `401020: push 22`; call at 401024 |
| second-call-arg-zero | x86-32 / seed.exe | Argument 0 is 33 at the second invocation | `40102e: push 33`; call at 401030 |
| branch-input-unknown | x86-32 / seed.exe | Branch depends on unknown incoming EAX | `401040: test eax,eax`; conditional branch at 401042 |
| first-return-site | x86-32 / seed.exe | First selected return is 1 | `401044: mov eax,1`; return at 401049 |
| second-return-site | x86-32 / seed.exe | Second selected return is 2 | `40104a: mov eax,2`; return at 40104f |
| memory-unknown | x86-32 / seed.exe | Pointed-to memory is unresolved | `401060: mov eax,[ecx]` |
| stack-spill | x86-32 / traversal.exe | Store 73 supplies the stack reload | Store at 401043, reload at 40104a |
| global-store | x86-32 / traversal.exe | Store 73 to address 500000 supplies the load | Store at 401060, load at 40106a |
| helper-return | x86-32 / traversal.exe | Dependency evaluates as 17 + 5 = 22 | Push at 401000; call at 401002; helper parameter load at 401020 and add at 401024 |
| recursive-boundary | x86-32 / traversal.exe | Recursive dependency remains unresolved | `401080: call 401080`; traversal reports recursion_limit |
| ambiguous-store | x86-32 / ambiguous.exe | Unknown pointer store can overwrite the stack slot | `40104a: mov [ecx],eax`; reload at 40104c remains ambiguous_alias |
| x64-dispatch | x86-64 / dispatch.elf | Constant function pointer selects 401020 | `401000: movabs rax,401020`; `40100a: call rax`; target is labeled heuristic / cfg_resolved_indirect |
| aarch64-length | AArch64 / length.elf | Length argument 2 is 17 + 5 = 22 | `401000: mov w2,17`; `401004: add w2,w2,5`; BL at 401008 |
| arm-comparison | ARM32 / comparison.elf | Unknown R0 is compared with 7 | `401000: cmp r0,7`; BNE at 401004. Branch outcome stays unresolved |
| mips-return | MIPS32 / return-mips.elf | V0 contains 42 | `401000: addiu v0,zero,42`; JR RA at 401004 with NOP delay slot |
| riscv-return | RISC-V64 / return-riscv.elf | A0 contains 29 | `401000: addi a0,zero,29`; return at 401004 |

The runner checks the dependency graph against these answers. Its small value
interpreter follows explicit local edges and context links, evaluates supported
constant/copy/add/sub operations, and requires alternative values to agree.
It does not infer branch feasibility. Four tasks explicitly expect unresolved
values; a correct boundary is recorded as a correct negative answer, never as a
recovered value. The ARM task identifies the comparison constant while retaining
its unknown input. Dispatch resolution is heuristic, not a proof of execution.

Every retained current-build origin is independently looked up in the fixture
bytes and decoded as raw P-code. Its typed operation, operation index, function,
and snapshot identity must match the emitted evidence. Required source addresses
must appear in the evidence. Baseline v1 snapshots lack retained raw origins;
the report records this as absent instruction-origin evidence, not an evidence
accuracy pass based only on a matching file hash.

The current workflow runs the semantic query once. The baseline workflow runs
SSA JSON, selects a variable from the legacy terminator, and queries that
variable when one exists. Dispatch is answered directly from the legacy dump's
resolved target, without requiring a return-value slice. Failure to expose a selectable root is measured as an
unsolved task. This evaluates a prescribed deterministic tool workflow, not an
unconstrained human analyst or autonomous LLM. The baseline cannot expand helper
contexts or provide the new call-resolution fields. A comparison is still run
on every identical input and failures remain in the report.

Each workflow is repeated three times. Current runs include disabled, cold, and
warm caches, with an independent cache for each task/repetition. Warm runs set
both decode and SSA work allowances to zero; every participating function must
be a cache hit. Slice/evidence equality is checked across all three cache states.
Process deadlines are 30 seconds; timed-out children are killed and reaped.

Reproduce after building the CLI:

```bash
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  target/release/rsleigh full-results.json --full-corpus \
  --write-fixtures fixture-output/
cargo run --release -p rsleigh-cli --example agent_re_eval -- \
  /path/to/baseline/rsleigh baseline-results.json --full-corpus --baseline
```

`--write-fixtures DIR` is optional and writes the exact deterministic inputs for
inspection. The runner otherwise removes temporary inputs after saving its JSON
report. Reports retain command arguments/output, executable and fixture SHA-256,
host OS/architecture, answers, evidence results, command/byte/time measurements,
cache storage, and recomputation checks. The evaluation does not execute any
fixture instructions on the host CPU.

MIPS/RISC-V call argument binding and frame-memory forwarding remain unsupported;
their explicit native return registers are supported. Raw-firmware and WASM
frontends are outside this native brief/card/index evaluation. Optional future
live-model comparisons must record the model, prompt, and settings and remain
separate from this required deterministic CI gate.
