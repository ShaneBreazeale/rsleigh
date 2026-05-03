# printer-hangs/

Crash/hang regression fixtures for rsleigh's printer pass.

## tdpserver_0x1591c_arm32.bin (2328 bytes, ARM32 LE)

Function at virtual address `0x0001591c` carved from
`/usr/bin/tdpServer` in TP-Link AX6000 v2 firmware
`ax6000v2-ax6000v1-up-ver1-4-3-P1[20250725-rel18118]`. Looks like
an unrolled crypto round (MD5/SHA-style: long arithmetic chains
with `add r3,lr,r3,ror`, `eor`, `orr`, repeated `ldr`/`str` on a
shared base+offset state struct). 580+ instructions, single
straight-line basic block.

### What it triggers

Pre-fix: the printer's `expr_has_tracked_reg` walks the SSA
expression cone unmemoized; on a deep DAG with shared subexpressions
the recursion blows up (effectively infinite hang on this function).
M2 firmware-triage discovered it via a per-function timeout bisect
across 710 tdpServer functions; this was the only entry that
hit the printer hang, but it stalled `--vulnscan`, `--callgraph`,
`--xrefs`, and `--smt-explore` on the entire binary.

Sample profiler trace (lldb):
  expr_has_tracked_reg → expr_has_tracked_reg → ... 770 frames deep,
  100% of CPU samples in the recursion.

### Repro

```sh
gtimeout -s KILL 30 \
  target/release/rsleigh \
  test-harness/fixtures/printer-hangs/tdpserver_0x1591c_arm32.bin \
  --raw arm32 FUN_00000000 >/dev/null
# pre-fix: rc=137 (SIGKILL after 30s)
# post-fix: rc=0 in <2s
```

The function's bytes are public TP-Link firmware released for AX6000;
no PII or proprietary content.
