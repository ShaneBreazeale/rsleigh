# Firmware investigations

Two real firmware investigations helped improve rsleigh's terminal analysis
workflow. These notes summarize recorded engineering results from the commit
history; they are not freshly rerun benchmarks or complete firmware extraction
tutorials. The vendor firmware images are not bundled with these notes.

## Sony α7R II camera firmware

The investigation covered the camera's BIONZ X `av-cam.bin` firmware and PE
components carved from `Update_ILCE7RM2V401.exe`.

Mixed ARM/Thumb code exposed two function-discovery problems: byte patterns
that looked like calls produced excessive candidates, and ARM-to-Thumb
`BLX` immediate calls were missing from the scan. Prologue validation and
explicit `BLX` discovery reduced the recorded candidate count from 113,988
to 24,261 on the 13.4 MB image. This is a reduction in discovery candidates,
not a measured count of correctly decompiled functions.

The Windows updater exposed a separate issue: carved executables could retain
certificate-table references beyond the extracted file. Lenient PE parsing
and supplemental call-based discovery changed the recorded results from
0 to 328 functions for `UserFirmUpTool.exe`, and from 3 to 40 for
`XpStorageDevice_WinXp2k.dll`.

The useful workflow is to discover code, follow cross-references, and inspect
instructions in the correct ARM/Thumb mode. Dense Thumb-2 pseudocode remains
a limitation; the discovery results do not establish decompilation accuracy.
For current commands, see [raw firmware analysis](../cli-reference.md) and the
[architecture matrix](../architectures.md). Raw images require an explicit
architecture and the appropriate load base.

Recorded changes:

- [ARM/Thumb discovery and its synthetic regression test](https://github.com/ShaneBreazeale/rsleigh/commit/9455a60c72d858c9403f582caaf601bc83ba7ea1)
- [Carved PE parsing and supplemental function discovery](https://github.com/ShaneBreazeale/rsleigh/commit/318c9048d4d1274da2e70435b45f557ce8ac2403)

## TP-Link AX6000 v2 router firmware

The extracted root filesystem supplied ARM32 Linux executables including
`tdpServer`, `miniupnpd`, `dnsmasq`, `dropbear`, and `avahi-daemon`.

An initial question was where `tdpServer` receives network input. Its ARM32
PLT stubs were not being mapped to imported function names, hiding the
`recvfrom` relationship from analysis. Adding an ARM32 PLT decoder resolved
the stub at `0x125d8` to `recvfrom`; the recorded callers were at `0x1be08`
and `0x1d618` in that particular binary. Those addresses are sample-specific.

The investigation also exposed a spurious ARM call-target tag and a printer
performance problem. Later work expanded source-to-sink analysis across the
router daemons. The resulting solver candidates identify paths for review;
they do not establish an exploitable overflow or a new CVE. Use the current
[SMT interpretation guide](../smt-backend.md#what-the-verdict-means) when
reading those results.

For an extracted ELF executable, start with a function map and network API
search, then inspect an address returned for your own sample:

```bash
rsleigh ./tdpServer --agent-brief
rsleigh ./tdpServer --search --api recvfrom
```

This uses the normal ELF workflow; it does not require raw-image load settings.
Firmware extraction is a separate prerequisite.

Recorded changes:

- [ARM32 import resolution](https://github.com/ShaneBreazeale/rsleigh/commit/d56189f)
- [Early router analysis limits and fixes](https://github.com/ShaneBreazeale/rsleigh/commit/263294f)
- [Later cross-daemon source-to-sink campaign](https://github.com/ShaneBreazeale/rsleigh/commit/1a22339)

For a completed flag-recovery investigation, see the
[PyVMProtect crackme walkthrough](crackme3-pyvmprotect.md).
