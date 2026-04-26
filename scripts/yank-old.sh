#!/usr/bin/env bash
# Yank v0.2.0 of the 37 old per-arch split decoder crates.
# Replaced by 6 collapsed `rsleigh-gen-<arch>` crates in v0.3.0+.
# Yanked versions stay resolvable in existing lockfiles; new resolves blocked.

set -u

VERSION="${1:-0.2.0}"

yank() {
  local crate="$1"
  echo "--- cargo yank --version $VERSION $crate ---"
  cargo yank --version "$VERSION" "$crate" 2>&1 || true
}

# shared/subtables/root × 6 archs
for arch in x86 x86-32 aarch64 arm32 mips riscv; do
  for split in shared subtables root; do
    yank "rsleigh-gen-${arch}-${split}"
  done
done

# instr-NN per arch
for n in 00 01 02 03 04 05 06 07; do yank "rsleigh-gen-x86-instr-${n}"; done
for n in 00 01 02 03;             do yank "rsleigh-gen-x86-32-instr-${n}"; done
for n in 00 01 02 03;             do yank "rsleigh-gen-aarch64-instr-${n}"; done
for n in 00 01;                   do yank "rsleigh-gen-arm32-instr-${n}"; done
for n in 00 01;                   do yank "rsleigh-gen-mips-instr-${n}"; done
for n in 00 01;                   do yank "rsleigh-gen-riscv-instr-${n}"; done

echo "=== DONE ==="
