#!/usr/bin/env bash
# Build the M1 SMT fixtures.
#
# Output: test-harness/fixtures/smt/bin/<name>
#
# Compile flags:
#   -O0     keep the SSA shape simple — fold may inline calls at -O2
#           which the v0 path collector does not yet handle.
#   -fno-inline -fno-omit-frame-pointer
#           same reason; keep `vuln_*` separately addressable so the
#           CLI can target it by name.
#   -Wno-format-security
#           the scanf_sprintf fixture intentionally passes a non-
#           literal format string to sprintf; the compiler flags
#           that as a security risk, which is exactly the bug.
#
# Host-native compile. The fixtures don't link external libraries
# beyond libc; the resulting binaries are platform-native (Mach-O
# on macOS, ELF on Linux). Both formats land symbols rsleigh's
# import resolver recognises.

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin

CFLAGS="-O0 -fno-inline -fno-omit-frame-pointer -fno-stack-protector -Wno-format-security"

for src in src/*.c; do
    name="$(basename "$src" .c)"
    cc $CFLAGS "$src" -o "bin/$name"
    echo "  built bin/$name ($(stat -f%z "bin/$name" 2>/dev/null || stat -c%s "bin/$name") bytes)"
done
