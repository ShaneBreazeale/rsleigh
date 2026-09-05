#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
mkdir -p build
for variant in direct indirect; do
    defines=(-DINDIRECT=0)
    if [[ "$variant" == indirect ]]; then defines=(-DINDIRECT=1); fi
    "$CLANG" --target=x86_64-pc-windows-msvc -c fixture.S \
        "${defines[@]}" -o "build/$variant.obj"
    "$LLD_LINK" /entry:entry /subsystem:console /machine:x64 /nodefaultlib \
        /timestamp:0 /fixed /base:0x140000000 /filealign:512 \
        /export:payload /export:protected_fault /export:smc_handler \
        "/implib:build/$variant.lib" "/out:$variant.exe" "build/$variant.obj"
done
