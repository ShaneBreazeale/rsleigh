#!/bin/sh
set -eu
cd "$(dirname "$0")"
for kind in none zlib zstd; do
    out=$kind.elf
    [ "$kind" = none ] && out=plain.elf
    gcc -g -O0 -gno-record-gcc-switches -fno-pie -no-pie -static -nostdlib \
        -ffile-prefix-map="$PWD"=. -gz="$kind" -o "$out" dwarf.c
done
