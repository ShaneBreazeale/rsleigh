#!/usr/bin/env bash
# Build checked-in FID databases for glibc / musl / libstdc++ by pulling
# canonical distro packages, extracting .so files, and running
# rsleigh-fid-gen against them. Produces rsleigh-fid/data/*.fidb.
#
# Usage:  scripts/build-fid-dbs.sh
#
# Reproducibility: exact package URLs + SHA256 pinned in the manifest
# (rsleigh-fid/data/MANIFEST.tsv). Rerun refetches the same revisions.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/rsleigh-fid/data"
WORK="$(mktemp -d)"
GEN="$ROOT/target/release/rsleigh-fid-gen"
MANIFEST="$OUT_DIR/MANIFEST.tsv"

mkdir -p "$OUT_DIR"

if [[ ! -x "$GEN" ]]; then
  echo "building rsleigh-fid-gen..."
  (cd "$ROOT" && cargo build -p rsleigh-fid --release)
fi

echo -e "package\tversion\tarch\tsource_url\tsha256\tfidb\tentries" > "$MANIFEST"

extract_deb() {
  # $1=deb  $2=out_dir
  local deb="$1" dest="$2"
  mkdir -p "$dest"
  ( cd "$dest" && ar x "$deb" )
  if   [[ -f "$dest/data.tar.xz"  ]]; then tar -xJf "$dest/data.tar.xz"  -C "$dest"
  elif [[ -f "$dest/data.tar.zst" ]]; then tar --zstd -xf "$dest/data.tar.zst" -C "$dest"
  elif [[ -f "$dest/data.tar.gz"  ]]; then tar -xzf "$dest/data.tar.gz"  -C "$dest"
  else echo "unknown data archive in $deb" >&2; return 1
  fi
}

extract_apk() {
  local apk="$1" dest="$2"
  mkdir -p "$dest"
  tar -xzf "$apk" -C "$dest" 2>/dev/null || true
}

fetch() {
  local url="$1" out="$2"
  curl -fsSL -o "$out" "$url"
  shasum -a 256 "$out" | awk '{print $1}'
}

log_manifest() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$MANIFEST"
}

build_glibc_amd64() {
  local url="http://ftp.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u13_amd64.deb"
  local deb="$WORK/libc6_amd64.deb"
  local dir="$WORK/libc6_amd64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local so; so=$(find "$dir" -name 'libc.so.6' | head -1)
  [[ -n "$so" ]] || { echo "libc.so.6 missing"; return 1; }
  "$GEN" --lib glibc --arch x86_64 --out "$OUT_DIR/glibc-x86_64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "libc6" "2.36-9+deb12u13" "amd64" "$url" "$sum" "glibc-x86_64.fidb" "$n"
}

build_glibc_arm64() {
  local url="http://ftp.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u13_arm64.deb"
  local deb="$WORK/libc6_arm64.deb"
  local dir="$WORK/libc6_arm64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local so; so=$(find "$dir" -name 'libc.so.6' | head -1)
  [[ -n "$so" ]] || { echo "libc.so.6 missing"; return 1; }
  "$GEN" --lib glibc --arch aarch64 --out "$OUT_DIR/glibc-aarch64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "libc6" "2.36-9+deb12u13" "arm64" "$url" "$sum" "glibc-aarch64.fidb" "$n"
}

build_libstdcxx_amd64() {
  local url="http://ftp.debian.org/debian/pool/main/g/gcc-12/libstdc++6_12.2.0-14+deb12u1_amd64.deb"
  local deb="$WORK/libstdcxx_amd64.deb"
  local dir="$WORK/libstdcxx_amd64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local so; so=$(find "$dir" -name 'libstdc++.so.6*' -type f | head -1)
  [[ -n "$so" ]] || { echo "libstdc++ missing"; return 1; }
  "$GEN" --lib libstdcxx --arch x86_64 --out "$OUT_DIR/libstdcxx-x86_64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "libstdc++6" "12.2.0-14+deb12u1" "amd64" "$url" "$sum" "libstdcxx-x86_64.fidb" "$n"
}

build_libstdcxx_arm64() {
  local url="http://ftp.debian.org/debian/pool/main/g/gcc-12/libstdc++6_12.2.0-14+deb12u1_arm64.deb"
  local deb="$WORK/libstdcxx_arm64.deb"
  local dir="$WORK/libstdcxx_arm64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local so; so=$(find "$dir" -name 'libstdc++.so.6*' -type f | head -1)
  [[ -n "$so" ]] || { echo "libstdc++ missing"; return 1; }
  "$GEN" --lib libstdcxx --arch aarch64 --out "$OUT_DIR/libstdcxx-aarch64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "libstdc++6" "12.2.0-14+deb12u1" "arm64" "$url" "$sum" "libstdcxx-aarch64.fidb" "$n"
}

build_musl_amd64() {
  local url="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/musl-1.2.5-r11.apk"
  local apk="$WORK/musl_amd64.apk"
  local dir="$WORK/musl_amd64"
  local sum; sum=$(fetch "$url" "$apk")
  extract_apk "$apk" "$dir"
  local so; so=$(find "$dir" -name 'libc.musl-*.so.1' -type f | head -1)
  [[ -n "$so" ]] || so=$(find "$dir" -name 'ld-musl-*.so.1' -type f | head -1)
  [[ -n "$so" ]] || { echo "musl libc missing"; return 1; }
  "$GEN" --lib musl --arch x86_64 --out "$OUT_DIR/musl-x86_64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "musl" "1.2.5-r11" "x86_64" "$url" "$sum" "musl-x86_64.fidb" "$n"
}

build_musl_arm64() {
  local url="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/aarch64/musl-1.2.5-r11.apk"
  local apk="$WORK/musl_arm64.apk"
  local dir="$WORK/musl_arm64"
  local sum; sum=$(fetch "$url" "$apk")
  extract_apk "$apk" "$dir"
  local so; so=$(find "$dir" -name 'libc.musl-*.so.1' -type f | head -1)
  [[ -n "$so" ]] || so=$(find "$dir" -name 'ld-musl-*.so.1' -type f | head -1)
  [[ -n "$so" ]] || { echo "musl libc missing"; return 1; }
  "$GEN" --lib musl --arch aarch64 --out "$OUT_DIR/musl-aarch64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "musl" "1.2.5-r11" "aarch64" "$url" "$sum" "musl-aarch64.fidb" "$n"
}

build_zlib_amd64() {
  local url="http://ftp.debian.org/debian/pool/main/z/zlib/zlib1g_1.2.13.dfsg-1_amd64.deb"
  local deb="$WORK/zlib_amd64.deb"
  local dir="$WORK/zlib_amd64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local so; so=$(find "$dir" -name 'libz.so.1*' -type f | head -1)
  [[ -n "$so" ]] || { echo "libz missing"; return 1; }
  "$GEN" --lib zlib --arch x86_64 --out "$OUT_DIR/zlib-x86_64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "zlib1g" "1.2.13.dfsg-1" "amd64" "$url" "$sum" "zlib-x86_64.fidb" "$n"
}

build_zlib_arm64() {
  local url="http://ftp.debian.org/debian/pool/main/z/zlib/zlib1g_1.2.13.dfsg-1_arm64.deb"
  local deb="$WORK/zlib_arm64.deb"
  local dir="$WORK/zlib_arm64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local so; so=$(find "$dir" -name 'libz.so.1*' -type f | head -1)
  [[ -n "$so" ]] || { echo "libz missing"; return 1; }
  "$GEN" --lib zlib --arch aarch64 --out "$OUT_DIR/zlib-aarch64.fidb" "$so" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "zlib1g" "1.2.13.dfsg-1" "arm64" "$url" "$sum" "zlib-aarch64.fidb" "$n"
}

build_openssl_amd64() {
  local url="http://ftp.debian.org/debian/pool/main/o/openssl/libssl3_3.0.17-1~deb12u2_amd64.deb"
  local deb="$WORK/openssl_amd64.deb"
  local dir="$WORK/openssl_amd64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local ssl; ssl=$(find "$dir" -name 'libssl.so.3' -type f | head -1)
  local crypto; crypto=$(find "$dir" -name 'libcrypto.so.3' -type f | head -1)
  [[ -n "$ssl" && -n "$crypto" ]] || { echo "openssl missing"; return 1; }
  "$GEN" --lib openssl --arch x86_64 --out "$OUT_DIR/openssl-x86_64.fidb" "$ssl" "$crypto" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "libssl3+libcrypto3" "3.0.17-1~deb12u2" "amd64" "$url" "$sum" "openssl-x86_64.fidb" "$n"
}

build_openssl_arm64() {
  local url="http://ftp.debian.org/debian/pool/main/o/openssl/libssl3_3.0.17-1~deb12u2_arm64.deb"
  local deb="$WORK/openssl_arm64.deb"
  local dir="$WORK/openssl_arm64"
  local sum; sum=$(fetch "$url" "$deb")
  extract_deb "$deb" "$dir"
  local ssl; ssl=$(find "$dir" -name 'libssl.so.3' -type f | head -1)
  local crypto; crypto=$(find "$dir" -name 'libcrypto.so.3' -type f | head -1)
  [[ -n "$ssl" && -n "$crypto" ]] || { echo "openssl missing"; return 1; }
  "$GEN" --lib openssl --arch aarch64 --out "$OUT_DIR/openssl-aarch64.fidb" "$ssl" "$crypto" 2>&1 | tee -a "$WORK/log"
  local n; n=$(grep -Eo 'wrote [0-9]+ entries' "$WORK/log" | tail -1 | awk '{print $2}')
  log_manifest "libssl3+libcrypto3" "3.0.17-1~deb12u2" "arm64" "$url" "$sum" "openssl-aarch64.fidb" "$n"
}

build_glibc_amd64
build_glibc_arm64
build_libstdcxx_amd64
build_libstdcxx_arm64
build_musl_amd64
build_musl_arm64
build_zlib_amd64
build_zlib_arm64
build_openssl_amd64
build_openssl_arm64

echo
echo "=== results ==="
ls -l "$OUT_DIR"/*.fidb
echo
cat "$MANIFEST"
echo
echo "workdir: $WORK (remove manually)"
