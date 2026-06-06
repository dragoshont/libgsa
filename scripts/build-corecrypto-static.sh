#!/usr/bin/env bash
#
# build-corecrypto-static.sh — compile Apple corecrypto into a static archive
# so libgsa's SRP output can be diffed byte-for-byte against Apple's (the
# behavioral oracle).
#
# LEGAL: Apple's corecrypto Internal Use License permits download + use for
# security verification but FORBIDS redistribution of the source or the built
# .a. This script therefore:
#   * does NOT download anything — YOU bring the zip you fetched from Apple;
#   * writes the .a into a local, gitignored dir (default ./.corecrypto-out);
#   * is meant to run on a machine YOU control (your laptop or a self-hosted
#     runner), never as a published/public CI artifact.
# By running it you accept Apple's corecrypto Internal Use License.
#
# Usage:
#   scripts/build-corecrypto-static.sh /path/to/corecrypto.zip [OUT_DIR]
#
# On success it prints the absolute path to libcorecrypto_static.a; pass that to
#   cmake -B build -DGSA_DIFF_CORECRYPTO=<that path>
set -euo pipefail

ZIP="${1:?usage: build-corecrypto-static.sh <corecrypto.zip> [out_dir]}"
OUT_DIR="${2:-$(pwd)/.corecrypto-out}"
PIN_FILE="$(cd "$(dirname "$0")/.." && pwd)/corecrypto.pin"

[ -f "$ZIP" ] || { echo "ERROR: $ZIP not found"; exit 1; }

# Integrity guard against the pinned drop (warn-only; a drift is the whole point
# of validating, so we don't hard-fail — we surface it).
if [ -f "$PIN_FILE" ]; then
  pinned="$(grep '^CORECRYPTO_SHA256=' "$PIN_FILE" | cut -d= -f2- || true)"
  got="$(shasum -a 256 "$ZIP" | awk '{print $1}')"
  if [ -n "$pinned" ] && [ "$pinned" != "$got" ]; then
    echo "WARN: corecrypto.zip SHA ($got) != pinned ($pinned) — Apple may have"
    echo "      revved corecrypto. Differential results define the NEW baseline."
  fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$ZIP" "$WORK/corecrypto.zip"
cd "$WORK"
unzip -q corecrypto.zip
rm -rf __MACOSX

# Apple silently revs the top-level dir name (corecrypto/ -> corecrypto-2024/).
cml="$(find . -maxdepth 2 -name CMakeLists.txt -path '*corecrypto*' | head -n1)"
[ -n "$cml" ] || { echo "ERROR: no corecrypto CMakeLists.txt after unzip"; exit 1; }
src="$(dirname "$cml")"
[ "$src" = "./corecrypto" ] || { rm -rf corecrypto; mv "$src" corecrypto; }

# Strip the StableCoder code-coverage include Apple references but never ships,
# and fix the one ccrng_static.c path that points at a non-existent subdir.
sed -i.bak -E '/include\(scripts\/code-coverage\.cmake\)/d; /add_code_coverage\(\)/d; /target_code_coverage\(/d' corecrypto/CMakeLists.txt
sed -i.bak 's#"corecrypto_static/ccrng_static.c"#"ccrng_static.c"#' corecrypto/CoreCryptoSources.cmake

cd corecrypto
mkdir -p build && cd build
CC=clang CXX=clang++ cmake .. >/dev/null
# Skip perf/test targets that aren't needed for the static archive.
sed -i.bak -E 's|^(all: CMakeFiles/corecrypto_perf)|#\1|' CMakeFiles/Makefile2 2>/dev/null || true
sed -i.bak -E 's|^(all: CMakeFiles/corecrypto_test)|#\1|' CMakeFiles/Makefile2 2>/dev/null || true
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" corecrypto_static

a="$(find . -name 'libcorecrypto_static.a' | head -n1)"
[ -n "$a" ] || { echo "ERROR: libcorecrypto_static.a not produced"; exit 1; }

mkdir -p "$OUT_DIR"
cp "$a" "$OUT_DIR/libcorecrypto_static.a"
echo "$OUT_DIR/libcorecrypto_static.a"
