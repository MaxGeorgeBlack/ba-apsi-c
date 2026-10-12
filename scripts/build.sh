#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j "$(nproc)"
ctest --test-dir build --output-on-failure

if [[ "${1:-}" == "--sanitize" ]]; then
    cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DBA_SANITIZE=ON
    cmake --build build-asan -j "$(nproc)"
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-asan --output-on-failure
fi
