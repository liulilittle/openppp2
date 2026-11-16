#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=${1:-normal}
if [ "$#" -gt 0 ]; then shift; fi
case "$MODE" in
    normal) ASAN=OFF; TSAN=OFF ;;
    asan) ASAN=ON; TSAN=OFF ;;
    tsan) ASAN=OFF; TSAN=ON ;;
    *) echo "Usage: sh scripts/run-p2p-v2-exchanger-recovery.sh [normal|asan|tsan] [CMake options...]" >&2; exit 2 ;;
esac
BUILD_DIR=${OPENPPP2_P2P_RECOVERY_BUILD_DIR:-"$ROOT/build/p2p-v2-exchanger-$MODE"}
cmake -S "$ROOT" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_C_COMPILER="${CC:-clang}" \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DPPP_OUTPUT_DIR="$BUILD_DIR/bin" \
    "$@" \
    -DENABLE_TESTS=OFF -DENABLE_P2P_RECOVERY_TESTS=ON \
    -DENABLE_ASAN="$ASAN" -DENABLE_UBSAN="$ASAN" -DENABLE_TSAN="$TSAN"
cmake --build "$BUILD_DIR" --parallel "${OPENPPP2_BUILD_JOBS:-2}" \
    --target p2p_v2_exchanger_recovery_test
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1}" \
UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}" \
    ctest --test-dir "$BUILD_DIR" --output-on-failure \
    -R '^p2p_v2_exchanger_recovery_test$'
