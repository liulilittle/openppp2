#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BACKEND=${ENABLE_COROCC:-0}
SUFFIX=""
if [ "$BACKEND" = 1 ] || [ "$BACKEND" = ON ]; then SUFFIX=-corocc; fi
BUILD_DIR=${CPP_TEST_BUILD_DIR:-$ROOT/build/test-asan$SUFFIX}
cmake -S "$ROOT/tests/cpp" -B "$BUILD_DIR" -G Ninja -DENABLE_SANITIZERS=ON -DENABLE_COROCC="$BACKEND" "$@"
cmake --build "$BUILD_DIR" --parallel "${CPP_TEST_JOBS:-4}"
export ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
if uname -r | grep -qi microsoft; then
    exec setarch "$(uname -m)" -R ctest --test-dir "$BUILD_DIR" --output-on-failure
fi
exec ctest --test-dir "$BUILD_DIR" --output-on-failure
