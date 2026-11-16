#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BACKEND=${ENABLE_COROCC:-0}
SUFFIX=""
if [ "$BACKEND" = 1 ] || [ "$BACKEND" = ON ]; then SUFFIX=-corocc; fi
BUILD_DIR=${CPP_TEST_BUILD_DIR:-$ROOT/build/test$SUFFIX}
cmake -S "$ROOT/tests/cpp" -B "$BUILD_DIR" -G Ninja -DENABLE_COROCC="$BACKEND" "$@"
cmake --build "$BUILD_DIR" --parallel "${CPP_TEST_JOBS:-4}"
ctest --test-dir "$BUILD_DIR" --output-on-failure
