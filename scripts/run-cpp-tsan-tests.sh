#!/bin/sh
# Builds the standalone C++ test suite with ThreadSanitizer and runs it.
#
# ThreadSanitizer cannot be combined with ASan/UBSan, so this script uses its
# own build directory (build/test-tsan).  Use it to reproduce data races from
# the concurrency audit (shared_ptr/container/plain-field races are invisible
# to ASan/UBSan).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cmake -S "$ROOT/tests/cpp" -B "$ROOT/build/test-tsan" -G Ninja -DENABLE_TSAN=ON
cmake --build "$ROOT/build/test-tsan"
# ctest 3.29+ supports --env, but exporting TSAN_OPTIONS before the ctest
# invocation is simpler, works on older CMake versions, and also covers any
# helper subprocesses spawned by the test harness.
export TSAN_OPTIONS="suppressions=$ROOT/tests/cpp/tsan_suppressions.txt halt_on_error=0"
ctest --test-dir "$ROOT/build/test-tsan" --output-on-failure
