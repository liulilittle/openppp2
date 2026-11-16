#!/bin/sh
# Builds the standalone C++ test suite with ThreadSanitizer and runs it.
#
# ThreadSanitizer cannot be combined with ASan/UBSan, so this script uses its
# own build directory (build/test-tsan).  Use it to reproduce data races from
# the concurrency audit (shared_ptr/container/plain-field races are invisible
# to ASan/UBSan).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# High-entropy Linux ASLR can place PIE/shared libraries in TSan's shadow
# range before main(). Disable randomization for this process tree only.
if [ "$(uname -s)" = Linux ]; then
    personality=$(cat /proc/self/personality)
    if [ "$((0x$personality & 0x40000))" -eq 0 ]; then
        if ! command -v setarch >/dev/null 2>&1 ||
           ! setarch "$(uname -m)" -R true; then
            echo 'error: TSan needs ADDR_NO_RANDOMIZE on this Linux host; setarch -R is unavailable or denied. Run on a host/container that permits this personality flag.' >&2
            exit 1
        fi
        exec setarch "$(uname -m)" -R sh "$ROOT/scripts/run-cpp-tsan-tests.sh" "$@"
    fi
fi
BACKEND=${ENABLE_COROCC:-0}
SUFFIX=""
if [ "$BACKEND" = 1 ] || [ "$BACKEND" = ON ]; then SUFFIX=-corocc; fi
BUILD_DIR=${TSAN_BUILD_DIR:-${CPP_TEST_BUILD_DIR:-$ROOT/build/test-tsan$SUFFIX}}
cmake -S "$ROOT/tests/cpp" -B "$BUILD_DIR" -G Ninja "$@" -DENABLE_TSAN=ON -DENABLE_SANITIZERS=OFF -DENABLE_COROCC="$BACKEND"
cmake --build "$BUILD_DIR" --parallel "${CPP_TEST_JOBS:-4}"
# ctest 3.29+ supports --env, but exporting TSAN_OPTIONS before the ctest
# invocation is simpler, works on older CMake versions, and also covers any
# helper subprocesses spawned by the test harness.
export TSAN_OPTIONS="${TSAN_OPTIONS:-} suppressions=$ROOT/tests/cpp/tsan_suppressions.txt halt_on_error=0 exitcode=66"
ctest --test-dir "$BUILD_DIR" --output-on-failure
