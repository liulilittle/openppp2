#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR=${OPENPPP2_LIFECYCLE_SANITIZER_BUILD_DIR:-"$ROOT/build/lifecycle-sanitizers"}
DETECT_LEAKS=${OPENPPP2_ASAN_DETECT_LEAKS:-1}
DISABLE_ASLR=${OPENPPP2_ASAN_DISABLE_ASLR:-0}

cmake -S "$ROOT/tests/cpp" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DENABLE_SANITIZERS=ON
cmake --build "$BUILD_DIR" --target \
    runtime_lifecycle_test \
    runtime_stop_pipeline_test \
    client_lifecycle_stress_test \
    route_coordinator_test \
    dns_controller_test

for test_binary in \
    runtime_lifecycle_test \
    runtime_stop_pipeline_test \
    client_lifecycle_stress_test \
    route_coordinator_test \
    dns_controller_test
do
    echo "Running sanitizer target: $test_binary"
    if [ "$DISABLE_ASLR" = "1" ]; then
        setarch "$(uname -m)" -R env \
            ASAN_OPTIONS="detect_leaks=$DETECT_LEAKS:halt_on_error=1:strict_string_checks=1" \
            UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
            "$BUILD_DIR/$test_binary"
    else
        ASAN_OPTIONS="detect_leaks=$DETECT_LEAKS:halt_on_error=1:strict_string_checks=1" \
        UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
            "$BUILD_DIR/$test_binary"
    fi
done
