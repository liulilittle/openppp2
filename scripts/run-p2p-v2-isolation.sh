#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=${1:-normal}
case "$MODE" in
    normal) ASAN=OFF; TSAN=OFF ;;
    asan) ASAN=ON; TSAN=OFF ;;
    tsan) ASAN=OFF; TSAN=ON ;;
    *) echo "Usage: sh scripts/run-p2p-v2-isolation.sh [normal|asan|tsan]" >&2; exit 2 ;;
esac
BUILD_DIR=${OPENPPP2_P2P_BUILD_DIR:-"$ROOT/build/p2p-v2-$MODE"}
cmake -S "$ROOT/tests/cpp" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DENABLE_SANITIZERS="$ASAN" -DENABLE_TSAN="$TSAN"
cmake --build "$BUILD_DIR" --parallel "${OPENPPP2_BUILD_JOBS:-2}" --target \
    p2p_information_message_test p2p_stun_gatherer_test \
    p2p_native_socket_stun_test p2p_probe_coordinator_test \
    p2p_ingress_limiter_test p2p_v2_offer_test p2p_v2_channel_test \
    p2p_v2_noise_test p2p_v2_server_coordination_test \
    p2p_v2_integration_test p2p_v2_app_wiring_compile
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1}" \
UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}" \
    ctest --test-dir "$BUILD_DIR" --output-on-failure \
    -R '^p2p_(information_message|stun_gatherer|native_socket_stun|probe_coordinator|ingress_limiter|v2_offer|v2_channel|v2_noise|v2_server_coordination|v2_integration)_test$'
