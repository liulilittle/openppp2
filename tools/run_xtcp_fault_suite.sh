#!/usr/bin/env bash
# run_xtcp_fault_suite.sh - builds the pinned upstream XTCP tree standalone
# (tests + benches + checksum validation ON, unlike the embedded integration
# build which forces them OFF) and runs the fault-injection suite that backs
# the OPENPPP2 integration's loss/reorder/PMTU/half-close/RST/churn claims.
#
# usage:
#   tools/run_xtcp_fault_suite.sh          # fault suite only
#   tools/run_xtcp_fault_suite.sh --full   # every upstream test
#
# env:
#   XTCP_FAULT_BUILD_DIR  build directory (default: build/xtcp-fault-suite)
#   XTCP_FAULT_JOBS       parallel build/test jobs (default: nproc)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${XTCP_FAULT_BUILD_DIR:-${ROOT}/build/xtcp-fault-suite}"
JOBS="${XTCP_FAULT_JOBS:-$(nproc)}"
FULL=0
[[ "${1:-}" == "--full" ]] && FULL=1

bash "${ROOT}/tools/prepare_xtcp.sh"
SOURCE_DIR="${XTCP_SOURCE_DIR:-${ROOT}/third-party/xtcp}"

cmake -S "${SOURCE_DIR}" -B "${BUILD_DIR}" -G Ninja \
    -DXTCP_BUILD_TESTS=ON \
    -DXTCP_BUILD_BENCH=ON \
    -DXTCP_BUILD_SAMPLES=OFF \
    -DXTCP_BUILD_PLUGINS=OFF \
    -DXTCP_BUILD_LWIP=OFF \
    -DXTCP_BUILD_CC_PLUGINS=ON \
    -DXTCP_CHECKSUM_VALIDATE=ON
cmake --build "${BUILD_DIR}" -j"${JOBS}"

# The fault/stress subset backing each integration claim:
#   loss recovery      test_loss_recovery (retransmit-to-legacy ratio < 8)
#   reorder vs loss    test_reorder_gate (SACK gate must not fast-retx)
#   PMTU               test_pmtu / test_pmtud / test_mtu_probe
#   data+FIN tail      test_closewait_data / test_fin_data / test_fin_ooo_closing
#                        / test_finwait_data
#   RST                test_rst_peer / test_rst_closing / test_close_rst_comb
#   churn              test_conn_churn / test_conn_churn_threads /
#                        test_multi_close_churn
#   load               test_mixed_load / test_zero_window_backpressure /
#                        test_ack_storm
#   end-to-end/bench   test_e2e / test_bench
FAULT_REGEX='^(test_loss_recovery|test_reorder_gate|test_pmtu|test_pmtud|test_mtu_probe|test_closewait_data|test_fin_data|test_fin_ooo_closing|test_finwait_data|test_rst_peer|test_rst_closing|test_close_rst_comb|test_conn_churn|test_conn_churn_threads|test_multi_close_churn|test_mixed_load|test_zero_window_backpressure|test_ack_storm|test_e2e|test_bench)$'

cd "${BUILD_DIR}"
if [[ "${FULL}" == 1 ]]; then
    ctest --output-on-failure -j"${JOBS}"
else
    ctest --output-on-failure -j"${JOBS}" -R "${FAULT_REGEX}"
fi

# Throughput evidence (JSON: bytes/seconds/mbps/kpps) for the integration
# report. Not a ctest case, so run the binary directly.
if [[ -x "${BUILD_DIR}/bench_throughput" ]]; then
    echo "== bench_throughput =="
    "${BUILD_DIR}/bench_throughput"
fi
