// Send-side retransmit window.
//
// Field log (2026-10-18): mux sessions lived 2-10 s under high-throughput
// downloads; the server tore down every carrier with no client-side reason.
// Unacked bytes ~= BDP + carrier send buffers easily exceed the 8 MiB
// retransmit cap, which used to close_exec() the session. The cap is now a
// send window (frames stay queued) and only cap * hard factor is terminal.
#define BOOST_TEST_MODULE vmux_tx_backpressure_test
#include <boost/test/included/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include <ppp/app/mux/MuxTxBackpressure.h>

namespace mux = ppp::app::mux;

namespace {
constexpr std::size_t kSession = 8u << 20;
constexpr std::size_t kFlow = 2u << 20;
}

BOOST_AUTO_TEST_CASE(within_windows_sends) {
    BOOST_TEST((mux::AdmitTxFrame(0, 0, 1400, kSession, kFlow) == mux::MuxTxAdmit::Send));
    BOOST_TEST((mux::AdmitTxFrame(kSession - 1400, kFlow - 1400, 1400, kSession, kFlow) == mux::MuxTxAdmit::Send));
}

BOOST_AUTO_TEST_CASE(session_window_full_holds_instead_of_failing) {
    BOOST_TEST((mux::AdmitTxFrame(kSession - 1399, 0, 1400, kSession, kFlow) == mux::MuxTxAdmit::HoldSession));
    BOOST_TEST((mux::AdmitTxFrame(kSession, 0, 1, kSession, 0) == mux::MuxTxAdmit::HoldSession));
}

BOOST_AUTO_TEST_CASE(flow_window_is_checked_first) {
    // Both windows full: the flow verdict wins so only this flow is parked.
    BOOST_TEST((mux::AdmitTxFrame(kSession, kFlow, 1400, kSession, kFlow) == mux::MuxTxAdmit::HoldFlow));
    BOOST_TEST((mux::AdmitTxFrame(100, kFlow - 1399, 1400, kSession, kFlow) == mux::MuxTxAdmit::HoldFlow));
}

BOOST_AUTO_TEST_CASE(untracked_frames_always_send) {
    // ACK / FEC / flow_v2 control frames are never retained: never held.
    BOOST_TEST((mux::AdmitTxFrame(kSession * 4, kFlow * 4, 0, kSession, kFlow) == mux::MuxTxAdmit::Send));
}

BOOST_AUTO_TEST_CASE(zero_window_is_unlimited) {
    const std::size_t big = std::numeric_limits<std::size_t>::max() - 1;
    BOOST_TEST((mux::AdmitTxFrame(big, big, 1, 0, 0) == mux::MuxTxAdmit::Send));
    BOOST_TEST(!mux::MuxTxOverHardCap(big, 1, 0, 2));
}

BOOST_AUTO_TEST_CASE(empty_window_admits_oversized_frame) {
    // Progress guarantee: nothing in flight means no ACK will ever arrive, so
    // a frame larger than the window must still go out.
    BOOST_TEST(mux::MuxTxFitsWindow(0, 64, 32));
    BOOST_TEST((mux::AdmitTxFrame(0, 0, 64, 32, 32) == mux::MuxTxAdmit::Send));
    BOOST_TEST(!mux::MuxTxFitsWindow(1, 64, 32));
}

BOOST_AUTO_TEST_CASE(fits_window_boundaries_do_not_overflow) {
    BOOST_TEST(mux::MuxTxFitsWindow(900, 100, 1000));
    BOOST_TEST(!mux::MuxTxFitsWindow(901, 100, 1000));
    const std::size_t max = std::numeric_limits<std::size_t>::max();
    BOOST_TEST(!mux::MuxTxFitsWindow(max, max, 1000));
    BOOST_TEST(!mux::MuxTxFitsWindow(1, max, 1000));
}

BOOST_AUTO_TEST_CASE(hard_cap_is_terminal_bound) {
    BOOST_TEST(mux::MuxTxHardCap(kSession, 2) == 2 * kSession);
    BOOST_TEST(!mux::MuxTxOverHardCap(kSession, kSession, kSession, 2));
    BOOST_TEST(mux::MuxTxOverHardCap(kSession, kSession + 1, kSession, 2));
    BOOST_TEST(mux::MuxTxOverHardCap(0, 2 * kSession + 1, kSession, 2));
    // factor < 1 is treated as 1: the window itself is the hard bound.
    BOOST_TEST(mux::MuxTxHardCap(kSession, 0) == kSession);
    BOOST_TEST(mux::MuxTxOverHardCap(kSession, 1, kSession, 0));
}

BOOST_AUTO_TEST_CASE(hard_cap_saturates) {
    const std::size_t max = std::numeric_limits<std::size_t>::max();
    BOOST_TEST(mux::MuxTxHardCap(max / 2 + 1, 2) == max);
    BOOST_TEST(!mux::MuxTxOverHardCap(max - 1, 1, max / 2 + 1, 2));
}

BOOST_AUTO_TEST_CASE(acceleration_recouples_at_half_the_flow_cap) {
    // Early completion lets the read pump run ahead; at half the per-flow cap
    // it must wait for writes again so the cap itself is never reached.
    const std::size_t hw = 4096, max_frames = 256, max_bytes = 1 << 20;
    BOOST_TEST(!mux::MuxTxShouldCoupleCompletion(0, hw, false, 0, 0, max_frames, max_bytes));
    BOOST_TEST(!mux::MuxTxShouldCoupleCompletion(10, hw, false, 127, (512 << 10) - 1, max_frames, max_bytes));
    BOOST_TEST(mux::MuxTxShouldCoupleCompletion(10, hw, false, 128, 0, max_frames, max_bytes));
    BOOST_TEST(mux::MuxTxShouldCoupleCompletion(10, hw, false, 8, 512 << 10, max_frames, max_bytes));
}

BOOST_AUTO_TEST_CASE(acceleration_recouples_on_session_backlog_or_parked_flow) {
    BOOST_TEST(mux::MuxTxShouldCoupleCompletion(4096, 4096, false, 0, 0, 256, 1 << 20));
    BOOST_TEST(mux::MuxTxShouldCoupleCompletion(0, 4096, true, 0, 0, 256, 1 << 20));
    // Zero limits disable the respective check.
    BOOST_TEST(!mux::MuxTxShouldCoupleCompletion(100000, 0, false, 100000, 100000, 0, 0));
}

BOOST_AUTO_TEST_CASE(flow_control_ignores_stale_versions) {
    // XOFF v2 then XON v1 arriving late over another carrier: the XON is stale.
    BOOST_TEST(mux::MuxFlowControlIsFresh(false, 0, 1));
    BOOST_TEST(mux::MuxFlowControlIsFresh(true, 1, 2));
    BOOST_TEST(!mux::MuxFlowControlIsFresh(true, 2, 1));
    BOOST_TEST(!mux::MuxFlowControlIsFresh(true, 2, 2)); // duplicate
}

BOOST_AUTO_TEST_CASE(flow_control_version_wraps) {
    BOOST_TEST(mux::MuxFlowControlIsFresh(true, 0xFFFFFFFFu, 0u));
    BOOST_TEST(!mux::MuxFlowControlIsFresh(true, 0u, 0xFFFFFFFFu));
}

BOOST_AUTO_TEST_CASE(least_loaded_carrier_is_picked) {
    std::vector<mux::MuxLinkLoad> links(3);
    links[0].queued_bytes = 64 << 10; links[0].has_credit = true;
    links[1].queued_bytes = 8 << 10;  links[1].has_credit = true;
    links[2].queued_bytes = 0;        links[2].has_credit = false; // no room for this frame
    BOOST_TEST(mux::MuxPickLeastLoaded(links) == 1);
    links[0].queued_bytes = 8 << 10; // tie: lower SRTT wins
    links[0].has_rtt = true; links[0].srtt_ms = 40;
    links[1].has_rtt = true; links[1].srtt_ms = 90;
    BOOST_TEST(mux::MuxPickLeastLoaded(links) == 0);
    links[0].srtt_ms = 85; // within the 10 ms margin of 90: list order wins
    BOOST_TEST(mux::MuxPickLeastLoaded(links) == 0);
    links[0].queued_bytes = links[1].queued_bytes;
    links[1].srtt_ms = 80; // 85 vs 80: not a clear win either, first listed stays
    BOOST_TEST(mux::MuxPickLeastLoaded(links) == 0);
    links[1].srtt_ms = 60; // 25 ms faster: SRTT wins the tie
    BOOST_TEST(mux::MuxPickLeastLoaded(links) == 1);
    for (auto& l : links) { l.has_credit = false; }
    BOOST_TEST(mux::MuxPickLeastLoaded(links) == -1);
}

BOOST_AUTO_TEST_CASE(xon_resumes_at_half_the_threshold) {
    using A = mux::MuxFlowControlAction;
    const std::int64_t t = 1000;
    BOOST_TEST((mux::MuxFlowControlNext(true, 999, t) == A::None));
    BOOST_TEST((mux::MuxFlowControlNext(true, 1000, t) == A::SendXoff));
    BOOST_TEST((mux::MuxFlowControlNext(false, 501, t) == A::None)); // still draining
    BOOST_TEST((mux::MuxFlowControlNext(false, 500, t) == A::SendXon)); // half, not zero
    BOOST_TEST((mux::MuxFlowControlNext(false, 0, t) == A::SendXon));
    BOOST_TEST((mux::MuxFlowControlNext(true, 5000, 0) == A::None)); // disabled
}

BOOST_AUTO_TEST_CASE(zero_copy_push_only_for_well_filled_reads) {
    const int buf = 65526, min = 4096;
    BOOST_TEST(mux::MuxPushIsZeroCopy(65526, buf, min));
    BOOST_TEST(mux::MuxPushIsZeroCopy(32763, buf, min));   // exactly half
    BOOST_TEST(!mux::MuxPushIsZeroCopy(32762, buf, min));  // under half: copy
    BOOST_TEST(!mux::MuxPushIsZeroCopy(4096, buf, min));   // 16x waste: copy
    BOOST_TEST(!mux::MuxPushIsZeroCopy(1000, 1500, min));  // tiny: copy
    BOOST_TEST(mux::MuxPushIsZeroCopy(4096, 8000, min));
    BOOST_TEST(!mux::MuxPushIsZeroCopy(0, 0, 0));
}
