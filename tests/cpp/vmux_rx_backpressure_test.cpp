// Receive-side reorder backpressure and head-of-line gap clock.
//
// Field log (2026-10-18, client, mode=flow ordering=compat, 9 carriers):
//   "compat reorder cap exceeded: buffered=16770274 incoming=11689
//    cap=16777216; rebuilding session" ~10 s into every download.
// The cap is now soft (pause the delivering carrier) and only cap * hard
// factor rebuilds; the gap clock measures stall time, not buffer age.
#define BOOST_TEST_MODULE vmux_rx_backpressure_test
#include <boost/test/included/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>

#include <ppp/app/mux/MuxRxBackpressure.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(within_soft_cap_accepts) {
    BOOST_TEST((mux::AdmitReorderBytes(0, 100, 1000, 2) == mux::MuxReorderAdmit::Accept));
    BOOST_TEST((mux::AdmitReorderBytes(900, 100, 1000, 2) == mux::MuxReorderAdmit::Accept));
}

BOOST_AUTO_TEST_CASE(over_soft_cap_pauses_instead_of_rejecting) {
    // The exact field numbers: one frame over the 16 MiB cap.
    const std::size_t cap = 16u << 20;
    BOOST_TEST((mux::AdmitReorderBytes(16770274u, 11689u, cap, 2) == mux::MuxReorderAdmit::AcceptAndPause));
    BOOST_TEST((mux::AdmitReorderBytes(1000, 1, 1000, 2) == mux::MuxReorderAdmit::AcceptAndPause));
    BOOST_TEST((mux::AdmitReorderBytes(1999, 1, 1000, 2) == mux::MuxReorderAdmit::AcceptAndPause));
}

BOOST_AUTO_TEST_CASE(over_hard_cap_rejects) {
    BOOST_TEST((mux::AdmitReorderBytes(2000, 1, 1000, 2) == mux::MuxReorderAdmit::Reject));
    // factor < 1 is treated as 1: soft cap == hard cap (old terminal behaviour).
    BOOST_TEST((mux::AdmitReorderBytes(1000, 1, 1000, 0) == mux::MuxReorderAdmit::Reject));
}

BOOST_AUTO_TEST_CASE(zero_cap_is_unlimited) {
    BOOST_TEST((mux::AdmitReorderBytes(std::numeric_limits<std::size_t>::max() - 1, 1, 0, 2) ==
        mux::MuxReorderAdmit::Accept));
}

BOOST_AUTO_TEST_CASE(hard_cap_and_sum_saturate) {
    const std::size_t big = std::numeric_limits<std::size_t>::max() / 2 + 1;
    BOOST_TEST(mux::MuxReorderHardCap(big, 2) == std::numeric_limits<std::size_t>::max());
    BOOST_TEST(mux::MuxReorderHardCap(1000, 3) == 3000u);
    // buffered + incoming overflowing size_t must not wrap into Accept.
    BOOST_TEST((mux::AdmitReorderBytes(std::numeric_limits<std::size_t>::max(), 10, 1000, 2) ==
        mux::MuxReorderAdmit::Reject));
}

BOOST_AUTO_TEST_CASE(resume_uses_half_cap_hysteresis) {
    BOOST_TEST(!mux::MuxReorderShouldResume(501, 1000));
    BOOST_TEST(mux::MuxReorderShouldResume(500, 1000));
    BOOST_TEST(mux::MuxReorderShouldResume(0, 1000));
    BOOST_TEST(mux::MuxReorderShouldResume(123456, 0));
}

BOOST_AUTO_TEST_CASE(never_pause_every_live_carrier) {
    BOOST_TEST(!mux::MuxPauseWouldStallAll(8, 9));
    BOOST_TEST(mux::MuxPauseWouldStallAll(9, 9));
    BOOST_TEST(mux::MuxPauseWouldStallAll(1, 1)); // single carrier: backpressure must not self-deadlock
    BOOST_TEST(mux::MuxPauseWouldStallAll(0, 0));
}

BOOST_AUTO_TEST_CASE(gap_clock_restarts_on_progress_under_sustained_reorder) {
    // Sustained multi-carrier load: the buffer is never empty, but every 100 ms
    // in-order delivery advances. Over 10 s the gap clock must never exceed the
    // 3 s timeout. The old rule (tick of the first gap, cleared only on empty)
    // would have expired after 3 s.
    const std::uint64_t timeout = 3000;
    std::uint64_t clock = 0;
    std::uint64_t old_rule = 0;
    bool old_rule_expired = false;
    for (std::uint64_t now = 1000; now <= 11000; now += 100) {
        clock = mux::MuxGapClockOnBuffered(clock, now);       // a future frame is buffered
        if (old_rule == 0) {
            old_rule = now;
        }
        BOOST_TEST(!mux::MuxGapExpired(clock, now + 50, timeout));
        clock = mux::MuxGapClockAfterAdvance(now + 50, /*still_buffered=*/true); // head gap closed
        old_rule_expired = old_rule_expired || mux::MuxGapExpired(old_rule, now + 50, timeout);
    }
    BOOST_TEST(old_rule_expired);
}

BOOST_AUTO_TEST_CASE(gap_clock_expires_on_real_stall) {
    const std::uint64_t timeout = 3000;
    std::uint64_t clock = mux::MuxGapClockOnBuffered(0, 5000);
    clock = mux::MuxGapClockOnBuffered(clock, 5100);  // more frames, same gap: keep start
    BOOST_TEST(clock == 5000u);
    BOOST_TEST(!mux::MuxGapExpired(clock, 8000, timeout));
    BOOST_TEST(mux::MuxGapExpired(clock, 8001, timeout));
}

BOOST_AUTO_TEST_CASE(gap_clock_clears_when_drained) {
    BOOST_TEST(mux::MuxGapClockAfterAdvance(7000, /*still_buffered=*/false) == 0u);
    BOOST_TEST(!mux::MuxGapExpired(0, 1000000, 1));
}
