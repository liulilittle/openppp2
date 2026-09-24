// Wave 4: PTO exponential backoff (saturating shift), path-aware fast
// retransmit (time threshold), MarkRetransmitted link_id tracking, and
// spurious RTX detection.
//
// These tests exercise MuxRetransmitBuffer in isolation — no vmux_net,
// no real transport. The integration with vmux_net's per-link PTO and
// schedulable() link selection is validated by the existing wave0/wave3
// tests and the compile-time linkage of vmux_net.cpp.
#define BOOST_TEST_MODULE vmux_wave4_pto_rtx_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <vector>

#include <ppp/app/mux/MuxRetransmitBuffer.h>

namespace mux = ppp::app::mux;

namespace {
    std::shared_ptr<std::uint8_t> make_frame(int value) {
        return std::make_shared<std::uint8_t>(static_cast<std::uint8_t>(value));
    }
}

// ---------------------------------------------------------------------------
// Exponential backoff: CollectExpired uses base_pto << min(attempts, 5)
// clamped to pto_max.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(backoff_attempts_0_uses_base_pto) {
    // Fresh entry (attempts=0): effective PTO = base_pto.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));

    std::vector<std::uint64_t> not_expired;
    // now=1499, base=500 → 499 elapsed < 500 PTO → not expired
    rtx.CollectExpired(1499, 500, 60000, 32, not_expired);
    BOOST_TEST(not_expired.empty());

    // now=1500 → 500 >= 500 → expired
    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(1500, 500, 60000, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_attempts_3_uses_8x_base_pto) {
    // After 3 retransmissions, effective PTO = base << 3 = 8 * base.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    rtx.MarkRetransmitted(key, 1100, 1); // attempts=1
    rtx.MarkRetransmitted(key, 1200, 1); // attempts=2
    rtx.MarkRetransmitted(key, 1300, 1); // attempts=3, last_sent=1300

    std::vector<std::uint64_t> expired;
    // base=100, shift=3 → 800. now=1300+799=2099 < 1300+800=2100 → not expired
    rtx.CollectExpired(2099, 100, 60000, 32, expired);
    BOOST_TEST(expired.empty());

    // now=2100 → 800 elapsed >= 800 → expired
    rtx.CollectExpired(2100, 100, 60000, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_attempts_5_uses_32x_base_pto) {
    // After 5 retransmissions, shift=5 → 32x.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 5; ++i) {
        rtx.MarkRetransmitted(key, 1000 + i * 100, 1);
    }
    // attempts=5, last_sent=1500

    std::vector<std::uint64_t> expired;
    // base=100, shift=5 → 3200. now=1500+3199=4699 < 4700 → not expired
    rtx.CollectExpired(4699, 100, 60000, 32, expired);
    BOOST_TEST(expired.empty());

    // now=4700 → 3200 >= 3200 → expired
    rtx.CollectExpired(4700, 100, 60000, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_attempts_8_still_uses_32x_shift) {
    // Attempts > 5 are clamped to shift=5 (32x), not 256x.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 8; ++i) {
        rtx.MarkRetransmitted(key, 1000 + i * 100, 1);
    }
    // attempts=8, last_sent=1800

    std::vector<std::uint64_t> expired;
    // base=100, shift=5 (clamped from 8) → 3200.
    // now=1800+3199=4999 < 5000 → not expired
    rtx.CollectExpired(4999, 100, 60000, 32, expired);
    BOOST_TEST(expired.empty());

    // now=5000 → 3200 >= 3200 → expired
    rtx.CollectExpired(5000, 100, 60000, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_clamped_to_pto_max) {
    // Even with high attempts, effective PTO never exceeds pto_max.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 5; ++i) {
        rtx.MarkRetransmitted(key, 1000 + i * 100, 1);
    }
    // attempts=5, last_sent=1500

    std::vector<std::uint64_t> expired;
    // base=1000, shift=5 → 32000, but pto_max=5000 → clamp to 5000.
    // now=1500+4999=6499 < 6500 → not expired
    rtx.CollectExpired(6499, 1000, 5000, 32, expired);
    BOOST_TEST(expired.empty());

    // now=6500 → 5000 >= 5000 → expired
    rtx.CollectExpired(6500, 1000, 5000, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

// ---------------------------------------------------------------------------
// Saturating shift: no overflow to zero even with extreme base_pto.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(saturating_shift_no_overflow) {
    // base_pto near UINT64_MAX/2 should saturate, not wrap to 0.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    rtx.MarkRetransmitted(key, 1100, 1); // attempts=1

    std::vector<std::uint64_t> expired;
    // base = UINT64_MAX/2, shift=1 → would overflow without saturation.
    // pto_max = UINT64_MAX → effective should saturate to UINT64_MAX.
    // now - last_sent_tick = small, much less than UINT64_MAX → not expired.
    rtx.CollectExpired(1200, UINT64_MAX / 2, UINT64_MAX, 32, expired);
    BOOST_TEST(expired.empty());
}

// ---------------------------------------------------------------------------
// MarkRetransmitted updates last_link_id.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(mark_retransmitted_updates_last_link_id) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 5));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);

    // Verify orig_link_id is preserved.
    mux::MuxRtxEntry* entry = rtx.Find(key);
    BOOST_REQUIRE(entry != nullptr);
    BOOST_TEST(entry->orig_link_id == 5u);
    BOOST_TEST(entry->last_link_id == 5u);

    // Retransmit on a different link.
    rtx.MarkRetransmitted(key, 1100, 9);

    entry = rtx.Find(key);
    BOOST_REQUIRE(entry != nullptr);
    BOOST_TEST(entry->orig_link_id == 5u);  // Unchanged.
    BOOST_TEST(entry->last_link_id == 9u);   // Updated.
    BOOST_TEST(entry->attempts == 1u);
    BOOST_TEST(entry->last_sent_tick == 1100u);
}

BOOST_AUTO_TEST_CASE(mark_retransmitted_default_link_id_is_zero) {
    // Default parameter link_id=0 should not crash and should set last_link_id=0.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    rtx.MarkRetransmitted(key, 1100); // No link_id argument.

    mux::MuxRtxEntry* entry = rtx.Find(key);
    BOOST_REQUIRE(entry != nullptr);
    BOOST_TEST(entry->last_link_id == 0u);
    BOOST_TEST(entry->attempts == 1u);
}

// ---------------------------------------------------------------------------
// Fast retransmit time threshold: entries sent too recently are not
// flagged as fast-RTX candidates even when DSN gap >= fast_threshold.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(fast_time_threshold_suppresses_recent_sends) {
    mux::MuxRetransmitBuffer rtx;
    // Send frames 1..6 at tick=1000.
    for (uint32_t seq = 1; seq <= 6; ++seq) {
        BOOST_TEST(rtx.Track(3, seq, make_frame((int)seq), 10, 1000, 1 << 20, 0));
    }

    // ACK covers 4..6 with largest=6 at tick=1010.
    // Gap for seq 1: 6-1=5 >= 3 (fast_threshold), but time elapsed = 10ms.
    // fast_time_threshold=50 → 10 < 50 → suppressed.
    std::vector<uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {4, 6} };
    rtx.Ack(3, 6, ranges, 1010, 3, 50, fast);
    BOOST_TEST(fast.empty());

    // Same ACK at tick=1060: 60 >= 50 → candidates appear.
    std::vector<uint64_t> fast2;
    rtx.Ack(3, 6, ranges, 1060, 3, 50, fast2);
    // Note: fast_rtx_mark was NOT set in the suppressed call, so these are
    // still eligible.
    BOOST_REQUIRE_EQUAL(fast2.size(), 3u);
    for (uint64_t key : fast2) {
        const uint32_t seq = static_cast<uint32_t>(key & 0xFFFFFFFFu);
        BOOST_TEST(seq <= 3u);
    }
}

BOOST_AUTO_TEST_CASE(fast_time_threshold_zero_disables_time_gate) {
    // fast_time_threshold=0 → pure packet-count threshold (backward compatible).
    mux::MuxRetransmitBuffer rtx;
    for (uint32_t seq = 1; seq <= 6; ++seq) {
        BOOST_TEST(rtx.Track(3, seq, make_frame((int)seq), 10, 1000, 1 << 20, 0));
    }

    std::vector<uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {4, 6} };
    // tick=1001, just 1ms after send. With time_threshold=0, should still fire.
    rtx.Ack(3, 6, ranges, 1001, 3, 0, fast);
    BOOST_REQUIRE_EQUAL(fast.size(), 3u);
}

// ---------------------------------------------------------------------------
// Spurious RTX scenario: a frame is scheduled for retransmission but gets
// ACKed before retransmit_pending can act on it. Find() returns nullptr,
// and the caller should skip it (tested here by the absence of crash and
// correct remaining state).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(spurious_rtx_frame_acked_before_resend) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));
    BOOST_TEST(rtx.Track(0, 2, make_frame(2), 10, 1000, 1 << 20, 0));
    BOOST_TEST(rtx.Track(0, 3, make_frame(3), 10, 1000, 1 << 20, 0));

    // Simulate: seq 1 gets fast-RTX candidate, but is ACKed before resend.
    const uint64_t key1 = mux::MuxRetransmitBuffer::Key(0, 1);

    // ACK covers only seq 1 → releases it.
    std::vector<uint64_t> fast;
    std::vector<mux::MuxAckRange> ack_ranges = { {1, 1} };
    rtx.Ack(0, 1, ack_ranges, 1100, 3, 0, fast);

    // Now Find(key1) returns nullptr — spurious RTX.
    mux::MuxRtxEntry* entry = rtx.Find(key1);
    BOOST_TEST(entry == nullptr);

    // The other entries are still there.
    BOOST_TEST(rtx.size() == 2u);

    // MarkRetransmitted on a missing key is a safe no-op.
    rtx.MarkRetransmitted(key1, 1200, 1);
    BOOST_TEST(rtx.size() == 2u); // No phantom entry created.
}

// ---------------------------------------------------------------------------
// Mixed: entry with high attempts doesn't interfere with fresh entry.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(backoff_per_entry_isolation) {
    mux::MuxRetransmitBuffer rtx;
    // Entry A: seq 1, sent at 1000, 4 retransmissions (shift=4).
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, 0));
    const uint64_t keyA = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 4; ++i) {
        rtx.MarkRetransmitted(keyA, 1000 + i * 100, 1);
    }
    // Entry B: seq 2, sent at 1000, no retransmissions (shift=0).
    BOOST_TEST(rtx.Track(0, 2, make_frame(2), 10, 1000, 1 << 20, 0));

    // base=100:
    //   A: shift=4 → 1600ms PTO. last_sent=1400. Expires at 1400+1600=3000.
    //   B: shift=0 → 100ms PTO. last_sent=1000. Expires at 1000+100=1100.
    std::vector<uint64_t> expired;
    rtx.CollectExpired(1100, 100, 60000, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
    // Only B should expire (key for seq 2).
    const uint32_t exp_seq = static_cast<uint32_t>(expired[0] & 0xFFFFFFFFu);
    BOOST_TEST(exp_seq == 2u);

    // A expires later at 3000. B is also expired at this point (expired at
    // 1100), so we verify A is among the expired entries.
    std::vector<uint64_t> expired2;
    rtx.CollectExpired(3000, 100, 60000, 32, expired2);
    BOOST_REQUIRE_EQUAL(expired2.size(), 2u);
    // A (seq 1) should be in the result.
    bool found_a = false;
    for (uint64_t k : expired2) {
        const uint32_t s = static_cast<uint32_t>(k & 0xFFFFFFFFu);
        if (s == 1u) found_a = true;
    }
    BOOST_TEST(found_a);
}
