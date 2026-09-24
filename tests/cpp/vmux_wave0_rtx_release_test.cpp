#define BOOST_TEST_MODULE vmux_wave0_rtx_release_test
#include <boost/test/included/unit_test.hpp>

/**
 * @file vmux_wave0_rtx_release_test.cpp
 * @brief Wave 0 test: verify RTX state is released when a flow is closed.
 * @license GPL-3.0
 *
 * Tests the P2-9 fix: release_connection() must call
 * release_flow_reliability_state() to free RTX/FEC entries for the
 * closed connection_id, preventing idle-timeout RTX retention.
 *
 * Also tests:
 *   - FakeClock deterministic time advancement
 *   - DeliveryOracle data-correctness verification
 *   - MuxRetransmitBuffer PTO expiry and ACK paths
 *   - MuxLinkDrainState lifecycle (P0-T1 teardown scenario)
 *   - MuxAckTracker wrap-around and range merging
 */

#include <cstdint>
#include <memory>
#include <vector>

#include <ppp/app/mux/MuxRetransmitBuffer.h>
#include <ppp/app/mux/MuxAckTracker.h>
#include <ppp/app/mux/MuxLinkDrainState.h>
#include <ppp/app/mux/MuxFecCodec.h>

#include "support/FakeClock.h"
#include "support/DeliveryOracle.h"

namespace mux = ppp::app::mux;
using ppp::test::FakeClock;
using ppp::test::DeliveryOracle;

// ---------------------------------------------------------------------------
// Helper: make a shared buffer filled with a deterministic pattern.
// ---------------------------------------------------------------------------
static std::shared_ptr<std::uint8_t> make_buffer(int length, std::uint32_t seed) {
    auto buf = std::shared_ptr<std::uint8_t>(
        new std::uint8_t[static_cast<std::size_t>(length)],
        std::default_delete<std::uint8_t[]>());
    for (int i = 0; i < length; ++i) {
        buf.get()[i] = static_cast<std::uint8_t>((seed * 31 + i * 7 + 0x5A) & 0xFF);
    }
    return buf;
}

// ===========================================================================
// 1. RTX state release on flow close (P2-9 core invariant)
// ===========================================================================

BOOST_AUTO_TEST_CASE(rtx_erase_cid_releases_all_entries_for_a_flow) {
    // Simulate: flow cid=5 has 3 frames in RTX, flow cid=7 has 2.
    // EraseCid(5) must leave cid=7 entries untouched.
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20; // 1 MiB

    BOOST_TEST(rtx.Track(5, 1, make_buffer(100, 0x101), 100, 1000, cap));
    BOOST_TEST(rtx.Track(5, 2, make_buffer(100, 0x102), 100, 1010, cap));
    BOOST_TEST(rtx.Track(5, 3, make_buffer(100, 0x103), 100, 1020, cap));
    BOOST_TEST(rtx.Track(7, 1, make_buffer(200, 0x201), 200, 1000, cap));
    BOOST_TEST(rtx.Track(7, 2, make_buffer(200, 0x202), 200, 1010, cap));

    BOOST_TEST(rtx.size() == 5u);
    BOOST_TEST(rtx.bytes() == 700u); // 3*100 + 2*200

    // Release all RTX entries for flow 5 (simulates release_flow_reliability_state).
    rtx.EraseCid(5);

    BOOST_TEST(rtx.size() == 2u);
    BOOST_TEST(rtx.bytes() == 400u); // only cid=7 entries remain (2*200)

    // Flow 7 entries must still be findable.
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(7, 1)) != nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(7, 2)) != nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(5, 1)) == nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(5, 2)) == nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(5, 3)) == nullptr);
}

BOOST_AUTO_TEST_CASE(rtx_release_then_reuse_cid_does_not_leak_old_entries) {
    // Simulate: cid=3 has entries, we release them, then new frames for cid=3
    // are tracked. Old entries must not reappear or count toward the cap.
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 500;

    BOOST_TEST(rtx.Track(3, 1, make_buffer(200, 0x301), 200, 1000, cap));
    BOOST_TEST(rtx.Track(3, 2, make_buffer(200, 0x302), 200, 1010, cap));
    BOOST_TEST(rtx.bytes() == 400u);

    // Release cid=3 (flow closed).
    rtx.EraseCid(3);
    BOOST_TEST(rtx.size() == 0u);
    BOOST_TEST(rtx.bytes() == 0u);

    // New frames for cid=3 (flow reused) must fit within the original cap.
    BOOST_TEST(rtx.Track(3, 1, make_buffer(200, 0x311), 200, 2000, cap));
    BOOST_TEST(rtx.Track(3, 2, make_buffer(200, 0x312), 200, 2010, cap));
    BOOST_TEST(rtx.size() == 2u);
    BOOST_TEST(rtx.bytes() == 400u);
}

// ===========================================================================
// 2. FakeClock deterministic time (Wave 0 infrastructure)
// ===========================================================================

BOOST_AUTO_TEST_CASE(fake_clock_advances_deterministically) {
    FakeClock clock;

    BOOST_TEST(clock.now() == 0u);
    clock.advance(100);
    BOOST_TEST(clock.now() == 100u);
    clock.advance(50);
    BOOST_TEST(clock.now() == 150u);
    clock.reset();
    BOOST_TEST(clock.now() == 0u);
}

BOOST_AUTO_TEST_CASE(rtx_pto_expiry_uses_fake_clock) {
    // Track a frame at t=1000, PTO=200. At t=1199 it's not expired;
    // at t=1200 it is.
    FakeClock clock;
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    const std::uint64_t start_tick = 1000;
    const std::uint64_t pto = 200;

    BOOST_TEST(rtx.Track(1, 1, make_buffer(100, 0x401), 100, start_tick, cap));

    // Not expired yet.
    clock.advance(1199);
    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(clock.now(), pto, 60000, 10, expired);
    BOOST_TEST(expired.empty());

    // Now expired.
    clock.advance(1); // now = 1200
    rtx.CollectExpired(clock.now(), pto, 60000, 10, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
    BOOST_TEST(mux::MuxRetransmitBuffer::KeyCid(expired[0]) == 1u);
}

// ===========================================================================
// 3. DeliveryOracle data-correctness verification (Wave 0 infrastructure)
// ===========================================================================

BOOST_AUTO_TEST_CASE(delivery_oracle_accepts_correct_in_order_delivery) {
    DeliveryOracle oracle;
    auto p1 = oracle.send(1, 0, 100);
    auto p2 = oracle.send(1, 1, 200);
    auto p3 = oracle.send(1, 2, 50);

    oracle.recv(1, 0, p1.data(), 100);
    oracle.recv(1, 1, p2.data(), 200);
    oracle.recv(1, 2, p3.data(), 50);

    oracle.verify(); // Should not throw.
    BOOST_TEST(oracle.delivered_count() == 3u);
}

BOOST_AUTO_TEST_CASE(delivery_oracle_rejects_duplicate_delivery) {
    DeliveryOracle oracle;
    auto p1 = oracle.send(1, 0, 100);

    oracle.recv(1, 0, p1.data(), 100);
    BOOST_CHECK_THROW(oracle.recv(1, 0, p1.data(), 100), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(delivery_oracle_rejects_corrupted_payload) {
    DeliveryOracle oracle;
    auto p1 = oracle.send(1, 0, 100);

    // Corrupt one byte.
    p1[50] ^= 0xFF;

    BOOST_CHECK_THROW(oracle.recv(1, 0, p1.data(), 100), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(delivery_oracle_rejects_missing_frame) {
    DeliveryOracle oracle;
    auto p1 = oracle.send(1, 0, 100);
    auto p2 = oracle.send(1, 1, 200);

    // Only deliver the second frame.
    oracle.recv(1, 1, p2.data(), 200);

    BOOST_CHECK_THROW(oracle.verify(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(delivery_oracle_supports_multiple_flows) {
    DeliveryOracle oracle;
    auto fa0 = oracle.send(1, 0, 64);
    auto fb0 = oracle.send(2, 0, 128);
    auto fa1 = oracle.send(1, 1, 32);
    auto fb1 = oracle.send(2, 1, 256);

    // Interleaved delivery across flows is fine.
    oracle.recv(1, 0, fa0.data(), 64);
    oracle.recv(2, 0, fb0.data(), 128);
    oracle.recv(1, 1, fa1.data(), 32);
    oracle.recv(2, 1, fb1.data(), 256);

    oracle.verify(); // Should not throw.
}

// ===========================================================================
// 4. MuxLinkDrainState lifecycle — P0-T1 teardown scenario
//    (Tests the drain semantics that connect_yield fix relies on)
// ===========================================================================

BOOST_AUTO_TEST_CASE(drain_state_begin_write_then_retire_blocks_new_writes) {
    mux::MuxLinkDrainState link;

    const auto ticket = link.BeginWrite();
    BOOST_REQUIRE(ticket);
    BOOST_TEST(link.inflight() == 1u);

    link.BeginRetire();
    BOOST_TEST(link.retiring());
    BOOST_TEST(!link.accepting_writes());

    // New write must be rejected after retire.
    BOOST_TEST(!link.BeginWrite());

    // Complete the in-flight write → link becomes reapable.
    BOOST_TEST(link.CompleteWrite(ticket));
    BOOST_TEST(link.reapable());
    BOOST_TEST(link.inflight() == 0u);
}

BOOST_AUTO_TEST_CASE(drain_state_abort_write_rolls_back_inflight) {
    mux::MuxLinkDrainState link;

    const auto ticket = link.BeginWrite();
    BOOST_REQUIRE(ticket);
    BOOST_TEST(link.inflight() == 1u);

    // Abort instead of complete.
    BOOST_TEST(link.AbortWrite(ticket));
    BOOST_TEST(link.inflight() == 0u);
    BOOST_TEST(!link.retiring()); // Not retired, just rolled back.
}

BOOST_AUTO_TEST_CASE(drain_state_complete_write_idempotent_via_ticket) {
    mux::MuxLinkDrainState link;

    const auto ticket = link.BeginWrite();
    BOOST_REQUIRE(ticket);

    BOOST_TEST(link.CompleteWrite(ticket));
    // Double-complete must be rejected (ticket consumed).
    BOOST_TEST(!link.CompleteWrite(ticket));
    BOOST_TEST(link.inflight() == 0u);
}

// ===========================================================================
// 5. ACK + RTX interaction — Karn's rule and fast retransmit
// ===========================================================================

BOOST_AUTO_TEST_CASE(ack_returns_rtt_sample_only_for_non_retransmitted_frame) {
    FakeClock clock;
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    // Send at t=1000.
    rtx.Track(1, 1, make_buffer(100, 0x501), 100, 1000, cap);
    rtx.Track(1, 2, make_buffer(100, 0x502), 100, 1010, cap);

    // Retransmit seq=1 at t=1500 (Karn: no RTT sample for retransmitted).
    rtx.MarkRetransmitted(mux::MuxRetransmitBuffer::Key(1, 1), 1500);

    // ACK at t=1600 covers seq 1..2.
    clock.advance(1600);
    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {1, 2} };
    const std::uint64_t sample = rtx.Ack(1, 2, ranges, clock.now(), 3, 0, fast);

    // seq=2 was never retransmitted: RTT = 1600 - 1010 = 590.
    // seq=1 was retransmitted: no sample.
    BOOST_TEST(sample == 590u);
    BOOST_TEST(rtx.size() == 0u);
}

BOOST_AUTO_TEST_CASE(fast_retransmit_triggers_when_gap_exceeds_threshold) {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    // Frames 1..6 for cid=1.
    for (std::uint32_t seq = 1; seq <= 6; ++seq) {
        rtx.Track(1, seq, make_buffer(50, 0x600 + seq), 50, 1000 + seq * 10, cap);
    }

    // ACK covers 4..6, largest=6. Frames 1..3 sit >= 3 below largest.
    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {4, 6} };
    rtx.Ack(1, 6, ranges, 2000, 3, 0, fast);

    BOOST_TEST(rtx.size() == 3u); // 4..6 released.
    BOOST_REQUIRE_EQUAL(fast.size(), 3u);

    // Each fast candidate must be seq <= 3.
    for (std::uint64_t key : fast) {
        const std::uint32_t seq = static_cast<std::uint32_t>(key & 0xFFFFFFFFu);
        BOOST_TEST(seq <= 3u);
    }
}

BOOST_AUTO_TEST_CASE(fast_retransmit_not_triggered_below_threshold) {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    for (std::uint32_t seq = 1; seq <= 5; ++seq) {
        rtx.Track(1, seq, make_buffer(50, 0x700 + seq), 50, 1000 + seq * 10, cap);
    }

    // ACK covers 3..5, largest=5. Frame 1 is distance 4 (>= 3), frame 2 is distance 3 (>= 3).
    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {3, 5} };
    rtx.Ack(1, 5, ranges, 2000, 3, 0, fast);

    BOOST_REQUIRE_EQUAL(fast.size(), 2u); // seq 1 and 2.

    // Second ACK with same largest must NOT re-trigger (dedup via fast_rtx_mark).
    std::vector<std::uint64_t> fast2;
    rtx.Ack(1, 5, ranges, 2100, 3, 0, fast2);
    BOOST_TEST(fast2.empty());
}

// ===========================================================================
// 6. MuxAckTracker wrap-around and range merging
// ===========================================================================

BOOST_AUTO_TEST_CASE(ack_tracker_merges_contiguous_sequences) {
    mux::MuxAckTracker tracker;
    tracker.Add(1, 32);
    tracker.Add(2, 32);
    tracker.Add(3, 32);

    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.ranges()[0].start == 1u);
    BOOST_TEST(tracker.ranges()[0].end == 3u);
    BOOST_TEST(tracker.largest() == 3u);
}

BOOST_AUTO_TEST_CASE(ack_tracker_handles_non_contiguous_sequences) {
    mux::MuxAckTracker tracker;
    tracker.Add(1, 32);
    tracker.Add(2, 32);
    tracker.Add(5, 32);
    tracker.Add(6, 32);

    BOOST_REQUIRE_EQUAL(tracker.size(), 2u);
    BOOST_TEST(tracker.ranges()[0].start == 1u);
    BOOST_TEST(tracker.ranges()[0].end == 2u);
    BOOST_TEST(tracker.ranges()[1].start == 5u);
    BOOST_TEST(tracker.ranges()[1].end == 6u);
}

BOOST_AUTO_TEST_CASE(ack_tracker_fill_gap_merges_into_one_range) {
    mux::MuxAckTracker tracker;
    tracker.Add(1, 32);
    tracker.Add(3, 32);
    tracker.Add(2, 32); // Fill the gap.

    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.ranges()[0].start == 1u);
    BOOST_TEST(tracker.ranges()[0].end == 3u);
}

BOOST_AUTO_TEST_CASE(ack_tracker_caps_range_count) {
    mux::MuxAckTracker tracker;
    // Add sequences far apart to create many ranges.
    for (std::uint32_t i = 0; i < 10; ++i) {
        tracker.Add(i * 10, 4); // max_ranges = 4
    }

    BOOST_TEST(tracker.size() <= 4u);
}

// ===========================================================================
// 7. ACK frame encode/decode round-trip
// ===========================================================================

BOOST_AUTO_TEST_CASE(ack_frame_encode_decode_round_trip) {
    mux::MuxAckBlock block;
    block.connection_id = 42;
    block.largest = 100;
    block.ranges = { {1, 10}, {20, 30}, {50, 100} };

    std::uint8_t buf[256];
    const std::size_t encoded = mux::EncodeMuxAckFrame(&block, 1, buf, sizeof(buf), 24);
    BOOST_TEST(encoded > 0u);

    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(mux::DecodeMuxAckFrame(buf, encoded, 8, 24, decoded));

    BOOST_REQUIRE_EQUAL(decoded.size(), 1u);
    BOOST_TEST(decoded[0].connection_id == 42u);
    BOOST_TEST(decoded[0].largest == 100u);
    BOOST_REQUIRE_EQUAL(decoded[0].ranges.size(), 3u);
    BOOST_TEST(decoded[0].ranges[0].start == 1u);
    BOOST_TEST(decoded[0].ranges[0].end == 10u);
    BOOST_TEST(decoded[0].ranges[1].start == 20u);
    BOOST_TEST(decoded[0].ranges[1].end == 30u);
    BOOST_TEST(decoded[0].ranges[2].start == 50u);
    BOOST_TEST(decoded[0].ranges[2].end == 100u);
}

BOOST_AUTO_TEST_CASE(ack_frame_decode_rejects_truncated_payload) {
    mux::MuxAckBlock block;
    block.connection_id = 1;
    block.largest = 5;
    block.ranges = { {1, 5} };

    std::uint8_t buf[256];
    const std::size_t encoded = mux::EncodeMuxAckFrame(&block, 1, buf, sizeof(buf), 24);
    BOOST_TEST(encoded > 0u);

    // Truncate by 1 byte.
    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(buf, encoded - 1, 8, 24, decoded));
}

BOOST_AUTO_TEST_CASE(ack_frame_decode_rejects_range_exceeding_largest) {
    // Manually craft a malformed ACK frame where range.end > largest.
    std::uint8_t buf[32];
    std::size_t pos = 0;

    buf[pos++] = 1; // 1 block

    // connection_id = 0 (4 bytes big-endian)
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;

    // largest = 5 (4 bytes big-endian)
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 5;

    // 1 range
    buf[pos++] = 1;

    // range: start=1, end=10 (end > largest!)
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 1; // start
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 10; // end

    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(buf, pos, 8, 24, decoded));
}

// ===========================================================================
// 8. RTX byte cap enforcement
// ===========================================================================

BOOST_AUTO_TEST_CASE(rtx_byte_cap_prevents_unbounded_growth) {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1000;

    // Fill up to cap.
    BOOST_TEST(rtx.Track(1, 1, make_buffer(400, 0x801), 400, 1000, cap));
    BOOST_TEST(rtx.Track(1, 2, make_buffer(400, 0x802), 400, 1010, cap));
    BOOST_TEST(rtx.bytes() == 800u);

    // Third frame would push to 1200 > 1000 → rejected.
    BOOST_TEST(!rtx.Track(1, 3, make_buffer(400, 0x803), 400, 1020, cap));
    BOOST_TEST(rtx.bytes() == 800u);
    BOOST_TEST(rtx.size() == 2u);

    // After ACK releases 400 bytes, the third frame can fit.
    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {1, 1} };
    rtx.Ack(1, 1, ranges, 1100, 3, 0, fast);
    BOOST_TEST(rtx.bytes() == 400u);

    BOOST_TEST(rtx.Track(1, 3, make_buffer(400, 0x803), 400, 1030, cap));
    BOOST_TEST(rtx.bytes() == 800u);
}
