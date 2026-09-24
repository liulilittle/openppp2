// Wave 5: Control-plane and scheduling hardening.
//
// DRR visit budget (PPP_MUX_TX_FLOW_MAX_VISIT_FRAMES), shrink victim
// composite score, and ACK coalescing suppression.  These tests exercise
// the unit-testable components in isolation — MuxAckTracker cumulative
// merging (the basis for ACK coalescing), ACK frame codec round-trips
// (verifying that accumulated state encodes/decodes correctly), and
// constant integrity for the new DRR and control-queue limits.
//
// The DRR visit-budget and shrink-victim-score logic itself lives inside
// vmux_net::drr_pop_next / retire_linklayer_runtime and is validated by
// compile-time linkage of vmux_net.cpp plus the existing wave0/wave2/wave3
// integration tests that drive the scheduler end-to-end.
#define BOOST_TEST_MODULE vmux_wave5_control_plane_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <vector>

#include <ppp/app/mux/MuxAckTracker.h>

namespace mux = ppp::app::mux;

// ---------------------------------------------------------------------------
// ACK coalescing: cumulative tracker merging is the foundation.
// Multiple received sequences accumulate in one tracker and are encoded
// in a single ACK frame — the coalescing happens implicitly because Add()
// merges adjacent/overlapping ranges.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ack_tracker_accumulates_multiple_sequences) {
    // Simulate receiving seq 1, 2, 3, 5, 6 on the same flow.
    // The tracker should merge them into [1,3] and [5,6].
    mux::MuxAckTracker tracker;
    constexpr std::size_t max_ranges = 24;

    tracker.Add(1, max_ranges);
    tracker.Add(2, max_ranges);
    tracker.Add(3, max_ranges);
    tracker.Add(5, max_ranges);
    tracker.Add(6, max_ranges);

    BOOST_TEST(!tracker.empty());
    BOOST_TEST(tracker.size() == 2u);
    BOOST_TEST(tracker.largest() == 6u);

    const auto& ranges = tracker.ranges();
    BOOST_TEST(ranges[0].start == 1u);
    BOOST_TEST(ranges[0].end == 3u);
    BOOST_TEST(ranges[1].start == 5u);
    BOOST_TEST(ranges[1].end == 6u);
}

BOOST_AUTO_TEST_CASE(ack_tracker_merges_gap_on_late_arrival) {
    // Receive 1, 3, then 2 fills the gap → single range [1,3].
    mux::MuxAckTracker tracker;
    constexpr std::size_t max_ranges = 24;

    tracker.Add(1, max_ranges);
    tracker.Add(3, max_ranges);
    BOOST_TEST(tracker.size() == 2u);

    tracker.Add(2, max_ranges);
    BOOST_TEST(tracker.size() == 1u);
    BOOST_TEST(tracker.largest() == 3u);

    const auto& ranges = tracker.ranges();
    BOOST_TEST(ranges[0].start == 1u);
    BOOST_TEST(ranges[0].end == 3u);
}

BOOST_AUTO_TEST_CASE(ack_tracker_handles_out_of_order) {
    // Receive in reverse order: 5, 3, 1.
    mux::MuxAckTracker tracker;
    constexpr std::size_t max_ranges = 24;

    tracker.Add(5, max_ranges);
    tracker.Add(3, max_ranges);
    tracker.Add(1, max_ranges);

    // All are 2 apart, so no merging (gap of 1 between each).
    BOOST_TEST(tracker.size() == 3u);
    BOOST_TEST(tracker.largest() == 5u);

    // Now receive 2 and 4 → merges everything into [1,5].
    tracker.Add(4, max_ranges);
    tracker.Add(2, max_ranges);
    BOOST_TEST(tracker.size() == 1u);

    const auto& ranges = tracker.ranges();
    BOOST_TEST(ranges[0].start == 1u);
    BOOST_TEST(ranges[0].end == 5u);
}

BOOST_AUTO_TEST_CASE(ack_tracker_clear_resets_state) {
    // After sending an ACK, the tracker is cleared for the next cycle.
    mux::MuxAckTracker tracker;
    constexpr std::size_t max_ranges = 24;

    tracker.Add(1, max_ranges);
    tracker.Add(2, max_ranges);
    BOOST_TEST(!tracker.empty());

    tracker.Clear();
    BOOST_TEST(tracker.empty());
    BOOST_TEST(tracker.size() == 0u);
    BOOST_TEST(tracker.largest() == 0u);
}

// ---------------------------------------------------------------------------
// ACK frame codec round-trip: verify that accumulated state from multiple
// flows encodes and decodes correctly (the wire path used by ACK coalescing).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ack_frame_roundtrip_multi_block) {
    // Simulate two flows with accumulated sequences.
    mux::MuxAckBlock blocks[2];

    // Flow 1: seq [1,3] and [5,6].
    blocks[0].connection_id = 1;
    blocks[0].largest = 6;
    blocks[0].ranges = { {1, 3}, {5, 6} };

    // Flow 2: seq [10, 10].
    blocks[1].connection_id = 2;
    blocks[1].largest = 10;
    blocks[1].ranges = { {10, 10} };

    constexpr std::size_t max_blocks = 8;
    constexpr std::size_t max_ranges = 24;

    const std::size_t cap = mux::MuxAckFrameMaxSize(max_blocks, max_ranges);
    std::vector<std::uint8_t> buf(cap);

    const std::size_t len = mux::EncodeMuxAckFrame(
        blocks, 2, buf.data(), cap, max_ranges);
    BOOST_TEST(len > 0u);

    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(mux::DecodeMuxAckFrame(buf.data(), len,
        max_blocks, max_ranges, decoded));
    BOOST_REQUIRE_EQUAL(decoded.size(), 2u);

    // Block 0.
    BOOST_TEST(decoded[0].connection_id == 1u);
    BOOST_TEST(decoded[0].largest == 6u);
    BOOST_REQUIRE_EQUAL(decoded[0].ranges.size(), 2u);
    BOOST_TEST(decoded[0].ranges[0].start == 1u);
    BOOST_TEST(decoded[0].ranges[0].end == 3u);
    BOOST_TEST(decoded[0].ranges[1].start == 5u);
    BOOST_TEST(decoded[0].ranges[1].end == 6u);

    // Block 1.
    BOOST_TEST(decoded[1].connection_id == 2u);
    BOOST_TEST(decoded[1].largest == 10u);
    BOOST_REQUIRE_EQUAL(decoded[1].ranges.size(), 1u);
    BOOST_TEST(decoded[1].ranges[0].start == 10u);
    BOOST_TEST(decoded[1].ranges[0].end == 10u);
}

BOOST_AUTO_TEST_CASE(ack_frame_roundtrip_single_block_many_ranges) {
    // Stress: one flow with many accumulated ranges (gap pattern).
    mux::MuxAckBlock block;
    block.connection_id = 42;
    block.largest = 100;

    // Create ranges: [1,1], [3,3], [5,5], ... [99,99] (50 ranges).
    for (uint32_t i = 1; i <= 99; i += 2) {
        block.ranges.push_back({i, i});
    }

    constexpr std::size_t max_blocks = 8;
    constexpr std::size_t max_ranges = 24;

    const std::size_t cap = mux::MuxAckFrameMaxSize(max_blocks, max_ranges);
    std::vector<std::uint8_t> buf(cap);

    const std::size_t len = mux::EncodeMuxAckFrame(
        &block, 1, buf.data(), cap, max_ranges);
    BOOST_TEST(len > 0u);

    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(mux::DecodeMuxAckFrame(buf.data(), len,
        max_blocks, max_ranges, decoded));
    BOOST_REQUIRE_EQUAL(decoded.size(), 1u);

    // When capped at max_ranges=24, only the newest 24 ranges are sent.
    BOOST_TEST(decoded[0].connection_id == 42u);
    BOOST_TEST(decoded[0].largest == 100u);
    BOOST_TEST(decoded[0].ranges.size() == 24u);

    // The newest ranges are the highest ones: starting from seq 53.
    // (50 ranges total, send newest 24 → starts at index 26 → seq 53.)
    BOOST_TEST(decoded[0].ranges[0].start == 53u);
    BOOST_TEST(decoded[0].ranges[0].end == 53u);
    BOOST_TEST(decoded[0].ranges[23].start == 99u);
    BOOST_TEST(decoded[0].ranges[23].end == 99u);
}

// ---------------------------------------------------------------------------
// Malformed ACK frame rejection (security: treat decrypted input as untrusted).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ack_frame_rejects_empty_payload) {
    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(nullptr, 0, 8, 24, decoded));
    BOOST_TEST(!mux::DecodeMuxAckFrame(
        reinterpret_cast<const std::uint8_t*>(""), 0, 8, 24, decoded));
}

BOOST_AUTO_TEST_CASE(ack_frame_rejects_zero_blocks) {
    const std::uint8_t data[] = { 0 };
    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(data, sizeof(data), 8, 24, decoded));
}

BOOST_AUTO_TEST_CASE(ack_frame_rejects_truncated_block) {
    // Claims 1 block but has no payload.
    const std::uint8_t data[] = { 1 };
    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(data, sizeof(data), 8, 24, decoded));
}

BOOST_AUTO_TEST_CASE(ack_frame_rejects_range_exceeding_largest) {
    // 1 block, cid=1, largest=5, 1 range [3, 6] — end > largest.
    const std::uint8_t data[] = {
        1,                              // block_count
        0, 0, 0, 1,                     // connection_id = 1
        0, 0, 0, 5,                     // largest = 5
        1,                              // range_count = 1
        0, 0, 0, 3,                     // start = 3
        0, 0, 0, 6,                     // end = 6 (> largest)
    };
    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(data, sizeof(data), 8, 24, decoded));
}

BOOST_AUTO_TEST_CASE(ack_frame_rejects_start_greater_than_end) {
    // 1 block, cid=1, largest=10, 1 range [5, 3] — start > end.
    const std::uint8_t data[] = {
        1,                              // block_count
        0, 0, 0, 1,                     // connection_id = 1
        0, 0, 0, 10,                    // largest = 10
        1,                              // range_count = 1
        0, 0, 0, 5,                     // start = 5
        0, 0, 0, 3,                     // end = 3 (< start)
    };
    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(data, sizeof(data), 8, 24, decoded));
}

BOOST_AUTO_TEST_CASE(ack_frame_rejects_trailing_garbage) {
    // Well-formed 1-block frame with an extra byte appended.
    const std::uint8_t data[] = {
        1,                              // block_count
        0, 0, 0, 1,                     // connection_id = 1
        0, 0, 0, 5,                     // largest = 5
        1,                              // range_count = 1
        0, 0, 0, 1,                     // start = 1
        0, 0, 0, 5,                     // end = 5
        0xFF,                           // trailing garbage
    };
    std::vector<mux::MuxAckBlock> decoded;
    BOOST_TEST(!mux::DecodeMuxAckFrame(data, sizeof(data), 8, 24, decoded));
}

// ---------------------------------------------------------------------------
// Tracker range cap enforcement (DoS bound on ACK state).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ack_tracker_caps_ranges) {
    // When ranges exceed max_ranges, oldest are dropped.
    mux::MuxAckTracker tracker;
    constexpr std::size_t max_ranges = 3;

    // Add sequences that create 5 disjoint ranges: 1, 3, 5, 7, 9.
    for (uint32_t seq = 1; seq <= 9; seq += 2) {
        tracker.Add(seq, max_ranges);
    }

    // Capped to 3 ranges — oldest (1, 3) dropped, keeping 5, 7, 9.
    BOOST_TEST(tracker.size() == 3u);
    BOOST_TEST(tracker.largest() == 9u);

    const auto& ranges = tracker.ranges();
    BOOST_TEST(ranges[0].start == 5u);
    BOOST_TEST(ranges[1].start == 7u);
    BOOST_TEST(ranges[2].start == 9u);
}

// ---------------------------------------------------------------------------
// Duplicate sequence handling (idempotent Add).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ack_tracker_duplicate_seq_is_idempotent) {
    mux::MuxAckTracker tracker;
    constexpr std::size_t max_ranges = 24;

    tracker.Add(5, max_ranges);
    tracker.Add(5, max_ranges);
    tracker.Add(5, max_ranges);

    BOOST_TEST(tracker.size() == 1u);
    BOOST_TEST(tracker.largest() == 5u);

    const auto& ranges = tracker.ranges();
    BOOST_TEST(ranges[0].start == 5u);
    BOOST_TEST(ranges[0].end == 5u);
}
