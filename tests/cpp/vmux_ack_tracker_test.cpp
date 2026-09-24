#define BOOST_TEST_MODULE vmux_ack_tracker_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <vector>

#include <ppp/app/mux/MuxAckTracker.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(merges_contiguous_sequences_into_one_range) {
    mux::MuxAckTracker tracker;
    tracker.Add(1, 24);
    tracker.Add(2, 24);
    tracker.Add(3, 24);

    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.ranges()[0].start == 1u);
    BOOST_TEST(tracker.ranges()[0].end == 3u);
    BOOST_TEST(tracker.largest() == 3u);
}

BOOST_AUTO_TEST_CASE(bridges_a_gap_when_the_missing_sequence_arrives) {
    mux::MuxAckTracker tracker;
    tracker.Add(1, 24);
    tracker.Add(3, 24);
    BOOST_REQUIRE_EQUAL(tracker.size(), 2u);

    tracker.Add(4, 24);
    BOOST_REQUIRE_EQUAL(tracker.size(), 2u);

    tracker.Add(2, 24);
    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.ranges()[0].start == 1u);
    BOOST_TEST(tracker.ranges()[0].end == 4u);
}

BOOST_AUTO_TEST_CASE(duplicate_and_inside_range_adds_are_noops) {
    mux::MuxAckTracker tracker;
    tracker.Add(10, 24);
    tracker.Add(12, 24);
    tracker.Add(11, 24); // bridges into [10,12]
    tracker.Add(11, 24); // duplicate
    tracker.Add(10, 24); // inside range

    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.ranges()[0].start == 10u);
    BOOST_TEST(tracker.ranges()[0].end == 12u);
}

BOOST_AUTO_TEST_CASE(cap_drops_oldest_ranges) {
    mux::MuxAckTracker tracker;
    for (std::uint32_t seq = 1; seq <= 20; seq += 2) {
        tracker.Add(seq, 3);
    }

    BOOST_REQUIRE_EQUAL(tracker.size(), 3u);
    // The three NEWEST singleton ranges survive.
    BOOST_TEST(tracker.ranges()[0].start == 15u);
    BOOST_TEST(tracker.ranges()[2].start == 19u);
}

BOOST_AUTO_TEST_CASE(uint32_max_merges_with_adjacent_range_below) {
    mux::MuxAckTracker tracker;
    tracker.Add(0xFFFFFFFEu, 24);
    tracker.Add(0xFFFFFFFFu, 24);

    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.ranges()[0].start == 0xFFFFFFFEu);
    BOOST_TEST(tracker.ranges()[0].end == 0xFFFFFFFFu);
    BOOST_TEST(tracker.largest() == 0xFFFFFFFFu);
}

BOOST_AUTO_TEST_CASE(wrap_heuristic_resets_the_tracker) {
    mux::MuxAckTracker tracker;
    tracker.Add(0xFFFFFFF0u, 24);
    tracker.Add(5u, 24); // counter wrapped

    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.ranges()[0].start == 5u);
    BOOST_TEST(tracker.ranges()[0].end == 5u);
}

BOOST_AUTO_TEST_CASE(encode_decode_roundtrip_preserves_blocks) {
    mux::MuxAckBlock blocks[2];
    blocks[0].connection_id = 0;
    blocks[0].largest = 100;
    blocks[0].ranges = { {1, 50}, {60, 100} };
    blocks[1].connection_id = 77;
    blocks[1].largest = 9;
    blocks[1].ranges = { {2, 4}, {9, 9} };

    std::vector<std::uint8_t> wire(mux::MuxAckFrameMaxSize(8, 24));
    const std::size_t len = mux::EncodeMuxAckFrame(blocks, 2, wire.data(), wire.size(), 24);
    BOOST_REQUIRE(len > 0);

    std::vector<mux::MuxAckBlock> decoded;
    BOOST_REQUIRE(mux::DecodeMuxAckFrame(wire.data(), len, 8, 24, decoded));
    BOOST_REQUIRE_EQUAL(decoded.size(), 2u);

    BOOST_TEST(decoded[0].connection_id == 0u);
    BOOST_TEST(decoded[0].largest == 100u);
    BOOST_REQUIRE_EQUAL(decoded[0].ranges.size(), 2u);
    BOOST_TEST(decoded[0].ranges[0].start == 1u);
    BOOST_TEST(decoded[0].ranges[0].end == 50u);
    BOOST_TEST(decoded[0].ranges[1].start == 60u);
    BOOST_TEST(decoded[0].ranges[1].end == 100u);

    BOOST_TEST(decoded[1].connection_id == 77u);
    BOOST_TEST(decoded[1].largest == 9u);
    BOOST_REQUIRE_EQUAL(decoded[1].ranges.size(), 2u);
    BOOST_TEST(decoded[1].ranges[1].start == 9u);
    BOOST_TEST(decoded[1].ranges[1].end == 9u);
}

BOOST_AUTO_TEST_CASE(encode_respects_output_capacity) {
    mux::MuxAckBlock block;
    block.connection_id = 1;
    block.largest = 5;
    block.ranges = { {1, 5} };

    std::uint8_t tiny[4] = {};
    BOOST_TEST(mux::EncodeMuxAckFrame(&block, 1, tiny, sizeof(tiny), 24) == 0u);
}

BOOST_AUTO_TEST_CASE(decode_rejects_malformed_payloads) {
    std::vector<mux::MuxAckBlock> decoded;

    // Empty payload.
    BOOST_TEST(!mux::DecodeMuxAckFrame(nullptr, 0, 8, 24, decoded));

    // block_count = 0.
    const std::uint8_t zero_blocks[] = { 0 };
    BOOST_TEST(!mux::DecodeMuxAckFrame(zero_blocks, sizeof(zero_blocks), 8, 24, decoded));

    // Truncated block header.
    const std::uint8_t truncated[] = { 1, 0, 0 };
    BOOST_TEST(!mux::DecodeMuxAckFrame(truncated, sizeof(truncated), 8, 24, decoded));

    // range_count = 0.
    const std::uint8_t no_ranges[] = { 1, 0, 0, 0, 1, 0, 0, 0, 5, 0 };
    BOOST_TEST(!mux::DecodeMuxAckFrame(no_ranges, sizeof(no_ranges), 8, 24, decoded));

    // start > end.
    const std::uint8_t inverted[] = { 1, 0, 0, 0, 1, 0, 0, 0, 5, 1,
        0, 0, 0, 5, 0, 0, 0, 3 };
    BOOST_TEST(!mux::DecodeMuxAckFrame(inverted, sizeof(inverted), 8, 24, decoded));

    // end > largest.
    const std::uint8_t beyond[] = { 1, 0, 0, 0, 1, 0, 0, 0, 5, 1,
        0, 0, 0, 1, 0, 0, 0, 6 };
    BOOST_TEST(!mux::DecodeMuxAckFrame(beyond, sizeof(beyond), 8, 24, decoded));

    // Trailing garbage after a valid block.
    const std::uint8_t garbage[] = { 1, 0, 0, 0, 1, 0, 0, 0, 5, 1,
        0, 0, 0, 1, 0, 0, 0, 5, 0xAA };
    BOOST_TEST(!mux::DecodeMuxAckFrame(garbage, sizeof(garbage), 8, 24, decoded));
}
