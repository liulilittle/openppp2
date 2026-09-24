#define BOOST_TEST_MODULE p2p_coalesce_frames_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PPacketHeader.h>

#include <array>
#include <cstring>
#include <vector>

using namespace ppp::p2p;

BOOST_AUTO_TEST_CASE(coalesce_and_demux_round_trip) {
    const std::uint8_t a[] = {1, 2, 3};
    const std::uint8_t b[] = {4, 5};
    const std::uint8_t c[] = {6, 7, 8, 9};
    const std::pair<const std::uint8_t*, int> frames[] = {
        {a, 3},
        {b, 2},
        {c, 4},
    };

    std::array<std::uint8_t, 64> payload{};
    const int written = CoalesceFrames(
        payload.data(), static_cast<int>(payload.size()), frames, 3);
    BOOST_REQUIRE(written == 3 + 2 + 2 + 2 + 4 + 2);

    std::pair<int, int> demuxed[MAX_COALESCED_FRAMES]{};
    const int count = DemuxCoalescedFrames(
        payload.data(), written, demuxed, MAX_COALESCED_FRAMES);
    BOOST_REQUIRE(count == 3);
    BOOST_TEST(demuxed[0].second == 3);
    BOOST_TEST(demuxed[1].second == 2);
    BOOST_TEST(demuxed[2].second == 4);
    BOOST_TEST(std::memcmp(payload.data() + demuxed[0].first, a, 3) == 0);
    BOOST_TEST(std::memcmp(payload.data() + demuxed[1].first, b, 2) == 0);
    BOOST_TEST(std::memcmp(payload.data() + demuxed[2].first, c, 4) == 0);
}

BOOST_AUTO_TEST_CASE(demux_rejects_truncated_and_zero_length) {
    const std::uint8_t truncated[] = {0x00, 0x03, 1, 2};
    std::pair<int, int> frames[4]{};
    BOOST_TEST(DemuxCoalescedFrames(truncated, 4, frames, 4) == -1);

    const std::uint8_t zero_len[] = {0x00, 0x00};
    BOOST_TEST(DemuxCoalescedFrames(zero_len, 2, frames, 4) == -1);
}

BOOST_AUTO_TEST_CASE(coalesce_rejects_overflow_and_null_frame) {
    const std::uint8_t a[] = {1, 2, 3, 4};
    const std::pair<const std::uint8_t*, int> frames[] = {
        {a, 4},
        {nullptr, 1},
    };
    std::array<std::uint8_t, 8> out{};
    BOOST_TEST(CoalesceFrames(out.data(), static_cast<int>(out.size()),
        frames, 2) == -1);

    const std::pair<const std::uint8_t*, int> one[] = {{a, 4}};
    BOOST_TEST(CoalesceFrames(out.data(), 4, one, 1) == -1);
}
