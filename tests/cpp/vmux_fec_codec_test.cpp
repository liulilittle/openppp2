#define BOOST_TEST_MODULE vmux_fec_codec_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

#include <ppp/app/mux/MuxFecCodec.h>

namespace mux = ppp::app::mux;

namespace {
    std::vector<std::uint8_t> make_frame(std::uint8_t seed, std::size_t length) {
        std::vector<std::uint8_t> frame(length);
        for (std::size_t i = 0; i < length; ++i) {
            frame[i] = static_cast<std::uint8_t>(seed + i * 31);
        }
        return frame;
    }
}

BOOST_AUTO_TEST_CASE(build_parse_roundtrip_preserves_group) {
    mux::MuxFecEncoder encoder;
    encoder.Reset(1000);
    const auto f1 = make_frame(1, 20);
    const auto f2 = make_frame(2, 35);
    const auto f3 = make_frame(3, 10);
    encoder.Add(11, 1, f1.data(), (int)f1.size());
    encoder.Add(11, 2, f2.data(), (int)f2.size());
    encoder.Add(12, 1, f3.data(), (int)f3.size());

    BOOST_TEST(encoder.count() == 3);
    BOOST_TEST(encoder.first_add_tick() == 1000u);

    std::vector<std::uint8_t> wire(encoder.MaxPayloadSize());
    const int len = encoder.Build(wire.data(), (int)wire.size());
    BOOST_REQUIRE(len > 0);

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(wire.data(), len, 16, view));
    BOOST_REQUIRE_EQUAL(view.entries.size(), 3u);
    BOOST_TEST(view.entries[0].connection_id == 11u);
    BOOST_TEST(view.entries[0].sequence == 1u);
    BOOST_TEST(view.entries[2].connection_id == 12u);
    // Parity covers the longest block: 2-byte length prefix + 35 frame bytes.
    BOOST_TEST(view.parity.size() == 37u);
}

BOOST_AUTO_TEST_CASE(recovers_the_single_missing_frame_byte_exact) {
    const auto f1 = make_frame(9, 20);
    const auto f2 = make_frame(40, 35); // longest
    const auto f3 = make_frame(77, 10);

    mux::MuxFecEncoder encoder;
    encoder.Reset(0);
    encoder.Add(1, 1, f1.data(), (int)f1.size());
    encoder.Add(1, 2, f2.data(), (int)f2.size());
    encoder.Add(1, 3, f3.data(), (int)f3.size());

    std::vector<std::uint8_t> wire(encoder.MaxPayloadSize());
    const int len = encoder.Build(wire.data(), (int)wire.size());
    BOOST_REQUIRE(len > 0);

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(wire.data(), len, 16, view));

    // Lose f2 (index 1); present slots carry f1 and f3.
    const std::uint8_t* present[3] = { f1.data(), nullptr, f3.data() };
    const int present_lengths[3] = { (int)f1.size(), 0, (int)f3.size() };

    std::vector<std::uint8_t> recovered(view.parity.size());
    const int recovered_len = mux::MuxFecRecover(view, present, present_lengths, 1,
        recovered.data(), (int)recovered.size());
    BOOST_REQUIRE(recovered_len == (int)f2.size());
    BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);
}

BOOST_AUTO_TEST_CASE(recover_rejects_multiple_missing_slots) {
    const auto f1 = make_frame(5, 12);
    const auto f2 = make_frame(6, 12);

    mux::MuxFecEncoder encoder;
    encoder.Reset(0);
    encoder.Add(1, 1, f1.data(), (int)f1.size());
    encoder.Add(1, 2, f2.data(), (int)f2.size());

    std::vector<std::uint8_t> wire(encoder.MaxPayloadSize());
    const int len = encoder.Build(wire.data(), (int)wire.size());
    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(wire.data(), len, 16, view));

    // Two missing slots (index 0 "recovered" while index 1 is also absent).
    const std::uint8_t* present[2] = { nullptr, nullptr };
    const int present_lengths[2] = { 0, 0 };
    std::vector<std::uint8_t> recovered(view.parity.size());
    BOOST_TEST(mux::MuxFecRecover(view, present, present_lengths, 0,
        recovered.data(), (int)recovered.size()) == 0);
}

BOOST_AUTO_TEST_CASE(build_respects_output_capacity) {
    mux::MuxFecEncoder encoder;
    encoder.Reset(0);
    const auto f1 = make_frame(3, 50);
    encoder.Add(1, 1, f1.data(), (int)f1.size());

    std::uint8_t tiny[8] = {};
    BOOST_TEST(encoder.Build(tiny, (int)sizeof(tiny)) == 0);

    mux::MuxFecEncoder empty;
    empty.Reset(0);
    std::uint8_t room[64] = {};
    BOOST_TEST(empty.Build(room, (int)sizeof(room)) == 0);
}

BOOST_AUTO_TEST_CASE(parse_rejects_malformed_payloads) {
    mux::MuxFecFrameView view;

    BOOST_TEST(!mux::ParseMuxFecFrame(nullptr, 0, 16, view));

    const std::uint8_t zero_count[] = { 0 };
    BOOST_TEST(!mux::ParseMuxFecFrame(zero_count, sizeof(zero_count), 16, view));

    // Truncated entry list.
    const std::uint8_t truncated[] = { 2, 0, 0, 0, 1 };
    BOOST_TEST(!mux::ParseMuxFecFrame(truncated, sizeof(truncated), 16, view));

    // parity_len smaller than the minimum block (2-byte length + 1 frame byte).
    const std::uint8_t tiny_parity[] = { 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2, 0xAA, 0xBB };
    BOOST_TEST(!mux::ParseMuxFecFrame(tiny_parity, sizeof(tiny_parity), 16, view));

    // parity_len not matching the remaining bytes.
    const std::uint8_t stray[] = { 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 5, 0xAA, 0xBB, 0xCC };
    BOOST_TEST(!mux::ParseMuxFecFrame(stray, sizeof(stray), 16, view));

    // Count beyond the negotiated cap.
    const std::uint8_t over_cap[] = { 4 };
    BOOST_TEST(!mux::ParseMuxFecFrame(over_cap, sizeof(over_cap), 2, view));
}
