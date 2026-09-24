#define BOOST_TEST_MODULE p2p_data_datagram_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PDataDatagram.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

using namespace ppp::p2p;

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> Bytes(std::uint8_t seed) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<std::uint8_t>(seed + i);
    }
    return value;
}

P2PDataPacketHeader Header() {
    P2PDataPacketHeader header;
    header.offer_hash = Bytes<32>(10);
    header.sender_role = 0;
    header.receiver_role = 1;
    header.direction = 0;
    header.connection_epoch = Bytes<16>(50);
    header.sequence = 0x01020304;
    return header;
}

std::vector<std::uint8_t> Hex(const std::string& value) {
    const auto nibble = [](char c) -> std::uint8_t {
        return static_cast<std::uint8_t>(
            c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10);
    };
    std::vector<std::uint8_t> bytes;
    bytes.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        bytes.push_back(static_cast<std::uint8_t>(
            nibble(value[i]) << 4 | nibble(value[i + 1])));
    }
    return bytes;
}

std::vector<std::uint8_t> Seal(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> datagram;
    BOOST_REQUIRE(SealP2PDataDatagram(
        Header(), Bytes<32>(90), Bytes<12>(130),
        payload.data(), payload.size(), datagram));
    return datagram;
}
}

BOOST_AUTO_TEST_CASE(seals_and_opens_the_exact_version_one_vector) {
    const std::vector<std::uint8_t> payload{1, 3, 5, 7};
    const auto datagram = Seal(payload);
    BOOST_TEST(datagram == Hex(
        "010500000a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"
        "262728290001000032333435363738393a3b3c3d3e3f4041010203040004"
        "4555bc564a579353f78779f357445d3c394dc40e"));
    BOOST_TEST(datagram.size() ==
        P2PDataPacketHeader::HeaderSize + payload.size() +
            P2PDataPacketHeader::TagSize);
    BOOST_TEST(datagram[0] == 1u);
    BOOST_TEST(datagram[1] == 5u);
    BOOST_TEST(datagram[2] == 0u);
    BOOST_TEST(datagram[3] == 0u);
    BOOST_TEST(datagram[36] == 0u);
    BOOST_TEST(datagram[37] == 1u);
    BOOST_TEST(datagram[38] == 0u);
    BOOST_TEST(datagram[39] == 0u);
    BOOST_TEST(datagram[56] == 1u);
    BOOST_TEST(datagram[57] == 2u);
    BOOST_TEST(datagram[58] == 3u);
    BOOST_TEST(datagram[59] == 4u);
    BOOST_TEST(datagram[60] == 0u);
    BOOST_TEST(datagram[61] == payload.size());

    P2PDataPacketHeader parsed;
    BOOST_REQUIRE(ParseP2PDataPacketHeader(datagram, parsed));
    BOOST_TEST(parsed.offer_hash == Header().offer_hash);
    BOOST_TEST(parsed.connection_epoch == Header().connection_epoch);
    BOOST_TEST(parsed.sequence == Header().sequence);
    BOOST_TEST(parsed.payload_length == payload.size());

    std::vector<std::uint8_t> opened;
    BOOST_REQUIRE(OpenP2PDataDatagram(
        datagram, Header(), Bytes<32>(90), Bytes<12>(130), opened));
    BOOST_TEST(opened == payload);
}

BOOST_AUTO_TEST_CASE(rejects_every_truncation_and_oversized_datagram_atomically) {
    const auto datagram = Seal({1, 2, 3});
    P2PDataPacketHeader output;
    output.sequence = 99;
    for (std::size_t size = 0; size < datagram.size(); ++size) {
        const std::vector<std::uint8_t> truncated(
            datagram.begin(), datagram.begin() + size);
        BOOST_TEST(!ParseP2PDataPacketHeader(truncated, output));
        BOOST_TEST(output.sequence == 99u);
    }
    auto oversized = datagram;
    oversized.push_back(0);
    BOOST_TEST(!ParseP2PDataPacketHeader(oversized, output));
    BOOST_TEST(output.sequence == 99u);
}

BOOST_AUTO_TEST_CASE(rejects_flags_reserved_roles_direction_and_length) {
    const auto valid = Seal({1, 2, 3});
    for (const std::size_t offset : {2u, 3u, 39u}) {
        auto invalid = valid;
        invalid[offset] = 1;
        P2PDataPacketHeader parsed;
        BOOST_TEST(!ParseP2PDataPacketHeader(invalid, parsed));
    }
    for (const std::pair<std::size_t, std::uint8_t> mutation : {
             std::pair<std::size_t, std::uint8_t>{0, 2},
             {1, 4}, {36, 2}, {37, 0}, {38, 1}, {60, 1}, {61, 4}}) {
        auto invalid = valid;
        invalid[mutation.first] = mutation.second;
        P2PDataPacketHeader parsed;
        BOOST_TEST(!ParseP2PDataPacketHeader(invalid, parsed));
    }
}

BOOST_AUTO_TEST_CASE(rejects_empty_and_too_large_payload_without_mutating_output) {
    const auto key = Bytes<32>(90);
    const auto nonce = Bytes<12>(130);
    std::vector<std::uint8_t> output{9, 8, 7};
    const auto baseline = output;
    BOOST_TEST(!SealP2PDataDatagram(
        Header(), key, nonce, nullptr, 0, output));
    BOOST_TEST(output == baseline);

    const std::vector<std::uint8_t> oversized(
        P2PDataPacketHeader::MaxPayloadSize + 1, 1);
    BOOST_TEST(!SealP2PDataDatagram(
        Header(), key, nonce, oversized.data(), oversized.size(), output));
    BOOST_TEST(output == baseline);
}

BOOST_AUTO_TEST_CASE(rejects_tampered_header_ciphertext_tag_and_expectation_atomically) {
    const auto key = Bytes<32>(90);
    const auto nonce = Bytes<12>(130);
    const auto valid = Seal({1, 2, 3});
    std::vector<std::uint8_t> output{9, 8, 7};
    const auto baseline = output;

    const std::array<std::size_t, 3> tamper_offsets{
        4, P2PDataPacketHeader::HeaderSize,
        valid.size() - P2PDataPacketHeader::TagSize};
    for (const std::size_t offset : tamper_offsets) {
        auto tampered = valid;
        tampered[offset] ^= 1;
        BOOST_TEST(!OpenP2PDataDatagram(
            tampered, Header(), key, nonce, output));
        BOOST_TEST(output == baseline);
    }

    auto wrong_expected = Header();
    ++wrong_expected.sequence;
    BOOST_TEST(!OpenP2PDataDatagram(
        valid, wrong_expected, key, nonce, output));
    BOOST_TEST(output == baseline);
}
