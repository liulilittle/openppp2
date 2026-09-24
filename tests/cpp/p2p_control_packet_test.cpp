#define BOOST_TEST_MODULE p2p_control_packet_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PControlPacket.h>

#include <vector>

using namespace ppp::p2p;

namespace {
std::vector<std::uint8_t> ValidProbe() {
    std::vector<std::uint8_t> bytes(P2PControlPacket::WireSize, 0);
    bytes[0] = 1;
    bytes[1] = static_cast<std::uint8_t>(P2PControlType::Probe);
    bytes[4 + 32] = 0;
    bytes[4 + 33] = 1;
    bytes[4 + 34] = 0;
    bytes[4 + 35 + 16] = 4;
    bytes[4 + 35 + 16 + 1 + 10] = 0xff;
    bytes[4 + 35 + 16 + 1 + 11] = 0xff;
    bytes[4 + 35 + 16 + 1 + 12] = 192;
    bytes[4 + 35 + 16 + 1 + 13] = 0;
    bytes[4 + 35 + 16 + 1 + 14] = 2;
    bytes[4 + 35 + 16 + 1 + 15] = 1;
    bytes[4 + 35 + 16 + 17] = 0x12;
    bytes[4 + 35 + 16 + 18] = 0x34;
    bytes[4 + 35 + 16 + 19] = 6;
    bytes[4 + 35 + 16 + 19 + 1] = 0x20;
    bytes[4 + 35 + 16 + 19 + 2] = 0x01;
    bytes[4 + 35 + 16 + 19 + 3] = 0x0d;
    bytes[4 + 35 + 16 + 19 + 4] = 0xb8;
    bytes[4 + 35 + 16 + 19 + 16] = 1;
    bytes[4 + 35 + 16 + 19 + 17] = 0x56;
    bytes[4 + 35 + 16 + 19 + 18] = 0x78;
    bytes[109] = 30;
    for (std::size_t i = 0; i < 16; ++i) bytes[110 + i] = 0xa0 + i;
    return bytes;
}

std::vector<std::uint8_t> ValidProbeAck() {
    auto bytes = ValidProbe();
    bytes[1] = static_cast<std::uint8_t>(P2PControlType::ProbeAck);
    bytes[4 + 32] = 1;
    bytes[4 + 33] = 0;
    bytes[4 + 34] = 1;
    bytes.resize(P2PControlPacket::ProbeAckWireSize);
    for (std::size_t i = 0; i < 32; ++i) {
        bytes[P2PControlPacket::WireSize + i] = 0x40 + i;
    }
    return bytes;
}
}

BOOST_AUTO_TEST_CASE(parses_a_bounded_version_one_probe_vector) {
    P2PControlPacket packet;
    const auto bytes = ValidProbe();
    BOOST_REQUIRE(ParseP2PControlPacket(bytes, packet));
    BOOST_TEST(packet.version == 1u);
    BOOST_TEST(packet.source.address_family == 4u);
    BOOST_TEST(packet.source.port == 0x1234u);
    BOOST_TEST(packet.ttl_seconds == 30u);
    BOOST_TEST(packet.token[0] == 0xa0u);
    BOOST_TEST(packet.token[15] == 0xafu);
}

BOOST_AUTO_TEST_CASE(rejects_unknown_version_and_message_type) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[0] = 2;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[1] = 0xff;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
}

BOOST_AUTO_TEST_CASE(rejects_reserved_bits_and_bytes) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[2] = 1;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[3] = 1;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
}

BOOST_AUTO_TEST_CASE(rejects_every_truncated_vector_and_oversized_vector) {
    P2PControlPacket packet;
    const auto valid = ValidProbe();
    for (std::size_t size = 0; size < valid.size(); ++size) {
        BOOST_TEST(!ParseP2PControlPacket(
            std::vector<std::uint8_t>(valid.begin(), valid.begin() + size), packet));
    }
    auto oversized = valid;
    oversized.push_back(0);
    BOOST_TEST(!ParseP2PControlPacket(oversized, packet));
}

BOOST_AUTO_TEST_CASE(rejects_invalid_roles_direction_ttl_and_address_family) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[4 + 32] = 2;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[4 + 33] = 0;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[4 + 34] = 2;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[109] = 0;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[4 + 35 + 16] = 5;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
}

BOOST_AUTO_TEST_CASE(rejects_noncanonical_ipv4_and_direction_role_mismatch) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[4 + 34] = 1;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));

    bytes = ValidProbe();
    const auto source = 4 + 35 + 16;
    bytes[source] = 4;
    bytes[source + 1 + 10] = 0;
    bytes[source + 1 + 11] = 0;
    bytes[source + 1 + 10] = 0xff;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));

    bytes[source + 1 + 11] = 0xff;
    BOOST_TEST(ParseP2PControlPacket(bytes, packet));
}

BOOST_AUTO_TEST_CASE(probe_ack_requires_and_preserves_probe_transcript_hash) {
    P2PControlPacket packet;
    const auto bytes = ValidProbeAck();
    BOOST_REQUIRE(ParseP2PControlPacket(bytes, packet));
    BOOST_TEST(static_cast<int>(packet.type) ==
        static_cast<int>(P2PControlType::ProbeAck));
    BOOST_TEST(packet.probe_transcript_hash[0] == 0x40u);
    BOOST_TEST(packet.probe_transcript_hash[31] == 0x5fu);

    for (std::size_t size = 0; size < bytes.size(); ++size) {
        BOOST_TEST(!ParseP2PControlPacket(
            std::vector<std::uint8_t>(bytes.begin(), bytes.begin() + size), packet));
    }
    auto oversized_ack = bytes;
    oversized_ack.push_back(0);
    BOOST_TEST(!ParseP2PControlPacket(oversized_ack, packet));
    auto oversized_probe = ValidProbe();
    oversized_probe.resize(P2PControlPacket::ProbeAckWireSize);
    BOOST_TEST(!ParseP2PControlPacket(oversized_probe, packet));

    auto zero_hash = bytes;
    std::fill(zero_hash.begin() + P2PControlPacket::WireSize, zero_hash.end(), 0);
    BOOST_TEST(!ParseP2PControlPacket(zero_hash, packet));
}

BOOST_AUTO_TEST_CASE(migrate_challenge_and_ack_round_trip) {
    auto challenge = ValidProbe();
    challenge[1] = static_cast<std::uint8_t>(P2PControlType::MigrateChallenge);
    P2PControlPacket packet;
    BOOST_REQUIRE(ParseP2PControlPacket(challenge, packet));
    BOOST_TEST(static_cast<int>(packet.type) ==
        static_cast<int>(P2PControlType::MigrateChallenge));
    std::vector<std::uint8_t> encoded;
    BOOST_REQUIRE(SerializeP2PControlPacket(packet, encoded));
    BOOST_TEST(encoded == challenge);

    auto ack = challenge;
    ack[1] = static_cast<std::uint8_t>(P2PControlType::MigrateAck);
    BOOST_REQUIRE(ParseP2PControlPacket(ack, packet));
    BOOST_TEST(static_cast<int>(packet.type) ==
        static_cast<int>(P2PControlType::MigrateAck));
    BOOST_REQUIRE(SerializeP2PControlPacket(packet, encoded));
    BOOST_TEST(encoded == ack);
}

BOOST_AUTO_TEST_CASE(serializes_strict_probe_and_probe_ack_round_trips) {
    for (const auto& bytes : {ValidProbe(), ValidProbeAck()}) {
        P2PControlPacket packet;
        BOOST_REQUIRE(ParseP2PControlPacket(bytes, packet));
        std::vector<std::uint8_t> encoded;
        BOOST_REQUIRE(SerializeP2PControlPacket(packet, encoded));
        BOOST_TEST(encoded == bytes);
    }

    P2PControlPacket invalid;
    std::vector<std::uint8_t> output{1, 2, 3};
    const auto baseline = output;
    BOOST_TEST(!SerializeP2PControlPacket(invalid, output));
    BOOST_TEST(output == baseline);

    P2PControlPacket probe;
    BOOST_REQUIRE(ParseP2PControlPacket(ValidProbe(), probe));
    probe.probe_transcript_hash[0] = 1;
    BOOST_TEST(!SerializeP2PControlPacket(probe, output));
    BOOST_TEST(output == baseline);
}

BOOST_AUTO_TEST_CASE(rejects_unspecified_and_cross_family_candidate_encodings) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    const std::size_t source = 55;
    std::fill(bytes.begin() + source + 1 + 12,
        bytes.begin() + source + 1 + 16, 0);
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));

    bytes = ValidProbe();
    const std::size_t destination = 74;
    std::fill(bytes.begin() + destination + 1,
        bytes.begin() + destination + 17, 0);
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));

    bytes = ValidProbe();
    std::fill(bytes.begin() + destination + 1,
        bytes.begin() + destination + 17, 0);
    bytes[destination + 1 + 10] = 0xff;
    bytes[destination + 1 + 11] = 0xff;
    bytes[destination + 1 + 12] = 192;
    bytes[destination + 1 + 14] = 2;
    bytes[destination + 1 + 15] = 1;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
}
