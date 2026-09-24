#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ppp::p2p {

enum class P2PControlType : std::uint8_t {
    Probe = 1,
    ProbeAck = 2,
    MigrateChallenge = 3,
    MigrateAck = 4,
};

struct P2PCandidateEndpoint {
    std::uint8_t address_family = 0;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;

    friend bool operator==(const P2PCandidateEndpoint& a,
                           const P2PCandidateEndpoint& b) noexcept {
        return a.address_family == b.address_family &&
               a.address == b.address && a.port == b.port;
    }
};

struct P2PControlPacket {
    static constexpr std::size_t WireSize = 126;
    static constexpr std::size_t ProbeAckWireSize = WireSize + 32;

    std::uint8_t version = 0;
    P2PControlType type = P2PControlType::Probe;
    std::array<std::uint8_t, 32> offer_hash{};
    std::uint8_t sender_role = 0;
    std::uint8_t receiver_role = 0;
    std::uint8_t direction = 0;
    std::array<std::uint8_t, 16> connection_epoch{};
    P2PCandidateEndpoint source;
    P2PCandidateEndpoint destination;
    std::uint32_t sequence = 0;
    std::array<std::uint8_t, 12> nonce{};
    std::uint8_t ttl_seconds = 0;
    std::array<std::uint8_t, 16> token{};
    std::array<std::uint8_t, 32> probe_transcript_hash{};
};

inline bool IsCanonicalP2PCandidate(
    const P2PCandidateEndpoint& candidate) noexcept {
    if ((candidate.address_family != 4 && candidate.address_family != 6) ||
        candidate.port == 0) {
        return false;
    }
    const bool mapped = std::all_of(
            candidate.address.begin(), candidate.address.begin() + 10,
            [](std::uint8_t byte) { return byte == 0; }) &&
        candidate.address[10] == 0xff && candidate.address[11] == 0xff;
    if (candidate.address_family == 4) {
        const bool payload_nonzero = std::any_of(
            candidate.address.begin() + 12, candidate.address.end(),
            [](std::uint8_t byte) { return byte != 0; });
        return mapped && payload_nonzero;
    }
    const bool address_nonzero = std::any_of(
        candidate.address.begin(), candidate.address.end(),
        [](std::uint8_t byte) { return byte != 0; });
    return address_nonzero && !mapped;
}

namespace detail {
inline bool ValidControlFields(const P2PControlPacket& packet) noexcept {
    const auto type = static_cast<std::uint8_t>(packet.type);
    const bool is_probe_ack = packet.type == P2PControlType::ProbeAck;
    return packet.version == 1 &&
        type >= static_cast<std::uint8_t>(P2PControlType::Probe) &&
        type <= static_cast<std::uint8_t>(P2PControlType::MigrateAck) &&
        packet.sender_role <= 1 && packet.receiver_role <= 1 &&
        packet.sender_role != packet.receiver_role &&
        packet.direction == packet.sender_role &&
        packet.ttl_seconds >= 1 && packet.ttl_seconds <= 30 &&
        IsCanonicalP2PCandidate(packet.source) &&
        IsCanonicalP2PCandidate(packet.destination) &&
        (is_probe_ack ==
            (packet.probe_transcript_hash != std::array<std::uint8_t, 32>{}));
}

inline bool ParseCandidate(const std::vector<std::uint8_t>& bytes,
                           std::size_t offset,
                           P2PCandidateEndpoint& candidate) noexcept {
    candidate.address_family = bytes[offset];
    for (std::size_t i = 0; i < candidate.address.size(); ++i) {
        candidate.address[i] = bytes[offset + 1 + i];
    }
    candidate.port = static_cast<std::uint16_t>(bytes[offset + 17]) << 8 |
                     static_cast<std::uint16_t>(bytes[offset + 18]);
    return IsCanonicalP2PCandidate(candidate);
}
}

inline bool ParseP2PControlPacket(const std::vector<std::uint8_t>& bytes,
                                  P2PControlPacket& packet) noexcept {
    if (bytes.size() < P2PControlPacket::WireSize || bytes[0] != 1 ||
        bytes[2] != 0 || bytes[3] != 0) {
        return false;
    }
    if (bytes[1] < static_cast<std::uint8_t>(P2PControlType::Probe) ||
        bytes[1] > static_cast<std::uint8_t>(P2PControlType::MigrateAck)) {
        return false;
    }
    const auto type = static_cast<P2PControlType>(bytes[1]);
    const std::size_t expected_size = type == P2PControlType::ProbeAck
        ? P2PControlPacket::ProbeAckWireSize
        : P2PControlPacket::WireSize;
    if (bytes.size() != expected_size) {
        return false;
    }

    P2PControlPacket parsed;
    parsed.version = bytes[0];
    parsed.type = static_cast<P2PControlType>(bytes[1]);
    for (std::size_t i = 0; i < parsed.offer_hash.size(); ++i) {
        parsed.offer_hash[i] = bytes[4 + i];
    }
    parsed.sender_role = bytes[36];
    parsed.receiver_role = bytes[37];
    parsed.direction = bytes[38];
    for (std::size_t i = 0; i < parsed.connection_epoch.size(); ++i) {
        parsed.connection_epoch[i] = bytes[39 + i];
    }
    if (!detail::ParseCandidate(bytes, 55, parsed.source) ||
        !detail::ParseCandidate(bytes, 74, parsed.destination)) {
        return false;
    }
    parsed.sequence = static_cast<std::uint32_t>(bytes[93]) << 24 |
                      static_cast<std::uint32_t>(bytes[94]) << 16 |
                      static_cast<std::uint32_t>(bytes[95]) << 8 |
                      static_cast<std::uint32_t>(bytes[96]);
    for (std::size_t i = 0; i < parsed.nonce.size(); ++i) {
        parsed.nonce[i] = bytes[97 + i];
    }
    parsed.ttl_seconds = bytes[109];
    for (std::size_t i = 0; i < parsed.token.size(); ++i) {
        parsed.token[i] = bytes[110 + i];
    }
    if (parsed.type == P2PControlType::ProbeAck) {
        for (std::size_t i = 0; i < parsed.probe_transcript_hash.size(); ++i) {
            parsed.probe_transcript_hash[i] = bytes[P2PControlPacket::WireSize + i];
        }
    }
    if (!detail::ValidControlFields(parsed)) {
        return false;
    }
    packet = parsed;
    return true;
}

inline bool SerializeP2PControlPacket(
    const P2PControlPacket& packet,
    std::vector<std::uint8_t>& output) noexcept {
    if (!detail::ValidControlFields(packet)) {
        return false;
    }

    const std::size_t size = packet.type == P2PControlType::ProbeAck
        ? P2PControlPacket::ProbeAckWireSize
        : P2PControlPacket::WireSize;
    std::vector<std::uint8_t> bytes;
    try {
        bytes.resize(size);
    }
    catch (...) {
        return false;
    }

    bytes[0] = packet.version;
    bytes[1] = static_cast<std::uint8_t>(packet.type);
    std::copy(packet.offer_hash.begin(), packet.offer_hash.end(), bytes.begin() + 4);
    bytes[36] = packet.sender_role;
    bytes[37] = packet.receiver_role;
    bytes[38] = packet.direction;
    std::copy(packet.connection_epoch.begin(), packet.connection_epoch.end(), bytes.begin() + 39);
    const auto write_candidate = [&bytes](std::size_t offset,
                                          const P2PCandidateEndpoint& candidate) noexcept {
        bytes[offset] = candidate.address_family;
        std::copy(candidate.address.begin(), candidate.address.end(), bytes.begin() + offset + 1);
        bytes[offset + 17] = static_cast<std::uint8_t>(candidate.port >> 8);
        bytes[offset + 18] = static_cast<std::uint8_t>(candidate.port);
    };
    write_candidate(55, packet.source);
    write_candidate(74, packet.destination);
    bytes[93] = static_cast<std::uint8_t>(packet.sequence >> 24);
    bytes[94] = static_cast<std::uint8_t>(packet.sequence >> 16);
    bytes[95] = static_cast<std::uint8_t>(packet.sequence >> 8);
    bytes[96] = static_cast<std::uint8_t>(packet.sequence);
    std::copy(packet.nonce.begin(), packet.nonce.end(), bytes.begin() + 97);
    bytes[109] = packet.ttl_seconds;
    std::copy(packet.token.begin(), packet.token.end(), bytes.begin() + 110);
    if (packet.type == P2PControlType::ProbeAck) {
        std::copy(packet.probe_transcript_hash.begin(),
            packet.probe_transcript_hash.end(),
            bytes.begin() + P2PControlPacket::WireSize);
    }
    output.swap(bytes);
    return true;
}

}
