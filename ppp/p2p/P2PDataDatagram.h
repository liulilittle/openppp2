#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ppp::p2p {

struct P2PDataPacketHeader final {
    static constexpr std::size_t HeaderSize = 62;
    static constexpr std::size_t TagSize = 16;
    static constexpr std::size_t MaxPayloadSize = 1514;

    std::array<std::uint8_t, 32> offer_hash{};
    std::uint8_t sender_role = 0;
    std::uint8_t receiver_role = 1;
    std::uint8_t direction = 0;
    std::array<std::uint8_t, 16> connection_epoch{};
    std::uint32_t sequence = 0;
    std::uint16_t payload_length = 0;
};

bool ParseP2PDataPacketHeader(
    const std::vector<std::uint8_t>& datagram,
    P2PDataPacketHeader& output) noexcept;

bool SealP2PDataDatagram(
    const P2PDataPacketHeader& header,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 12>& nonce,
    const std::uint8_t* payload,
    std::size_t payload_length,
    std::vector<std::uint8_t>& output) noexcept;

bool OpenP2PDataDatagram(
    const std::vector<std::uint8_t>& datagram,
    const P2PDataPacketHeader& expected,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 12>& nonce,
    std::vector<std::uint8_t>& output) noexcept;

}
