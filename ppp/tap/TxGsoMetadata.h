#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace ppp::tap {

enum class TxGsoType : std::uint8_t {
    TcpV4,
};

enum class TxChecksumState : std::uint8_t {
    Complete,
};

/**
 * @brief Immutable, platform-neutral transmit segmentation contract.
 * @note Instances can only be created by strict packet validation; callers
 *       must never infer offload state from packet length.
 */
class TxGsoMetadata final {
public:
    static constexpr std::uint16_t MaximumSegments = 128;

    static std::optional<TxGsoMetadata> ParseTcpV4(
        const void* packet, std::size_t packet_size,
        std::uint32_t gso_size, std::uint16_t segments) noexcept {
        const auto* bytes = static_cast<const std::uint8_t*>(packet);
        if (bytes == nullptr || packet_size < 40 ||
            packet_size > std::numeric_limits<std::uint16_t>::max() ||
            gso_size == 0 || gso_size > std::numeric_limits<std::uint16_t>::max() ||
            segments < 2 || segments > MaximumSegments || (bytes[0] >> 4U) != 4) {
            return std::nullopt;
        }
        const std::size_t ihl = static_cast<std::size_t>(bytes[0] & 0x0fU) * 4U;
        const std::uint16_t total_length = static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes[2]) << 8U | bytes[3]);
        const std::uint16_t fragment = static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes[6]) << 8U | bytes[7]);
        if (ihl < 20 || ihl > packet_size || total_length != packet_size ||
            (fragment & 0x3fffU) != 0 || bytes[9] != 6 || packet_size < ihl + 20) {
            return std::nullopt;
        }
        const std::size_t tcp_header = static_cast<std::size_t>(bytes[ihl + 12] >> 4U) * 4U;
        if (tcp_header < 20 || tcp_header > packet_size - ihl) {
            return std::nullopt;
        }
        const std::size_t header_length = ihl + tcp_header;
        const std::size_t payload_length = packet_size - header_length;
        if (payload_length <= gso_size ||
            (payload_length + gso_size - 1U) / gso_size != segments) {
            return std::nullopt;
        }
        return TxGsoMetadata(static_cast<std::uint16_t>(header_length),
            static_cast<std::uint16_t>(gso_size), segments);
    }

    TxGsoType Type() const noexcept { return type_; }
    std::uint16_t HeaderLength() const noexcept { return header_length_; }
    std::uint16_t GsoSize() const noexcept { return gso_size_; }
    std::uint16_t Segments() const noexcept { return segments_; }
    TxChecksumState ChecksumState() const noexcept { return checksum_state_; }

private:
    TxGsoMetadata(std::uint16_t header_length, std::uint16_t gso_size,
        std::uint16_t segments) noexcept
        : header_length_(header_length), gso_size_(gso_size), segments_(segments) {}

    TxGsoType type_ = TxGsoType::TcpV4;
    std::uint16_t header_length_;
    std::uint16_t gso_size_;
    std::uint16_t segments_;
    TxChecksumState checksum_state_ = TxChecksumState::Complete;
};

} // namespace ppp::tap
