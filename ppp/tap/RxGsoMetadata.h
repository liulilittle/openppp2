#pragma once

#include <cstdint>

namespace ppp::tap {

/**
 * @brief Immutable TCPv4 GRO receive contract supplied by a trusted producer.
 * @note This is RX-only metadata. It deliberately does not reuse XTCP's TX
 *       buffer metadata, which describes a different ownership contract.
 */
class RxTcpV4GroMetadata final {
public:
    static constexpr std::uint16_t MaximumSegments = 128;

    constexpr RxTcpV4GroMetadata(std::uint16_t header_length,
        std::uint16_t gso_size, std::uint16_t segments) noexcept
        : header_length_(header_length), gso_size_(gso_size), segments_(segments) {}

    constexpr std::uint16_t HeaderLength() const noexcept { return header_length_; }
    constexpr std::uint16_t GsoSize() const noexcept { return gso_size_; }
    constexpr std::uint16_t Segments() const noexcept { return segments_; }

private:
    std::uint16_t header_length_ = 0;
    std::uint16_t gso_size_ = 0;
    std::uint16_t segments_ = 0;
};

} // namespace ppp::tap
