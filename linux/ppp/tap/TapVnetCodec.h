// Strict Linux TUN VNET v1 inbound frame codec.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <ppp/tap/TxGsoMetadata.h>

#include <endian.h>
#include <netinet/in.h>
// Linux UAPI exposes a member named `class`; protect C++ parsing.
#define class class_
#include <linux/virtio_net.h>
#undef class

namespace ppp {
namespace tap {
namespace vnet {

struct TcpV4GsoFrame final {
    uint8_t* ip = nullptr;
    size_t packet_size = 0;
    size_t ihl = 0;
    size_t tcp_header_size = 0;
    size_t header_size = 0;
    size_t payload_size = 0;
    size_t gso_size = 0;
    uint32_t initial_sequence = 0;
};

inline constexpr size_t kStandardVirtioHeaderSize = sizeof(virtio_net_hdr);
inline constexpr size_t kMaximumIpv4PacketSize = std::numeric_limits<uint16_t>::max();

inline bool IsStandardHeaderSize(size_t header_size) noexcept {
    return header_size == kStandardVirtioHeaderSize;
}

inline bool ReadCapacity(size_t header_size, size_t& capacity) noexcept {
    if (!IsStandardHeaderSize(header_size) || header_size > std::numeric_limits<size_t>::max() - kMaximumIpv4PacketSize) {
        return false;
    }
    capacity = header_size + kMaximumIpv4PacketSize;
    return true;
}

inline uint16_t ReadBE16(const uint8_t* bytes) noexcept {
    return static_cast<uint16_t>(bytes[0] << 8U | bytes[1]);
}

inline uint32_t ReadBE32(const uint8_t* bytes) noexcept {
    return (static_cast<uint32_t>(bytes[0]) << 24U) | (static_cast<uint32_t>(bytes[1]) << 16U) |
        (static_cast<uint32_t>(bytes[2]) << 8U) | bytes[3];
}

inline void WriteBE16(uint8_t* bytes, uint16_t value) noexcept {
    bytes[0] = static_cast<uint8_t>(value >> 8U);
    bytes[1] = static_cast<uint8_t>(value);
}

inline void WriteBE32(uint8_t* bytes, uint32_t value) noexcept {
    bytes[0] = static_cast<uint8_t>(value >> 24U);
    bytes[1] = static_cast<uint8_t>(value >> 16U);
    bytes[2] = static_cast<uint8_t>(value >> 8U);
    bytes[3] = static_cast<uint8_t>(value);
}

inline uint32_t ChecksumSum(const uint8_t* bytes, size_t size, uint32_t sum = 0) noexcept {
    while (size >= 2) {
        sum += ReadBE16(bytes);
        bytes += 2;
        size -= 2;
    }
    return size == 0 ? sum : sum + static_cast<uint16_t>(bytes[0] << 8U);
}

inline uint16_t FoldChecksum(uint32_t sum) noexcept {
    while (sum >> 16U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return static_cast<uint16_t>(~sum);
}

inline bool BuildTcpV4GsoHeader(const uint8_t* packet, size_t packet_size,
    const ppp::tap::TxGsoMetadata& metadata, virtio_net_hdr& header) noexcept {
    if (metadata.Type() != ppp::tap::TxGsoType::TcpV4 ||
        metadata.ChecksumState() != ppp::tap::TxChecksumState::Complete) {
        return false;
    }
    const auto validated = ppp::tap::TxGsoMetadata::ParseTcpV4(
        packet, packet_size, metadata.GsoSize(), metadata.Segments());
    if (!validated || validated->HeaderLength() != metadata.HeaderLength()) {
        return false;
    }
    std::memset(&header, 0, sizeof(header));
    header.flags = 0;
    header.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    header.hdr_len = htole16(metadata.HeaderLength());
    header.gso_size = htole16(metadata.GsoSize());
    return true;
}

inline bool ReadHeader(const uint8_t* frame, size_t frame_size, size_t header_size, virtio_net_hdr& header) noexcept {
    if (frame == nullptr || !IsStandardHeaderSize(header_size) || frame_size <= header_size) {
        return false;
    }
    std::memcpy(&header, frame, sizeof(header));
    return true;
}

inline bool ParseIPv4Tcp(uint8_t* ip, size_t packet_size, TcpV4GsoFrame& result) noexcept {
    if (ip == nullptr || packet_size < 20 || packet_size > kMaximumIpv4PacketSize || (ip[0] >> 4U) != 4 || ip[9] != IPPROTO_TCP) {
        return false;
    }

    const size_t ihl = static_cast<size_t>(ip[0] & 0x0fU) * 4U;
    if (ihl < 20 || ihl > packet_size || ReadBE16(ip + 2) != packet_size || (ReadBE16(ip + 6) & 0x3fffU) != 0 || packet_size < ihl + 20) {
        return false;
    }

    uint8_t* tcp = ip + ihl;
    const size_t tcp_header_size = static_cast<size_t>(tcp[12] >> 4U) * 4U;
    if (tcp_header_size < 20 || tcp_header_size > packet_size - ihl) {
        return false;
    }

    result.ip = ip;
    result.packet_size = packet_size;
    result.ihl = ihl;
    result.tcp_header_size = tcp_header_size;
    result.header_size = ihl + tcp_header_size;
    result.payload_size = packet_size - result.header_size;
    result.initial_sequence = ReadBE32(tcp + 4);
    return true;
}

inline bool HasTcpChecksumMetadata(const virtio_net_hdr& header, const TcpV4GsoFrame& frame) noexcept {
    const size_t csum_start = le16toh(header.csum_start);
    const size_t csum_offset = le16toh(header.csum_offset);
    return csum_start == frame.ihl && csum_offset == 16 &&
        csum_start <= frame.packet_size && csum_offset <= frame.packet_size - csum_start &&
        sizeof(uint16_t) <= frame.packet_size - csum_start - csum_offset;
}

inline uint16_t TcpChecksum(const TcpV4GsoFrame& frame) noexcept {
    const size_t tcp_size = frame.packet_size - frame.ihl;
    uint32_t sum = ChecksumSum(frame.ip + 12, 8);
    const uint8_t pseudo_header[] = {
        0,
        IPPROTO_TCP,
        static_cast<uint8_t>(tcp_size >> 8U),
        static_cast<uint8_t>(tcp_size),
    };
    sum = ChecksumSum(pseudo_header, sizeof(pseudo_header), sum);
    return FoldChecksum(ChecksumSum(frame.ip + frame.ihl, tcp_size, sum));
}

// Handles the sole checksum-only VNET input we support: a complete IPv4 TCP
// packet whose checksum field is described by the canonical TUN metadata.
inline bool CompleteChecksumOnlyTcpV4(uint8_t* frame, size_t frame_size, size_t header_size) noexcept {
    virtio_net_hdr header{};
    if (!ReadHeader(frame, frame_size, header_size, header) ||
        header.flags != VIRTIO_NET_HDR_F_NEEDS_CSUM || header.gso_type != VIRTIO_NET_HDR_GSO_NONE ||
        le16toh(header.hdr_len) != 0 || le16toh(header.gso_size) != 0) {
        return false;
    }

    TcpV4GsoFrame packet;
    if (!ParseIPv4Tcp(frame + header_size, frame_size - header_size, packet) || !HasTcpChecksumMetadata(header, packet)) {
        return false;
    }

    uint8_t* tcp = packet.ip + packet.ihl;
    tcp[16] = 0;
    tcp[17] = 0;
    WriteBE16(tcp + 16, TcpChecksum(packet));
    return true;
}

inline bool ParseTcpV4Gso(uint8_t* frame, size_t frame_size, size_t header_size, size_t maximum_segment_size, TcpV4GsoFrame& result) noexcept {
    virtio_net_hdr header{};
    if (!ReadHeader(frame, frame_size, header_size, header) ||
        header.flags != VIRTIO_NET_HDR_F_NEEDS_CSUM || header.gso_type != VIRTIO_NET_HDR_GSO_TCPV4) {
        return false;
    }

    TcpV4GsoFrame packet;
    if (!ParseIPv4Tcp(frame + header_size, frame_size - header_size, packet) || !HasTcpChecksumMetadata(header, packet)) {
        return false;
    }

    const size_t virtio_header_size = le16toh(header.hdr_len);
    const size_t gso_size = le16toh(header.gso_size);
    if (virtio_header_size != packet.header_size || gso_size == 0 || packet.payload_size == 0 ||
        packet.header_size > maximum_segment_size || gso_size > maximum_segment_size - packet.header_size) {
        return false;
    }

    packet.gso_size = gso_size;
    result = packet;
    return true;
}

inline bool CompleteTcpV4GsoChecksums(TcpV4GsoFrame& frame) noexcept {
    if (frame.ip == nullptr || frame.packet_size == 0 || frame.ihl < 20 ||
        frame.header_size < frame.ihl + 20 || frame.header_size > frame.packet_size) {
        return false;
    }

    frame.ip[10] = 0;
    frame.ip[11] = 0;
    WriteBE16(frame.ip + 10, FoldChecksum(ChecksumSum(frame.ip, frame.ihl)));

    uint8_t* tcp = frame.ip + frame.ihl;
    tcp[16] = 0;
    tcp[17] = 0;
    WriteBE16(tcp + 16, TcpChecksum(frame));
    return true;
}

// Builds one fully checksummed packet from a fully validated TCPv4 GSO frame.
inline bool BuildTcpV4GsoSegment(const TcpV4GsoFrame& source, size_t payload_offset,
    uint8_t* output, size_t output_capacity, size_t& output_size) noexcept {
    if (source.ip == nullptr || source.gso_size == 0 || payload_offset >= source.payload_size ||
        payload_offset % source.gso_size != 0) {
        return false;
    }

    const size_t payload_size = source.payload_size - payload_offset < source.gso_size
        ? source.payload_size - payload_offset
        : source.gso_size;
    output_size = source.header_size + payload_size;
    if (output == nullptr || output_size > output_capacity || output_size > kMaximumIpv4PacketSize) {
        return false;
    }

    std::memcpy(output, source.ip, source.header_size);
    std::memcpy(output + source.header_size, source.ip + source.header_size + payload_offset, payload_size);
    WriteBE16(output + 2, static_cast<uint16_t>(output_size));
    WriteBE32(output + source.ihl + 4, source.initial_sequence + static_cast<uint32_t>(payload_offset));
    if (payload_offset + payload_size != source.payload_size) {
        output[source.ihl + 13] &= static_cast<uint8_t>(~0x08U);
    }

    output[10] = 0;
    output[11] = 0;
    WriteBE16(output + 10, FoldChecksum(ChecksumSum(output, source.ihl)));

    TcpV4GsoFrame segment;
    if (!ParseIPv4Tcp(output, output_size, segment)) {
        return false;
    }
    uint8_t* tcp = output + segment.ihl;
    tcp[16] = 0;
    tcp[17] = 0;
    WriteBE16(tcp + 16, TcpChecksum(segment));
    return true;
}

} // namespace vnet
} // namespace tap
} // namespace ppp
