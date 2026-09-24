#define BOOST_TEST_MODULE tap_vnet_codec_test
#include <boost/test/included/unit_test.hpp>

#include <linux/ppp/tap/TapVnetCodec.h>
#include <ppp/tap/ITap.h>

#include <cstring>
#include <vector>

namespace {
using namespace ppp::tap::vnet;

std::vector<uint8_t> MakeIpv4Tcp(size_t payload_size) {
    std::vector<uint8_t> packet(20 + 20 + payload_size, 0);
    packet[0] = 0x45;
    WriteBE16(packet.data() + 2, static_cast<uint16_t>(packet.size()));
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = IPPROTO_TCP;
    packet[12] = 10;
    packet[15] = 1;
    packet[16] = 10;
    packet[19] = 2;
    uint8_t* tcp = packet.data() + 20;
    WriteBE16(tcp, 40000);
    WriteBE16(tcp + 2, 40001);
    WriteBE32(tcp + 4, 0x10203040U);
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    for (size_t index = 0; index < payload_size; ++index) {
        tcp[20 + index] = static_cast<uint8_t>(index + 1);
    }
    WriteBE16(packet.data() + 10, FoldChecksum(ChecksumSum(packet.data(), 20)));
    return packet;
}

std::vector<uint8_t> MakeVnetFrame(const std::vector<uint8_t>& packet, bool gso = false) {
    std::vector<uint8_t> frame(kStandardVirtioHeaderSize + packet.size(), 0);
    virtio_net_hdr header{};
    header.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header.gso_type = gso ? VIRTIO_NET_HDR_GSO_TCPV4 : VIRTIO_NET_HDR_GSO_NONE;
    header.hdr_len = htole16(gso ? 40 : 0);
    header.gso_size = htole16(gso ? 100 : 0);
    header.csum_start = htole16(20);
    header.csum_offset = htole16(16);
    std::memcpy(frame.data(), &header, sizeof(header));
    std::memcpy(frame.data() + kStandardVirtioHeaderSize, packet.data(), packet.size());
    return frame;
}

bool HasValidTcpChecksum(uint8_t* packet, size_t size) {
    TcpV4GsoFrame parsed;
    return ParseIPv4Tcp(packet, size, parsed) && TcpChecksum(parsed) == 0;
}
} // namespace

BOOST_AUTO_TEST_CASE(standard_vnet_header_derives_ipv4_read_capacity) {
    size_t capacity = 0;
    BOOST_TEST(IsStandardHeaderSize(sizeof(virtio_net_hdr)));
    BOOST_REQUIRE(ReadCapacity(sizeof(virtio_net_hdr), capacity));
    BOOST_TEST(capacity == sizeof(virtio_net_hdr) + kMaximumIpv4PacketSize);
    BOOST_TEST(!ReadCapacity(sizeof(virtio_net_hdr) - 1, capacity));
}

BOOST_AUTO_TEST_CASE(complete_checksum_tcpv4_gso_header_is_encoded_for_tun) {
    std::vector<uint8_t> packet = MakeIpv4Tcp(2400);
    const auto metadata = ppp::tap::TxGsoMetadata::ParseTcpV4(
        packet.data(), packet.size(), 1400, 2);
    BOOST_REQUIRE(metadata);
    BOOST_TEST(metadata->HeaderLength() == 40U);
    BOOST_TEST(static_cast<unsigned>(metadata->ChecksumState()) ==
        static_cast<unsigned>(ppp::tap::TxChecksumState::Complete));

    virtio_net_hdr header{};
    BOOST_REQUIRE(BuildTcpV4GsoHeader(packet.data(), packet.size(), *metadata, header));
    BOOST_TEST(header.flags == 0U);
    BOOST_TEST(header.gso_type == VIRTIO_NET_HDR_GSO_TCPV4);
    BOOST_TEST(le16toh(header.hdr_len) == 40U);
    BOOST_TEST(le16toh(header.gso_size) == 1400U);
    BOOST_TEST(le16toh(header.csum_start) == 0U);
    BOOST_TEST(le16toh(header.csum_offset) == 0U);

    packet[6] = 0x20;
    BOOST_TEST(!BuildTcpV4GsoHeader(packet.data(), packet.size(), *metadata, header));
    packet[6] = 0x40;
    packet[3] -= 1;
    BOOST_TEST(!BuildTcpV4GsoHeader(packet.data(), packet.size(), *metadata, header));
}

BOOST_AUTO_TEST_CASE(checksum_only_tcpv4_is_finalized_before_delivery) {
    std::vector<uint8_t> frame = MakeVnetFrame(MakeIpv4Tcp(37));
    BOOST_REQUIRE(CompleteChecksumOnlyTcpV4(frame.data(), frame.size(), kStandardVirtioHeaderSize));
    BOOST_TEST(HasValidTcpChecksum(frame.data() + kStandardVirtioHeaderSize, frame.size() - kStandardVirtioHeaderSize));
}

BOOST_AUTO_TEST_CASE(checksum_only_rejects_unsupported_or_malformed_metadata) {
    std::vector<uint8_t> non_tcp = MakeVnetFrame(MakeIpv4Tcp(1));
    non_tcp[kStandardVirtioHeaderSize + 9] = IPPROTO_UDP;
    BOOST_TEST(!CompleteChecksumOnlyTcpV4(non_tcp.data(), non_tcp.size(), kStandardVirtioHeaderSize));

    std::vector<uint8_t> bad_offset = MakeVnetFrame(MakeIpv4Tcp(1));
    virtio_net_hdr header{};
    std::memcpy(&header, bad_offset.data(), sizeof(header));
    header.csum_offset = htole16(15);
    std::memcpy(bad_offset.data(), &header, sizeof(header));
    BOOST_TEST(!CompleteChecksumOnlyTcpV4(bad_offset.data(), bad_offset.size(), kStandardVirtioHeaderSize));

    std::vector<uint8_t> bad_length = MakeVnetFrame(MakeIpv4Tcp(1));
    bad_length[kStandardVirtioHeaderSize + 3] -= 1;
    BOOST_TEST(!CompleteChecksumOnlyTcpV4(bad_length.data(), bad_length.size(), kStandardVirtioHeaderSize));
}

BOOST_AUTO_TEST_CASE(tcpv4_gso_requires_canonical_metadata_and_builds_segments) {
    std::vector<uint8_t> frame = MakeVnetFrame(MakeIpv4Tcp(180), true);
    TcpV4GsoFrame gso;
    BOOST_REQUIRE(ParseTcpV4Gso(frame.data(), frame.size(), kStandardVirtioHeaderSize, 1500, gso));
    BOOST_TEST(gso.header_size == 40U);
    BOOST_TEST(gso.gso_size == 100U);
    BOOST_TEST(gso.payload_size == 180U);

    std::vector<uint8_t> first(1500);
    std::vector<uint8_t> second(1500);
    size_t first_size = 0;
    size_t second_size = 0;
    BOOST_REQUIRE(BuildTcpV4GsoSegment(gso, 0, first.data(), first.size(), first_size));
    BOOST_REQUIRE(BuildTcpV4GsoSegment(gso, 100, second.data(), second.size(), second_size));
    BOOST_TEST(first_size == 140U);
    BOOST_TEST(second_size == 120U);
    BOOST_TEST(HasValidTcpChecksum(first.data(), first_size));
    BOOST_TEST(HasValidTcpChecksum(second.data(), second_size));
    BOOST_TEST((first[20 + 13] & 0x08U) == 0U);
    BOOST_TEST((second[20 + 13] & 0x08U) != 0U);
    BOOST_TEST(ReadBE32(second.data() + 24) == 0x102030a4U);

    virtio_net_hdr header{};
    std::memcpy(&header, frame.data(), sizeof(header));
    header.flags = 0;
    std::memcpy(frame.data(), &header, sizeof(header));
    BOOST_TEST(!ParseTcpV4Gso(frame.data(), frame.size(), kStandardVirtioHeaderSize, 1500, gso));

    header.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header.csum_start = htole16(19);
    std::memcpy(frame.data(), &header, sizeof(header));
    BOOST_TEST(!ParseTcpV4Gso(frame.data(), frame.size(), kStandardVirtioHeaderSize, 1500, gso));

    header.csum_start = htole16(20);
    header.hdr_len = htole16(39);
    std::memcpy(frame.data(), &header, sizeof(header));
    BOOST_TEST(!ParseTcpV4Gso(frame.data(), frame.size(), kStandardVirtioHeaderSize, 1500, gso));

    header.hdr_len = htole16(40);
    header.gso_size = htole16(1461);
    std::memcpy(frame.data(), &header, sizeof(header));
    BOOST_TEST(!ParseTcpV4Gso(frame.data(), frame.size(), kStandardVirtioHeaderSize, 1500, gso));
}

BOOST_AUTO_TEST_CASE(tcpv4_gso_whole_frame_delivery_requires_consumer_capability) {
    ppp::tap::ITap::PacketInputEventArgs ordinary{};
    ordinary.TcpV4Gso = false;
    BOOST_TEST(ppp::tap::ITap::ShouldDeliverWholeTcpV4Gso(ordinary, false));

    ppp::tap::ITap::PacketInputEventArgs gso{};
    gso.TcpV4Gso = true;
    BOOST_TEST(!ppp::tap::ITap::ShouldDeliverWholeTcpV4Gso(gso, false));
    BOOST_TEST(ppp::tap::ITap::ShouldDeliverWholeTcpV4Gso(gso, true));
}

BOOST_AUTO_TEST_CASE(tcpv4_gso_can_be_completed_for_direct_stack_injection) {
    std::vector<uint8_t> frame = MakeVnetFrame(MakeIpv4Tcp(180), true);
    TcpV4GsoFrame gso;
    BOOST_REQUIRE(ParseTcpV4Gso(frame.data(), frame.size(), kStandardVirtioHeaderSize, 1500, gso));
    BOOST_REQUIRE(CompleteTcpV4GsoChecksums(gso));
    BOOST_TEST(FoldChecksum(ChecksumSum(gso.ip, gso.ihl)) == 0U);
    BOOST_TEST(TcpChecksum(gso) == 0U);
}
