#define BOOST_TEST_MODULE icmp_path_mtu_test
#include <boost/test/included/unit_test.hpp>

#include <cstring>

#include <ppp/app/protocol/VirtualEthernetPathMtu.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>

using ppp::Byte;
using ppp::app::protocol::IcmpPathMtuError;
using ppp::app::protocol::TryParseIcmpPathMtuError;
using ppp::app::protocol::GetVirtualEthernetPathMtuCache;
using ppp::app::protocol::ComputeDynamicTcpMss;
using ppp::app::protocol::kVEthernetTunnelOverhead;
using ppp::net::native::icmp_hdr;
using ppp::net::native::ip_hdr;
using ppp::app::protocol::IcmpIPv6PathMtuError;
using ppp::app::protocol::TryParseIcmpIPv6PathMtuError;
using ppp::app::protocol::GetVirtualEthernetIPv6PathMtuCache;
using ppp::app::protocol::VirtualEthernetIPv6PathMtuAddress;

namespace {

constexpr int kOuterHeaderLength = 20;
constexpr int kIcmpHeaderLength = 8;
constexpr int kQuotedHeaderLength = 20;
constexpr int kQuotedTransportLength = 8;
constexpr int kPacketLength = kOuterHeaderLength + kIcmpHeaderLength +
    kQuotedHeaderLength + kQuotedTransportLength;
constexpr ppp::UInt32 kRouter = 0xc0000201; // 192.0.2.1
constexpr ppp::UInt32 kClient = 0x0a000002; // 10.0.0.2
constexpr ppp::UInt32 kRemote = 0xc6336401; // 198.51.100.1

void BuildIcmpError(Byte* packet, Byte type, Byte code, unsigned short mtu) {
    std::memset(packet, 0, kPacketLength);

    ip_hdr* outer = reinterpret_cast<ip_hdr*>(packet);
    outer->v_hl = 0x45;
    outer->len = htons(kPacketLength);
    outer->ttl = 64;
    outer->proto = ip_hdr::IP_PROTO_ICMP;
    outer->src = htonl(kRouter);
    outer->dest = htonl(kClient);

    icmp_hdr* icmp = reinterpret_cast<icmp_hdr*>(packet + kOuterHeaderLength);
    icmp->icmp_type = type;
    icmp->icmp_code = code;
    icmp->icmp_id = 0;
    icmp->icmp_seq = htons(mtu);

    ip_hdr* quoted = reinterpret_cast<ip_hdr*>(packet + kOuterHeaderLength + kIcmpHeaderLength);
    quoted->v_hl = 0x45;
    quoted->len = htons(kQuotedHeaderLength + kQuotedTransportLength);
    quoted->ttl = 64;
    quoted->proto = ip_hdr::IP_PROTO_UDP;
    quoted->src = htonl(kClient);
    quoted->dest = htonl(kRemote);

    icmp->icmp_chksum = ppp::net::native::inet_chksum(icmp,
        kPacketLength - kOuterHeaderLength);
    outer->chksum = ppp::net::native::inet_chksum(outer, kOuterHeaderLength);
}

constexpr int kIPv6OuterHeaderLength = ppp::ipv6::IPv6_HEADER_MIN_SIZE;
constexpr int kIPv6IcmpHeaderLength = 8;
constexpr int kIPv6QuotedHeaderLength = ppp::ipv6::IPv6_HEADER_MIN_SIZE;
constexpr int kIPv6PacketLength = kIPv6OuterHeaderLength + kIPv6IcmpHeaderLength + kIPv6QuotedHeaderLength;
const Byte kIPv6Router[ppp::ipv6::IPv6_ADDRESS_SIZE] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const Byte kIPv6Client[ppp::ipv6::IPv6_ADDRESS_SIZE] = { 0xfd, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
const Byte kIPv6Remote[ppp::ipv6::IPv6_ADDRESS_SIZE] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };

void BuildIcmpIPv6PacketTooBig(Byte* packet, Byte type, Byte code, ppp::UInt32 mtu) {
    std::memset(packet, 0, kIPv6PacketLength);

    ppp::ipv6::PacketHeader* outer = reinterpret_cast<ppp::ipv6::PacketHeader*>(packet);
    outer->VersionTrafficClass = 0x60;
    outer->PayloadLength = htons(kIPv6IcmpHeaderLength + kIPv6QuotedHeaderLength);
    outer->NextHeader = IPPROTO_ICMPV6;
    outer->HopLimit = 64;
    std::memcpy(outer->Source, kIPv6Router, sizeof(outer->Source));
    std::memcpy(outer->Destination, kIPv6Client, sizeof(outer->Destination));

    Byte* icmp = packet + kIPv6OuterHeaderLength;
    icmp[0] = type;
    icmp[1] = code;
    ppp::UInt32 network_mtu = htonl(mtu);
    std::memcpy(icmp + 4, &network_mtu, sizeof(network_mtu));

    ppp::ipv6::PacketHeader* quoted = reinterpret_cast<ppp::ipv6::PacketHeader*>(icmp + kIPv6IcmpHeaderLength);
    quoted->VersionTrafficClass = 0x60;
    quoted->NextHeader = IPPROTO_UDP;
    std::memcpy(quoted->Source, kIPv6Client, sizeof(quoted->Source));
    std::memcpy(quoted->Destination, kIPv6Remote, sizeof(quoted->Destination));

    boost::asio::ip::address_v6::bytes_type source_bytes;
    boost::asio::ip::address_v6::bytes_type destination_bytes;
    std::memcpy(source_bytes.data(), outer->Source, source_bytes.size());
    std::memcpy(destination_bytes.data(), outer->Destination, destination_bytes.size());
    const unsigned short checksum = ppp::ipv6::ComputePseudoChecksum(
        reinterpret_cast<unsigned char*>(icmp), kIPv6IcmpHeaderLength + kIPv6QuotedHeaderLength,
        boost::asio::ip::address_v6(source_bytes), boost::asio::ip::address_v6(destination_bytes), IPPROTO_ICMPV6);
    std::memcpy(icmp + 2, &checksum, sizeof(checksum));
}

} // namespace

BOOST_AUTO_TEST_CASE(parses_fragmentation_needed_and_preserves_next_hop_mtu) {
    Byte packet[kPacketLength];
    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 4, 1300);

    IcmpPathMtuError error;
    BOOST_REQUIRE(TryParseIcmpPathMtuError(packet, kPacketLength, error));
    BOOST_TEST(error.IsPathMtuUpdate);
    BOOST_TEST(error.NextHopMtu == 1300);
    BOOST_TEST(error.OuterDestination == htonl(kClient));
    BOOST_TEST(error.QuotedSource == htonl(kClient));
    BOOST_TEST(error.QuotedDestination == htonl(kRemote));
    BOOST_TEST(error.QuotedProtocol == ip_hdr::IP_PROTO_UDP);
}

BOOST_AUTO_TEST_CASE(accepts_time_exceeded_without_pmtu_update) {
    Byte packet[kPacketLength];
    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_TE, 0, 0);

    IcmpPathMtuError error;
    BOOST_REQUIRE(TryParseIcmpPathMtuError(packet, kPacketLength, error));
    BOOST_TEST(!error.IsPathMtuUpdate);
    BOOST_TEST(error.NextHopMtu == 0);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_checksum_unsupported_code_and_short_quote) {
    Byte packet[kPacketLength];
    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 4, 1300);
    packet[kOuterHeaderLength + kIcmpHeaderLength + kQuotedHeaderLength] ^= 0x01;

    IcmpPathMtuError error;
    BOOST_TEST(!TryParseIcmpPathMtuError(packet, kPacketLength, error));

    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 3, 1300);
    BOOST_TEST(!TryParseIcmpPathMtuError(packet, kPacketLength, error));

    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 4, 1300);
    BOOST_TEST(!TryParseIcmpPathMtuError(packet, kPacketLength - 1, error));
}

BOOST_AUTO_TEST_CASE(cache_only_lowers_pmtu_and_expires) {
    auto& cache = GetVirtualEthernetPathMtuCache();
    cache.Clear();
    const ppp::UInt32 destination = htonl(kRemote);
    const ppp::UInt64 now = 1000;

    BOOST_TEST(cache.Observe(destination, 1300, now));
    BOOST_TEST(cache.Lookup(destination, now) == 1300);
    BOOST_TEST(!cache.Observe(destination, 1400, now + 1));
    BOOST_TEST(cache.Lookup(destination, now + 1) == 1300);
    BOOST_TEST(ComputeDynamicTcpMss(true, kVEthernetTunnelOverhead,
        cache.Lookup(destination, now + 1)) == 1260);
    BOOST_TEST(cache.Lookup(destination,
        now + ppp::app::protocol::VirtualEthernetPathMtuCache::kLifetimeMilliseconds + 2) == 0);
}

BOOST_AUTO_TEST_CASE(parses_ipv6_packet_too_big_and_preserves_addresses) {
    Byte packet[kIPv6PacketLength];
    BuildIcmpIPv6PacketTooBig(packet, 2, 0, 1280);

    IcmpIPv6PathMtuError error;
    BOOST_REQUIRE(TryParseIcmpIPv6PathMtuError(packet, kIPv6PacketLength, error));
    BOOST_TEST(error.NextHopMtu == 1280U);
    BOOST_TEST(std::memcmp(error.OuterDestination.Bytes.data(), kIPv6Client,
        error.OuterDestination.Bytes.size()) == 0);
    BOOST_TEST(std::memcmp(error.QuotedSource.Bytes.data(), kIPv6Client,
        error.QuotedSource.Bytes.size()) == 0);
    BOOST_TEST(error.QuotedProtocol == IPPROTO_UDP);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_ipv6_pmtu_control_packets) {
    Byte packet[kIPv6PacketLength];
    IcmpIPv6PathMtuError error;

    BuildIcmpIPv6PacketTooBig(packet, 2, 0, 1280);
    packet[kIPv6OuterHeaderLength + kIPv6IcmpHeaderLength + kIPv6QuotedHeaderLength - 1] ^= 0x01;
    BOOST_TEST(!TryParseIcmpIPv6PathMtuError(packet, kIPv6PacketLength, error));

    BuildIcmpIPv6PacketTooBig(packet, 1, 0, 1280);
    BOOST_TEST(!TryParseIcmpIPv6PathMtuError(packet, kIPv6PacketLength, error));
    BuildIcmpIPv6PacketTooBig(packet, 2, 1, 1280);
    BOOST_TEST(!TryParseIcmpIPv6PathMtuError(packet, kIPv6PacketLength, error));
    BuildIcmpIPv6PacketTooBig(packet, 2, 0, 1279);
    BOOST_TEST(!TryParseIcmpIPv6PathMtuError(packet, kIPv6PacketLength, error));

    BuildIcmpIPv6PacketTooBig(packet, 2, 0, 1280);
    BOOST_TEST(!TryParseIcmpIPv6PathMtuError(packet, kIPv6PacketLength - 1, error));
    BuildIcmpIPv6PacketTooBig(packet, 2, 0, 1280);
    reinterpret_cast<ppp::ipv6::PacketHeader*>(packet)->NextHeader = 0;
    BOOST_TEST(!TryParseIcmpIPv6PathMtuError(packet, kIPv6PacketLength, error));
}

BOOST_AUTO_TEST_CASE(ipv6_cache_only_lowers_pmtu_and_expires) {
    auto& cache = GetVirtualEthernetIPv6PathMtuCache();
    cache.Clear();
    VirtualEthernetIPv6PathMtuAddress destination;
    BOOST_REQUIRE(VirtualEthernetIPv6PathMtuAddress::TryCreate(kIPv6Remote, destination));
    const ppp::UInt64 now = 1000;

    BOOST_TEST(cache.Observe(destination, 1400, now));
    BOOST_TEST(cache.Lookup(destination, now) == 1400);
    BOOST_TEST(!cache.Observe(destination, 1450, now + 1));
    BOOST_TEST(cache.Observe(destination, 1280, now + 2));
    BOOST_TEST(cache.Lookup(destination, now + 2) == 1280);
    BOOST_TEST(cache.Lookup(destination,
        now + ppp::app::protocol::VirtualEthernetIPv6PathMtuCache::kLifetimeMilliseconds + 3) == 0);
}
