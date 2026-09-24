#define BOOST_TEST_MODULE tcp_mss_clamp_test
#include <boost/test/included/unit_test.hpp>

#include <cstring>

#include <ppp/app/protocol/VirtualEthernetTcpMss.h>

using ppp::Byte;
using ppp::app::protocol::ClampTcpMssIPv4;
using ppp::app::protocol::ClampTcpMssIPv6;
using ppp::app::protocol::ComputeDynamicTcpMss;
using ppp::app::protocol::kVEthernetTunnelOverhead;
using ppp::net::native::ip_hdr;
using ppp::net::native::tcp_hdr;

namespace {

constexpr int kIpHeaderLength = 20;
constexpr int kTcpHeaderLength = 24; // 20-byte header + 4-byte MSS option
constexpr int kIPv4PacketLength = kIpHeaderLength + kTcpHeaderLength;
constexpr int kIPv6PacketLength = ppp::ipv6::IPv6_HEADER_MIN_SIZE + kTcpHeaderLength;

void WriteMssOption(Byte* options, unsigned short mss) {
    options[0] = 2; // kind: MSS
    options[1] = 4; // length
    *reinterpret_cast<unsigned short*>(options + 2) = htons(mss);
}

unsigned short ReadMssOption(const Byte* options) {
    return ntohs(*reinterpret_cast<const unsigned short*>(options + 2));
}

// Builds an IPv4 TCP packet with an MSS option; flags selects the TCP flags (e.g. TCP_SYN).
void BuildIPv4TcpPacket(Byte* packet, unsigned short tcp_flags, unsigned short mss) {
    std::memset(packet, 0, kIPv4PacketLength);

    ip_hdr* iphdr = reinterpret_cast<ip_hdr*>(packet);
    iphdr->v_hl = 0x45;
    iphdr->tos = 0;
    iphdr->len = htons(kIPv4PacketLength);
    iphdr->id = htons(1);
    iphdr->flags = htons(ip_hdr::IP_DF);
    iphdr->ttl = 64;
    iphdr->proto = ip_hdr::IP_PROTO_TCP;
    iphdr->src = htonl(0x0a000002);
    iphdr->dest = htonl(0x0a000001);
    iphdr->chksum = 0;
    iphdr->chksum = ppp::net::native::inet_chksum(iphdr, kIpHeaderLength);

    tcp_hdr* tcphdr = reinterpret_cast<tcp_hdr*>(packet + kIpHeaderLength);
    tcphdr->src = htons(12345);
    tcphdr->dest = htons(443);
    tcphdr->seqno = htonl(1000);
    tcphdr->ackno = 0;
    tcphdr->hdrlen_rsvd_flags = htons((unsigned short)((kTcpHeaderLength / 4) << 12) | tcp_flags);
    tcphdr->wnd = htons(65535);
    tcphdr->urgp = 0;
    WriteMssOption(reinterpret_cast<Byte*>(tcphdr) + tcp_hdr::TCP_HLEN, mss);
    tcphdr->chksum = 0;
    tcphdr->chksum = ppp::net::native::inet_chksum_pseudo(
        reinterpret_cast<unsigned char*>(tcphdr), IPPROTO_TCP, kTcpHeaderLength, iphdr->src, iphdr->dest);
}

void BuildIPv6TcpPacket(Byte* packet, unsigned short tcp_flags, unsigned short mss) {
    std::memset(packet, 0, kIPv6PacketLength);

    ppp::ipv6::PacketHeader* header = reinterpret_cast<ppp::ipv6::PacketHeader*>(packet);
    header->VersionTrafficClass = 0x60;
    header->PayloadLength = htons(kTcpHeaderLength);
    header->NextHeader = IPPROTO_TCP;
    header->HopLimit = 64;
    header->Source[0] = 0xfd;
    header->Source[1] = 0x42;
    header->Source[15] = 0x01;
    header->Destination[0] = 0xfd;
    header->Destination[1] = 0x42;
    header->Destination[15] = 0x02;

    tcp_hdr* tcphdr = reinterpret_cast<tcp_hdr*>(packet + ppp::ipv6::IPv6_HEADER_MIN_SIZE);
    tcphdr->src = htons(12345);
    tcphdr->dest = htons(443);
    tcphdr->seqno = htonl(1000);
    tcphdr->ackno = 0;
    tcphdr->hdrlen_rsvd_flags = htons((unsigned short)((kTcpHeaderLength / 4) << 12) | tcp_flags);
    tcphdr->wnd = htons(65535);
    tcphdr->urgp = 0;
    WriteMssOption(reinterpret_cast<Byte*>(tcphdr) + tcp_hdr::TCP_HLEN, mss);
    tcphdr->chksum = 0;
    tcphdr->chksum = ppp::ipv6::ComputePseudoChecksum(
        reinterpret_cast<unsigned char*>(tcphdr), kTcpHeaderLength,
        boost::asio::ip::make_address_v6("fd42::1"), boost::asio::ip::make_address_v6("fd42::2"), IPPROTO_TCP);
}

} // namespace

BOOST_AUTO_TEST_CASE(compute_dynamic_mss_matches_tunnel_overhead) {
    // 1500 (ITap::Mtu) - 80 (tunnel overhead) - 20 (IPv4) - 20 (TCP) = 1380.
    BOOST_TEST(ComputeDynamicTcpMss(true, kVEthernetTunnelOverhead) == 1380);
    // 1500 - 80 - 40 (IPv6) - 20 (TCP) = 1360.
    BOOST_TEST(ComputeDynamicTcpMss(false, kVEthernetTunnelOverhead) == 1360);
}

BOOST_AUTO_TEST_CASE(compute_dynamic_ipv6_mss_uses_learned_pmtu_without_exceeding_tunnel_budget) {
    // IPv6 minimum MTU: 1280 - 40-byte IPv6 header - 20-byte TCP header = 1220.
    BOOST_TEST(ComputeDynamicTcpMss(false, kVEthernetTunnelOverhead, 1280) == 1220);
    // A learned MTU above the static tunnel budget must not increase the static MSS.
    BOOST_TEST(ComputeDynamicTcpMss(false, kVEthernetTunnelOverhead, 1500) == 1360);
}

BOOST_AUTO_TEST_CASE(compute_dynamic_mss_respects_clamp_bounds) {
    BOOST_TEST(ComputeDynamicTcpMss(true, 0) == ppp::app::protocol::kTcpMssIPv4Max);
    BOOST_TEST(ComputeDynamicTcpMss(false, 0) == ppp::app::protocol::kTcpMssIPv6Max);
    BOOST_TEST(ComputeDynamicTcpMss(true, 100000) == ppp::app::protocol::kTcpMssIPv4Min);
    BOOST_TEST(ComputeDynamicTcpMss(false, 100000) == ppp::app::protocol::kTcpMssIPv6Min);
    // Negative overhead is treated as zero.
    BOOST_TEST(ComputeDynamicTcpMss(true, -5) == ppp::app::protocol::kTcpMssIPv4Max);
}

BOOST_AUTO_TEST_CASE(clamp_ipv4_syn_lowers_mss_and_fixes_checksums) {
    Byte packet[kIPv4PacketLength];
    BuildIPv4TcpPacket(packet, tcp_hdr::TCP_SYN, 1460);

    const unsigned short clamped = ComputeDynamicTcpMss(true, kVEthernetTunnelOverhead);
    BOOST_TEST(ClampTcpMssIPv4(packet, kIPv4PacketLength, clamped));

    tcp_hdr* tcphdr = reinterpret_cast<tcp_hdr*>(packet + kIpHeaderLength);
    BOOST_TEST(ReadMssOption(reinterpret_cast<Byte*>(tcphdr) + tcp_hdr::TCP_HLEN) == clamped);

    // IP header checksum must verify over the whole header (result folds to zero).
    ip_hdr* iphdr = reinterpret_cast<ip_hdr*>(packet);
    BOOST_TEST(ppp::net::native::inet_chksum(iphdr, kIpHeaderLength) == 0);

    // TCP checksum must match a fresh pseudo-header recomputation.
    unsigned short stored = tcphdr->chksum;
    tcphdr->chksum = 0;
    BOOST_TEST(ppp::net::native::inet_chksum_pseudo(
        reinterpret_cast<unsigned char*>(tcphdr), IPPROTO_TCP, kTcpHeaderLength, iphdr->src, iphdr->dest) == stored);
}

BOOST_AUTO_TEST_CASE(clamp_ipv4_syn_with_lower_mss_is_untouched) {
    Byte packet[kIPv4PacketLength];
    BuildIPv4TcpPacket(packet, tcp_hdr::TCP_SYN, 1200);

    Byte original[kIPv4PacketLength];
    std::memcpy(original, packet, kIPv4PacketLength);

    BOOST_TEST(!ClampTcpMssIPv4(packet, kIPv4PacketLength, 1380));
    BOOST_TEST(std::memcmp(original, packet, kIPv4PacketLength) == 0);
}

BOOST_AUTO_TEST_CASE(clamp_ipv4_non_syn_is_untouched) {
    Byte packet[kIPv4PacketLength];
    BuildIPv4TcpPacket(packet, tcp_hdr::TCP_ACK, 1460);

    Byte original[kIPv4PacketLength];
    std::memcpy(original, packet, kIPv4PacketLength);

    BOOST_TEST(!ClampTcpMssIPv4(packet, kIPv4PacketLength, 1380));
    BOOST_TEST(std::memcmp(original, packet, kIPv4PacketLength) == 0);
}

BOOST_AUTO_TEST_CASE(clamp_ipv4_syn_without_mss_option_is_untouched) {
    Byte packet[kIPv4PacketLength];
    BuildIPv4TcpPacket(packet, tcp_hdr::TCP_SYN, 1460);

    // Replace the MSS option with NOP + EOL padding.
    tcp_hdr* tcphdr = reinterpret_cast<tcp_hdr*>(packet + kIpHeaderLength);
    Byte* options = reinterpret_cast<Byte*>(tcphdr) + tcp_hdr::TCP_HLEN;
    options[0] = 1;
    options[1] = 1;
    options[2] = 1;
    options[3] = 0;

    BOOST_TEST(!ClampTcpMssIPv4(packet, kIPv4PacketLength, 1380));
}

BOOST_AUTO_TEST_CASE(clamp_ipv4_rejects_truncated_packets) {
    Byte packet[kIPv4PacketLength];
    BuildIPv4TcpPacket(packet, tcp_hdr::TCP_SYN, 1460);

    BOOST_TEST(!ClampTcpMssIPv4(nullptr, kIPv4PacketLength, 1380));
    BOOST_TEST(!ClampTcpMssIPv4(packet, kIpHeaderLength - 1, 1380));
    BOOST_TEST(!ClampTcpMssIPv4(packet, kIpHeaderLength + tcp_hdr::TCP_HLEN - 1, 1380));
}

BOOST_AUTO_TEST_CASE(clamp_ipv6_syn_lowers_mss_and_fixes_checksum) {
    Byte packet[kIPv6PacketLength];
    BuildIPv6TcpPacket(packet, tcp_hdr::TCP_SYN, 1440);

    const unsigned short clamped = ComputeDynamicTcpMss(false, kVEthernetTunnelOverhead);
    BOOST_TEST(ClampTcpMssIPv6(packet, kIPv6PacketLength, clamped));

    tcp_hdr* tcphdr = reinterpret_cast<tcp_hdr*>(packet + ppp::ipv6::IPv6_HEADER_MIN_SIZE);
    BOOST_TEST(ReadMssOption(reinterpret_cast<Byte*>(tcphdr) + tcp_hdr::TCP_HLEN) == clamped);

    unsigned short stored = tcphdr->chksum;
    tcphdr->chksum = 0;
    BOOST_TEST(ppp::ipv6::ComputePseudoChecksum(
        reinterpret_cast<unsigned char*>(tcphdr), kTcpHeaderLength,
        boost::asio::ip::make_address_v6("fd42::1"), boost::asio::ip::make_address_v6("fd42::2"), IPPROTO_TCP) == stored);
}

BOOST_AUTO_TEST_CASE(clamp_ipv6_non_tcp_is_untouched) {
    Byte packet[kIPv6PacketLength];
    BuildIPv6TcpPacket(packet, tcp_hdr::TCP_SYN, 1440);

    ppp::ipv6::PacketHeader* header = reinterpret_cast<ppp::ipv6::PacketHeader*>(packet);
    header->NextHeader = IPPROTO_UDP;

    BOOST_TEST(!ClampTcpMssIPv6(packet, kIPv6PacketLength, 1360));
}
