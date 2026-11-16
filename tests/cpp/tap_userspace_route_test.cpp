#include <ppp/tap/TapUserspaceRoute.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

namespace {
    using ppp::tap::ClassifyTapUserspacePacket;
    using ppp::tap::TapUserspaceRoute;

    void Require(bool condition, const char* message) {
        if (!condition) {
            std::cerr << message << std::endl;
            std::exit(1);
        }
    }

    // Network-byte-order IPv4 address from dotted parts, matching ITap::IPAddress.
    uint32_t Address(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
        const unsigned char bytes[4] = { a, b, c, d };
        uint32_t value = 0;
        memcpy(&value, bytes, sizeof(value));
        return value;
    }

    std::vector<unsigned char> Packet(uint32_t source, uint32_t destination, unsigned char proto, unsigned char tcp_flags = 0) {
        std::vector<unsigned char> packet(40, 0);
        packet[0] = 0x45;
        packet[9] = proto;
        memcpy(packet.data() + 12, &source, sizeof(source));
        memcpy(packet.data() + 16, &destination, sizeof(destination));
        packet[20 + 13] = tcp_flags;
        return packet;
    }
}

int main() {
    const uint32_t local = Address(10, 0, 0, 2);
    const uint32_t peer = Address(10, 0, 0, 3);
    const uint32_t other = Address(192, 0, 2, 1);
    constexpr unsigned char tcp = 6;
    constexpr unsigned char udp = 17;
    constexpr unsigned char syn = 0x02;
    constexpr unsigned char ack = 0x10;

    auto route = [&](const std::vector<unsigned char>& packet) {
        return ClassifyTapUserspacePacket(packet.data(), static_cast<int>(packet.size()), local);
    };

    Require(route(Packet(local, peer, tcp, syn)) == TapUserspaceRoute::Tunnel,
        "stack-originated SYN must enter the tunnel");
    Require(route(Packet(peer, local, tcp, syn | ack)) == TapUserspaceRoute::Host,
        "peer SYN-ACK must reach the in-process stack");
    Require(route(Packet(peer, local, tcp, ack)) == TapUserspaceRoute::Host,
        "peer data must reach the in-process stack");
    Require(route(Packet(peer, local, tcp, syn)) == TapUserspaceRoute::HostSyn,
        "peer SYN must be reported separately so only forwarded ports are admitted");
    Require(route(Packet(peer, local, udp)) == TapUserspaceRoute::Host,
        "peer UDP addressed to the virtual IP must reach the stack");
    Require(route(Packet(peer, other, tcp, ack)) == TapUserspaceRoute::Drop,
        "packets unrelated to the virtual IP must be dropped");

    auto ipv6 = Packet(local, peer, tcp, syn);
    ipv6[0] = 0x60;
    Require(route(ipv6) == TapUserspaceRoute::Drop, "non-IPv4 packets must be dropped");

    auto bad_header = Packet(peer, local, tcp, ack);
    bad_header[0] = 0x4f;  // 60-byte header longer than the 40-byte packet
    Require(route(bad_header) == TapUserspaceRoute::Drop, "truncated headers must be dropped");

    Require(ClassifyTapUserspacePacket(nullptr, 40, local) == TapUserspaceRoute::Drop, "null packet must be dropped");
    Require(ClassifyTapUserspacePacket(ipv6.data(), 19, local) == TapUserspaceRoute::Drop, "short packet must be dropped");

    auto forwarded = Packet(peer, local, tcp, syn);
    forwarded[22] = 0x1f;  // destination port 8080
    forwarded[23] = 0x90;
    Require(ppp::tap::TapUserspaceTcpDestinationPort(forwarded.data(), static_cast<int>(forwarded.size())) == 8080,
        "TCP destination port must be read in host order");
    auto datagram = Packet(peer, local, udp);
    Require(ppp::tap::TapUserspaceTcpDestinationPort(datagram.data(), static_cast<int>(datagram.size())) == 0,
        "non-TCP packets have no TCP destination port");

    std::cout << "tap userspace route tests passed\n";
    return 0;
}
