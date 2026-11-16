#include <ppp/net/Socket.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/tap/ITap.h>

#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

// Link-only stubs: Socket.cpp is not linked (UdpFrame/IPFrame only read the TOS
// flag from it), and the test always passes a null BufferswapAllocator.
namespace ppp {
    namespace net {
        Socket::SOCKET_RESTRICTIONS::SOCKET_RESTRICTIONS() noexcept
            : IPV6_TCLASS_ON(true)
            , IP_TOS_ON(true)
            , IP_TOS_DEFAULT_FLASH(true) {
        }

        Socket::SOCKET_RESTRICTIONS Socket::SOCKET_RESTRICTIONS_;
    }

    namespace threading {
        void* BufferswapAllocator::Alloc(uint32_t) noexcept {
            return nullptr;
        }

        bool BufferswapAllocator::Free(const void*) noexcept {
            return false;
        }
    }
}

namespace {

using ppp::net::IPEndPoint;
using ppp::net::packet::BufferSegment;
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;

void Require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// Reference: the frame-object path the client used for every downstream datagram.
std::vector<ppp::Byte> Reference(const IPEndPoint& source, const IPEndPoint& destination, const std::vector<ppp::Byte>& payload) {
    auto messages = std::make_shared<BufferSegment>();
    messages->Buffer = std::shared_ptr<ppp::Byte>(new ppp::Byte[payload.size()], std::default_delete<ppp::Byte[]>());
    std::memcpy(messages->Buffer.get(), payload.data(), payload.size());
    messages->Length = static_cast<int>(payload.size());

    UdpFrame frame;
    frame.AddressesFamily = ppp::net::AddressFamily::InterNetwork;
    frame.Source = source;
    frame.Destination = destination;
    frame.Payload = messages;

    std::shared_ptr<IPFrame> ip = UdpFrame::ToIp(nullptr, &frame);
    Require(ip != nullptr, "reference ToIp failed");

    ppp::vector<IPFrame::IPFramePtr> fragments;
    int count = IPFrame::Subpackages(fragments, ip);
    Require(count == 1, "reference unexpectedly fragmented");

    std::shared_ptr<BufferSegment> bytes = IPFrame::ToArray(nullptr, ip.get());
    Require(bytes != nullptr, "reference ToArray failed");
    return std::vector<ppp::Byte>(bytes->Buffer.get(), bytes->Buffer.get() + bytes->Length);
}

void CheckEquivalent(std::mt19937& rng, bool flash_tos) {
    ppp::net::Socket::SetDefaultFlashTypeOfService(flash_tos);

    const int max_udp = ((ppp::tap::ITap::Mtu - static_cast<int>(sizeof(ppp::net::native::ip_hdr))) >> 3) << 3;
    const int max_payload = max_udp - static_cast<int>(sizeof(ppp::net::native::udp_hdr));

    std::vector<int> sizes = { 1, 2, 3, 7, 8, 9, 63, 64, 65, 512, 1199, 1200, max_payload - 1, max_payload };
    for (int i = 0; i < 300; i++) {
        sizes.push_back(1 + static_cast<int>(rng() % static_cast<unsigned>(max_payload)));
    }

    for (int size : sizes) {
        std::vector<ppp::Byte> payload(size);
        for (auto& b : payload) {
            b = static_cast<ppp::Byte>(rng());
        }

        IPEndPoint source(static_cast<ppp::UInt32>(rng()), 1 + static_cast<int>(rng() % 65535));
        IPEndPoint destination(static_cast<ppp::UInt32>(rng()), 1 + static_cast<int>(rng() % 65535));

        std::vector<ppp::Byte> expected = Reference(source, destination, payload);

        int length = 0;
        std::shared_ptr<ppp::Byte> actual = UdpFrame::ToIPv4Packet(nullptr, source, destination, IPFrame::DefaultTtl,
            payload.data(), size, length);
        Require(actual != nullptr, "ToIPv4Packet failed for size " + std::to_string(size));
        Require(length == static_cast<int>(expected.size()), "length differs for size " + std::to_string(size));
        Require(std::memcmp(actual.get(), expected.data(), expected.size()) == 0,
            "bytes differ for size " + std::to_string(size));
    }

    // Datagrams that need IPv4 fragmentation must be left to the frame-object path.
    std::vector<ppp::Byte> big(max_payload + 1, 0x5A);
    int length = -1;
    Require(UdpFrame::ToIPv4Packet(nullptr, IPEndPoint(0x0100000A, 53), IPEndPoint(0x0200000A, 5353),
        IPFrame::DefaultTtl, big.data(), static_cast<int>(big.size()), length) == nullptr && length == 0,
        "oversized datagram was not rejected");
    Require(UdpFrame::ToIPv4Packet(nullptr, IPEndPoint(0x0100000A, 53), IPEndPoint(0x0200000A, 5353),
        IPFrame::DefaultTtl, nullptr, 0, length) == nullptr, "empty datagram was not rejected");
}

} // namespace

int main() {
    try {
        std::mt19937 rng(20261011);
        CheckEquivalent(rng, false);
        CheckEquivalent(rng, true);
    }
    catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "PASS: udp_frame_ipv4_packet_test" << std::endl;
    return 0;
}
