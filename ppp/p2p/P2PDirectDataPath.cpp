#include <ppp/stdafx.h>
#include <ppp/p2p/P2PDirectDataPath.h>
#include <ppp/net/native/ip.h>

namespace ppp::p2p {

namespace {

bool AllowsVirtualPeerPacket(const void* packet, int packet_size,
    std::uint32_t expected_source,
    std::uint32_t expected_destination) noexcept {
    if (!packet || packet_size < 1 || expected_source == 0 ||
        expected_destination == 0) return false;

    ppp::net::native::ip_hdr packet_header{};
    if (packet_size < static_cast<int>(sizeof(packet_header))) return false;
    std::memcpy(&packet_header, packet, sizeof(packet_header));
    const int header_size =
        (packet_header.v_hl & 0x0f) << 2;
    if ((packet_header.v_hl >> 4) != ppp::net::native::ip_hdr::IP_VER ||
        header_size < static_cast<int>(sizeof(packet_header)) ||
        header_size > packet_size || packet_header.ttl == 0 ||
        ntohs(packet_header.len) != packet_size) return false;

    int parsed_size = packet_size;
    const auto* header = ppp::net::native::ip_hdr::Parse(packet, parsed_size);
    return header && header->src == expected_source &&
        header->dest == expected_destination;
}

}

bool P2PDirectDataPath::AllowsOutboundPacket(const void* packet,
    int packet_size, std::uint32_t local_virtual_ip,
    std::uint32_t peer_virtual_ip) noexcept {
    return AllowsVirtualPeerPacket(
        packet, packet_size, local_virtual_ip, peer_virtual_ip);
}

bool P2PDirectDataPath::AllowsInboundPacket(const void* packet,
    int packet_size, std::uint32_t local_virtual_ip,
    std::uint32_t peer_virtual_ip) noexcept {
    return AllowsVirtualPeerPacket(
        packet, packet_size, peer_virtual_ip, local_virtual_ip);
}

bool P2PDirectDataPath::Begin(std::uint64_t generation) noexcept {
    return activation_.Begin(generation);
}

bool P2PDirectDataPath::StageAuthenticatedAck(
    P2PAuthenticatedProbeAck&& ack, std::uint64_t generation) noexcept {
    return activation_.StageAuthenticatedAck(std::move(ack), generation);
}

bool P2PDirectDataPath::Activate(
    bool transport_ready, std::uint64_t generation) noexcept {
    return activation_.Activate(transport_ready, generation);
}

bool P2PDirectDataPath::MarkSuspect(std::uint64_t generation) noexcept {
    return activation_.MarkSuspect(generation);
}

bool P2PDirectDataPath::AcceptRecoveryAck(
    P2PAuthenticatedProbeAck&& ack, std::uint64_t generation) noexcept {
    return activation_.AcceptRecoveryAck(std::move(ack), generation);
}

bool P2PDirectDataPath::RecoverFromAuthenticatedData(
    std::uint64_t generation) noexcept {
    return activation_.RecoverFromAuthenticatedData(generation);
}

bool P2PDirectDataPath::Fallback(P2PFallbackReason reason,
    bool relay_prerequisites_available, std::uint64_t generation) noexcept {
    return activation_.Fallback(
        reason, relay_prerequisites_available, generation);
}

bool P2PDirectDataPath::Reset(std::uint64_t generation) noexcept {
    return activation_.Reset(generation);
}

bool P2PDirectDataPath::Send(P2PClientOfferSession& session,
    IP2PDatagramTransport& transport,
    const boost::asio::ip::udp::endpoint& peer,
    const std::uint8_t* payload,
    std::size_t payload_length,
    std::uint64_t now_ms,
    std::uint64_t generation) noexcept {
    if (activation_.State() != P2PState::Direct || !transport.IsReady() ||
        peer.address().is_unspecified() || peer.port() == 0 ||
        !payload || payload_length == 0) {
        return false;
    }

    std::vector<std::uint8_t> datagram;
    if (!session.SealData(payload, payload_length,
            now_ms, generation, datagram)) return false;
    return transport.SendTo(datagram.data(),
        static_cast<int>(datagram.size()), peer);
}

bool P2PDirectDataPath::Open(P2PClientOfferSession& session,
    const std::vector<std::uint8_t>& datagram,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept {
    const P2PState state = activation_.State();
    if (state != P2PState::Probing && state != P2PState::Direct &&
        state != P2PState::Suspect) {
        return false;
    }
    if (!session.OpenData(datagram, now_ms, generation, output)) {
        return false;
    }
    if (state == P2PState::Suspect) {
        activation_.RecoverFromAuthenticatedData(generation);
    }
    return true;
}

P2PState P2PDirectDataPath::State() const noexcept {
    return activation_.State();
}

const char* P2PDirectDataPath::EffectivePath() const noexcept {
    return activation_.EffectivePath();
}

}
