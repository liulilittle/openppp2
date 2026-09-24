#pragma once

#include <ppp/p2p/P2PClientOfferSession.h>
#include <ppp/p2p/P2PDatagramTransport.h>
#include <ppp/p2p/P2PDirectActivationCoordinator.h>

#include <cstdint>
#include <vector>

namespace ppp::p2p {

class P2PDirectDataPath final {
public:
    static bool AllowsOutboundPacket(const void* packet, int packet_size,
        std::uint32_t local_virtual_ip,
        std::uint32_t peer_virtual_ip) noexcept;
    static bool AllowsInboundPacket(const void* packet, int packet_size,
        std::uint32_t local_virtual_ip,
        std::uint32_t peer_virtual_ip) noexcept;

    bool Begin(std::uint64_t generation) noexcept;
    bool StageAuthenticatedAck(P2PAuthenticatedProbeAck&& ack,
        std::uint64_t generation) noexcept;
    bool Activate(bool transport_ready, std::uint64_t generation) noexcept;
    bool MarkSuspect(std::uint64_t generation) noexcept;
    bool AcceptRecoveryAck(P2PAuthenticatedProbeAck&& ack,
        std::uint64_t generation) noexcept;
    bool RecoverFromAuthenticatedData(std::uint64_t generation) noexcept;
    bool Fallback(P2PFallbackReason reason,
        bool relay_prerequisites_available,
        std::uint64_t generation) noexcept;
    bool Reset(std::uint64_t generation) noexcept;

    bool Send(P2PClientOfferSession& session,
        IP2PDatagramTransport& transport,
        const boost::asio::ip::udp::endpoint& peer,
        const std::uint8_t* payload,
        std::size_t payload_length,
        std::uint64_t now_ms,
        std::uint64_t generation) noexcept;
    bool Send(P2PClientOfferSession& session,
        IP2PDatagramTransport& transport,
        const boost::asio::ip::udp::endpoint& peer,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t now_ms,
        std::uint64_t generation) noexcept {
        return Send(session, transport, peer,
            payload.data(), payload.size(), now_ms, generation);
    }
    bool Open(P2PClientOfferSession& session,
        const std::vector<std::uint8_t>& datagram,
        std::uint64_t now_ms,
        std::uint64_t generation,
        std::vector<std::uint8_t>& output) noexcept;

    P2PState State() const noexcept;
    const char* EffectivePath() const noexcept;

private:
    P2PDirectActivationCoordinator activation_;
};

}
