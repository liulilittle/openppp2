#pragma once

#include <ppp/p2p/P2PClientOfferSession.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace ppp::p2p {

enum class P2PControlDatagramAction : std::uint8_t {
    None,
    Reply,
    AuthenticatedAck,
    AuthenticatedMigrateAck,
};

struct P2PControlDatagramResult {
    P2PControlDatagramAction action = P2PControlDatagramAction::None;
    std::vector<std::uint8_t> reply;
    std::optional<P2PAuthenticatedProbeAck> authenticated_ack;
};

bool CreateAuthenticatedProbeDatagram(
    P2PClientOfferSession& session,
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept;

bool CreateAuthenticatedMigrateChallengeDatagram(
    P2PClientOfferSession& session,
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept;

bool HandleAuthenticatedControlDatagram(
    P2PClientOfferSession& session,
    const std::vector<std::uint8_t>& datagram,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    P2PControlDatagramResult& output) noexcept;

}
