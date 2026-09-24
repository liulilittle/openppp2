#pragma once

#include <ppp/p2p/P2PAuthenticatedProbeAck.h>
#include <ppp/p2p/P2PControlPacket.h>
#include <ppp/p2p/P2PReplayWindow.h>

#include <array>
#include <cstdint>
#include <optional>

namespace ppp::p2p {

using P2POfferToken = std::array<std::uint8_t, 16>;

struct P2POfferBinding {
    std::uint8_t version = 0;
    std::array<std::uint8_t, 16> offer_id{};
    std::array<std::uint8_t, 16> initiator_session_id{};
    std::array<std::uint8_t, 16> responder_session_id{};
    std::array<std::uint8_t, 16> initiator_peer_id{};
    std::array<std::uint8_t, 16> responder_peer_id{};
    std::array<std::uint8_t, 16> connection_epoch{};
    P2PControlType message_type = P2PControlType::Probe;
    std::array<std::uint8_t, 32> offer_hash{};
    std::uint8_t sender_role = 0;
    std::uint8_t receiver_role = 0;
    std::uint8_t direction = 0;
    P2PCandidateEndpoint source;
    P2PCandidateEndpoint destination;
    std::uint32_t sequence = 0;
    std::array<std::uint8_t, 12> nonce{};
    std::uint8_t ttl_seconds = 0;
    std::array<std::uint8_t, 32> probe_transcript_hash{};

    friend bool operator==(const P2POfferBinding& a,
                           const P2POfferBinding& b) noexcept {
        return a.version == b.version && a.offer_id == b.offer_id &&
            a.initiator_session_id == b.initiator_session_id &&
            a.responder_session_id == b.responder_session_id &&
            a.initiator_peer_id == b.initiator_peer_id &&
            a.responder_peer_id == b.responder_peer_id &&
            a.connection_epoch == b.connection_epoch &&
            a.message_type == b.message_type && a.offer_hash == b.offer_hash &&
            a.sender_role == b.sender_role && a.receiver_role == b.receiver_role &&
            a.direction == b.direction && a.source == b.source &&
            a.destination == b.destination &&
            a.sequence == b.sequence && a.nonce == b.nonce &&
            a.ttl_seconds == b.ttl_seconds &&
            a.probe_transcript_hash == b.probe_transcript_hash;
    }
};

bool CreateP2POfferToken(const std::array<std::uint8_t, 32>& token_key,
                         const P2POfferBinding& binding,
                         P2POfferToken& token) noexcept;

bool CreateP2PProbeTranscriptHash(
    const P2POfferBinding& probe,
    std::array<std::uint8_t, 32>& transcript_hash) noexcept;

bool ValidateP2POfferToken(const std::array<std::uint8_t, 32>& token_key,
                           const P2POfferBinding& received,
                           const P2POfferBinding& current,
                           const P2PCandidateEndpoint& observed_source,
                           const P2PCandidateEndpoint& observed_destination,
                           std::uint64_t elapsed_milliseconds,
                           const P2POfferToken& token,
                           const std::array<std::uint8_t, 8>& expected_nonce_prefix,
                           P2PReplayWindow& replay_window) noexcept;

std::optional<P2PAuthenticatedProbeAck> AuthenticateP2PProbeAck(
    const std::array<std::uint8_t, 32>& token_key,
    const P2POfferBinding& received,
    const P2POfferBinding& outstanding_probe,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t elapsed_milliseconds,
    const P2POfferToken& token,
    const std::array<std::uint8_t, 8>& expected_nonce_prefix,
    P2PReplayWindow& replay_window) noexcept;

std::optional<P2PAuthenticatedProbeAck> AuthenticateP2PMigrateAck(
    const std::array<std::uint8_t, 32>& token_key,
    const P2POfferBinding& received,
    const P2POfferBinding& outstanding_challenge,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t elapsed_milliseconds,
    const P2POfferToken& token,
    const std::array<std::uint8_t, 8>& expected_nonce_prefix,
    P2PReplayWindow& replay_window) noexcept;

}
