#include <ppp/p2p/P2POfferToken.h>
#include <ppp/p2p/P2PCrypto.h>
#include <ppp/p2p/P2PKeyDerivation.h>

#include <openssl/evp.h>

#include <array>

namespace ppp::p2p {
namespace {
constexpr std::size_t BaseCanonicalSize = 107;
constexpr std::size_t ProbeAckCanonicalSize = BaseCanonicalSize + 32;

struct CanonicalTranscript {
    std::array<std::uint8_t, ProbeAckCanonicalSize> bytes{};
    std::size_t size = 0;
};

bool ValidEndpoint(const P2PCandidateEndpoint& endpoint) noexcept {
    return IsCanonicalP2PCandidate(endpoint);
}

bool ValidBinding(const P2POfferBinding& binding) noexcept {
    const auto type = static_cast<std::uint8_t>(binding.message_type);
    return binding.version == 1 &&
        type >= static_cast<std::uint8_t>(P2PControlType::Probe) &&
        type <= static_cast<std::uint8_t>(P2PControlType::MigrateAck) &&
        binding.sender_role <= 1 && binding.receiver_role <= 1 &&
        binding.sender_role != binding.receiver_role &&
        binding.direction == binding.sender_role &&
        binding.ttl_seconds >= 1 && binding.ttl_seconds <= 30 &&
        binding.initiator_peer_id != binding.responder_peer_id &&
        binding.initiator_session_id != binding.responder_session_id &&
        ValidEndpoint(binding.source) && ValidEndpoint(binding.destination) &&
        ((binding.message_type == P2PControlType::ProbeAck) ==
            (binding.probe_transcript_hash != std::array<std::uint8_t, 32>{}));
}

bool SameStaticContext(const P2POfferBinding& a,
                       const P2POfferBinding& b) noexcept {
    return a.version == b.version && a.offer_id == b.offer_id &&
        a.offer_hash == b.offer_hash &&
        a.initiator_session_id == b.initiator_session_id &&
        a.responder_session_id == b.responder_session_id &&
        a.initiator_peer_id == b.initiator_peer_id &&
        a.responder_peer_id == b.responder_peer_id &&
        a.connection_epoch == b.connection_epoch &&
        a.sender_role == b.sender_role && a.receiver_role == b.receiver_role &&
        a.direction == b.direction && a.source == b.source &&
        a.destination == b.destination && a.ttl_seconds == b.ttl_seconds &&
        a.probe_transcript_hash == b.probe_transcript_hash;
}

bool AckMatchesProbe(const P2POfferBinding& ack,
                     const P2POfferBinding& probe) noexcept {
    return probe.message_type == P2PControlType::Probe &&
        ack.message_type == P2PControlType::ProbeAck &&
        ack.version == probe.version && ack.offer_id == probe.offer_id &&
        ack.offer_hash == probe.offer_hash &&
        ack.initiator_session_id == probe.initiator_session_id &&
        ack.responder_session_id == probe.responder_session_id &&
        ack.initiator_peer_id == probe.initiator_peer_id &&
        ack.responder_peer_id == probe.responder_peer_id &&
        ack.connection_epoch == probe.connection_epoch &&
        ack.sender_role == probe.receiver_role &&
        ack.receiver_role == probe.sender_role &&
        ack.direction == ack.sender_role &&
        ack.source == probe.destination && ack.destination == probe.source &&
        ack.ttl_seconds == probe.ttl_seconds;
}

bool AckMatchesMigrate(const P2POfferBinding& ack,
                       const P2POfferBinding& challenge) noexcept {
    return challenge.message_type == P2PControlType::MigrateChallenge &&
        ack.message_type == P2PControlType::MigrateAck &&
        ack.version == challenge.version && ack.offer_id == challenge.offer_id &&
        ack.offer_hash == challenge.offer_hash &&
        ack.initiator_session_id == challenge.initiator_session_id &&
        ack.responder_session_id == challenge.responder_session_id &&
        ack.initiator_peer_id == challenge.initiator_peer_id &&
        ack.responder_peer_id == challenge.responder_peer_id &&
        ack.connection_epoch == challenge.connection_epoch &&
        ack.sender_role == challenge.receiver_role &&
        ack.receiver_role == challenge.sender_role &&
        ack.direction == ack.sender_role &&
        ack.source == challenge.destination &&
        ack.destination == challenge.source &&
        ack.ttl_seconds == challenge.ttl_seconds &&
        ack.probe_transcript_hash == std::array<std::uint8_t, 32>{} &&
        challenge.probe_transcript_hash == std::array<std::uint8_t, 32>{};
}

void AppendEndpoint(std::array<std::uint8_t, ProbeAckCanonicalSize>& bytes,
                    std::size_t& offset,
                    const P2PCandidateEndpoint& endpoint) noexcept {
    bytes[offset++] = endpoint.address_family;
    for (const auto byte : endpoint.address) bytes[offset++] = byte;
    bytes[offset++] = static_cast<std::uint8_t>(endpoint.port >> 8);
    bytes[offset++] = static_cast<std::uint8_t>(endpoint.port);
}

CanonicalTranscript Canonicalize(
    const P2POfferBinding& binding) noexcept {
    CanonicalTranscript transcript;
    auto& bytes = transcript.bytes;
    std::size_t offset = 0;
    bytes[offset++] = static_cast<std::uint8_t>(binding.message_type);
    const auto append = [&bytes, &offset](const auto& field) {
        for (const auto byte : field) bytes[offset++] = byte;
    };
    append(binding.offer_hash);
    bytes[offset++] = binding.sender_role;
    bytes[offset++] = binding.receiver_role;
    bytes[offset++] = binding.direction;
    append(binding.connection_epoch);
    AppendEndpoint(bytes, offset, binding.source);
    AppendEndpoint(bytes, offset, binding.destination);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence >> 24);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence >> 16);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence >> 8);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence);
    append(binding.nonce);
    bytes[offset++] = binding.ttl_seconds;
    if (binding.message_type == P2PControlType::ProbeAck) {
        append(binding.probe_transcript_hash);
    }
    transcript.size = offset;
    return transcript;
}
}

bool CreateP2POfferToken(const std::array<std::uint8_t, 32>& token_key,
                         const P2POfferBinding& binding,
                         P2POfferToken& token) noexcept {
    if (!ValidBinding(binding)) return false;
    const auto canonical = Canonicalize(binding);
    return TokenGenerate(token_key.data(), canonical.bytes.data(), canonical.size, token.data());
}

bool CreateP2PProbeTranscriptHash(
    const P2POfferBinding& probe,
    std::array<std::uint8_t, 32>& transcript_hash) noexcept {
    if (!ValidBinding(probe) || probe.message_type != P2PControlType::Probe) {
        return false;
    }
    const auto canonical = Canonicalize(probe);
    unsigned int digest_size = 0;
    std::array<std::uint8_t, 32> digest{};
    if (EVP_Digest(canonical.bytes.data(), canonical.size,
            digest.data(), &digest_size, EVP_sha256(), nullptr) != 1 ||
        digest_size != digest.size()) {
        return false;
    }
    transcript_hash = digest;
    return true;
}

bool ValidateP2POfferToken(const std::array<std::uint8_t, 32>& token_key,
                           const P2POfferBinding& received,
                           const P2POfferBinding& current,
                           const P2PCandidateEndpoint& observed_source,
                           const P2PCandidateEndpoint& observed_destination,
                           std::uint64_t elapsed_milliseconds,
                           const P2POfferToken& token,
                           const std::array<std::uint8_t, 8>& expected_nonce_prefix,
                           P2PReplayWindow& replay_window) noexcept {
    if (!ValidBinding(received) || !ValidBinding(current) ||
        !SameStaticContext(received, current) ||
        !(received.source == observed_source) ||
        !(received.destination == observed_destination) ||
        elapsed_milliseconds >= static_cast<std::uint64_t>(received.ttl_seconds) * 1000) {
        return false;
    }
    if (received.nonce != BuildP2PV1Nonce(expected_nonce_prefix, received.sequence)) {
        return false;
    }
    const auto canonical = Canonicalize(received);
    if (!TokenVerify(token_key.data(), canonical.bytes.data(), canonical.size, token.data())) {
        return false;
    }
    return replay_window.Accept(received.sequence);
}

std::optional<P2PAuthenticatedProbeAck> AuthenticateP2PProbeAck(
    const std::array<std::uint8_t, 32>& token_key,
    const P2POfferBinding& received,
    const P2POfferBinding& outstanding_probe,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t elapsed_milliseconds,
    const P2POfferToken& token,
    const std::array<std::uint8_t, 8>& expected_nonce_prefix,
    P2PReplayWindow& replay_window) noexcept {
    std::array<std::uint8_t, 32> expected_probe_hash{};
    if (!AckMatchesProbe(received, outstanding_probe) ||
        !CreateP2PProbeTranscriptHash(outstanding_probe, expected_probe_hash) ||
        received.probe_transcript_hash != expected_probe_hash ||
        !ValidateP2POfferToken(token_key, received, received,
            observed_source, observed_destination, elapsed_milliseconds,
            token, expected_nonce_prefix, replay_window)) {
        return std::nullopt;
    }
    return detail::P2PAuthenticatedProbeAckFactory::Create();
}

std::optional<P2PAuthenticatedProbeAck> AuthenticateP2PMigrateAck(
    const std::array<std::uint8_t, 32>& token_key,
    const P2POfferBinding& received,
    const P2POfferBinding& outstanding_challenge,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t elapsed_milliseconds,
    const P2POfferToken& token,
    const std::array<std::uint8_t, 8>& expected_nonce_prefix,
    P2PReplayWindow& replay_window) noexcept {
    if (!AckMatchesMigrate(received, outstanding_challenge) ||
        !ValidateP2POfferToken(token_key, received, received,
            observed_source, observed_destination, elapsed_milliseconds,
            token, expected_nonce_prefix, replay_window)) {
        return std::nullopt;
    }
    return detail::P2PAuthenticatedProbeAckFactory::Create();
}

}
