#pragma once

#include <ppp/p2p/P2PKeyDerivation.h>
#include <ppp/p2p/P2PDataDatagram.h>
#include <ppp/p2p/P2POfferToken.h>
#include <ppp/p2p/P2PRelayOfferConsumer.h>
#include <ppp/p2p/P2PState.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace ppp::p2p {

struct P2PClientOfferSnapshot {
    bool active = false;
    P2PState state = P2PState::Relay;
    const char* effective_path = "relay";
    P2PId offer_id{};
    P2PId connection_epoch{};
    P2PId peer_session_id{};
    P2PId peer_id{};
    P2PPeerRole local_role = P2PPeerRole::Initiator;
    std::uint64_t received_at_ms = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t generation = 0;
};

class P2PClientOfferSession final {
public:
    P2PClientOfferSession() noexcept = default;
    ~P2PClientOfferSession() noexcept;

    P2PClientOfferSession(const P2PClientOfferSession&) = delete;
    P2PClientOfferSession& operator=(const P2PClientOfferSession&) = delete;

    bool Accept(
        const std::string& encoded,
        const P2PRelayOfferRecipientContext& context,
        const P2PRelayOfferExporter& exporter,
        std::uint64_t received_at_ms,
        std::uint64_t generation = 0) noexcept;

    bool Expire(
        std::uint64_t now_ms,
        std::uint64_t* expired_generation = nullptr) noexcept;
    void AdvanceGeneration(std::uint64_t generation) noexcept;
    bool IsActiveGeneration(std::uint64_t generation) const noexcept;
    bool ResetGeneration(std::uint64_t generation) noexcept;
    void Reset() noexcept;
    P2PClientOfferSnapshot Snapshot() const noexcept;

    bool CreateAuthenticatedProbe(
        const P2PCandidateEndpoint& source,
        const P2PCandidateEndpoint& destination,
        std::uint64_t now_ms,
        std::uint64_t generation,
        P2PControlPacket& output) noexcept;
    bool CreateAuthenticatedProbeAck(
        const P2PControlPacket& probe,
        const P2PCandidateEndpoint& observed_source,
        const P2PCandidateEndpoint& observed_destination,
        std::uint64_t now_ms,
        std::uint64_t generation,
        P2PControlPacket& output) noexcept;
    std::optional<P2PAuthenticatedProbeAck> AuthenticateProbeAck(
        const P2PControlPacket& packet,
        const P2PCandidateEndpoint& observed_source,
        const P2PCandidateEndpoint& observed_destination,
        std::uint64_t now_ms,
        std::uint64_t generation) noexcept;
    bool CreateAuthenticatedMigrateChallenge(
        const P2PCandidateEndpoint& source,
        const P2PCandidateEndpoint& destination,
        std::uint64_t now_ms,
        std::uint64_t generation,
        P2PControlPacket& output) noexcept;
    bool CreateAuthenticatedMigrateAck(
        const P2PControlPacket& challenge,
        const P2PCandidateEndpoint& observed_source,
        const P2PCandidateEndpoint& observed_destination,
        std::uint64_t now_ms,
        std::uint64_t generation,
        P2PControlPacket& output) noexcept;
    std::optional<P2PAuthenticatedProbeAck> AuthenticateMigrateAck(
        const P2PControlPacket& packet,
        const P2PCandidateEndpoint& observed_source,
        const P2PCandidateEndpoint& observed_destination,
        std::uint64_t now_ms,
        std::uint64_t generation) noexcept;
    bool SealData(
        const std::uint8_t* payload,
        std::size_t payload_length,
        std::uint64_t now_ms,
        std::uint64_t generation,
        std::vector<std::uint8_t>& output) noexcept;
    bool SealData(
        const std::vector<std::uint8_t>& payload,
        std::uint64_t now_ms,
        std::uint64_t generation,
        std::vector<std::uint8_t>& output) noexcept {
        return SealData(payload.data(), payload.size(),
            now_ms, generation, output);
    }
    bool OpenData(
        const std::vector<std::uint8_t>& datagram,
        std::uint64_t now_ms,
        std::uint64_t generation,
        std::vector<std::uint8_t>& output) noexcept;
    bool SealHeartbeat(
        std::uint64_t now_ms,
        std::uint64_t generation,
        std::vector<std::uint8_t>& output) noexcept;
    std::uint64_t LastReceiveActivityMs() const noexcept;

private:
    static constexpr std::size_t ReplayCapacity = 256;

    bool SeenLocked(const P2PId& offer_id) const noexcept;
    void RememberLocked(const P2PId& offer_id) noexcept;
    void ClearReplayLocked() noexcept;
    void ClearActiveLocked() noexcept;
    bool CreateSignedControlLocked(
        P2PControlType type,
        const P2PCandidateEndpoint& source,
        const P2PCandidateEndpoint& destination,
        std::uint64_t now_ms,
        std::uint64_t generation,
        bool track_outstanding,
        P2PControlPacket& output) noexcept;

    mutable std::mutex mutex_;
    bool active_ = false;
    P2PState state_ = P2PState::Relay;
    P2PRelayOfferV1 offer_;
    P2POfferHash offer_hash_{};
    P2PV1KeyMaterial key_material_{};
    P2PPeerRole local_role_ = P2PPeerRole::Initiator;
    P2PId peer_session_id_{};
    P2PId peer_id_{};
    std::uint64_t received_at_ms_ = 0;
    std::uint64_t deadline_ms_ = 0;
    std::uint64_t generation_ = 0;
    std::uint64_t generation_floor_ = 0;
    std::uint64_t last_receive_activity_ms_ = 0;
    P2POfferBinding outstanding_probe_{};
    P2POfferBinding outstanding_migrate_{};
    P2POfferBinding cached_received_probe_{};
    P2POfferToken cached_received_probe_token_{};
    P2PControlPacket cached_probe_ack_{};
    P2PReplayWindow rx_replay_window_{};
    std::uint32_t next_tx_sequence_ = 0;
    std::uint8_t probe_rounds_ = 0;
    std::uint8_t received_probe_rounds_ = 0;
    std::uint8_t migrate_rounds_ = 0;
    std::uint8_t received_migrate_rounds_ = 0;
    bool has_outstanding_probe_ = false;
    bool has_outstanding_migrate_ = false;
    bool has_cached_probe_ack_ = false;
    bool data_authorized_ = false;
    std::array<P2PId, ReplayCapacity> seen_offer_ids_{};
    std::size_t seen_count_ = 0;
    std::size_t seen_next_ = 0;
};

}
