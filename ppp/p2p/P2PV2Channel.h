#pragma once

#include <ppp/p2p/P2PRelayOfferV2.h>
#include <ppp/p2p/P2PState.h>

#include <memory>

namespace ppp::p2p {

struct P2PV2RecipientContext {
    P2PId local_session_id{}, local_peer_id{};
    std::uint64_t local_candidate_revision = 0, peer_candidate_revision = 0;
    std::vector<P2PCandidateEndpoint> local_candidates, peer_candidates;
};

struct P2PV2Outbound {
    std::vector<std::uint8_t> datagram;
    P2PCandidateEndpoint destination;
};

enum class P2PV2ControlEvent : std::uint8_t {
    None, ProbeAck, ReverseProbeNeeded, Activated, Migrated, Fallback
};

struct P2PV2ControlResult {
    P2PV2ControlEvent event = P2PV2ControlEvent::None;
    std::vector<P2PV2Outbound> outbound;
    P2PCandidateEndpoint local_candidate, peer_candidate;
    P2POfferHash offer_hash{}, cancelled_offer_hash{};
    std::uint32_t probe_sequence = 0;
};

struct P2PV2TickResult {
    std::vector<P2PV2Outbound> outbound;
    bool renew = false, activated = false, fallback = false;
    P2POfferHash current_offer_hash{}, cancelled_offer_hash{};
};

struct P2PV2Snapshot {
    P2PState state = P2PState::Relay;
    const char* effective_path = "relay";
    bool has_current = false, has_pending = false, has_previous = false;
    bool pending_ready = false, commit_started = false, migration_pending = false;
    P2PPeerRole local_role = P2PPeerRole::Initiator;
    // Remote peer identity from the authenticated relay offer.
    P2PId peer_uuid{};
    P2POfferHash current_offer_hash{}, pending_offer_hash{}, previous_offer_hash{};
    P2PCandidateEndpoint local_candidate, peer_candidate;
    std::uint64_t generation = 0, key_generation = 0;
    std::uint64_t key_deadline_ms = 0, setup_deadline_ms = 0;
    std::uint64_t last_receive_ms = 0, previous_deadline_ms = 0;
};

// Owns all keys/proofs. Callers schedule candidate pairs and send returned bytes;
// only this object can authenticate and nominate or promote a key slot.
class P2PV2Channel final {
public:
    P2PV2Channel() noexcept;
    ~P2PV2Channel() noexcept;
    P2PV2Channel(const P2PV2Channel&) = delete;
    P2PV2Channel& operator=(const P2PV2Channel&) = delete;

    bool AcceptOffer(const std::string&, const P2PV2RecipientContext&,
        const P2PSessionExporter&, std::uint64_t now_ms,
        std::uint64_t generation) noexcept;
    // Same pair returns exactly the cached transaction on its second call,
    // >= 2 seconds later, within the original 4-second probing window.
    // Both roles prime candidates; nomination narrows the remaining retries.
    bool CreateProbe(const P2PCandidateEndpoint& local,
        const P2PCandidateEndpoint& peer, std::uint64_t now_ms,
        std::uint64_t generation, std::vector<std::uint8_t>&) noexcept;
    bool HandleControl(const std::vector<std::uint8_t>&,
        const P2PCandidateEndpoint& observed_source, std::uint64_t now_ms,
        std::uint64_t generation, P2PV2ControlResult&) noexcept;
    bool SealData(const std::uint8_t*, std::size_t,
        std::uint64_t now_ms, std::uint64_t generation,
        std::vector<std::uint8_t>&) noexcept;
    bool SealData(const std::vector<std::uint8_t>& data,
        std::uint64_t now_ms, std::uint64_t generation,
        std::vector<std::uint8_t>& out) noexcept {
        return SealData(data.data(), data.size(), now_ms, generation, out);
    }
    bool OpenData(const std::vector<std::uint8_t>&,
        const P2PCandidateEndpoint& observed_source, std::uint64_t now_ms,
        std::uint64_t generation, std::vector<std::uint8_t>&) noexcept;
    // AEAD/replay check without committing replay, liveness or plaintext;
    // creates a bounded migration only after successful authentication.
    bool HandleNewEndpointData(const std::vector<std::uint8_t>&,
        const P2PCandidateEndpoint& observed_source, std::uint64_t now_ms,
        std::uint64_t generation, P2PV2ControlResult&) noexcept;
    P2PV2TickResult Tick(std::uint64_t now_ms, std::uint64_t generation) noexcept;
    // Cancel an in-flight offer and request an authenticated replacement on
    // the next Tick. The current direct key, when present, remains usable.
    void RequestRenew(std::uint64_t generation) noexcept;
    P2PV2Snapshot Snapshot() const noexcept;
    void RequestRenew() noexcept;
    void SetRelayOnly(bool enabled) noexcept;
    void Reset(std::uint64_t generation) noexcept;
    void ConfigureLiveness(int interval_ms, int miss_max,
        int suspect_timeout_ms, int migration_grace_ms) noexcept;
    // Monotonic advance only; cannot reset/reuse a nonce. Used by boundary tests.
    bool AdvanceTxSequenceForTesting(std::uint32_t) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
