#pragma once

#include <ppp/p2p/P2PRelayOfferCoordinator.h>
#include <ppp/p2p/P2PControlPacket.h>

namespace ppp::p2p {

inline constexpr char P2PWrapExporterLabelV2[] = "EXPORTER-OPENPPP2-P2P-WRAP-v2";
using P2PRelayOfferV2Bytes = std::array<std::uint8_t, 193>;
using P2PExporterContextV2 = std::array<std::uint8_t, 145>;
using P2PRelayOfferRecipientV2Bytes = std::array<std::uint8_t, 270>;

struct P2PRelayOfferV2 {
    std::uint8_t version = 2;
    P2PId offer_id{}, initiator_session_id{}, responder_session_id{};
    P2PId initiator_peer_id{}, responder_peer_id{}, connection_epoch{};
    std::uint64_t key_generation = 0;
    P2POfferHash previous_offer_hash{};
    std::uint8_t setup_ttl_seconds = 10;
    std::uint16_t key_lifetime_seconds = 60;
    std::uint16_t refresh_after_seconds = 40;
    std::uint16_t previous_receive_grace_ms = 5000;
    std::uint8_t cipher = 1;
    std::uint64_t initiator_candidate_revision = 0;
    std::uint64_t responder_candidate_revision = 0;
    P2POfferHash candidate_set_hash{};
};

struct P2PRelayOfferV2Input {
    P2PId initiator_session_id{}, responder_session_id{};
    P2PId initiator_peer_id{}, responder_peer_id{};
    std::uint64_t key_generation = 1;
    P2POfferHash previous_offer_hash{};
    std::uint64_t initiator_candidate_revision = 0;
    std::uint64_t responder_candidate_revision = 0;
    P2POfferHash candidate_set_hash{};
};

struct P2PRelayOfferV2Bundle {
    P2PRelayOfferV2 offer;
    P2PWrappedPairSeed initiator_envelope, responder_envelope;
};

using P2PAsyncSessionExporterV2 = std::function<void(
    const char*, const P2PExporterContextV2&, P2PExporterKey&,
    const P2PExportCompletion&)>;
using P2PRelayOfferV2Completion = std::function<void(bool,
    const P2PRelayOfferV2Bundle&)>;

bool SerializeP2PRelayOfferV2(const P2PRelayOfferV2&, P2PRelayOfferV2Bytes&) noexcept;
bool HashP2PRelayOfferV2(const P2PRelayOfferV2&, P2POfferHash&) noexcept;
bool BuildP2PExporterContextV2(const P2PRelayOfferV2&, P2PPeerRole,
    P2PExporterContextV2&) noexcept;
bool DeriveP2PV2KeyMaterial(const P2PPairSeed&, const P2POfferHash&,
    P2PV1KeyMaterial&) noexcept;
bool HashP2PV2CandidateSet(const P2PId& initiator_session,
    const P2PId& responder_session, std::uint64_t initiator_revision,
    std::uint64_t responder_revision,
    const std::vector<P2PCandidateEndpoint>& initiator_candidates,
    const std::vector<P2PCandidateEndpoint>& responder_candidates,
    P2POfferHash&) noexcept;
bool BuildP2PRelayOfferV2Bundle(const P2PRelayOfferV2Input&,
    const P2PExporterKey&, const P2PExporterKey&,
    const P2PRelayOfferSecrets&, P2PRelayOfferV2Bundle&) noexcept;
bool CreateP2PRelayOfferV2Bundle(const P2PRelayOfferV2Input&,
    const P2PSessionExporter&, const P2PSessionExporter&,
    P2PRelayOfferV2Bundle&) noexcept;
bool CreateP2PRelayOfferV2BundleAsync(const P2PRelayOfferV2Input&,
    const P2PAsyncSessionExporterV2&, const P2PAsyncSessionExporterV2&,
    const P2PRelayOfferV2Completion&) noexcept;
P2PAsyncSessionExporterV2 ScheduleP2PSessionExporterV2(
    const P2PTaskScheduler&, const P2PSessionExporter&) noexcept;
bool EncodeP2PRelayOfferRecipientV2Hex(const P2PRelayOfferV2&,
    const P2PWrappedPairSeed&, std::string&) noexcept;
bool ParseP2PRelayOfferRecipientV2Hex(const std::string&,
    P2PRelayOfferV2&, P2PWrappedPairSeed&) noexcept;
bool OpenP2PRelayOfferRecipientV2(const std::string&,
    const P2PId& local_session, const P2PId& local_peer,
    const P2PSessionExporter&, P2PRelayOfferV2&, P2PPeerRole&,
    P2PPairSeed&) noexcept;

}
