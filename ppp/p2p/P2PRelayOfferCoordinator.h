#pragma once

#include <ppp/p2p/P2PRelayOffer.h>

#include <cstddef>
#include <functional>
#include <vector>

namespace ppp::p2p {

struct P2PRelayOfferInput {
    P2PId initiator_session_id{};
    P2PId responder_session_id{};
    P2PId initiator_peer_id{};
    P2PId responder_peer_id{};
    std::uint8_t ttl_seconds = 0;
    P2POfferHash candidate_set_hash{};
};

struct P2PRelayOfferSecrets {
    P2PId offer_id{};
    P2PId connection_epoch{};
    P2PPairSeed pair_seed{};
    P2PWrapNonce initiator_wrap_nonce{};
    P2PWrapNonce responder_wrap_nonce{};
};

struct P2PRelayOfferBundle {
    P2PRelayOfferV1 offer;
    P2PWrappedPairSeed initiator_envelope;
    P2PWrappedPairSeed responder_envelope;
};

struct P2PCandidateV1 {
    std::uint8_t address_family = 0;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;
};

using P2PSessionExporter = std::function<bool(
    const char* label,
    const std::uint8_t* context,
    std::size_t context_length,
    std::uint8_t* output,
    std::size_t output_length)>;

using P2PExportCompletion = std::function<void(bool)>;
using P2PAsyncSessionExporter = std::function<void(
    const char* label,
    const P2PExporterContext& context,
    P2PExporterKey& output,
    const P2PExportCompletion& completion)>;
using P2PRelayOfferCompletion = std::function<void(
    bool ok,
    const P2PRelayOfferBundle& bundle)>;
using P2PTask = std::function<void()>;
using P2PTaskScheduler = std::function<bool(const P2PTask& task)>;

bool BuildP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PExporterKey& initiator_exporter,
    const P2PExporterKey& responder_exporter,
    const P2PRelayOfferSecrets& secrets,
    P2PRelayOfferBundle& output) noexcept;

bool CreateP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PSessionExporter& initiator_exporter,
    const P2PSessionExporter& responder_exporter,
    P2PRelayOfferBundle& output) noexcept;

bool CreateP2PRelayOfferBundleAsync(
    const P2PRelayOfferInput& input,
    const P2PAsyncSessionExporter& initiator_exporter,
    const P2PAsyncSessionExporter& responder_exporter,
    const P2PRelayOfferCompletion& completion) noexcept;

P2PAsyncSessionExporter ScheduleP2PSessionExporter(
    const P2PTaskScheduler& scheduler,
    const P2PSessionExporter& exporter) noexcept;

bool HashP2PCandidateSet(
    const std::vector<P2PCandidateV1>& candidates,
    P2POfferHash& output) noexcept;

}
