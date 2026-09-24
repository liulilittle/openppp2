#pragma once

#include <ppp/p2p/P2PRelayOffer.h>

#include <cstddef>
#include <functional>
#include <string>

namespace ppp::p2p {

struct P2PRelayOfferRecipientContext {
    P2PId local_session_id{};
    P2PId local_peer_id{};
    P2POfferHash candidate_set_hash{};
};

struct P2PRelayOfferRecipientResult {
    P2PRelayOfferV1 offer;
    P2PPairSeed pair_seed{};
    P2PPeerRole local_role = P2PPeerRole::Initiator;
    P2PId peer_session_id{};
    P2PId peer_id{};
    std::uint8_t ttl_seconds = 0;
};

using P2PRelayOfferExporter = std::function<bool(
    const char* label,
    const std::uint8_t* context,
    std::size_t context_length,
    std::uint8_t* output,
    std::size_t output_length)>;

bool OpenP2PRelayOfferRecipient(
    const std::string& encoded,
    const P2PRelayOfferRecipientContext& context,
    const P2PRelayOfferExporter& exporter,
    P2PRelayOfferRecipientResult& output) noexcept;

}
