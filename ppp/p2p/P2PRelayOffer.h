#pragma once

#include <ppp/p2p/P2PKeyDerivation.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace ppp::p2p {

inline constexpr char P2PWrapExporterLabel[] = "EXPORTER-OPENPPP2-P2P-WRAP-v1";

using P2PId = std::array<std::uint8_t, 16>;
using P2POfferHash = std::array<std::uint8_t, 32>;
using P2PExporterKey = std::array<std::uint8_t, 32>;
using P2PWrapKey = std::array<std::uint8_t, 32>;
using P2PPairSeed = std::array<std::uint8_t, 32>;
using P2PWrapNonce = std::array<std::uint8_t, 12>;
using P2PWrapTag = std::array<std::uint8_t, 16>;
using P2PRelayOfferBytes = std::array<std::uint8_t, 131>;
using P2PExporterContext = std::array<std::uint8_t, 113>;
using P2PRelayOfferRecipientBytes = std::array<std::uint8_t, 208>;

struct P2PRelayOfferV1 {
    std::uint8_t version = 1;
    P2PId offer_id{};
    P2PId initiator_session_id{};
    P2PId responder_session_id{};
    P2PId initiator_peer_id{};
    P2PId responder_peer_id{};
    P2PId connection_epoch{};
    std::uint8_t ttl_seconds = 0;
    std::uint8_t cipher = 1;
    P2POfferHash candidate_set_hash{};
};

struct P2PWrappedPairSeed {
    P2PId recipient_peer_id{};
    P2PPeerRole recipient_role = P2PPeerRole::Initiator;
    P2PWrapNonce wrap_nonce{};
    P2PPairSeed ciphertext{};
    P2PWrapTag auth_tag{};
};

bool SerializeP2PRelayOffer(
    const P2PRelayOfferV1& offer,
    P2PRelayOfferBytes& output) noexcept;

bool HashP2PRelayOffer(
    const P2PRelayOfferV1& offer,
    P2POfferHash& output) noexcept;

bool BuildP2PExporterContext(
    const P2PRelayOfferV1& offer,
    P2PPeerRole recipient_role,
    P2PExporterContext& output) noexcept;

bool DeriveP2PWrapKey(
    const P2PExporterKey& exporter_key,
    const P2POfferHash& offer_hash,
    P2PPeerRole recipient_role,
    P2PWrapKey& output) noexcept;

bool WrapP2PPairSeed(
    const P2PWrapKey& wrap_key,
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id,
    P2PPeerRole recipient_role,
    const P2PWrapNonce& nonce,
    const P2PPairSeed& pair_seed,
    P2PWrappedPairSeed& output) noexcept;

bool UnwrapP2PPairSeed(
    const P2PWrapKey& wrap_key,
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id,
    P2PPeerRole recipient_role,
    const P2PWrappedPairSeed& envelope,
    P2PPairSeed& output) noexcept;

bool SerializeP2PRelayOfferRecipient(
    const P2PRelayOfferV1& offer,
    const P2PWrappedPairSeed& envelope,
    P2PRelayOfferRecipientBytes& output) noexcept;

bool ParseP2PRelayOfferRecipient(
    const std::uint8_t* data,
    std::size_t length,
    P2PRelayOfferV1& offer,
    P2PWrappedPairSeed& envelope) noexcept;

bool EncodeP2PRelayOfferRecipientHex(
    const P2PRelayOfferV1& offer,
    const P2PWrappedPairSeed& envelope,
    std::string& output) noexcept;

bool ParseP2PRelayOfferRecipientHex(
    const std::string& encoded,
    P2PRelayOfferV1& offer,
    P2PWrappedPairSeed& envelope) noexcept;

}
