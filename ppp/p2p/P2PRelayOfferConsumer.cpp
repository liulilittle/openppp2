#include <ppp/p2p/P2PRelayOfferConsumer.h>

#include <openssl/crypto.h>

namespace ppp::p2p {
namespace {

template <typename T>
void Cleanse(T& value) noexcept {
    OPENSSL_cleanse(value.data(), value.size());
}

}

bool OpenP2PRelayOfferRecipient(
    const std::string& encoded,
    const P2PRelayOfferRecipientContext& context,
    const P2PRelayOfferExporter& exporter,
    P2PRelayOfferRecipientResult& output) noexcept {
    if (!exporter) {
        return false;
    }

    P2PRelayOfferV1 offer;
    P2PWrappedPairSeed envelope;
    if (!ParseP2PRelayOfferRecipientHex(encoded, offer, envelope)) {
        return false;
    }

    const P2PPeerRole role = envelope.recipient_role;
    const P2PId& local_session = role == P2PPeerRole::Initiator
        ? offer.initiator_session_id
        : offer.responder_session_id;
    const P2PId& local_peer = role == P2PPeerRole::Initiator
        ? offer.initiator_peer_id
        : offer.responder_peer_id;
    if (local_session != context.local_session_id ||
        local_peer != context.local_peer_id ||
        offer.candidate_set_hash != context.candidate_set_hash) {
        return false;
    }

    P2PExporterContext exporter_context{};
    P2PExporterKey exporter_key{};
    P2POfferHash offer_hash{};
    P2PWrapKey wrap_key{};
    P2PPairSeed pair_seed{};
    bool exported = false;
    if (BuildP2PExporterContext(offer, role, exporter_context)) {
        try {
            exported = exporter(
                P2PWrapExporterLabel,
                exporter_context.data(), exporter_context.size(),
                exporter_key.data(), exporter_key.size());
        }
        catch (...) {
        }
    }

    const bool opened = exported &&
        HashP2PRelayOffer(offer, offer_hash) &&
        DeriveP2PWrapKey(exporter_key, offer_hash, role, wrap_key) &&
        UnwrapP2PPairSeed(
            wrap_key, offer_hash, context.local_peer_id,
            role, envelope, pair_seed);
    if (opened) {
        P2PRelayOfferRecipientResult result;
        result.offer = offer;
        result.pair_seed = pair_seed;
        result.local_role = role;
        result.peer_session_id = role == P2PPeerRole::Initiator
            ? offer.responder_session_id
            : offer.initiator_session_id;
        result.peer_id = role == P2PPeerRole::Initiator
            ? offer.responder_peer_id
            : offer.initiator_peer_id;
        result.ttl_seconds = offer.ttl_seconds;
        output = result;
        Cleanse(result.pair_seed);
    }

    Cleanse(exporter_context);
    Cleanse(exporter_key);
    Cleanse(offer_hash);
    Cleanse(wrap_key);
    Cleanse(pair_seed);
    return opened;
}

}
