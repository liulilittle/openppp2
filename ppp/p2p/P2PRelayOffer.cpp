#include <ppp/p2p/P2PRelayOffer.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <cstring>

namespace ppp::p2p {
namespace {

template <std::size_t N>
bool IsZero(const std::array<std::uint8_t, N>& value) noexcept {
    std::uint8_t combined = 0;
    for (std::uint8_t byte : value) {
        combined |= byte;
    }
    return combined == 0;
}

bool ValidOffer(const P2PRelayOfferV1& offer) noexcept {
    return offer.version == 1 &&
        offer.ttl_seconds >= 1 && offer.ttl_seconds <= 30 &&
        offer.cipher == 1 &&
        !IsZero(offer.offer_id) &&
        !IsZero(offer.initiator_session_id) &&
        !IsZero(offer.responder_session_id) &&
        !IsZero(offer.initiator_peer_id) &&
        !IsZero(offer.responder_peer_id) &&
        !IsZero(offer.connection_epoch) &&
        !IsZero(offer.candidate_set_hash) &&
        offer.initiator_session_id != offer.responder_session_id &&
        offer.initiator_peer_id != offer.responder_peer_id;
}

bool ValidRole(P2PPeerRole role) noexcept {
    return role == P2PPeerRole::Initiator ||
        role == P2PPeerRole::Responder;
}

int HexValue(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

template <std::size_t N>
void Append(std::uint8_t*& cursor, const std::array<std::uint8_t, N>& value) noexcept {
    std::memcpy(cursor, value.data(), value.size());
    cursor += value.size();
}

template <std::size_t N>
void Read(const std::uint8_t*& cursor, std::array<std::uint8_t, N>& value) noexcept {
    std::memcpy(value.data(), cursor, value.size());
    cursor += value.size();
}

std::array<std::uint8_t, 48> BuildWrapAad(
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id) noexcept {
    std::array<std::uint8_t, 48> aad{};
    std::memcpy(aad.data(), offer_hash.data(), offer_hash.size());
    std::memcpy(aad.data() + offer_hash.size(),
        recipient_peer_id.data(), recipient_peer_id.size());
    return aad;
}

bool CryptPairSeed(
    bool encrypt,
    const P2PWrapKey& wrap_key,
    const P2PWrapNonce& nonce,
    const std::array<std::uint8_t, 48>& aad,
    const P2PPairSeed& input,
    const P2PWrapTag* input_tag,
    P2PPairSeed& output,
    P2PWrapTag* output_tag) noexcept {
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) {
        return false;
    }

    P2PPairSeed temporary{};
    int length = 0;
    int total = 0;
    bool ok = EVP_CipherInit_ex(
            context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr,
            encrypt ? 1 : 0) == 1 &&
        EVP_CIPHER_CTX_ctrl(
            context, EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(nonce.size()), nullptr) == 1 &&
        EVP_CipherInit_ex(
            context, nullptr, nullptr, wrap_key.data(), nonce.data(),
            encrypt ? 1 : 0) == 1 &&
        EVP_CipherUpdate(
            context, nullptr, &length, aad.data(),
            static_cast<int>(aad.size())) == 1;

    if (ok && !encrypt) {
        ok = input_tag != nullptr &&
            EVP_CIPHER_CTX_ctrl(
                context, EVP_CTRL_AEAD_SET_TAG,
                static_cast<int>(input_tag->size()),
                const_cast<std::uint8_t*>(input_tag->data())) == 1;
    }
    if (ok) {
        ok = EVP_CipherUpdate(
            context, temporary.data(), &length, input.data(),
            static_cast<int>(input.size())) == 1;
        total = length;
    }
    if (ok) {
        ok = EVP_CipherFinal_ex(context, temporary.data() + total, &length) == 1;
        total += length;
    }

    P2PWrapTag tag{};
    if (ok && encrypt) {
        ok = output_tag != nullptr &&
            EVP_CIPHER_CTX_ctrl(
                context, EVP_CTRL_AEAD_GET_TAG,
                static_cast<int>(tag.size()), tag.data()) == 1;
    }
    ok = ok && total == static_cast<int>(temporary.size());
    EVP_CIPHER_CTX_free(context);

    if (ok) {
        output = temporary;
        if (encrypt) {
            *output_tag = tag;
        }
    }
    OPENSSL_cleanse(temporary.data(), temporary.size());
    OPENSSL_cleanse(tag.data(), tag.size());
    return ok;
}

}

bool SerializeP2PRelayOffer(
    const P2PRelayOfferV1& offer,
    P2PRelayOfferBytes& output) noexcept {
    if (!ValidOffer(offer)) {
        return false;
    }

    P2PRelayOfferBytes serialized{};
    std::uint8_t* cursor = serialized.data();
    *cursor++ = offer.version;
    Append(cursor, offer.offer_id);
    Append(cursor, offer.initiator_session_id);
    Append(cursor, offer.responder_session_id);
    Append(cursor, offer.initiator_peer_id);
    Append(cursor, offer.responder_peer_id);
    Append(cursor, offer.connection_epoch);
    *cursor++ = offer.ttl_seconds;
    *cursor++ = offer.cipher;
    Append(cursor, offer.candidate_set_hash);
    if (cursor != serialized.data() + serialized.size()) {
        return false;
    }
    output = serialized;
    return true;
}

bool HashP2PRelayOffer(
    const P2PRelayOfferV1& offer,
    P2POfferHash& output) noexcept {
    P2PRelayOfferBytes serialized{};
    if (!SerializeP2PRelayOffer(offer, serialized)) {
        return false;
    }

    P2POfferHash digest{};
    unsigned int digest_size = 0;
    const bool ok = EVP_Digest(
        serialized.data(), serialized.size(),
        digest.data(), &digest_size, EVP_sha256(), nullptr) == 1 &&
        digest_size == digest.size();
    if (ok) {
        output = digest;
    }
    OPENSSL_cleanse(digest.data(), digest.size());
    return ok;
}

bool BuildP2PExporterContext(
    const P2PRelayOfferV1& offer,
    P2PPeerRole recipient_role,
    P2PExporterContext& output) noexcept {
    if (!ValidOffer(offer) || !ValidRole(recipient_role)) {
        return false;
    }

    P2PExporterContext context{};
    std::uint8_t* cursor = context.data();
    Append(cursor, recipient_role == P2PPeerRole::Initiator
        ? offer.initiator_session_id
        : offer.responder_session_id);
    Append(cursor, offer.initiator_peer_id);
    Append(cursor, offer.responder_peer_id);
    Append(cursor, offer.initiator_session_id);
    Append(cursor, offer.responder_session_id);
    Append(cursor, offer.connection_epoch);
    Append(cursor, offer.offer_id);
    *cursor++ = offer.version;
    if (cursor != context.data() + context.size()) {
        return false;
    }
    output = context;
    return true;
}

bool DeriveP2PWrapKey(
    const P2PExporterKey& exporter_key,
    const P2POfferHash& offer_hash,
    P2PPeerRole recipient_role,
    P2PWrapKey& output) noexcept {
    if (IsZero(exporter_key) || IsZero(offer_hash) ||
        !ValidRole(recipient_role)) {
        return false;
    }

    static constexpr char info[] = "openppp2 p2p v1 wrap key";
    // OpenSSL 3.0.13 replaces provider HKDF info on repeated add calls.
    std::array<std::uint8_t, sizeof(info)> info_with_role{};
    std::memcpy(info_with_role.data(), info, sizeof(info) - 1);
    info_with_role.back() = static_cast<std::uint8_t>(recipient_role);
    P2PWrapKey derived{};
    std::size_t derived_size = derived.size();
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!context) {
        return false;
    }

    const bool ok = EVP_PKEY_derive_init(context) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(
            context, offer_hash.data(), offer_hash.size()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(
            context, exporter_key.data(), exporter_key.size()) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            context, info_with_role.data(), info_with_role.size()) > 0 &&
        EVP_PKEY_derive(context, derived.data(), &derived_size) > 0 &&
        derived_size == derived.size();
    EVP_PKEY_CTX_free(context);
    if (ok) {
        output = derived;
    }
    OPENSSL_cleanse(derived.data(), derived.size());
    return ok;
}

bool WrapP2PPairSeed(
    const P2PWrapKey& wrap_key,
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id,
    P2PPeerRole recipient_role,
    const P2PWrapNonce& nonce,
    const P2PPairSeed& pair_seed,
    P2PWrappedPairSeed& output) noexcept {
    if (IsZero(wrap_key) || IsZero(offer_hash) || IsZero(recipient_peer_id) ||
        IsZero(nonce) || IsZero(pair_seed) || !ValidRole(recipient_role)) {
        return false;
    }

    P2PWrappedPairSeed envelope;
    envelope.recipient_peer_id = recipient_peer_id;
    envelope.recipient_role = recipient_role;
    envelope.wrap_nonce = nonce;
    const auto aad = BuildWrapAad(offer_hash, recipient_peer_id);
    if (!CryptPairSeed(
            true, wrap_key, nonce, aad, pair_seed, nullptr,
            envelope.ciphertext, &envelope.auth_tag)) {
        return false;
    }
    output = envelope;
    return true;
}

bool UnwrapP2PPairSeed(
    const P2PWrapKey& wrap_key,
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id,
    P2PPeerRole recipient_role,
    const P2PWrappedPairSeed& envelope,
    P2PPairSeed& output) noexcept {
    if (IsZero(wrap_key) || IsZero(offer_hash) || IsZero(recipient_peer_id) ||
        !ValidRole(recipient_role) ||
        envelope.recipient_peer_id != recipient_peer_id ||
        envelope.recipient_role != recipient_role ||
        IsZero(envelope.wrap_nonce)) {
        return false;
    }

    P2PPairSeed pair_seed{};
    const auto aad = BuildWrapAad(offer_hash, recipient_peer_id);
    const bool ok = CryptPairSeed(
        false, wrap_key, envelope.wrap_nonce, aad, envelope.ciphertext,
        &envelope.auth_tag, pair_seed, nullptr);
    if (ok) {
        output = pair_seed;
    }
    OPENSSL_cleanse(pair_seed.data(), pair_seed.size());
    return ok;
}

bool SerializeP2PRelayOfferRecipient(
    const P2PRelayOfferV1& offer,
    const P2PWrappedPairSeed& envelope,
    P2PRelayOfferRecipientBytes& output) noexcept {
    const bool initiator = envelope.recipient_role == P2PPeerRole::Initiator;
    const bool responder = envelope.recipient_role == P2PPeerRole::Responder;
    if ((!initiator && !responder) || IsZero(envelope.wrap_nonce) ||
        envelope.recipient_peer_id != (initiator
            ? offer.initiator_peer_id
            : offer.responder_peer_id)) {
        return false;
    }

    P2PRelayOfferBytes common{};
    if (!SerializeP2PRelayOffer(offer, common)) {
        return false;
    }

    P2PRelayOfferRecipientBytes wire{};
    std::uint8_t* cursor = wire.data();
    Append(cursor, common);
    Append(cursor, envelope.recipient_peer_id);
    *cursor++ = static_cast<std::uint8_t>(envelope.recipient_role);
    Append(cursor, envelope.wrap_nonce);
    Append(cursor, envelope.ciphertext);
    Append(cursor, envelope.auth_tag);
    if (cursor != wire.data() + wire.size()) {
        return false;
    }
    output = wire;
    return true;
}

bool ParseP2PRelayOfferRecipient(
    const std::uint8_t* data,
    std::size_t length,
    P2PRelayOfferV1& offer,
    P2PWrappedPairSeed& envelope) noexcept {
    if (!data || length != P2PRelayOfferRecipientBytes{}.size()) {
        return false;
    }

    const std::uint8_t* cursor = data;
    P2PRelayOfferV1 parsed_offer;
    parsed_offer.version = *cursor++;
    Read(cursor, parsed_offer.offer_id);
    Read(cursor, parsed_offer.initiator_session_id);
    Read(cursor, parsed_offer.responder_session_id);
    Read(cursor, parsed_offer.initiator_peer_id);
    Read(cursor, parsed_offer.responder_peer_id);
    Read(cursor, parsed_offer.connection_epoch);
    parsed_offer.ttl_seconds = *cursor++;
    parsed_offer.cipher = *cursor++;
    Read(cursor, parsed_offer.candidate_set_hash);

    P2PWrappedPairSeed parsed_envelope;
    Read(cursor, parsed_envelope.recipient_peer_id);
    parsed_envelope.recipient_role = static_cast<P2PPeerRole>(*cursor++);
    Read(cursor, parsed_envelope.wrap_nonce);
    Read(cursor, parsed_envelope.ciphertext);
    Read(cursor, parsed_envelope.auth_tag);
    if (cursor != data + length || !ValidOffer(parsed_offer) ||
        !ValidRole(parsed_envelope.recipient_role) ||
        IsZero(parsed_envelope.wrap_nonce)) {
        return false;
    }
    const auto& expected_peer =
        parsed_envelope.recipient_role == P2PPeerRole::Initiator
            ? parsed_offer.initiator_peer_id
            : parsed_offer.responder_peer_id;
    if (parsed_envelope.recipient_peer_id != expected_peer) {
        return false;
    }

    offer = parsed_offer;
    envelope = parsed_envelope;
    return true;
}

bool EncodeP2PRelayOfferRecipientHex(
    const P2PRelayOfferV1& offer,
    const P2PWrappedPairSeed& envelope,
    std::string& output) noexcept {
    P2PRelayOfferRecipientBytes wire{};
    if (!SerializeP2PRelayOfferRecipient(offer, envelope, wire)) {
        return false;
    }

    static constexpr char hex[] = "0123456789abcdef";
    std::string encoded;
    encoded.resize(wire.size() * 2);
    for (std::size_t i = 0; i < wire.size(); ++i) {
        encoded[i * 2] = hex[wire[i] >> 4];
        encoded[i * 2 + 1] = hex[wire[i] & 0x0f];
    }
    output = std::move(encoded);
    return true;
}

bool ParseP2PRelayOfferRecipientHex(
    const std::string& encoded,
    P2PRelayOfferV1& offer,
    P2PWrappedPairSeed& envelope) noexcept {
    P2PRelayOfferRecipientBytes wire{};
    if (encoded.size() != wire.size() * 2) {
        return false;
    }
    for (std::size_t i = 0; i < wire.size(); ++i) {
        const int high = HexValue(encoded[i * 2]);
        const int low = HexValue(encoded[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        wire[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return ParseP2PRelayOfferRecipient(
        wire.data(), wire.size(), offer, envelope);
}

}
