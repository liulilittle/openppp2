#include <ppp/p2p/P2PKeyDerivation.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <cstring>

namespace ppp::p2p {
namespace {
bool Derive(const std::array<std::uint8_t, 32>& pair_seed,
            const std::array<std::uint8_t, 32>& offer_hash,
            const char* info, std::uint8_t* output, std::size_t output_size) noexcept {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!context) return false;
    std::size_t derived_size = output_size;
    const bool ok = EVP_PKEY_derive_init(context) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(context, offer_hash.data(), offer_hash.size()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(context, pair_seed.data(), pair_seed.size()) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(context,
            reinterpret_cast<const std::uint8_t*>(info), std::strlen(info)) > 0 &&
        EVP_PKEY_derive(context, output, &derived_size) > 0 &&
        derived_size == output_size;
    EVP_PKEY_CTX_free(context);
    return ok;
}
}

bool DeriveP2PV1KeyMaterial(const std::array<std::uint8_t, 32>& pair_seed,
                            const std::array<std::uint8_t, 32>& offer_hash,
                            P2PV1KeyMaterial& output) noexcept {
    P2PV1KeyMaterial derived;
    if (!Derive(pair_seed, offer_hash,
            "openppp2 p2p v1 initiator to responder key",
            derived.initiator_to_responder_key.data(),
            derived.initiator_to_responder_key.size()) ||
        !Derive(pair_seed, offer_hash,
            "openppp2 p2p v1 responder to initiator key",
            derived.responder_to_initiator_key.data(),
            derived.responder_to_initiator_key.size()) ||
        !Derive(pair_seed, offer_hash,
            "openppp2 p2p v1 initiator to responder nonce",
            derived.initiator_to_responder_nonce.data(),
            derived.initiator_to_responder_nonce.size()) ||
        !Derive(pair_seed, offer_hash,
            "openppp2 p2p v1 responder to initiator nonce",
            derived.responder_to_initiator_nonce.data(),
            derived.responder_to_initiator_nonce.size()) ||
        !Derive(pair_seed, offer_hash, "openppp2 p2p v1 offer token",
            derived.offer_token_key.data(), derived.offer_token_key.size())) {
        return false;
    }
    output = derived;
    return true;
}

P2PV1DirectionalKeys SelectP2PV1Direction(
    const P2PV1KeyMaterial& material, P2PPeerRole local_role) noexcept {
    if (local_role == P2PPeerRole::Initiator) {
        return {material.initiator_to_responder_key,
                material.responder_to_initiator_key,
                material.initiator_to_responder_nonce,
                material.responder_to_initiator_nonce};
    }
    return {material.responder_to_initiator_key,
            material.initiator_to_responder_key,
            material.responder_to_initiator_nonce,
            material.initiator_to_responder_nonce};
}

}
