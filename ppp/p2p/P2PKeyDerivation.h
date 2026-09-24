#pragma once

#include <array>
#include <cstdint>

namespace ppp::p2p {

enum class P2PPeerRole : std::uint8_t { Initiator = 0, Responder = 1 };

struct P2PV1KeyMaterial {
    std::array<std::uint8_t, 32> initiator_to_responder_key{};
    std::array<std::uint8_t, 32> responder_to_initiator_key{};
    std::array<std::uint8_t, 8> initiator_to_responder_nonce{};
    std::array<std::uint8_t, 8> responder_to_initiator_nonce{};
    std::array<std::uint8_t, 32> offer_token_key{};
};

struct P2PV1DirectionalKeys {
    std::array<std::uint8_t, 32> tx_key{};
    std::array<std::uint8_t, 32> rx_key{};
    std::array<std::uint8_t, 8> tx_nonce_prefix{};
    std::array<std::uint8_t, 8> rx_nonce_prefix{};
};

bool DeriveP2PV1KeyMaterial(const std::array<std::uint8_t, 32>& pair_seed,
                            const std::array<std::uint8_t, 32>& offer_hash,
                            P2PV1KeyMaterial& output) noexcept;

P2PV1DirectionalKeys SelectP2PV1Direction(
    const P2PV1KeyMaterial& material, P2PPeerRole local_role) noexcept;

inline std::array<std::uint8_t, 12> BuildP2PV1Nonce(
    const std::array<std::uint8_t, 8>& prefix, std::uint32_t sequence) noexcept {
    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < prefix.size(); ++i) nonce[i] = prefix[i];
    nonce[8] = static_cast<std::uint8_t>(sequence >> 24);
    nonce[9] = static_cast<std::uint8_t>(sequence >> 16);
    nonce[10] = static_cast<std::uint8_t>(sequence >> 8);
    nonce[11] = static_cast<std::uint8_t>(sequence);
    return nonce;
}

}
