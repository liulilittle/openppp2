#define BOOST_TEST_MODULE p2p_key_derivation_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PKeyDerivation.h>

#include <algorithm>
#include <array>

using namespace ppp::p2p;

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> Filled(std::uint8_t start) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) value[i] = start + i;
    return value;
}
}

BOOST_AUTO_TEST_CASE(derives_complementary_directional_keys_for_both_roles) {
    const auto pair_seed = Filled<32>(1);
    const auto offer_hash = Filled<32>(41);
    P2PV1KeyMaterial material;
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(pair_seed, offer_hash, material));

    const auto initiator = SelectP2PV1Direction(material, P2PPeerRole::Initiator);
    const auto responder = SelectP2PV1Direction(material, P2PPeerRole::Responder);
    BOOST_TEST(initiator.tx_key == responder.rx_key);
    BOOST_TEST(initiator.rx_key == responder.tx_key);
    BOOST_TEST(initiator.tx_nonce_prefix == responder.rx_nonce_prefix);
    BOOST_TEST(initiator.rx_nonce_prefix == responder.tx_nonce_prefix);
}

BOOST_AUTO_TEST_CASE(fixed_kdf_contexts_are_domain_separated) {
    P2PV1KeyMaterial material;
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(Filled<32>(2), Filled<32>(73), material));
    BOOST_TEST(material.initiator_to_responder_key != material.responder_to_initiator_key);
    BOOST_TEST(material.initiator_to_responder_nonce != material.responder_to_initiator_nonce);
    BOOST_TEST(!std::equal(material.offer_token_key.begin(), material.offer_token_key.end(),
                           material.initiator_to_responder_key.begin()));
}

BOOST_AUTO_TEST_CASE(pair_seed_and_offer_hash_both_bind_every_output) {
    P2PV1KeyMaterial baseline;
    P2PV1KeyMaterial changed_seed;
    P2PV1KeyMaterial changed_offer;
    auto seed = Filled<32>(3);
    auto hash = Filled<32>(91);
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(seed, hash, baseline));
    seed[0] ^= 1;
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(seed, hash, changed_seed));
    seed[0] ^= 1;
    hash[0] ^= 1;
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(seed, hash, changed_offer));
    BOOST_TEST(baseline.offer_token_key != changed_seed.offer_token_key);
    BOOST_TEST(baseline.offer_token_key != changed_offer.offer_token_key);
}

BOOST_AUTO_TEST_CASE(builds_exact_version_one_nonce_for_zero_and_max_sequence) {
    const auto prefix = Filled<8>(0x10);
    const auto zero = BuildP2PV1Nonce(prefix, 0);
    const auto maximum = BuildP2PV1Nonce(prefix, UINT32_MAX);
    BOOST_TEST(std::equal(prefix.begin(), prefix.end(), zero.begin()));
    BOOST_TEST(zero[8] == 0u);
    BOOST_TEST(zero[11] == 0u);
    BOOST_TEST(maximum[8] == 0xffu);
    BOOST_TEST(maximum[11] == 0xffu);
    BOOST_TEST(zero != maximum);
}

BOOST_AUTO_TEST_CASE(sequence_is_encoded_big_endian_and_changes_only_suffix) {
    const auto prefix = Filled<8>(0x20);
    const auto one = BuildP2PV1Nonce(prefix, 1);
    const auto next = BuildP2PV1Nonce(prefix, 0x01020304u);
    BOOST_TEST(std::equal(prefix.begin(), prefix.end(), next.begin()));
    BOOST_TEST(next[8] == 1u);
    BOOST_TEST(next[9] == 2u);
    BOOST_TEST(next[10] == 3u);
    BOOST_TEST(next[11] == 4u);
    BOOST_TEST(one != next);
}
