#define BOOST_TEST_MODULE p2p_relay_offer_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PRelayOffer.h>

#include <algorithm>
#include <array>
#include <string_view>

using namespace ppp::p2p;

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> Bytes(std::uint8_t seed) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) value[i] = seed + i;
    return value;
}

std::uint8_t HexNibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return 0xff;
}

template <std::size_t N>
std::array<std::uint8_t, N> Hex(std::string_view value) {
    BOOST_REQUIRE_EQUAL(value.size(), N * 2);
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i) {
        const auto high = HexNibble(value[i * 2]);
        const auto low = HexNibble(value[i * 2 + 1]);
        BOOST_REQUIRE(high <= 0x0f);
        BOOST_REQUIRE(low <= 0x0f);
        bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return bytes;
}

P2PRelayOfferV1 Offer() {
    P2PRelayOfferV1 offer;
    offer.version = 1;
    offer.offer_id = Bytes<16>(1);
    offer.initiator_session_id = Bytes<16>(21);
    offer.responder_session_id = Bytes<16>(41);
    offer.initiator_peer_id = Bytes<16>(61);
    offer.responder_peer_id = Bytes<16>(81);
    offer.connection_epoch = Bytes<16>(101);
    offer.ttl_seconds = 30;
    offer.cipher = 1;
    offer.candidate_set_hash = Bytes<32>(141);
    return offer;
}
}

BOOST_AUTO_TEST_CASE(serializes_the_exact_version_one_transcript) {
    const auto offer = Offer();
    P2PRelayOfferBytes bytes{};
    BOOST_REQUIRE(SerializeP2PRelayOffer(offer, bytes));
    BOOST_TEST(bytes.size() == 131u);
    BOOST_TEST(bytes[0] == 1u);
    BOOST_TEST(std::equal(offer.offer_id.begin(), offer.offer_id.end(), bytes.begin() + 1));
    BOOST_TEST(std::equal(offer.responder_session_id.begin(), offer.responder_session_id.end(), bytes.begin() + 33));
    BOOST_TEST(std::equal(offer.connection_epoch.begin(), offer.connection_epoch.end(), bytes.begin() + 81));
    BOOST_TEST(bytes[97] == 30u);
    BOOST_TEST(bytes[98] == 1u);
    BOOST_TEST(std::equal(offer.candidate_set_hash.begin(), offer.candidate_set_hash.end(), bytes.begin() + 99));
    BOOST_TEST(bytes == Hex<131>(
        "010102030405060708090a0b0c0d0e0f1015161718191a1b1c1d1e1f2021222324"
        "292a2b2c2d2e2f3031323334353637383d3e3f404142434445464748494a4b4c"
        "5152535455565758595a5b5c5d5e5f6065666768696a6b6c6d6e6f7071727374"
        "1e018d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabac"));
}

BOOST_AUTO_TEST_CASE(rejects_invalid_or_ambiguous_offer_identity) {
    P2PRelayOfferBytes bytes{};
    auto offer = Offer();
    offer.version = 2;
    BOOST_TEST(!SerializeP2PRelayOffer(offer, bytes));
    offer = Offer();
    offer.ttl_seconds = 0;
    BOOST_TEST(!SerializeP2PRelayOffer(offer, bytes));
    offer.ttl_seconds = 31;
    BOOST_TEST(!SerializeP2PRelayOffer(offer, bytes));
    offer = Offer();
    offer.cipher = 2;
    BOOST_TEST(!SerializeP2PRelayOffer(offer, bytes));
    offer = Offer();
    offer.responder_peer_id = offer.initiator_peer_id;
    BOOST_TEST(!SerializeP2PRelayOffer(offer, bytes));
    offer = Offer();
    offer.responder_session_id = offer.initiator_session_id;
    BOOST_TEST(!SerializeP2PRelayOffer(offer, bytes));
}

BOOST_AUTO_TEST_CASE(hash_binds_every_canonical_offer_section) {
    const auto offer = Offer();
    P2POfferHash baseline{};
    BOOST_REQUIRE(HashP2PRelayOffer(offer, baseline));
    BOOST_TEST(baseline == Hex<32>(
        "98529d1b5173ea7417204ce7ab56783c618355eee22000e39fbe33b0ebbce32d"));
    auto changed = offer;
    changed.offer_id[0] ^= 1;
    P2POfferHash changed_offer{};
    BOOST_REQUIRE(HashP2PRelayOffer(changed, changed_offer));
    BOOST_TEST(baseline != changed_offer);
    changed = offer;
    changed.candidate_set_hash[31] ^= 1;
    BOOST_REQUIRE(HashP2PRelayOffer(changed, changed_offer));
    BOOST_TEST(baseline != changed_offer);
    changed = offer;
    changed.ttl_seconds--;
    BOOST_REQUIRE(HashP2PRelayOffer(changed, changed_offer));
    BOOST_TEST(baseline != changed_offer);
}

BOOST_AUTO_TEST_CASE(exporter_context_is_exact_and_recipient_specific) {
    const auto offer = Offer();
    P2PExporterContext initiator{};
    P2PExporterContext responder{};
    BOOST_REQUIRE(BuildP2PExporterContext(offer, P2PPeerRole::Initiator, initiator));
    BOOST_REQUIRE(BuildP2PExporterContext(offer, P2PPeerRole::Responder, responder));
    BOOST_TEST(initiator.size() == 113u);
    BOOST_TEST(std::equal(offer.initiator_session_id.begin(), offer.initiator_session_id.end(), initiator.begin()));
    BOOST_TEST(std::equal(offer.responder_session_id.begin(), offer.responder_session_id.end(), responder.begin()));
    BOOST_TEST(std::equal(offer.initiator_peer_id.begin(), offer.initiator_peer_id.end(), initiator.begin() + 16));
    BOOST_TEST(std::equal(offer.responder_peer_id.begin(), offer.responder_peer_id.end(), initiator.begin() + 32));
    BOOST_TEST(std::equal(offer.initiator_session_id.begin(), offer.initiator_session_id.end(), initiator.begin() + 48));
    BOOST_TEST(std::equal(offer.responder_session_id.begin(), offer.responder_session_id.end(), initiator.begin() + 64));
    BOOST_TEST(std::equal(offer.connection_epoch.begin(), offer.connection_epoch.end(), initiator.begin() + 80));
    BOOST_TEST(std::equal(offer.offer_id.begin(), offer.offer_id.end(), initiator.begin() + 96));
    BOOST_TEST(initiator[112] == 1u);
    BOOST_TEST(initiator != responder);
    BOOST_TEST(initiator == Hex<113>(
        "15161718191a1b1c1d1e1f20212223243d3e3f404142434445464748494a4b4c"
        "5152535455565758595a5b5c5d5e5f6015161718191a1b1c1d1e1f2021222324"
        "292a2b2c2d2e2f30313233343536373865666768696a6b6c6d6e6f7071727374"
        "0102030405060708090a0b0c0d0e0f1001"));
    BOOST_TEST(responder == Hex<113>(
        "292a2b2c2d2e2f3031323334353637383d3e3f404142434445464748494a4b4c"
        "5152535455565758595a5b5c5d5e5f6015161718191a1b1c1d1e1f2021222324"
        "292a2b2c2d2e2f30313233343536373865666768696a6b6c6d6e6f7071727374"
        "0102030405060708090a0b0c0d0e0f1001"));
    P2PExporterContext invalid{};
    BOOST_TEST(!BuildP2PExporterContext(
        offer, static_cast<P2PPeerRole>(2), invalid));
}

BOOST_AUTO_TEST_CASE(wrap_key_is_bound_to_offer_and_recipient_role) {
    const auto exporter = Bytes<32>(3);
    const auto offer_hash = Bytes<32>(53);
    P2PWrapKey initiator{};
    P2PWrapKey responder{};
    BOOST_REQUIRE(DeriveP2PWrapKey(exporter, offer_hash, P2PPeerRole::Initiator, initiator));
    BOOST_REQUIRE(DeriveP2PWrapKey(exporter, offer_hash, P2PPeerRole::Responder, responder));
    BOOST_TEST(initiator == Hex<32>(
        "be6a48a9595732ba6d36daf6d7b625379236b134aff2e1779b857a78f6e2f83d"));
    BOOST_TEST(responder == Hex<32>(
        "6a581783a7716bcc309be11ce2f5a3f7c946259b8418f4f38947a9bc015d2f42"));
    BOOST_TEST(initiator != responder);
    auto changed_hash = offer_hash;
    changed_hash[0] ^= 1;
    P2PWrapKey changed{};
    BOOST_REQUIRE(DeriveP2PWrapKey(exporter, changed_hash, P2PPeerRole::Initiator, changed));
    BOOST_TEST(initiator != changed);
    BOOST_TEST(!DeriveP2PWrapKey(
        exporter, offer_hash, static_cast<P2PPeerRole>(2), changed));
}

BOOST_AUTO_TEST_CASE(pair_seed_round_trips_only_for_its_offer_and_recipient) {
    const auto offer = Offer();
    P2POfferHash offer_hash{};
    BOOST_REQUIRE(HashP2PRelayOffer(offer, offer_hash));
    P2PWrapKey key{};
    BOOST_REQUIRE(DeriveP2PWrapKey(
        Bytes<32>(5), offer_hash, P2PPeerRole::Initiator, key));
    const auto pair_seed = Bytes<32>(109);
    const auto nonce = Bytes<12>(201);
    P2PWrappedPairSeed envelope;
    BOOST_REQUIRE(WrapP2PPairSeed(
        key, offer_hash, offer.initiator_peer_id, P2PPeerRole::Initiator,
        nonce, pair_seed, envelope));
    BOOST_TEST(key == Hex<32>(
        "248413d434f5317fab1755e18c5011a7fdd5c94c4e16e507c18de3a4b9806ead"));
    BOOST_TEST(envelope.ciphertext == Hex<32>(
        "ec0c293a312bda5030484ac4ec5649aa1beb13d6627ec1509363b323a02e409a"));
    BOOST_TEST(envelope.auth_tag == Hex<16>(
        "c55aad966c566439b2c5d5781044eb27"));

    P2PPairSeed unwrapped{};
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        key, offer_hash, offer.initiator_peer_id, P2PPeerRole::Initiator,
        envelope, unwrapped));
    BOOST_TEST(unwrapped == pair_seed);

    const auto unchanged = Bytes<32>(0xee);
    const auto rejects_without_output = [&](const P2PWrapKey& candidate_key,
                                            const P2POfferHash& candidate_hash,
                                            const P2PId& candidate_peer_id,
                                            P2PPeerRole candidate_role,
                                            const P2PWrappedPairSeed& candidate_envelope) {
        unwrapped = unchanged;
        BOOST_TEST(!UnwrapP2PPairSeed(
            candidate_key, candidate_hash, candidate_peer_id, candidate_role,
            candidate_envelope, unwrapped));
        BOOST_TEST(unwrapped == unchanged);
    };

    auto tampered = envelope;
    tampered.auth_tag[0] ^= 1;
    rejects_without_output(key, offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, tampered);
    tampered = envelope;
    tampered.wrap_nonce[0] ^= 1;
    rejects_without_output(key, offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, tampered);
    tampered = envelope;
    tampered.recipient_peer_id[0] ^= 1;
    rejects_without_output(key, offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, tampered);
    tampered = envelope;
    tampered.recipient_role = P2PPeerRole::Responder;
    rejects_without_output(key, offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, tampered);
    rejects_without_output(key, offer_hash, offer.responder_peer_id,
        P2PPeerRole::Initiator, envelope);
    rejects_without_output(key, offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Responder, envelope);

    auto wrong_hash = offer_hash;
    wrong_hash[0] ^= 1;
    rejects_without_output(key, wrong_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, envelope);
    auto wrong_key = key;
    wrong_key[0] ^= 1;
    rejects_without_output(wrong_key, offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, envelope);
    tampered = envelope;
    tampered.ciphertext[31] ^= 1;
    rejects_without_output(key, offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, tampered);
    BOOST_TEST(!WrapP2PPairSeed(
        key, offer_hash, offer.initiator_peer_id,
        static_cast<P2PPeerRole>(2), nonce, pair_seed, envelope));
}

BOOST_AUTO_TEST_CASE(recipient_wire_round_trips_both_roles) {
    const auto offer = Offer();
    const auto offer_hash = Bytes<32>(61);
    const auto pair_seed = Bytes<32>(93);
    P2PWrappedPairSeed initiator;
    P2PWrappedPairSeed responder;
    BOOST_REQUIRE(WrapP2PPairSeed(
        Bytes<32>(3), offer_hash, offer.initiator_peer_id,
        P2PPeerRole::Initiator, Bytes<12>(125), pair_seed, initiator));
    BOOST_REQUIRE(WrapP2PPairSeed(
        Bytes<32>(35), offer_hash, offer.responder_peer_id,
        P2PPeerRole::Responder, Bytes<12>(145), pair_seed, responder));

    for (const auto& envelope : {initiator, responder}) {
        P2PRelayOfferRecipientBytes wire{};
        BOOST_REQUIRE(SerializeP2PRelayOfferRecipient(offer, envelope, wire));
        P2PRelayOfferV1 parsed_offer;
        P2PWrappedPairSeed parsed_envelope;
        BOOST_REQUIRE(ParseP2PRelayOfferRecipient(
            wire.data(), wire.size(), parsed_offer, parsed_envelope));
        BOOST_TEST(parsed_offer.offer_id == offer.offer_id);
        BOOST_TEST(parsed_offer.candidate_set_hash == offer.candidate_set_hash);
        BOOST_TEST(parsed_envelope.recipient_peer_id == envelope.recipient_peer_id);
        BOOST_TEST(static_cast<int>(parsed_envelope.recipient_role) ==
            static_cast<int>(envelope.recipient_role));
        BOOST_TEST(parsed_envelope.wrap_nonce == envelope.wrap_nonce);
        BOOST_TEST(parsed_envelope.ciphertext == envelope.ciphertext);
        BOOST_TEST(parsed_envelope.auth_tag == envelope.auth_tag);
    }
}

BOOST_AUTO_TEST_CASE(recipient_wire_rejects_malformed_input_without_output) {
    const auto offer = Offer();
    P2PWrappedPairSeed envelope;
    BOOST_REQUIRE(WrapP2PPairSeed(
        Bytes<32>(3), Bytes<32>(61), offer.initiator_peer_id,
        P2PPeerRole::Initiator, Bytes<12>(125), Bytes<32>(93), envelope));
    P2PRelayOfferRecipientBytes wire{};
    BOOST_REQUIRE(SerializeP2PRelayOfferRecipient(offer, envelope, wire));

    P2PRelayOfferV1 parsed_offer;
    parsed_offer.offer_id = Bytes<16>(231);
    P2PWrappedPairSeed parsed_envelope;
    parsed_envelope.recipient_peer_id = Bytes<16>(211);
    const auto offer_baseline = parsed_offer.offer_id;
    const auto envelope_baseline = parsed_envelope.recipient_peer_id;

    BOOST_TEST(!ParseP2PRelayOfferRecipient(
        wire.data(), wire.size() - 1, parsed_offer, parsed_envelope));
    BOOST_TEST(parsed_offer.offer_id == offer_baseline);
    BOOST_TEST(parsed_envelope.recipient_peer_id == envelope_baseline);

    auto tampered = wire;
    tampered[P2PRelayOfferBytes{}.size() + P2PId{}.size()] = 2;
    BOOST_TEST(!ParseP2PRelayOfferRecipient(
        tampered.data(), tampered.size(), parsed_offer, parsed_envelope));
    BOOST_TEST(parsed_offer.offer_id == offer_baseline);
    BOOST_TEST(parsed_envelope.recipient_peer_id == envelope_baseline);

    tampered = wire;
    tampered[P2PRelayOfferBytes{}.size()] ^= 0x80;
    BOOST_TEST(!ParseP2PRelayOfferRecipient(
        tampered.data(), tampered.size(), parsed_offer, parsed_envelope));
    BOOST_TEST(parsed_offer.offer_id == offer_baseline);
    BOOST_TEST(parsed_envelope.recipient_peer_id == envelope_baseline);
}

BOOST_AUTO_TEST_CASE(recipient_wire_hex_is_canonical_and_strict) {
    const auto offer = Offer();
    P2PWrappedPairSeed envelope;
    BOOST_REQUIRE(WrapP2PPairSeed(
        Bytes<32>(3), Bytes<32>(61), offer.initiator_peer_id,
        P2PPeerRole::Initiator, Bytes<12>(125), Bytes<32>(93), envelope));

    std::string encoded;
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(offer, envelope, encoded));
    BOOST_TEST(encoded.size() == P2PRelayOfferRecipientBytes{}.size() * 2);
    BOOST_TEST(std::all_of(encoded.begin(), encoded.end(), [](char value) {
        return (value >= '0' && value <= '9') ||
            (value >= 'a' && value <= 'f');
    }));

    P2PRelayOfferV1 parsed_offer;
    P2PWrappedPairSeed parsed_envelope;
    BOOST_REQUIRE(ParseP2PRelayOfferRecipientHex(
        encoded, parsed_offer, parsed_envelope));
    BOOST_TEST(parsed_offer.offer_id == offer.offer_id);
    BOOST_TEST(parsed_envelope.ciphertext == envelope.ciphertext);

    parsed_offer.offer_id = Bytes<16>(231);
    parsed_envelope.recipient_peer_id = Bytes<16>(211);
    const auto offer_baseline = parsed_offer.offer_id;
    const auto envelope_baseline = parsed_envelope.recipient_peer_id;
    encoded[17] = 'g';
    BOOST_TEST(!ParseP2PRelayOfferRecipientHex(
        encoded, parsed_offer, parsed_envelope));
    BOOST_TEST(parsed_offer.offer_id == offer_baseline);
    BOOST_TEST(parsed_envelope.recipient_peer_id == envelope_baseline);
    encoded.pop_back();
    BOOST_TEST(!ParseP2PRelayOfferRecipientHex(
        encoded, parsed_offer, parsed_envelope));
    BOOST_TEST(parsed_offer.offer_id == offer_baseline);
    BOOST_TEST(parsed_envelope.recipient_peer_id == envelope_baseline);
}
