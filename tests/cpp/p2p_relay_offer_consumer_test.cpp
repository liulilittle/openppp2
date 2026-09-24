#define BOOST_TEST_MODULE p2p_relay_offer_consumer_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PRelayOfferConsumer.h>
#include <ppp/p2p/P2PRelayOfferCoordinator.h>

#include <algorithm>

namespace {

using namespace ppp::p2p;

template <std::size_t N>
std::array<std::uint8_t, N> Bytes(std::uint8_t first) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<std::uint8_t>(first + i);
    }
    return value;
}

P2PRelayOfferInput Input() {
    P2PRelayOfferInput input;
    input.initiator_session_id = Bytes<16>(1);
    input.responder_session_id = Bytes<16>(21);
    input.initiator_peer_id = Bytes<16>(41);
    input.responder_peer_id = Bytes<16>(61);
    input.ttl_seconds = 10;
    input.candidate_set_hash = Bytes<32>(81);
    return input;
}

P2PRelayOfferSecrets Secrets() {
    P2PRelayOfferSecrets secrets;
    secrets.offer_id = Bytes<16>(101);
    secrets.connection_epoch = Bytes<16>(121);
    secrets.pair_seed = Bytes<32>(141);
    secrets.initiator_wrap_nonce = Bytes<12>(181);
    secrets.responder_wrap_nonce = Bytes<12>(201);
    return secrets;
}

P2PRelayOfferBundle Bundle() {
    P2PRelayOfferBundle bundle;
    BOOST_REQUIRE(BuildP2PRelayOfferBundle(
        Input(), Bytes<32>(7), Bytes<32>(47), Secrets(), bundle));
    return bundle;
}

P2PRelayOfferRecipientContext InitiatorContext() {
    const auto input = Input();
    P2PRelayOfferRecipientContext context;
    context.local_session_id = input.initiator_session_id;
    context.local_peer_id = input.initiator_peer_id;
    context.candidate_set_hash = input.candidate_set_hash;
    return context;
}

P2PRelayOfferExporter Exporter(const P2PExporterKey& key) {
    return [key](const char* label,
                 const std::uint8_t*, std::size_t,
                 std::uint8_t* output, std::size_t output_length) {
        BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
        BOOST_REQUIRE_EQUAL(output_length, key.size());
        std::copy(key.begin(), key.end(), output);
        return true;
    };
}

}

BOOST_AUTO_TEST_CASE(opens_authenticated_offer_for_intended_recipient) {
    const auto bundle = Bundle();
    std::string encoded;
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(
        bundle.offer, bundle.initiator_envelope, encoded));
    P2PRelayOfferRecipientResult result;

    BOOST_REQUIRE(OpenP2PRelayOfferRecipient(
        encoded, InitiatorContext(), Exporter(Bytes<32>(7)), result));
    BOOST_TEST(result.offer.offer_id == bundle.offer.offer_id);
    BOOST_TEST(
        static_cast<int>(result.local_role) ==
        static_cast<int>(P2PPeerRole::Initiator));
    BOOST_TEST(result.peer_session_id == bundle.offer.responder_session_id);
    BOOST_TEST(result.peer_id == bundle.offer.responder_peer_id);
    BOOST_TEST(result.pair_seed == Secrets().pair_seed);
    BOOST_TEST(result.ttl_seconds == 10);
}

BOOST_AUTO_TEST_CASE(rejects_identity_candidate_and_exporter_mismatch) {
    const auto bundle = Bundle();
    std::string encoded;
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(
        bundle.offer, bundle.initiator_envelope, encoded));
    P2PRelayOfferRecipientResult result;
    result.pair_seed = Bytes<32>(231);
    const auto baseline = result.pair_seed;

    auto context = InitiatorContext();
    context.local_session_id = Input().responder_session_id;
    BOOST_TEST(!OpenP2PRelayOfferRecipient(encoded, context, Exporter(Bytes<32>(7)), result));
    BOOST_TEST(result.pair_seed == baseline);

    context = InitiatorContext();
    context.local_peer_id = Input().responder_peer_id;
    BOOST_TEST(!OpenP2PRelayOfferRecipient(encoded, context, Exporter(Bytes<32>(7)), result));
    BOOST_TEST(result.pair_seed == baseline);

    context = InitiatorContext();
    context.candidate_set_hash[0] ^= 0xff;
    BOOST_TEST(!OpenP2PRelayOfferRecipient(encoded, context, Exporter(Bytes<32>(7)), result));
    BOOST_TEST(result.pair_seed == baseline);

    BOOST_TEST(!OpenP2PRelayOfferRecipient(
        encoded, InitiatorContext(), Exporter(Bytes<32>(47)), result));
    BOOST_TEST(result.pair_seed == baseline);
}

BOOST_AUTO_TEST_CASE(rejects_tampered_recipient_envelope) {
    const auto bundle = Bundle();
    std::string encoded;
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(
        bundle.offer, bundle.initiator_envelope, encoded));
    encoded.back() = encoded.back() == '0' ? '1' : '0';
    P2PRelayOfferRecipientResult result;
    result.offer.offer_id = Bytes<16>(233);
    const auto baseline = result.offer.offer_id;

    BOOST_TEST(!OpenP2PRelayOfferRecipient(
        encoded, InitiatorContext(), Exporter(Bytes<32>(7)), result));
    BOOST_TEST(result.offer.offer_id == baseline);
}

BOOST_AUTO_TEST_CASE(opens_responder_role_with_bound_exporter_context) {
    const auto bundle = Bundle();
    std::string encoded;
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(
        bundle.offer, bundle.responder_envelope, encoded));
    P2PRelayOfferRecipientContext context;
    context.local_session_id = bundle.offer.responder_session_id;
    context.local_peer_id = bundle.offer.responder_peer_id;
    context.candidate_set_hash = bundle.offer.candidate_set_hash;
    P2PExporterContext expected_context{};
    BOOST_REQUIRE(BuildP2PExporterContext(
        bundle.offer, P2PPeerRole::Responder, expected_context));
    P2PRelayOfferRecipientResult result;

    BOOST_REQUIRE(OpenP2PRelayOfferRecipient(
        encoded, context,
        [&](const char* label, const std::uint8_t* exporter_context,
            std::size_t context_length, std::uint8_t* output,
            std::size_t output_length) {
            BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
            BOOST_REQUIRE_EQUAL(context_length, expected_context.size());
            BOOST_TEST(std::equal(
                expected_context.begin(), expected_context.end(),
                exporter_context));
            const auto key = Bytes<32>(47);
            BOOST_REQUIRE_EQUAL(output_length, key.size());
            std::copy(key.begin(), key.end(), output);
            return true;
        },
        result));
    BOOST_TEST(
        static_cast<int>(result.local_role) ==
        static_cast<int>(P2PPeerRole::Responder));
    BOOST_TEST(result.peer_session_id == bundle.offer.initiator_session_id);
    BOOST_TEST(result.peer_id == bundle.offer.initiator_peer_id);
    BOOST_TEST(result.pair_seed == Secrets().pair_seed);
}

BOOST_AUTO_TEST_CASE(exporter_exception_fails_closed) {
    const auto bundle = Bundle();
    std::string encoded;
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(
        bundle.offer, bundle.initiator_envelope, encoded));
    P2PRelayOfferRecipientResult result;
    result.pair_seed = Bytes<32>(231);
    const auto baseline = result.pair_seed;

    BOOST_TEST(!OpenP2PRelayOfferRecipient(
        encoded, InitiatorContext(),
        [](const char*, const std::uint8_t*, std::size_t,
           std::uint8_t*, std::size_t) -> bool {
            throw 1;
        },
        result));
    BOOST_TEST(result.pair_seed == baseline);
}
