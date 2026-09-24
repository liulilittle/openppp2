#define BOOST_TEST_MODULE p2p_relay_offer_coordinator_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PRelayOfferCoordinator.h>
#include <ppp/app/P2PCandidateAdapter.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

#include <algorithm>
#include <cstdint>
#include <cstring>

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

P2PCandidateV1 IPv4Candidate() {
    P2PCandidateV1 candidate;
    candidate.address_family = 4;
    candidate.address = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
        192, 0, 2, 1};
    candidate.port = 1000;
    return candidate;
}

P2PCandidateV1 IPv6Candidate() {
    P2PCandidateV1 candidate;
    candidate.address_family = 6;
    candidate.address = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1};
    candidate.port = 2000;
    return candidate;
}

}

BOOST_AUTO_TEST_CASE(candidate_set_hash_is_canonical) {
    const auto ipv4 = IPv4Candidate();
    const auto ipv6 = IPv6Candidate();
    const P2POfferHash expected{{
        0x91, 0x19, 0x97, 0xf4, 0x7b, 0xff, 0x4c, 0x15,
        0x09, 0x11, 0xac, 0x32, 0x74, 0x6f, 0x51, 0xd1,
        0x08, 0x66, 0x59, 0xac, 0x53, 0x7a, 0xfe, 0x95,
        0x2e, 0xc8, 0xff, 0x6e, 0xfa, 0xe8, 0x73, 0x8f}};
    P2POfferHash forward{};
    P2POfferHash reversed{};
    P2POfferHash duplicated{};

    BOOST_REQUIRE(HashP2PCandidateSet({ipv4, ipv6}, forward));
    BOOST_REQUIRE(HashP2PCandidateSet({ipv6, ipv4}, reversed));
    BOOST_REQUIRE(HashP2PCandidateSet({ipv4, ipv6, ipv4}, duplicated));
    BOOST_TEST(forward == expected);
    BOOST_TEST(reversed == expected);
    BOOST_TEST(duplicated == expected);
}

BOOST_AUTO_TEST_CASE(candidate_set_hash_rejects_invalid_candidates) {
    auto candidate = IPv4Candidate();
    P2POfferHash output = Bytes<32>(211);
    const auto baseline = output;

    candidate.port = 0;
    BOOST_TEST(!HashP2PCandidateSet({candidate}, output));
    BOOST_TEST(output == baseline);

    candidate = IPv4Candidate();
    candidate.address[10] = 0;
    BOOST_TEST(!HashP2PCandidateSet({candidate}, output));
    BOOST_TEST(output == baseline);

    candidate = IPv4Candidate();
    std::fill(candidate.address.begin() + 12, candidate.address.end(), 0);
    BOOST_TEST(!HashP2PCandidateSet({candidate}, output));
    BOOST_TEST(output == baseline);

    candidate = IPv6Candidate();
    candidate.address.fill(0);
    BOOST_TEST(!HashP2PCandidateSet({candidate}, output));
    BOOST_TEST(output == baseline);
}

BOOST_AUTO_TEST_CASE(endpoint_conversion_uses_canonical_candidate_encoding) {
    P2PCandidateV1 ipv4{};
    P2PCandidateV1 ipv6{};
    BOOST_REQUIRE(ppp::app::P2PCandidateFromEndpoint(
        {boost::asio::ip::make_address("192.0.2.1"), 1000}, ipv4));
    BOOST_REQUIRE(ppp::app::P2PCandidateFromEndpoint(
        {boost::asio::ip::make_address("2001:db8::1"), 2000}, ipv6));
    BOOST_TEST(ipv4.address_family == 4);
    BOOST_TEST(ipv4.address == IPv4Candidate().address);
    BOOST_TEST(ipv4.port == 1000);
    BOOST_TEST(ipv6.address_family == 6);
    BOOST_TEST(ipv6.address == IPv6Candidate().address);
    BOOST_TEST(ipv6.port == 2000);
    BOOST_TEST(ppp::app::P2PEndpointToString(
        {boost::asio::ip::make_address("192.0.2.1"), 1000}) == "192.0.2.1:1000");
    BOOST_TEST(ppp::app::P2PEndpointToString(
        {boost::asio::ip::make_address("2001:db8::1"), 2000}) == "[2001:db8::1]:2000");

    const auto baseline = ipv4;
    BOOST_TEST(!ppp::app::P2PCandidateFromEndpoint(
        {boost::asio::ip::address_v4::any(), 1000}, ipv4));
    BOOST_TEST(ipv4.address == baseline.address);
    BOOST_TEST(ipv4.port == baseline.port);
}

BOOST_AUTO_TEST_CASE(observed_udp_candidate_is_validated_and_deduplicated) {
    ppp::vector<ppp::app::protocol::P2PEndpointCandidate> candidates;
    const boost::asio::ip::udp::endpoint observed{
        boost::asio::ip::make_address("203.0.113.1"), 4000};

    BOOST_REQUIRE(ppp::app::P2PAppendObservedEndpointCandidate(
        observed, candidates));
    BOOST_REQUIRE(candidates.size() == 1);
    BOOST_TEST(candidates.front().endpoint == "203.0.113.1:4000");
    BOOST_TEST(candidates.front().source == "observed");

    BOOST_TEST(ppp::app::P2PAppendObservedEndpointCandidate(
        observed, candidates));
    BOOST_TEST(candidates.size() == 1);
    BOOST_TEST(!ppp::app::P2PAppendObservedEndpointCandidate(
        {boost::asio::ip::address_v4::any(), 4000}, candidates));
    BOOST_TEST(candidates.size() == 1);
}

BOOST_AUTO_TEST_CASE(wraps_one_pair_seed_for_two_session_exporters) {
    const auto input = Input();
    const auto secrets = Secrets();
    const auto initiator_exporter = Bytes<32>(7);
    const auto responder_exporter = Bytes<32>(47);
    P2PRelayOfferBundle bundle;

    BOOST_REQUIRE(BuildP2PRelayOfferBundle(
        input, initiator_exporter, responder_exporter, secrets, bundle));
    BOOST_TEST(bundle.initiator_envelope.recipient_peer_id == input.initiator_peer_id);
    BOOST_TEST(bundle.responder_envelope.recipient_peer_id == input.responder_peer_id);
    BOOST_TEST(bundle.initiator_envelope.ciphertext != bundle.responder_envelope.ciphertext);

    P2POfferHash offer_hash{};
    BOOST_REQUIRE(HashP2PRelayOffer(bundle.offer, offer_hash));
    P2PWrapKey initiator_key{};
    P2PWrapKey responder_key{};
    BOOST_REQUIRE(DeriveP2PWrapKey(
        initiator_exporter, offer_hash, P2PPeerRole::Initiator, initiator_key));
    BOOST_REQUIRE(DeriveP2PWrapKey(
        responder_exporter, offer_hash, P2PPeerRole::Responder, responder_key));

    P2PPairSeed initiator_seed{};
    P2PPairSeed responder_seed{};
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        initiator_key, offer_hash, input.initiator_peer_id,
        P2PPeerRole::Initiator, bundle.initiator_envelope, initiator_seed));
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        responder_key, offer_hash, input.responder_peer_id,
        P2PPeerRole::Responder, bundle.responder_envelope, responder_seed));
    BOOST_TEST(initiator_seed == secrets.pair_seed);
    BOOST_TEST(responder_seed == secrets.pair_seed);

    P2PPairSeed unchanged = Bytes<32>(3);
    const auto baseline = unchanged;
    BOOST_TEST(!UnwrapP2PPairSeed(
        initiator_key, offer_hash, input.responder_peer_id,
        P2PPeerRole::Responder, bundle.responder_envelope, unchanged));
    BOOST_TEST(unchanged == baseline);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_input_without_modifying_output) {
    auto input = Input();
    const auto secrets = Secrets();
    auto initiator_exporter = Bytes<32>(7);
    const auto responder_exporter = Bytes<32>(47);
    P2PRelayOfferBundle output;
    output.offer.offer_id = Bytes<16>(233);
    const auto baseline = output.offer.offer_id;

    initiator_exporter.fill(0);
    BOOST_TEST(!BuildP2PRelayOfferBundle(
        input, initiator_exporter, responder_exporter, secrets, output));
    BOOST_TEST(output.offer.offer_id == baseline);

    initiator_exporter = Bytes<32>(7);
    input.responder_peer_id = input.initiator_peer_id;
    BOOST_TEST(!BuildP2PRelayOfferBundle(
        input, initiator_exporter, responder_exporter, secrets, output));
    BOOST_TEST(output.offer.offer_id == baseline);

    input = Input();
    input.candidate_set_hash.fill(0);
    BOOST_TEST(!BuildP2PRelayOfferBundle(
        input, initiator_exporter, responder_exporter, secrets, output));
    BOOST_TEST(output.offer.offer_id == baseline);
}

BOOST_AUTO_TEST_CASE(creates_fresh_session_bound_bundles) {
    const auto input = Input();
    const auto initiator_exporter = Bytes<32>(7);
    const auto responder_exporter = Bytes<32>(47);
    P2PRelayOfferBundle first;
    P2PRelayOfferBundle second;
    P2PExporterContext initiator_context{};
    P2PExporterContext responder_context{};
    int initiator_calls = 0;
    int responder_calls = 0;

    const auto export_initiator = [&](const char* label,
                                      const std::uint8_t* context,
                                      std::size_t context_length,
                                      std::uint8_t* output,
                                      std::size_t output_length) {
        BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
        BOOST_REQUIRE_EQUAL(context_length, initiator_context.size());
        BOOST_REQUIRE_EQUAL(output_length, initiator_exporter.size());
        std::memcpy(initiator_context.data(), context, context_length);
        std::memcpy(output, initiator_exporter.data(), output_length);
        ++initiator_calls;
        return true;
    };
    const auto export_responder = [&](const char* label,
                                      const std::uint8_t* context,
                                      std::size_t context_length,
                                      std::uint8_t* output,
                                      std::size_t output_length) {
        BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
        BOOST_REQUIRE_EQUAL(context_length, responder_context.size());
        BOOST_REQUIRE_EQUAL(output_length, responder_exporter.size());
        std::memcpy(responder_context.data(), context, context_length);
        std::memcpy(output, responder_exporter.data(), output_length);
        ++responder_calls;
        return true;
    };

    BOOST_REQUIRE(CreateP2PRelayOfferBundle(
        input, export_initiator, export_responder, first));
    BOOST_REQUIRE(CreateP2PRelayOfferBundle(
        input, export_initiator, export_responder, second));
    BOOST_TEST(initiator_calls == 2);
    BOOST_TEST(responder_calls == 2);
    BOOST_TEST(first.offer.offer_id != second.offer.offer_id);
    BOOST_TEST(first.offer.connection_epoch != second.offer.connection_epoch);
    BOOST_TEST(first.initiator_envelope.wrap_nonce !=
        second.initiator_envelope.wrap_nonce);

    P2POfferHash offer_hash{};
    BOOST_REQUIRE(HashP2PRelayOffer(first.offer, offer_hash));
    P2PWrapKey initiator_key{};
    P2PWrapKey responder_key{};
    BOOST_REQUIRE(DeriveP2PWrapKey(
        initiator_exporter, offer_hash, P2PPeerRole::Initiator, initiator_key));
    BOOST_REQUIRE(DeriveP2PWrapKey(
        responder_exporter, offer_hash, P2PPeerRole::Responder, responder_key));
    P2PPairSeed initiator_seed{};
    P2PPairSeed responder_seed{};
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        initiator_key, offer_hash, input.initiator_peer_id,
        P2PPeerRole::Initiator, first.initiator_envelope, initiator_seed));
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        responder_key, offer_hash, input.responder_peer_id,
        P2PPeerRole::Responder, first.responder_envelope, responder_seed));
    BOOST_TEST(initiator_seed == responder_seed);
    BOOST_TEST(std::any_of(
        initiator_seed.begin(), initiator_seed.end(),
        [](std::uint8_t value) { return value != 0; }));

    P2PExporterContext expected_initiator_context{};
    P2PExporterContext expected_responder_context{};
    BOOST_REQUIRE(BuildP2PExporterContext(
        second.offer, P2PPeerRole::Initiator, expected_initiator_context));
    BOOST_REQUIRE(BuildP2PExporterContext(
        second.offer, P2PPeerRole::Responder, expected_responder_context));
    BOOST_TEST(initiator_context == expected_initiator_context);
    BOOST_TEST(responder_context == expected_responder_context);
}

BOOST_AUTO_TEST_CASE(exporter_failure_is_fail_closed) {
    const auto input = Input();
    P2PRelayOfferBundle output;
    output.offer.offer_id = Bytes<16>(233);
    const auto baseline = output.offer.offer_id;
    int responder_calls = 0;

    const P2PSessionExporter throwing_exporter =
        [](const char*, const std::uint8_t*, std::size_t,
           std::uint8_t*, std::size_t) -> bool {
        throw 1;
    };
    const P2PSessionExporter responder_exporter =
        [&](const char*, const std::uint8_t*, std::size_t,
            std::uint8_t*, std::size_t) {
        ++responder_calls;
        return true;
    };

    BOOST_TEST(!CreateP2PRelayOfferBundle(
        input, throwing_exporter, responder_exporter, output));
    BOOST_TEST(responder_calls == 0);
    BOOST_TEST(output.offer.offer_id == baseline);
}

BOOST_AUTO_TEST_CASE(async_exporters_run_in_order_and_complete_once) {
    const auto input = Input();
    const auto initiator_key = Bytes<32>(7);
    const auto responder_key = Bytes<32>(47);
    P2PExporterContext initiator_context{};
    P2PExporterContext responder_context{};
    P2PExportCompletion initiator_done;
    P2PExportCompletion responder_done;
    P2PExporterKey* initiator_output = nullptr;
    P2PExporterKey* responder_output = nullptr;
    int initiator_calls = 0;
    int responder_calls = 0;
    int completion_calls = 0;
    bool completion_ok = false;
    P2PRelayOfferBundle completed_bundle;

    const P2PAsyncSessionExporter initiator =
        [&](const char* label, const P2PExporterContext& context,
            P2PExporterKey& output, const P2PExportCompletion& completion) {
        BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
        ++initiator_calls;
        initiator_context = context;
        initiator_output = &output;
        initiator_done = completion;
    };
    const P2PAsyncSessionExporter responder =
        [&](const char* label, const P2PExporterContext& context,
            P2PExporterKey& output, const P2PExportCompletion& completion) {
        BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
        ++responder_calls;
        responder_context = context;
        responder_output = &output;
        responder_done = completion;
    };

    BOOST_REQUIRE(CreateP2PRelayOfferBundleAsync(
        input, initiator, responder,
        [&](bool ok, const P2PRelayOfferBundle& bundle) {
            ++completion_calls;
            completion_ok = ok;
            completed_bundle = bundle;
        }));
    BOOST_TEST(initiator_calls == 1);
    BOOST_TEST(responder_calls == 0);
    BOOST_TEST(completion_calls == 0);
    BOOST_REQUIRE(initiator_output);
    *initiator_output = initiator_key;
    const auto duplicate_initiator_done = initiator_done;
    initiator_done(true);
    BOOST_TEST(responder_calls == 1);
    duplicate_initiator_done(true);
    BOOST_TEST(responder_calls == 1);
    BOOST_TEST(completion_calls == 0);

    BOOST_REQUIRE(responder_output);
    *responder_output = responder_key;
    const auto duplicate_responder_done = responder_done;
    responder_done(true);
    duplicate_responder_done(true);
    BOOST_TEST(completion_calls == 1);
    BOOST_TEST(completion_ok);

    P2PExporterContext expected_initiator{};
    P2PExporterContext expected_responder{};
    BOOST_REQUIRE(BuildP2PExporterContext(
        completed_bundle.offer, P2PPeerRole::Initiator, expected_initiator));
    BOOST_REQUIRE(BuildP2PExporterContext(
        completed_bundle.offer, P2PPeerRole::Responder, expected_responder));
    BOOST_TEST(initiator_context == expected_initiator);
    BOOST_TEST(responder_context == expected_responder);
}

BOOST_AUTO_TEST_CASE(async_initiator_failure_skips_responder) {
    const auto input = Input();
    int responder_calls = 0;
    int completion_calls = 0;
    const P2PAsyncSessionExporter initiator =
        [](const char*, const P2PExporterContext&, P2PExporterKey&,
           const P2PExportCompletion& completion) {
        completion(false);
    };
    const P2PAsyncSessionExporter responder =
        [&](const char*, const P2PExporterContext&, P2PExporterKey&,
            const P2PExportCompletion&) {
        ++responder_calls;
    };

    BOOST_REQUIRE(CreateP2PRelayOfferBundleAsync(
        input, initiator, responder,
        [&](bool ok, const P2PRelayOfferBundle&) {
            BOOST_TEST(!ok);
            ++completion_calls;
        }));
    BOOST_TEST(responder_calls == 0);
    BOOST_TEST(completion_calls == 1);
}

BOOST_AUTO_TEST_CASE(scheduled_exporter_runs_only_on_scheduler) {
    P2PTask scheduled;
    int export_calls = 0;
    int completion_calls = 0;
    bool completion_ok = false;
    P2PExporterKey output{};
    const auto expected = Bytes<32>(17);
    P2PExporterContext context = Bytes<113>(31);

    const P2PTaskScheduler scheduler = [&](const P2PTask& task) {
        scheduled = task;
        return true;
    };
    const P2PSessionExporter exporter =
        [&](const char*, const std::uint8_t*, std::size_t,
            std::uint8_t* destination, std::size_t length) {
        ++export_calls;
        BOOST_REQUIRE_EQUAL(length, expected.size());
        std::memcpy(destination, expected.data(), expected.size());
        return true;
    };
    const auto async_exporter =
        ScheduleP2PSessionExporter(scheduler, exporter);

    async_exporter(
        P2PWrapExporterLabel, context, output,
        [&](bool ok) {
            ++completion_calls;
            completion_ok = ok;
        });
    BOOST_TEST(export_calls == 0);
    BOOST_TEST(completion_calls == 0);
    BOOST_REQUIRE(scheduled);
    scheduled();
    BOOST_TEST(export_calls == 1);
    BOOST_TEST(completion_calls == 1);
    BOOST_TEST(completion_ok);
    BOOST_TEST(output == expected);
}

BOOST_AUTO_TEST_CASE(scheduled_exporter_fails_when_post_is_rejected) {
    int export_calls = 0;
    int completion_calls = 0;
    P2PExporterKey output{};
    const P2PTaskScheduler scheduler = [](const P2PTask&) { return false; };
    const P2PSessionExporter exporter =
        [&](const char*, const std::uint8_t*, std::size_t,
            std::uint8_t*, std::size_t) {
        ++export_calls;
        return true;
    };
    const auto async_exporter =
        ScheduleP2PSessionExporter(scheduler, exporter);

    async_exporter(
        P2PWrapExporterLabel, Bytes<113>(31), output,
        [&](bool ok) {
            BOOST_TEST(!ok);
            ++completion_calls;
        });
    BOOST_TEST(export_calls == 0);
    BOOST_TEST(completion_calls == 1);
}
