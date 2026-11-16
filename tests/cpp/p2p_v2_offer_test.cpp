#define BOOST_TEST_MODULE p2p_v2_offer_test
#include <boost/test/included/unit_test.hpp>
#include "support/p2p_v2_fixture.h"
using namespace p2p_v2_test;

BOOST_AUTO_TEST_CASE(recipient_roundtrip_binds_session_role_exporter_and_ciphertext) {
    Pair pair; pair.Offer();
    P2PRelayOfferV2 offer; P2PPeerRole role; P2PPairSeed first{},second{};
    BOOST_REQUIRE(OpenP2PRelayOfferRecipientV2(pair.encoded[0],pair.contexts[0].local_session_id,
        pair.contexts[0].local_peer_id,pair.exporters[0],offer,role,first));
    BOOST_CHECK(role==P2PPeerRole::Initiator);
    BOOST_REQUIRE(OpenP2PRelayOfferRecipientV2(pair.encoded[1],pair.contexts[1].local_session_id,
        pair.contexts[1].local_peer_id,pair.exporters[1],offer,role,second));
    BOOST_CHECK(first==second);
    BOOST_CHECK(!OpenP2PRelayOfferRecipientV2(pair.encoded[0],pair.contexts[1].local_session_id,
        pair.contexts[0].local_peer_id,pair.exporters[0],offer,role,second));
    BOOST_CHECK(!OpenP2PRelayOfferRecipientV2(pair.encoded[0],pair.contexts[0].local_session_id,
        pair.contexts[0].local_peer_id,pair.exporters[1],offer,role,second));
    pair.encoded[0].back()=pair.encoded[0].back()=='0'?'1':'0';
    BOOST_CHECK(!OpenP2PRelayOfferRecipientV2(pair.encoded[0],pair.contexts[0].local_session_id,
        pair.contexts[0].local_peer_id,pair.exporters[0],offer,role,second));
}
BOOST_AUTO_TEST_CASE(candidate_hash_is_sorted_and_binds_revision_session_role_and_count) {
    auto si=Bytes<16>(1),sr=Bytes<16>(21); P2POfferHash a{},b{};
    BOOST_REQUIRE(HashP2PV2CandidateSet(si,sr,1,2,{Endpoint(1),Endpoint(3)},{Endpoint(2)},a));
    BOOST_REQUIRE(HashP2PV2CandidateSet(si,sr,1,2,{Endpoint(3),Endpoint(1)},{Endpoint(2)},b));
    BOOST_CHECK(a==b);
    BOOST_REQUIRE(HashP2PV2CandidateSet(si,sr,2,2,{Endpoint(1),Endpoint(3)},{Endpoint(2)},b)); BOOST_CHECK(a!=b);
    BOOST_REQUIRE(HashP2PV2CandidateSet(sr,si,1,2,{Endpoint(1),Endpoint(3)},{Endpoint(2)},b)); BOOST_CHECK(a!=b);
    BOOST_CHECK(!HashP2PV2CandidateSet(si,sr,1,2,{Endpoint(1),Endpoint(1)},{Endpoint(2)},b));
    BOOST_CHECK(!HashP2PV2CandidateSet(si,sr,0,2,{Endpoint(1)},{Endpoint(2)},b));
}
BOOST_AUTO_TEST_CASE(strict_offer_length_constants_and_protocol_parameters) {
    Pair pair; pair.Offer(); P2PRelayOfferV2 offer; P2PWrappedPairSeed envelope;
    BOOST_TEST(pair.encoded[0].size()==540u);
    BOOST_CHECK(!ParseP2PRelayOfferRecipientV2Hex(pair.encoded[0]+"00",offer,envelope));
    BOOST_CHECK(!ParseP2PRelayOfferRecipientV2Hex(pair.encoded[0].substr(2),offer,envelope));
    P2PRelayOfferV2Bytes bytes; offer=pair.bundle.offer; offer.refresh_after_seconds=41;
    BOOST_CHECK(!SerializeP2PRelayOfferV2(offer,bytes));
    P2PExporterContextV2 ci{},cr{};
    BOOST_REQUIRE(BuildP2PExporterContextV2(pair.bundle.offer,P2PPeerRole::Initiator,ci));
    BOOST_REQUIRE(BuildP2PExporterContextV2(pair.bundle.offer,P2PPeerRole::Responder,cr));
    BOOST_CHECK(ci!=cr);
}
BOOST_AUTO_TEST_CASE(async_owner_schedulers_preserve_context_and_complete_exactly_once) {
    Pair pair; pair.Offer();
    P2PRelayOfferV2Input input;
    input.initiator_session_id=pair.bundle.offer.initiator_session_id;
    input.responder_session_id=pair.bundle.offer.responder_session_id;
    input.initiator_peer_id=pair.bundle.offer.initiator_peer_id;
    input.responder_peer_id=pair.bundle.offer.responder_peer_id;
    input.initiator_candidate_revision=input.responder_candidate_revision=1;
    input.candidate_set_hash=pair.bundle.offer.candidate_set_hash;
    std::function<void()> first,second;
    auto ei=ScheduleP2PSessionExporterV2([&](const std::function<void()>& task) { first=task; return true; },pair.exporters[0]);
    auto er=ScheduleP2PSessionExporterV2([&](const std::function<void()>& task) { second=task; return true; },pair.exporters[1]);
    unsigned completions=0; bool success=false;
    BOOST_REQUIRE(CreateP2PRelayOfferV2BundleAsync(input,ei,er,[&](bool ok,const P2PRelayOfferV2Bundle&) { ++completions; success=ok; }));
    BOOST_REQUIRE(static_cast<bool>(first)); BOOST_CHECK(!second); BOOST_TEST(completions==0u);
    first(); BOOST_REQUIRE(static_cast<bool>(second)); BOOST_TEST(completions==0u);
    first(); second(); BOOST_TEST(completions==1u); BOOST_CHECK(success);
    second(); BOOST_TEST(completions==1u);
}
