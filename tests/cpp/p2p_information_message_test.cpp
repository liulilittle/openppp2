#define BOOST_TEST_MODULE p2p_information_message_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/VirtualEthernetInformation.h>

namespace protocol = ppp::app::protocol;

BOOST_AUTO_TEST_CASE(authenticated_offer_v1_round_trips_as_optional_json) {
    protocol::P2PControlMessage message;
    message.enabled = true;
    message.mode = "direct-preferred";
    message.action = "offer-v1";
    message.authenticated_offer_v1.assign(416, 'a');

    Json::Value json;
    message.ToJson(json);
    BOOST_TEST(json["authenticated-offer-v1"].asString() ==
        message.authenticated_offer_v1);
    BOOST_TEST(!json.isMember("token"));

    protocol::P2PControlMessage parsed;
    BOOST_REQUIRE(protocol::P2PControlMessage::FromJson(parsed, json));
    BOOST_TEST(parsed.authenticated_offer_v1 == message.authenticated_offer_v1);
    parsed.Clear();
    BOOST_TEST(parsed.authenticated_offer_v1.empty());
    BOOST_TEST(!parsed.HasAny());
}

BOOST_AUTO_TEST_CASE(legacy_offer_remains_compatible_without_v1_payload) {
    Json::Value json;
    json["enabled"] = true;
    json["mode"] = "direct-preferred";
    json["action"] = "offer";
    json["token"] = "legacy-token";

    protocol::P2PControlMessage parsed;
    BOOST_REQUIRE(protocol::P2PControlMessage::FromJson(parsed, json));
    BOOST_TEST(parsed.token == "legacy-token");
    BOOST_TEST(parsed.authenticated_offer_v1.empty());
}

BOOST_AUTO_TEST_CASE(v2_fields_roundtrip_without_losing_uint64_precision) {
    protocol::P2PControlMessage message;
    message.action = "offer-v2";
    message.supported_versions = {1, 2};
    message.candidate_revision = UINT64_MAX;
    message.peer_candidate_revision = 1;
    message.current_offer_hash.assign(64, 'a');
    message.cancel_offer_hash.assign(64, 'b');
    message.authenticated_offer_v2.assign(600, 'c');
    protocol::P2PEndpointCandidate candidate;
    candidate.endpoint = "192.0.2.1:4000";
    candidate.source = "host";
    message.local_candidates.push_back(candidate);
    Json::Value json;
    message.ToJson(json);
    BOOST_TEST(json["candidate-revision"].asString() == "18446744073709551615");
    protocol::P2PControlMessage parsed;
    BOOST_REQUIRE(protocol::P2PControlMessage::FromJson(parsed, json));
    BOOST_TEST(parsed.candidate_revision == UINT64_MAX);
    BOOST_TEST(parsed.local_candidates.size() == 1u);
    BOOST_TEST(parsed.authenticated_offer_v2 == message.authenticated_offer_v2);
    parsed.Clear();
    BOOST_TEST(!parsed.HasAny());
}

BOOST_AUTO_TEST_CASE(v2_rejects_noncanonical_revision_and_unbounded_candidates) {
    Json::Value json;
    json["action"] = "register";
    protocol::P2PControlMessage parsed;
    for (const auto* revision : {"0", "01", "-1", "18446744073709551616"}) {
        json["candidate-revision"] = revision;
        BOOST_TEST(!protocol::P2PControlMessage::FromJson(parsed, json));
        BOOST_TEST(!parsed.HasAny());
    }
    json["candidate-revision"] = "1";
    Json::Value candidates(Json::arrayValue);
    for (int i = 0; i < 3; ++i) {
        Json::Value item;
        item["endpoint"] = "192.0.2.1:4000";
        item["source"] = "host";
        candidates.append(item);
    }
    json["candidates"] = candidates;
    BOOST_TEST(!protocol::P2PControlMessage::FromJson(parsed, json));
    BOOST_TEST(!parsed.HasAny());
    json.removeMember("candidates");
    json["current-offer-hash"] = std::string(64, 'A').c_str();
    BOOST_TEST(!protocol::P2PControlMessage::FromJson(parsed, json));
}

BOOST_AUTO_TEST_CASE(v2_versions_are_bounded_and_unique) {
    Json::Value json;
    json["action"] = "register";
    Json::Value versions(Json::arrayValue);
    versions.append(2u);
    versions.append(2u);
    json["supported-versions"] = versions;
    protocol::P2PControlMessage parsed;
    BOOST_TEST(!protocol::P2PControlMessage::FromJson(parsed, json));
    versions.clear();
    versions.append(3u);
    json["supported-versions"] = versions;
    BOOST_TEST(!protocol::P2PControlMessage::FromJson(parsed, json));
}

BOOST_AUTO_TEST_CASE(v2_key_active_status_retains_pair_identity) {
    protocol::P2PControlMessage message;
    message.action = "status";
    message.enabled = true;
    message.reason = "key-active-current";
    message.virtual_ip = 0x0100000a;
    message.current_offer_hash.assign(64, 'a');
    for (const std::uint32_t peer : {0x0200000au, 0x0300000au}) {
        message.peer_virtual_ip = peer;
        Json::Value json;
        message.ToJson(json);
        protocol::P2PControlMessage parsed;
        BOOST_REQUIRE(protocol::P2PControlMessage::FromJson(parsed, json));
        BOOST_TEST(parsed.action == "status");
        BOOST_TEST(parsed.virtual_ip == message.virtual_ip);
        BOOST_TEST(parsed.peer_virtual_ip == peer);
        BOOST_TEST(parsed.reason == message.reason);
        BOOST_TEST(parsed.current_offer_hash == message.current_offer_hash);
    }
}
