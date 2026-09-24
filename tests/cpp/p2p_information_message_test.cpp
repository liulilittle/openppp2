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
