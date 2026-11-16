#define BOOST_TEST_MODULE policy_runtime_guard_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Error.h>
#include <json/json.h>

BOOST_AUTO_TEST_CASE(explicit_policy_cannot_be_silently_mixed_with_legacy) {
    ppp::configurations::AppConfiguration config;
    auto json = config.ToJson();
    json["client"]["policy"]["version"] = 2;
    BOOST_TEST(!config.Load(json));
    BOOST_TEST(static_cast<int>(ppp::diagnostics::GetLastErrorCode()) ==
        static_cast<int>(ppp::diagnostics::ErrorCode::ConfigTypeMismatch));
    json["client"]["policy"] = "invalid";
    BOOST_TEST(!config.Load(json));
    BOOST_TEST(static_cast<int>(ppp::diagnostics::GetLastErrorCode()) ==
        static_cast<int>(ppp::diagnostics::ErrorCode::ConfigTypeMismatch));
}

BOOST_AUTO_TEST_CASE(explicit_policy_definition_is_owned_for_runtime_preparation) {
    ppp::configurations::AppConfiguration config;
    Json::Value json;
    json["client"]["policy"]["version"] = 2;
    json["client"]["policy"]["rules"]["path"] = "routing.rules";
    BOOST_REQUIRE(config.Load(json));
    BOOST_REQUIRE(config.client.policy != nullptr);
    BOOST_TEST((*config.client.policy)["rules"]["path"].asString() == "routing.rules");
    BOOST_TEST(config.ToJson()["client"]["policy"] == json["client"]["policy"]);
}

BOOST_AUTO_TEST_CASE(legacy_configuration_and_null_policy_remain_loadable) {
    ppp::configurations::AppConfiguration config;
    auto json = config.ToJson();
    BOOST_REQUIRE(config.Load(json));
    json["client"]["policy"] = Json::Value();
    BOOST_TEST(config.Load(json));
}
