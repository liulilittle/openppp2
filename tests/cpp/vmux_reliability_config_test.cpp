// VMUX reliability configuration: PTO and dup-ACK fast retransmit are opt-in on
// reliable (TCP / WebSocket) carriers. Field log 2026-10-18: during an upload
// test 45% of sent frames were retransmissions (mux.rtx.send / mux.link.send)
// right before the peer tore the session down.
#define BOOST_TEST_MODULE vmux_reliability_config_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/configurations/AppConfiguration.h>

#include <json/json.h>

using ppp::configurations::AppConfiguration;

BOOST_AUTO_TEST_CASE(pto_and_fast_retransmit_default_off) {
    AppConfiguration config;

    BOOST_TEST(config.mux.reliability.enabled); // ACK + carrier-exit re-injection stay on
    BOOST_TEST(!config.mux.reliability.rtx.pto);
    BOOST_TEST(!config.mux.reliability.rtx.fast);

    Json::Value json = config.ToJson();
    BOOST_TEST(json["mux"]["reliability"]["rtx"]["pto"].asBool() == false);
    BOOST_TEST(json["mux"]["reliability"]["rtx"]["fast"].asBool() == false);
}

BOOST_AUTO_TEST_CASE(pto_and_fast_retransmit_can_be_enabled_and_roundtrip) {
    AppConfiguration defaults;
    Json::Value json = defaults.ToJson();
    json["mux"]["reliability"]["rtx"]["pto"] = true;
    json["mux"]["reliability"]["rtx"]["fast"] = true;

    AppConfiguration loaded;
    BOOST_REQUIRE(loaded.Load(json));
    BOOST_TEST(loaded.mux.reliability.rtx.pto);
    BOOST_TEST(loaded.mux.reliability.rtx.fast);

    Json::Value again = loaded.ToJson();
    BOOST_TEST(again["mux"]["reliability"]["rtx"]["pto"].asBool());
    BOOST_TEST(again["mux"]["reliability"]["rtx"]["fast"].asBool());
}

BOOST_AUTO_TEST_CASE(send_windows_default_to_bdp_sized_values) {
    // Field test 2026-10-18: with 8 MiB / 2 MiB windows mux throughput sat at
    // window / RTT (single flow ~165 Mbps, 8 flows ~516 Mbps) while mux-off ran
    // ~690 / ~850 Mbps. Defaults are now 32 MiB session / 8 MiB per flow.
    AppConfiguration config;
    BOOST_TEST(config.mux.reliability.rtx.bytes == (32 << 20));
    BOOST_TEST(config.mux.reliability.rtx.flow_bytes == (8 << 20));
    BOOST_TEST(config.ToJson()["mux"]["reliability"]["rtx"]["flow_bytes"].asInt() == (8 << 20));
}

BOOST_AUTO_TEST_CASE(receive_reorder_budget_covers_the_send_windows) {
    // Out-of-order frames are selectively ACKed, so a sender keeps sending
    // while a gap persists. A receive budget smaller than the send window reset
    // flows in a field test right after the windows were raised (8 MiB flow
    // window vs 1 MiB / 2 MiB reorder caps).
    AppConfiguration config;
    BOOST_TEST(config.mux.flow.reorder.bytes >= config.mux.reliability.rtx.flow_bytes);
    BOOST_TEST(config.mux.flow.session_reorder.bytes >= config.mux.reliability.rtx.bytes);
}

BOOST_AUTO_TEST_CASE(flow_window_is_configurable_and_clamped_to_session_window) {
    AppConfiguration defaults;
    Json::Value json = defaults.ToJson();
    json["mux"]["reliability"]["rtx"]["bytes"] = 4 << 20;
    json["mux"]["reliability"]["rtx"]["flow_bytes"] = 16 << 20;

    AppConfiguration loaded;
    BOOST_REQUIRE(loaded.Load(json));
    BOOST_TEST(loaded.mux.reliability.rtx.bytes == (4 << 20));
    BOOST_TEST(loaded.mux.reliability.rtx.flow_bytes == (4 << 20)); // clamped

    json["mux"]["reliability"]["rtx"]["flow_bytes"] = 1 << 20;
    AppConfiguration small;
    BOOST_REQUIRE(small.Load(json));
    BOOST_TEST(small.mux.reliability.rtx.flow_bytes == (1 << 20));

    json["mux"]["reliability"]["rtx"]["flow_bytes"] = 0;
    AppConfiguration zero;
    BOOST_REQUIRE(zero.Load(json));
    BOOST_TEST(zero.mux.reliability.rtx.flow_bytes == (4 << 20)); // default 8 MiB, clamped to 4 MiB
}

BOOST_AUTO_TEST_CASE(absent_keys_keep_defaults_for_older_configs) {
    AppConfiguration defaults;
    Json::Value json = defaults.ToJson();
    json["mux"]["reliability"]["rtx"].removeMember("pto");
    json["mux"]["reliability"]["rtx"].removeMember("fast");

    AppConfiguration loaded;
    BOOST_REQUIRE(loaded.Load(json));
    BOOST_TEST(!loaded.mux.reliability.rtx.pto);
    BOOST_TEST(!loaded.mux.reliability.rtx.fast);
}
