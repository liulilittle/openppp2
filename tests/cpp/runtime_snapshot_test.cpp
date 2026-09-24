#define BOOST_TEST_MODULE runtime_snapshot_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeSnapshotJson.h>

#include <fstream>
#include <iterator>
#include <string>

#ifndef OPENPPP2_RUNTIME_FIXTURE_DIR
#define OPENPPP2_RUNTIME_FIXTURE_DIR "tests/contracts/runtime-snapshot"
#endif

namespace runtime = ppp::app::runtime;

namespace {

std::string ReadFixture(const char* name) {
    const std::string path = std::string(OPENPPP2_RUNTIME_FIXTURE_DIR) + "/" + name;
    std::ifstream input(path, std::ios::binary);
    BOOST_REQUIRE_MESSAGE(input.good(), "unable to open runtime fixture: " << path);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

}

BOOST_AUTO_TEST_CASE(runtime_phase_round_trip) {
    BOOST_TEST(std::string(runtime::ToString(runtime::RuntimePhase::Connected)) == "connected");
    BOOST_TEST(
        static_cast<int>(runtime::ParseRuntimePhase("reconnecting")) ==
        static_cast<int>(runtime::RuntimePhase::Reconnecting));
}

BOOST_AUTO_TEST_CASE(p2p_state_mapping_is_stable_and_fail_closed) {
    using ppp::p2p::P2PState;

    const struct {
        P2PState state;
        const char* name;
        const char* path;
    } cases[] = {
        {P2PState::Disabled, "disabled", "relay"},
        {P2PState::Unavailable, "unavailable", "relay"},
        {P2PState::Relay, "relay", "relay"},
        {P2PState::Eligible, "eligible", "relay"},
        {P2PState::Probing, "probing", "relay"},
        {P2PState::Direct, "direct", "direct"},
        {P2PState::Suspect, "suspect", "relay"},
        {P2PState::FallingBack, "falling_back", "relay"},
        {P2PState::Failed, "failed", "relay"},
    };

    for (const auto& item : cases) {
        BOOST_TEST(std::string(ppp::p2p::ToString(item.state)) == item.name);
        BOOST_TEST(
            static_cast<int>(ppp::p2p::ParseP2PState(item.name)) ==
            static_cast<int>(item.state));
        BOOST_TEST(std::string(ppp::p2p::EffectivePath(item.state)) == item.path);
    }
    BOOST_TEST(
        static_cast<int>(ppp::p2p::ParseP2PState("future_state")) ==
        static_cast<int>(P2PState::Unavailable));
}

BOOST_AUTO_TEST_CASE(default_snapshot_is_idle_and_versioned) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(snapshot.schema_version == 1u);
    BOOST_TEST(snapshot.generation == 0u);
    BOOST_TEST(static_cast<int>(snapshot.phase) == static_cast<int>(runtime::RuntimePhase::Idle));
}

BOOST_AUTO_TEST_CASE(snapshot_json_preserves_generation_phase_and_error) {
    runtime::RuntimeSnapshot source;
    source.generation = 7;
    source.phase = runtime::RuntimePhase::Connected;
    source.requested_mux_mode = "balance";
    source.effective_mux_mode = "compat";
    source.mux_receiver_ordering = "compat";
    source.mux_active_links = 2;
    source.capabilities = {"mux.compat", "mux.flow", "mux.balance"};
    source.last_error.code = 42;
    source.last_error.retryable = true;

    const std::string json = runtime::SerializeRuntimeSnapshot(source);
    runtime::RuntimeSnapshot decoded;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(json, decoded));
    BOOST_TEST(decoded.generation == 7u);
    BOOST_TEST(static_cast<int>(decoded.phase) == static_cast<int>(runtime::RuntimePhase::Connected));
    BOOST_TEST(decoded.requested_mux_mode == "balance");
    BOOST_TEST(decoded.effective_mux_mode == "compat");
    BOOST_TEST(decoded.mux_receiver_ordering == "compat");
    BOOST_TEST(decoded.mux_active_links == 2u);
    BOOST_TEST(decoded.capabilities.size() == 3u);
    BOOST_TEST(decoded.capabilities[1] == "mux.flow");
    BOOST_TEST(decoded.last_error.code == 42u);
    BOOST_TEST(decoded.last_error.retryable);
}

BOOST_AUTO_TEST_CASE(snapshot_json_derives_effective_path_from_typed_p2p_state) {
    runtime::RuntimeSnapshot snapshot;
    snapshot.generation = 8;
    snapshot.phase = runtime::RuntimePhase::Connected;
    snapshot.p2p_state = ppp::p2p::P2PState::Probing;

    const std::string probing = runtime::SerializeRuntimeSnapshot(snapshot);
    BOOST_TEST(probing.find("\"p2p_state\":\"probing\"") != std::string::npos);
    BOOST_TEST(probing.find("\"effective_path\":\"relay\"") != std::string::npos);

    snapshot.p2p_state = ppp::p2p::P2PState::Direct;
    const std::string direct = runtime::SerializeRuntimeSnapshot(snapshot);
    BOOST_TEST(direct.find("\"effective_path\":\"direct\"") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(unknown_p2p_state_parses_fail_closed_and_ignores_claimed_direct_path) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"generation\":1,\"monotonic_ms\":1,"
        "\"phase\":\"connected\",\"p2p_state\":\"future_state\","
        "\"effective_path\":\"direct\"}",
        snapshot));
    BOOST_TEST(
        static_cast<int>(snapshot.p2p_state) ==
        static_cast<int>(ppp::p2p::P2PState::Unavailable));
    BOOST_TEST(std::string(ppp::p2p::EffectivePath(snapshot.p2p_state)) == "relay");
}

BOOST_AUTO_TEST_CASE(missing_optional_p2p_state_defaults_to_disabled_relay) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"generation\":1,\"monotonic_ms\":1,"
        "\"phase\":\"connected\"}",
        snapshot));
    BOOST_TEST(
        static_cast<int>(snapshot.p2p_state) ==
        static_cast<int>(ppp::p2p::P2PState::Disabled));
    BOOST_TEST(std::string(ppp::p2p::EffectivePath(snapshot.p2p_state)) == "relay");
}

BOOST_AUTO_TEST_CASE(p2p_failure_does_not_change_connected_runtime_phase) {
    runtime::RuntimeSnapshot snapshot;
    snapshot.phase = runtime::RuntimePhase::Connected;
    snapshot.p2p_state = ppp::p2p::P2PState::Failed;

    runtime::RuntimeSnapshot decoded;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(
        runtime::SerializeRuntimeSnapshot(snapshot), decoded));
    BOOST_TEST(
        static_cast<int>(decoded.phase) ==
        static_cast<int>(runtime::RuntimePhase::Connected));
    BOOST_TEST(std::string(ppp::p2p::EffectivePath(decoded.p2p_state)) == "relay");
}

BOOST_AUTO_TEST_CASE(valid_contract_fixtures_parse) {
    const char* fixtures[] = {
        "idle.json",
        "connected.json",
        "reconnecting.json",
        "failed.json",
    };

    for (const char* fixture : fixtures) {
        runtime::RuntimeSnapshot snapshot;
        BOOST_TEST_CONTEXT(fixture) {
            BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture(fixture), snapshot));
            BOOST_TEST(snapshot.schema_version == runtime::RuntimeSnapshot::SchemaVersion);
        }
    }
}

BOOST_AUTO_TEST_CASE(unsupported_schema_is_rejected) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(ReadFixture("unsupported-schema.json"), snapshot));
}

BOOST_AUTO_TEST_CASE(parsed_snapshot_records_schema_version) {
    runtime::RuntimeSnapshot snapshot;
    snapshot.schema_version = 0;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture("idle.json"), snapshot));
    BOOST_TEST(snapshot.schema_version == 1u);
}

BOOST_AUTO_TEST_CASE(unknown_optional_fields_are_ignored) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture("connected.json"), snapshot));
    BOOST_TEST(snapshot.generation == 7u);
    BOOST_TEST(snapshot.effective_mux_mode == "flow");
    BOOST_TEST(snapshot.capabilities.size() == 4u);
    BOOST_TEST(snapshot.capabilities[3] == "mux.stripe");
}

BOOST_AUTO_TEST_CASE(traffic_and_connect_time_round_trip) {
    runtime::RuntimeSnapshot snapshot;
    snapshot.generation = 3;
    snapshot.monotonic_ms = 900;
    snapshot.phase = runtime::RuntimePhase::Connected;
    snapshot.traffic.rx_bytes = 4096;
    snapshot.traffic.tx_bytes = 1024;
    snapshot.connected_monotonic_ms = 500;

    runtime::RuntimeSnapshot parsed;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(
        runtime::SerializeRuntimeSnapshot(snapshot), parsed));
    BOOST_TEST(parsed.traffic.rx_bytes == 4096u);
    BOOST_TEST(parsed.traffic.tx_bytes == 1024u);
    BOOST_TEST(parsed.connected_monotonic_ms == 500u);
}

BOOST_AUTO_TEST_CASE(connected_fixture_carries_traffic_and_connect_time) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture("connected.json"), snapshot));
    BOOST_TEST(snapshot.traffic.rx_bytes == 10485760u);
    BOOST_TEST(snapshot.traffic.tx_bytes == 2097152u);
    BOOST_TEST(snapshot.connected_monotonic_ms == 30000u);
}

BOOST_AUTO_TEST_CASE(absent_traffic_and_connect_time_default_to_zero) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture("idle.json"), snapshot));
    BOOST_TEST(snapshot.traffic.rx_bytes == 0u);
    BOOST_TEST(snapshot.traffic.tx_bytes == 0u);
    BOOST_TEST(snapshot.connected_monotonic_ms == 0u);
}

BOOST_AUTO_TEST_CASE(unknown_phase_is_rejected) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"generation\":1,\"monotonic_ms\":1,\"phase\":\"teleporting\"}",
        snapshot));
}

BOOST_AUTO_TEST_CASE(generation_and_monotonic_time_are_required) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"monotonic_ms\":1,\"phase\":\"idle\"}",
        snapshot));
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"generation\":1,\"phase\":\"idle\"}",
        snapshot));
}
