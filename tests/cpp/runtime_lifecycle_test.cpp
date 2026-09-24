#define BOOST_TEST_MODULE runtime_lifecycle_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeLifecycle.h>
#include <ppp/app/mux/MuxRuntimeState.h>

using ppp::app::runtime::RuntimeError;
using ppp::app::runtime::RuntimeLifecycle;
using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeReadiness;
using ppp::app::runtime::RuntimeSnapshot;
using ppp::app::runtime::RuntimeTraffic;

namespace {

RuntimeReadiness FullyReady() {
    RuntimeReadiness value;
    value.session = true;
    value.adapter = true;
    value.route = true;
    value.dns = true;
    value.policy = true;
    return value;
}

}

BOOST_AUTO_TEST_CASE(generations_are_monotonic_and_begin_at_starting) {
    RuntimeLifecycle lifecycle;
    RuntimeSnapshot seed;
    seed.role = "client";

    BOOST_TEST(lifecycle.Begin(seed, 10) == 1u);
    BOOST_TEST(lifecycle.GetSnapshot().generation == 1u);
    BOOST_TEST(lifecycle.GetSnapshot().monotonic_ms == 10u);
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Starting));
    BOOST_TEST(lifecycle.GetSnapshot().role == "client");

    BOOST_TEST(lifecycle.Begin(seed, 1) == 2u);
    BOOST_TEST(lifecycle.GetSnapshot().generation == 2u);
    BOOST_TEST(lifecycle.GetSnapshot().monotonic_ms > 10u);
}

BOOST_AUTO_TEST_CASE(connected_is_promoted_only_after_all_readiness_facts) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);

    BOOST_TEST(lifecycle.Transition(generation, RuntimePhase::Connected, 2));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::ApplyingPolicy));

    BOOST_TEST(lifecycle.UpdateReadiness(generation, FullyReady(), 3));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Connected));

    RuntimeReadiness lost = FullyReady();
    lost.route = false;
    BOOST_TEST(lifecycle.UpdateReadiness(generation, lost, 4));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::ApplyingPolicy));
}

BOOST_AUTO_TEST_CASE(stale_generation_cannot_publish_or_stop_current_session) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t old_generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 2);

    BOOST_TEST(!lifecycle.Transition(old_generation, RuntimePhase::Connected, 3));
    BOOST_TEST(!lifecycle.TryBeginStop(old_generation, 4));
    BOOST_TEST(lifecycle.TryBeginStop(generation, 5));
    BOOST_TEST(!lifecycle.TryBeginStop(generation, 6));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Stopping));
}

BOOST_AUTO_TEST_CASE(stop_completion_publishes_idle_or_failed) {
    RuntimeLifecycle lifecycle;
    std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    BOOST_REQUIRE(lifecycle.TryBeginStop(generation, 2));
    BOOST_TEST(lifecycle.CompleteStop(generation, true, RuntimeError(), 3));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Idle));

    generation = lifecycle.Begin(RuntimeSnapshot(), 4);
    BOOST_REQUIRE(lifecycle.TryBeginStop(generation, 5));
    RuntimeError error;
    error.code = 91;
    error.severity = "error";
    error.user_message_key = "CleanupFailed";
    BOOST_TEST(lifecycle.CompleteStop(generation, false, error, 6));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Failed));
    BOOST_TEST(lifecycle.GetSnapshot().last_error.code == 91u);
}

BOOST_AUTO_TEST_CASE(stop_completion_clears_active_mux_links) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    ppp::app::mux::MuxRuntimeState state;
    state.requested_mode = "flow";
    state.effective_mode = "flow";
    state.receiver_ordering = "flow_v2";
    state.active_links = 3;
    BOOST_REQUIRE(lifecycle.UpdateMuxState(generation, state, 2));
    BOOST_REQUIRE(lifecycle.TryBeginStop(generation, 3));
    BOOST_REQUIRE(lifecycle.CompleteStop(generation, true, RuntimeError(), 4));
    BOOST_TEST(lifecycle.GetSnapshot().mux_active_links == 0u);
}

BOOST_AUTO_TEST_CASE(stopping_or_completed_generation_cannot_be_revived) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    BOOST_REQUIRE(lifecycle.TryBeginStop(generation, 2));
    BOOST_TEST(!lifecycle.Transition(generation, RuntimePhase::Connected, 3));
    BOOST_TEST(!lifecycle.UpdateReadiness(generation, FullyReady(), 4));
    BOOST_REQUIRE(lifecycle.CompleteStop(generation, true, RuntimeError(), 5));
    BOOST_TEST(!lifecycle.Transition(generation, RuntimePhase::Connected, 6));
    BOOST_TEST(!lifecycle.UpdateReadiness(generation, FullyReady(), 7));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Idle));
}

BOOST_AUTO_TEST_CASE(mux_state_publishes_only_when_current_generation_changes) {
    RuntimeLifecycle lifecycle;
    std::size_t publications = 0;
    const std::uint64_t subscription = lifecycle.Subscribe(
        [&publications](const RuntimeSnapshot&) { ++publications; });
    BOOST_REQUIRE_NE(subscription, 0u);

    const std::uint64_t old_generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 2);
    ppp::app::mux::MuxRuntimeState state;
    state.requested_mode = "balance";
    state.effective_mode = "compat";
    state.receiver_ordering = "compat";
    state.active_links = 2;
    state.fallback_reason = "peer_missing_flow_v2";

    BOOST_TEST(!lifecycle.UpdateMuxState(old_generation, state, 3));
    BOOST_TEST(publications == 2u);
    BOOST_REQUIRE(lifecycle.UpdateMuxState(generation, state, 4));
    BOOST_TEST(publications == 3u);
    BOOST_REQUIRE(lifecycle.UpdateMuxState(generation, state, 5));
    BOOST_TEST(publications == 3u);

    const RuntimeSnapshot snapshot = lifecycle.GetSnapshot();
    BOOST_TEST(snapshot.requested_mux_mode == "balance");
    BOOST_TEST(snapshot.effective_mux_mode == "compat");
    BOOST_TEST(snapshot.mux_receiver_ordering == "compat");
    BOOST_TEST(snapshot.mux_active_links == 2u);
    BOOST_TEST(snapshot.mux_fallback_reason == "peer_missing_flow_v2");
    lifecycle.Unsubscribe(subscription);
}

BOOST_AUTO_TEST_CASE(p2p_state_publishes_only_for_the_live_generation) {
    RuntimeLifecycle lifecycle;
    std::size_t publications = 0;
    const std::uint64_t subscription = lifecycle.Subscribe(
        [&publications](const RuntimeSnapshot&) { ++publications; });
    BOOST_REQUIRE_NE(subscription, 0u);

    const std::uint64_t old_generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 2);
    BOOST_TEST(!lifecycle.UpdateP2PState(
        old_generation, ppp::p2p::P2PState::Eligible, 3));
    BOOST_TEST(publications == 2u);
    BOOST_REQUIRE(lifecycle.UpdateP2PState(
        generation, ppp::p2p::P2PState::Eligible, 4));
    BOOST_TEST(publications == 3u);
    BOOST_REQUIRE(lifecycle.UpdateP2PState(
        generation, ppp::p2p::P2PState::Eligible, 5));
    BOOST_TEST(publications == 3u);
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().p2p_state) ==
        static_cast<int>(ppp::p2p::P2PState::Eligible));

    BOOST_REQUIRE(lifecycle.TryBeginStop(generation, 6));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().p2p_state) ==
        static_cast<int>(ppp::p2p::P2PState::FallingBack));
    BOOST_TEST(std::string(ppp::p2p::EffectivePath(
        lifecycle.GetSnapshot().p2p_state)) == "relay");
    BOOST_TEST(!lifecycle.UpdateP2PState(
        generation, ppp::p2p::P2PState::Direct, 7));
    BOOST_REQUIRE(lifecycle.CompleteStop(
        generation, true, RuntimeError(), 8));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().p2p_state) ==
        static_cast<int>(ppp::p2p::P2PState::Disabled));
    BOOST_TEST(std::string(ppp::p2p::EffectivePath(
        lifecycle.GetSnapshot().p2p_state)) == "relay");
    lifecycle.Unsubscribe(subscription);
}

BOOST_AUTO_TEST_CASE(traffic_publishes_only_when_totals_change) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);

    RuntimeTraffic traffic;
    traffic.rx_bytes = 1024;
    traffic.tx_bytes = 512;
    BOOST_TEST(lifecycle.UpdateTraffic(generation, traffic, 2));
    BOOST_TEST(lifecycle.GetSnapshot().traffic.rx_bytes == 1024u);
    BOOST_TEST(lifecycle.GetSnapshot().traffic.tx_bytes == 512u);

    const std::uint64_t published = lifecycle.GetSnapshot().monotonic_ms;
    BOOST_TEST(lifecycle.UpdateTraffic(generation, traffic, 3));
    BOOST_TEST(lifecycle.GetSnapshot().monotonic_ms == published);

    BOOST_TEST(!lifecycle.UpdateTraffic(generation + 1, traffic, 4));
}

BOOST_AUTO_TEST_CASE(connected_time_is_stamped_once_and_cleared_on_leaving) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    BOOST_TEST(lifecycle.GetSnapshot().connected_monotonic_ms == 0u);

    BOOST_TEST(lifecycle.Transition(generation, RuntimePhase::Connected, 2));
    BOOST_TEST(lifecycle.GetSnapshot().connected_monotonic_ms == 0u);

    BOOST_TEST(lifecycle.UpdateReadiness(generation, FullyReady(), 3));
    const std::uint64_t connected_at = lifecycle.GetSnapshot().connected_monotonic_ms;
    BOOST_TEST(connected_at != 0u);
    BOOST_TEST(connected_at == lifecycle.GetSnapshot().monotonic_ms);

    RuntimeTraffic traffic;
    traffic.rx_bytes = 1;
    BOOST_TEST(lifecycle.UpdateTraffic(generation, traffic, 4));
    BOOST_TEST(lifecycle.GetSnapshot().connected_monotonic_ms == connected_at);

    BOOST_TEST(lifecycle.Transition(generation, RuntimePhase::Reconnecting, 5));
    BOOST_TEST(lifecycle.GetSnapshot().connected_monotonic_ms == 0u);
}

BOOST_AUTO_TEST_CASE(one_hundred_generations_cancel_from_every_startup_phase) {
    const RuntimePhase phases[] = {
        RuntimePhase::Starting,
        RuntimePhase::PreparingHost,
        RuntimePhase::Connecting,
        RuntimePhase::Handshaking,
        RuntimePhase::ApplyingPolicy,
        RuntimePhase::Reconnecting,
    };

    RuntimeLifecycle lifecycle;
    std::uint64_t now = 1;
    for (std::uint64_t cycle = 1; cycle <= 100; ++cycle) {
        const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), now++);
        BOOST_REQUIRE_EQUAL(generation, cycle);
        const RuntimePhase phase = phases[(cycle - 1) % (sizeof(phases) / sizeof(phases[0]))];
        BOOST_REQUIRE(lifecycle.Transition(generation, phase, now++));
        BOOST_REQUIRE(lifecycle.TryBeginStop(generation, now++));
        BOOST_TEST(!lifecycle.TryBeginStop(generation, now++));
        BOOST_REQUIRE(lifecycle.CompleteStop(generation, true, RuntimeError(), now++));
        BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
                   static_cast<int>(RuntimePhase::Idle));
    }
}
