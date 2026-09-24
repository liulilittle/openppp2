#define BOOST_TEST_MODULE vmux_negotiation_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxRuntimeState.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(old_peer_falls_back_without_changing_requested_mode) {
    const auto state = mux::NegotiateMuxRuntimeState("balance", true, false, 2);

    BOOST_TEST(state.requested_mode == "balance");
    BOOST_TEST(state.effective_mode == "compat");
    BOOST_TEST(state.receiver_ordering == "compat");
    BOOST_TEST(state.scheduler == "competition");
    BOOST_TEST(state.pool_policy == "fixed");
    BOOST_TEST(state.active_links == 2u);
    BOOST_TEST(state.fallback_reason == "peer_missing_flow_v2");
}

BOOST_AUTO_TEST_CASE(flow_without_turbo_keeps_mode_and_compat_ordering) {
    // flow without turbo does not require flow_v2; capability alone must not upgrade ordering.
    const auto state = mux::NegotiateMuxRuntimeState("flow", true, true, 1, /*turbo=*/false);

    BOOST_TEST(state.effective_mode == "flow");
    BOOST_TEST(state.receiver_ordering == "compat");
    BOOST_TEST(state.scheduler == "competition");
    BOOST_TEST(state.pool_policy == "fixed");
    BOOST_TEST(!state.turbo);
    BOOST_TEST(state.fallback_reason.empty());
}

BOOST_AUTO_TEST_CASE(flow_with_turbo_uses_flow_v2_when_peer_supports) {
    const auto state = mux::NegotiateMuxRuntimeState("flow", true, true, 1, /*turbo=*/true);

    BOOST_TEST(state.effective_mode == "flow");
    BOOST_TEST(state.receiver_ordering == "flow_v2");
    BOOST_TEST(state.pool_policy == "adaptive");
    BOOST_TEST(state.turbo);
    BOOST_TEST(state.fallback_reason.empty());
}

BOOST_AUTO_TEST_CASE(flow_with_turbo_keeps_mode_when_peer_lacks_flow_v2) {
    const auto state = mux::NegotiateMuxRuntimeState("flow", true, false, 1, /*turbo=*/true);

    BOOST_TEST(state.effective_mode == "flow");
    BOOST_TEST(state.receiver_ordering == "compat");
    BOOST_TEST(state.fallback_reason == "peer_missing_flow_v2");
}

BOOST_AUTO_TEST_CASE(stripe_reports_round_robin_scheduler) {
    const auto state = mux::NegotiateMuxRuntimeState("stripe", true, true, 3);

    BOOST_TEST(state.effective_mode == "stripe");
    BOOST_TEST(state.scheduler == "round_robin");
    BOOST_TEST(state.receiver_ordering == "flow_v2");
}

BOOST_AUTO_TEST_CASE(server_agreed_ordering_is_authoritative_across_mode_mismatch) {
    const auto server = mux::NegotiateMuxRuntimeState("balance", true, true, 2);
    const auto client = mux::ApplyAgreedMuxRuntimeState(
        "compat", server.receiver_ordering == "flow_v2", 2);

    BOOST_TEST(server.receiver_ordering == "flow_v2");
    BOOST_TEST(client.effective_mode == "compat");
    BOOST_TEST(client.receiver_ordering == server.receiver_ordering);
}

BOOST_AUTO_TEST_CASE(server_compat_result_downgrades_client_balance) {
    const auto server = mux::NegotiateMuxRuntimeState("compat", true, true, 2);
    const auto client = mux::ApplyAgreedMuxRuntimeState(
        "balance", server.receiver_ordering == "flow_v2", 2);

    BOOST_TEST(server.receiver_ordering == "compat");
    BOOST_TEST(client.effective_mode == "compat");
    BOOST_TEST(client.receiver_ordering == server.receiver_ordering);
}
