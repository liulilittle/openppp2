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

BOOST_AUTO_TEST_CASE(compat_server_honours_client_flow_v2_request) {
    // Field case: a flow+turbo client (caps = FLOW_V2 | REQUEST) against a compat
    // server must not be left on one global sequence space across its links.
    const auto server = mux::NegotiateMuxRuntimeState(
        "compat", true, true, 9, /*turbo=*/false,
        /*local_reliability=*/true, /*peer_reliability=*/true,
        /*local_fec=*/false, /*peer_fec=*/false,
        /*peer_requests_flow_v2=*/true);
    const auto client = mux::ApplyAgreedMuxRuntimeState(
        "flow", server.receiver_ordering == "flow_v2", 9, /*turbo=*/true,
        server.reliability, server.fec);

    BOOST_TEST(server.effective_mode == "compat"); // server scheduler preset unchanged
    BOOST_TEST(server.receiver_ordering == "flow_v2");
    BOOST_TEST(server.reliability);
    BOOST_TEST(client.effective_mode == "flow");
    BOOST_TEST(client.receiver_ordering == "flow_v2");
    BOOST_TEST(client.turbo);
}

BOOST_AUTO_TEST_CASE(flow_v2_request_alone_without_support_stays_compat) {
    // A request bit without the FLOW_V2 capability bit (malformed / partial
    // peer) must not upgrade ordering.
    const auto server = mux::NegotiateMuxRuntimeState(
        "compat", true, /*peer_supports_flow_v2=*/false, 2, false,
        false, false, false, false, /*peer_requests_flow_v2=*/true);

    BOOST_TEST(server.receiver_ordering == "compat");
    BOOST_TEST(server.effective_mode == "compat");
}

BOOST_AUTO_TEST_CASE(capability_without_request_keeps_compat_ordering) {
    // Old clients advertise FLOW_V2 as a capability only; behaviour is unchanged.
    const auto server = mux::NegotiateMuxRuntimeState("compat", true, true, 2);

    BOOST_TEST(server.receiver_ordering == "compat");
}

BOOST_AUTO_TEST_CASE(server_compat_result_downgrades_client_balance) {
    const auto server = mux::NegotiateMuxRuntimeState("compat", true, true, 2);
    const auto client = mux::ApplyAgreedMuxRuntimeState(
        "balance", server.receiver_ordering == "flow_v2", 2);

    BOOST_TEST(server.receiver_ordering == "compat");
    BOOST_TEST(client.effective_mode == "compat");
    BOOST_TEST(client.receiver_ordering == server.receiver_ordering);
}
