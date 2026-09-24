#define BOOST_TEST_MODULE vmux_runtime_state_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxRuntimeState.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(flow_v2_negotiation_reports_effective_ordering) {
    const auto state = mux::NegotiateMuxRuntimeState("balance", true, true, 3);

    BOOST_TEST(state.requested_mode == "balance");
    BOOST_TEST(state.effective_mode == "balance");
    BOOST_TEST(state.receiver_ordering == "flow_v2");
    BOOST_TEST(state.scheduler == "competition");
    BOOST_TEST(state.pool_policy == "fixed");
    BOOST_TEST(state.active_links == 3u);
    BOOST_TEST(state.fallback_reason.empty());
}

BOOST_AUTO_TEST_CASE(balance_falls_back_for_old_peer) {
    const auto state = mux::NegotiateMuxRuntimeState("balance", true, false, 1);

    BOOST_TEST(state.requested_mode == "balance");
    BOOST_TEST(state.effective_mode == "compat");
    BOOST_TEST(state.receiver_ordering == "compat");
    BOOST_TEST(state.fallback_reason == "peer_missing_flow_v2");
}

BOOST_AUTO_TEST_CASE(active_link_requires_completed_handshake_and_not_retiring) {
    BOOST_TEST(!mux::IsMuxLinkActive(false, false));
    BOOST_TEST(mux::IsMuxLinkActive(true, false));
    BOOST_TEST(!mux::IsMuxLinkActive(true, true));
}

BOOST_AUTO_TEST_CASE(presentation_helpers_map_presets) {
    BOOST_TEST(std::string(mux::MuxSchedulerName("stripe")) == "round_robin");
    BOOST_TEST(std::string(mux::MuxSchedulerName("balance")) == "competition");
    BOOST_TEST(std::string(mux::MuxPoolPolicyName("flow", true)) == "adaptive");
    BOOST_TEST(std::string(mux::MuxPoolPolicyName("flow", false)) == "fixed");
}
