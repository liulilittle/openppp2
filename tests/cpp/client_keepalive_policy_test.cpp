#define BOOST_TEST_MODULE client_keepalive_policy_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/ClientKeepAlivePolicy.h>

using ppp::app::client::ClientKeepAliveAction;
using ppp::app::client::ClientKeepAlivePolicy;

static int Action(ClientKeepAliveAction value) noexcept {
    return static_cast<int>(value);
}

BOOST_AUTO_TEST_CASE(connected_session_sends_on_schedule_and_refreshes_on_input) {
    ClientKeepAlivePolicy policy;
    policy.OnConnected(100, 20);

    BOOST_TEST(Action(policy.Evaluate(119, false, true, false, 100)) ==
        Action(ClientKeepAliveAction::None));
    BOOST_TEST(Action(policy.Evaluate(120, false, true, false, 100)) ==
        Action(ClientKeepAliveAction::SendEcho));
    policy.OnEchoSent(120, 20);

    policy.OnPacket(150);
    BOOST_TEST(Action(policy.Evaluate(249, false, true, false, 100)) ==
        Action(ClientKeepAliveAction::SendEcho));
    BOOST_TEST(Action(policy.Evaluate(250, false, true, false, 100)) ==
        Action(ClientKeepAliveAction::CloseTransport));
}

BOOST_AUTO_TEST_CASE(stale_mobile_session_defers_while_child_links_are_active) {
    ClientKeepAlivePolicy policy;
    policy.OnConnected(100, 20);

    BOOST_TEST(Action(policy.Evaluate(200, false, true, true, 100)) ==
        Action(ClientKeepAliveAction::DeferForChildLinks));
    BOOST_TEST(Action(policy.Evaluate(299, false, true, false, 100)) ==
        Action(ClientKeepAliveAction::SendEcho));
    BOOST_TEST(Action(policy.Evaluate(300, false, true, false, 100)) ==
        Action(ClientKeepAliveAction::CloseTransport));
}

BOOST_AUTO_TEST_CASE(reset_and_disconnected_sessions_are_inert) {
    ClientKeepAlivePolicy policy;
    policy.OnConnected(10, 5);
    policy.Reset();

    BOOST_TEST(Action(policy.Evaluate(1000, false, false, false, 20)) ==
        Action(ClientKeepAliveAction::None));
}
