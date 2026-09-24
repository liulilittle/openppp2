#define BOOST_TEST_MODULE udp_routing_selector_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/routing/UdpRoutingSelector.h>

namespace routing = ppp::app::client::routing;

namespace {

int ModeValue(routing::UdpRoutingMode mode) {
    return static_cast<int>(mode);
}

} // namespace

BOOST_AUTO_TEST_CASE(direct_uses_android_socket) {
    routing::UdpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Direct;
    input.platform = routing::UdpRoutingPlatform::Android;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::DirectSocket));
}

BOOST_AUTO_TEST_CASE(direct_fails_closed_without_platform_support) {
    routing::UdpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Direct;
    input.platform = routing::UdpRoutingPlatform::UnsupportedDirect;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::Reject));
}

BOOST_AUTO_TEST_CASE(proxy_always_uses_tunnel) {
    routing::UdpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Proxy;
    input.platform = routing::UdpRoutingPlatform::Android;
    input.legacy_bypass = true;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::Tunnel));
}

BOOST_AUTO_TEST_CASE(auto_preserves_android_legacy_bypass) {
    routing::UdpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Auto;
    input.platform = routing::UdpRoutingPlatform::Android;
    input.legacy_bypass = true;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::DirectSocket));
}

BOOST_AUTO_TEST_CASE(auto_uses_tunnel_without_android_bypass) {
    routing::UdpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Auto;
    input.platform = routing::UdpRoutingPlatform::Android;
    input.legacy_bypass = false;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::Tunnel));

    input.platform = routing::UdpRoutingPlatform::UnsupportedDirect;
    input.legacy_bypass = true;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::Tunnel));
}

BOOST_AUTO_TEST_CASE(udp_uses_preselected_ip_or_default_action) {
    routing::UdpRoutingSelectorInput input;
    input.platform = routing::UdpRoutingPlatform::Android;

    input.action = routing::RoutingAction::Direct;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::DirectSocket));

    input.action = routing::RoutingAction::Proxy;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::Tunnel));

    input.action = routing::RoutingAction::Auto;
    input.legacy_bypass = false;
    BOOST_TEST(ModeValue(routing::UdpRoutingSelector::Select(input)) ==
        ModeValue(routing::UdpRoutingMode::Tunnel));
}
