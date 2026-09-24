#define BOOST_TEST_MODULE tcp_routing_selector_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/routing/TcpRoutingSelector.h>

namespace routing = ppp::app::client::routing;

namespace {

int ModeValue(routing::TcpRoutingMode mode) {
    return static_cast<int>(mode);
}

} // namespace

BOOST_AUTO_TEST_CASE(unresolved_fake_destination_is_rejected) {
    routing::TcpRoutingSelectorInput input;
    input.is_fake_ip = true;
    input.is_resolved = false;
    BOOST_TEST(ModeValue(routing::TcpRoutingSelector::Select(input)) ==
        ModeValue(routing::TcpRoutingMode::Reject));
}

BOOST_AUTO_TEST_CASE(direct_forces_direct_when_supported) {
    routing::TcpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Direct;
    BOOST_TEST(ModeValue(routing::TcpRoutingSelector::Select(input)) ==
        ModeValue(routing::TcpRoutingMode::ForceDirect));
}

BOOST_AUTO_TEST_CASE(direct_fails_closed_when_platform_has_no_direct_path) {
    routing::TcpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Direct;
    input.direct_supported = false;
    BOOST_TEST(ModeValue(routing::TcpRoutingSelector::Select(input)) ==
        ModeValue(routing::TcpRoutingMode::Reject));
}

BOOST_AUTO_TEST_CASE(proxy_skips_direct_path) {
    routing::TcpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Proxy;
    BOOST_TEST(ModeValue(routing::TcpRoutingSelector::Select(input)) ==
        ModeValue(routing::TcpRoutingMode::ForceProxy));
}

BOOST_AUTO_TEST_CASE(auto_preserves_legacy_selection) {
    routing::TcpRoutingSelectorInput input;
    input.action = routing::RoutingAction::Auto;
    BOOST_TEST(ModeValue(routing::TcpRoutingSelector::Select(input)) ==
        ModeValue(routing::TcpRoutingMode::LegacyAuto));
}
