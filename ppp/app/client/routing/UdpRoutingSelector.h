#pragma once

#include <ppp/app/client/routing/HumanRoutingRules.h>

namespace ppp::app::client::routing {

    enum class UdpRoutingPlatform {
        Android,
        UnsupportedDirect,
    };

    enum class UdpRoutingMode {
        Reject,
        DirectSocket,
        Tunnel,
    };

    struct UdpRoutingSelectorInput final {
        RoutingAction action = RoutingAction::Auto;
        UdpRoutingPlatform platform = UdpRoutingPlatform::UnsupportedDirect;
        bool legacy_bypass = false;
    };

    class UdpRoutingSelector final {
    public:
        static UdpRoutingMode Select(const UdpRoutingSelectorInput& input) noexcept;
    };

} // namespace ppp::app::client::routing
