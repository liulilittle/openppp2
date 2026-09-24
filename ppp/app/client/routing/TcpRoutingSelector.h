#pragma once

#include <ppp/app/client/routing/HumanRoutingRules.h>

namespace ppp::app::client::routing {

    enum class TcpRoutingMode {
        Reject,
        ForceDirect,
        ForceProxy,
        LegacyAuto,
    };

    struct TcpRoutingSelectorInput final {
        RoutingAction action = RoutingAction::Auto;
        bool is_fake_ip = false;
        bool is_resolved = true;
        bool direct_supported = true;
    };

    class TcpRoutingSelector final {
    public:
        static TcpRoutingMode Select(const TcpRoutingSelectorInput& input) noexcept;
    };

} // namespace ppp::app::client::routing
