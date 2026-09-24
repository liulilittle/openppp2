#include "UdpRoutingSelector.h"

namespace ppp::app::client::routing {

    UdpRoutingMode UdpRoutingSelector::Select(
        const UdpRoutingSelectorInput& input) noexcept {
        switch (input.action) {
        case RoutingAction::Direct:
            return input.platform == UdpRoutingPlatform::Android
                ? UdpRoutingMode::DirectSocket
                : UdpRoutingMode::Reject;
        case RoutingAction::Proxy:
            return UdpRoutingMode::Tunnel;
        default:
            return input.platform == UdpRoutingPlatform::Android && input.legacy_bypass
                ? UdpRoutingMode::DirectSocket
                : UdpRoutingMode::Tunnel;
        }
    }

} // namespace ppp::app::client::routing
