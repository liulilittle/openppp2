#include "TcpRoutingSelector.h"

namespace ppp::app::client::routing {

    TcpRoutingMode TcpRoutingSelector::Select(
        const TcpRoutingSelectorInput& input) noexcept {
        if (input.is_fake_ip && !input.is_resolved) {
            return TcpRoutingMode::Reject;
        }

        switch (input.action) {
        case RoutingAction::Direct:
            return input.direct_supported
                ? TcpRoutingMode::ForceDirect
                : TcpRoutingMode::Reject;
        case RoutingAction::Proxy:
            return TcpRoutingMode::ForceProxy;
        default:
            return TcpRoutingMode::LegacyAuto;
        }
    }

} // namespace ppp::app::client::routing
