#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/WindowsRoutePlatform.h>

#if defined(_WIN32)

namespace ppp::app::client::route {

std::unique_ptr<IRoutePlatform> RouteCoordinator::NewPlatform(
    const RoutePlanInput& input) noexcept {
    if (!input.underlying_interface.gateway.is_v4()) {
        return nullptr;
    }

    return std::make_unique<WindowsRoutePlatform>(
        input.tap_gateway,
        input.underlying_interface.index,
        input.underlying_interface.gateway.to_string());
}

}

#endif
