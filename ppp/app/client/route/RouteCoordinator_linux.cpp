#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/LinuxRoutePlatform.h>

#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)

namespace ppp::app::client::route {

std::unique_ptr<IRoutePlatform> RouteCoordinator::NewPlatform(
    const RoutePlanInput& input) noexcept {
    if (input.tap_interface.name.empty() ||
        input.underlying_interface.name.empty()) {
        return nullptr;
    }

    return std::make_unique<LinuxRoutePlatform>(
        input.tap_gateway,
        input.tap_interface.name,
        input.underlying_interface.name,
        input.nics,
        input.tap_promiscuous);
}

}

#endif
