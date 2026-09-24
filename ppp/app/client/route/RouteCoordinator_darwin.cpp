#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>

#if defined(_MACOS)

namespace ppp::app::client::route {

std::unique_ptr<IRoutePlatform> RouteCoordinator::NewPlatform(
    const RoutePlanInput& input) noexcept {
    if (input.tap_gateway == 0) {
        return nullptr;
    }

    return std::make_unique<DarwinRoutePlatform>(
        input.tap_gateway,
        input.tap_promiscuous);
}

}

#endif
