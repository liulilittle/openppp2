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

    // Default-route setup precedes loading optional bypass files. Seed the
    // physical gateway mapping now, so captured defaults and server bypass
    // routes cannot fall back to the TAP before those files are loaded.
    auto nics = input.nics;
    if (input.underlying_interface.gateway.is_v4()) {
        nics.emplace(htonl(input.underlying_interface.gateway.to_v4().to_uint()),
            input.underlying_interface.name);
    }
    return std::make_unique<LinuxRoutePlatform>(
        input.tap_gateway,
        input.tap_interface.name,
        input.underlying_interface.name,
        std::move(nics),
        input.tap_promiscuous);
}

}

#endif
