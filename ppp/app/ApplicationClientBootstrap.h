#pragma once

/**
 * @file ApplicationClientBootstrap.h
 * @brief Client-mode TAP/switcher startup for PppApplication (PR2c).
 */

#include <memory>

namespace boost::asio {
class io_context;
}

namespace ppp {
namespace configurations {
class AppConfiguration;
}
namespace app {
struct NetworkInterface;
namespace client {
class VEthernetNetworkSwitcher;
}

/** Proxy-only startup must not enable the static transport. */
inline bool NormalizeClientStaticMode(bool requested_static_mode, bool proxy_only_runtime) noexcept {
    return requested_static_mode && !proxy_only_runtime;
}

/** CLI proxy mode and client.proxy-only both select proxy-only runtime. */
inline bool NormalizeClientProxyOnlyRuntime(bool proxy_mode, bool configured_proxy_only) noexcept {
    return proxy_mode || configured_proxy_only;
}

/** @brief Prepares client TAP, routes, and VEthernetNetworkSwitcher. */
bool PrepareClientLoopbackEnvironment(
    const std::shared_ptr<NetworkInterface>& network_interface,
    const std::shared_ptr<configurations::AppConfiguration>& configuration,
    const std::shared_ptr<boost::asio::io_context>& context,
    bool proxy_mode,
    std::shared_ptr<client::VEthernetNetworkSwitcher>& client_out) noexcept;

} // namespace app
} // namespace ppp
