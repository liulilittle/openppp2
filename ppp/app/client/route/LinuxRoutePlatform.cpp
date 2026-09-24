#include <ppp/stdafx.h>
#include <ppp/app/client/route/LinuxRoutePlatform.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/net/native/rib.h>

#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
#include <linux/ppp/tap/TapLinux.h>
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                namespace {

                    class LinuxRouteSnapshot final : public IRouteSnapshot {
                    public:
                        explicit LinuxRouteSnapshot(RouteSpec route) noexcept
                            : route(std::move(route)) {
                        }

                        RouteSpec route;
                    };

                    std::shared_ptr<const LinuxRouteSnapshot> AsLinuxSnapshot(
                        const RouteSnapshotPtr& snapshot) noexcept {
                        return std::dynamic_pointer_cast<const LinuxRouteSnapshot>(snapshot);
                    }

                    bool SameRoute(const RouteSpec& left, const RouteSpec& right) noexcept {
                        return left.network == right.network &&
                            left.gateway == right.gateway &&
                            left.prefix == right.prefix &&
                            left.interface_name == right.interface_name;
                    }

                }

                static ppp::string ToPppString(const std::string& value) {
                    return ppp::string(value.begin(), value.end());
                }

                std::string SelectLinuxInterface(
                    uint32_t next_hop,
                    uint32_t tap_gateway,
                    const std::string& tap_interface,
                    const std::string& /*underlying_interface*/,
                    const std::unordered_map<uint32_t, std::string>& nics) noexcept {
                    if (next_hop == tap_gateway) {
                        return tap_interface;
                    }

                    auto tail = nics.find(next_hop);
                    if (tail != nics.end() && !tail->second.empty()) {
                        return tail->second;
                    }
                    return tap_interface;
                }

                LinuxRoutePlatform::LinuxRoutePlatform(
                    uint32_t tap_gateway,
                    std::string tap_interface,
                    std::string underlying_interface,
                    std::unordered_map<uint32_t, std::string> nics,
                    bool promiscuous) noexcept
                    : LinuxRoutePlatform(
                        tap_gateway,
                        std::move(tap_interface),
                        std::move(underlying_interface),
                        std::move(nics),
                        promiscuous,
                        CreateSystemOperations()) {
                }

                LinuxRoutePlatform::LinuxRoutePlatform(
                    uint32_t tap_gateway,
                    std::string tap_interface,
                    std::string underlying_interface,
                    std::unordered_map<uint32_t, std::string> nics,
                    bool promiscuous,
                    LinuxRouteOperations operations) noexcept
                    : tap_gateway_(tap_gateway),
                      tap_interface_(std::move(tap_interface)),
                      underlying_interface_(std::move(underlying_interface)),
                      nics_(std::move(nics)),
                      promiscuous_(promiscuous),
                      operations_(std::move(operations)) {
                }

                DefaultRouteCapture LinuxRoutePlatform::CaptureDefaults() noexcept {
                    std::vector<RouteSnapshotPtr> snapshots;
                    if (promiscuous_) {
                        return snapshots;
                    }
                    if (!operations_.capture_defaults) {
                        return std::nullopt;
                    }
                    RouteInformationTablePtr routes;
                    if (!operations_.capture_defaults(tap_gateway_, routes)) {
                        return std::nullopt;
                    }
                    for (RouteSpec route : BuildRouteSpecs(routes)) {
                        snapshots.emplace_back(
                            std::make_shared<LinuxRouteSnapshot>(Resolve(std::move(route))));
                    }
                    return snapshots;
                }

                bool LinuxRoutePlatform::RemoveDefault(
                    const RouteSnapshotPtr& route) noexcept {
                    if (promiscuous_) {
                        return true;
                    }
                    const auto snapshot = AsLinuxSnapshot(route);
                    return snapshot && operations_.remove &&
                        operations_.remove(snapshot->route);
                }

                RouteAddResult LinuxRoutePlatform::Add(const RouteSpec& route) noexcept {
                    return operations_.add
                        ? operations_.add(Resolve(route))
                        : RouteAddResult::Failed;
                }

                bool LinuxRoutePlatform::Delete(const RouteSpec& route) noexcept {
                    return operations_.remove && operations_.remove(Resolve(route));
                }

                bool LinuxRoutePlatform::RestoreDefault(
                    const RouteSnapshotPtr& route) noexcept {
                    if (promiscuous_) {
                        return true;
                    }
                    const auto snapshot = AsLinuxSnapshot(route);
                    if (!snapshot) {
                        return false;
                    }
                    const DefaultRouteCapture current_defaults = CaptureDefaults();
                    if (!current_defaults) {
                        return false;
                    }
                    for (const RouteSnapshotPtr& current : *current_defaults) {
                        if (SameDefault(route, current)) {
                            return true;
                        }
                    }
                    return operations_.add &&
                        operations_.add(snapshot->route) != RouteAddResult::Failed;
                }

                bool LinuxRoutePlatform::SameDefault(
                    const RouteSnapshotPtr& left,
                    const RouteSnapshotPtr& right) noexcept {
                    const auto left_snapshot = AsLinuxSnapshot(left);
                    const auto right_snapshot = AsLinuxSnapshot(right);
                    return left_snapshot && right_snapshot &&
                        SameRoute(left_snapshot->route, right_snapshot->route);
                }

                RouteSpec LinuxRoutePlatform::Resolve(RouteSpec route) const noexcept {
                    if (route.interface_name.empty()) {
                        route.interface_name = SelectLinuxInterface(
                            route.gateway,
                            tap_gateway_,
                            tap_interface_,
                            underlying_interface_,
                            nics_);
                    }
                    return route;
                }

                LinuxRouteOperations LinuxRoutePlatform::CreateSystemOperations() noexcept {
                    LinuxRouteOperations operations;
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    operations.capture_defaults = [](uint32_t gateway,
                        RouteInformationTablePtr& routes) noexcept {
                        return ppp::tap::TapLinux::TryFindAllDefaultGatewayRoutes(
                            { gateway }, routes);
                    };
                    operations.add = [](const RouteSpec& route) noexcept {
                        const ppp::tap::TapLinux::RouteMutationResult result =
                            ppp::tap::TapLinux::AddRouteStatus(
                            ToPppString(route.interface_name),
                            route.network,
                            route.prefix,
                            route.gateway);
                        if (result == ppp::tap::TapLinux::RouteMutationResult::Changed) {
                            return RouteAddResult::Created;
                        }
                        if (result == ppp::tap::TapLinux::RouteMutationResult::Unchanged) {
                            return RouteAddResult::Unchanged;
                        }
                        return RouteAddResult::Failed;
                    };
                    operations.remove = [](const RouteSpec& route) noexcept {
                        return ppp::tap::TapLinux::DeleteRoute(
                            ToPppString(route.interface_name),
                            route.network,
                            route.prefix,
                            route.gateway);
                    };
#endif
                    return operations;
                }

            }
        }
    }
}
