#include <ppp/stdafx.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>

#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#include <darwin/ppp/tun/utun.h>
#endif

namespace ppp::app::client::route {

#if defined(_MACOS)
namespace {

class DarwinRouteSnapshot final : public IRouteSnapshot {
public:
    explicit DarwinRouteSnapshot(RouteSpec route) noexcept
        : route(std::move(route)) {
    }

    RouteSpec route;
};

std::shared_ptr<const DarwinRouteSnapshot> AsDarwinSnapshot(
    const RouteSnapshotPtr& snapshot) noexcept {
    return std::dynamic_pointer_cast<const DarwinRouteSnapshot>(snapshot);
}

bool SameDarwinRoute(const RouteSpec& left, const RouteSpec& right) noexcept {
    return left.network == right.network &&
        left.gateway == right.gateway &&
        left.prefix == right.prefix;
}

bool SameDarwinConflictKey(const RouteSpec& left, const RouteSpec& right) noexcept {
    return left.network == right.network && left.prefix == right.prefix;
}

}
#endif

DarwinRoutePlatform::DarwinRoutePlatform(uint32_t tap_gateway, bool promiscuous) noexcept
    : DarwinRoutePlatform(CreateSystemOperations(tap_gateway, promiscuous)) {
}

DarwinRoutePlatform::DarwinRoutePlatform(DarwinRouteOperations operations) noexcept
    : operations_(std::move(operations)) {
}

DefaultRouteCapture DarwinRoutePlatform::CaptureDefaults() noexcept {
    return operations_.capture_defaults
        ? operations_.capture_defaults()
        : DefaultRouteCapture();
}

bool DarwinRoutePlatform::RemoveDefault(const RouteSnapshotPtr& route) noexcept {
    return operations_.remove_default && operations_.remove_default(route);
}

RouteAddResult DarwinRoutePlatform::Add(const RouteSpec& route) noexcept {
    const RouteAddResult result = operations_.add
        ? operations_.add(route)
        : RouteAddResult::Failed;
    if (result != RouteAddResult::Unchanged) {
        return result;
    }
    bool exists = false;
    return operations_.route_exists &&
        operations_.route_exists(route, exists) && exists
        ? RouteAddResult::Unchanged
        : RouteAddResult::Failed;
}

bool DarwinRoutePlatform::Delete(const RouteSpec& route) noexcept {
    return operations_.remove && operations_.remove(route);
}

bool DarwinRoutePlatform::RestoreDefault(const RouteSnapshotPtr& route) noexcept {
    if (pending_compensation_) {
        const PendingCompensation pending = *pending_compensation_;
        if (!Compensate(pending.target, pending.conflict)) {
            return false;
        }
    }

    if (!operations_.exact_default_exists &&
        !operations_.remove_conflicting_default) {
        return operations_.restore_default && operations_.restore_default(route);
    }

    bool exact_exists = false;
    if (!operations_.exact_default_exists ||
        !operations_.exact_default_exists(route, exact_exists)) {
        return false;
    }
    if (exact_exists) {
        return true;
    }

    RouteSnapshotPtr conflict;
    if (operations_.remove_conflicting_default &&
        !operations_.remove_conflicting_default(route, conflict)) {
        return false;
    }
    if (!operations_.restore_default || !operations_.restore_default(route)) {
        if (conflict) {
            Compensate(route, conflict);
        }
        return false;
    }

    exact_exists = false;
    if (!operations_.exact_default_exists(route, exact_exists) || !exact_exists) {
        if (conflict) {
            Compensate(route, conflict);
        }
        return false;
    }
    return true;
}

bool DarwinRoutePlatform::Compensate(
    const RouteSnapshotPtr& target,
    const RouteSnapshotPtr& conflict) noexcept {
    if (!target || !conflict) {
        return true;
    }
    pending_compensation_ = PendingCompensation{ target, conflict };
    if (!operations_.remove_default || !operations_.remove_default(target)) {
        return false;
    }
    if (!operations_.restore_default || !operations_.restore_default(conflict)) {
        return false;
    }
    pending_compensation_.reset();
    return true;
}

bool DarwinRoutePlatform::SameDefault(
    const RouteSnapshotPtr& left,
    const RouteSnapshotPtr& right) noexcept {
    return operations_.same_default
        ? operations_.same_default(left, right)
        : left == right;
}

DarwinRouteOperations DarwinRoutePlatform::CreateSystemOperations(
    uint32_t tap_gateway,
    bool promiscuous) noexcept {
    DarwinRouteOperations operations;
#if defined(_MACOS)
    operations.capture_defaults = [tap_gateway, promiscuous]() noexcept
        -> DefaultRouteCapture {
        std::vector<RouteSnapshotPtr> snapshots;
        if (promiscuous) {
            return snapshots;
        }
        std::shared_ptr<ppp::tap::TapDarwin::RouteInformationTable> routes;
        if (!ppp::tap::TapDarwin::TryFindAllDefaultGatewayRoutes(
            { tap_gateway }, routes)) {
            return std::nullopt;
        }
        for (const ppp::net::native::RouteEntry& route : *routes) {
            snapshots.emplace_back(std::make_shared<DarwinRouteSnapshot>(RouteSpec{
                route.Destination,
                route.NextHop,
                route.Prefix,
                {},
            }));
        }
        return snapshots;
    };
    operations.remove_default = [promiscuous](const RouteSnapshotPtr& value) noexcept {
        if (promiscuous) {
            return true;
        }
        auto snapshot = AsDarwinSnapshot(value);
        return snapshot &&
            ppp::darwin::tun::utun_del_route_status(
                snapshot->route.network,
                snapshot->route.prefix,
                snapshot->route.gateway) !=
            ppp::darwin::tun::RouteMutationResult::Failed;
    };
    operations.add = [](const RouteSpec& route) noexcept {
        const ppp::darwin::tun::RouteMutationResult result =
            ppp::darwin::tun::utun_add_route_status(
                route.network, route.prefix, route.gateway);
        if (result == ppp::darwin::tun::RouteMutationResult::Changed) {
            return RouteAddResult::Created;
        }
        if (result == ppp::darwin::tun::RouteMutationResult::Unchanged) {
            return RouteAddResult::Unchanged;
        }
        return RouteAddResult::Failed;
    };
    operations.route_exists = [](const RouteSpec& route, bool& exists) noexcept {
        return ppp::tap::TapDarwin::TryRouteExists(
            route.network, route.prefix, route.gateway, exists);
    };
    operations.remove = [](const RouteSpec& route) noexcept {
        return ppp::darwin::tun::utun_del_route_status(
            route.network, route.prefix, route.gateway) !=
            ppp::darwin::tun::RouteMutationResult::Failed;
    };
    operations.exact_default_exists = [promiscuous](
        const RouteSnapshotPtr& value, bool& exists) noexcept {
        exists = false;
        if (promiscuous) {
            exists = true;
            return true;
        }
        auto snapshot = AsDarwinSnapshot(value);
        if (!snapshot) {
            return false;
        }
        std::shared_ptr<ppp::tap::TapDarwin::RouteInformationTable> routes;
        if (!ppp::tap::TapDarwin::TryFindAllDefaultGatewayRoutes({}, routes)) {
            return false;
        }
        for (const ppp::net::native::RouteEntry& entry : *routes) {
            const RouteSpec route{
                entry.Destination, entry.NextHop, entry.Prefix, {}
            };
            if (SameDarwinRoute(route, snapshot->route)) {
                exists = true;
                break;
            }
        }
        return true;
    };
    operations.remove_conflicting_default = [promiscuous](
        const RouteSnapshotPtr& value, RouteSnapshotPtr& removed) noexcept {
        removed.reset();
        if (promiscuous) {
            return true;
        }
        auto snapshot = AsDarwinSnapshot(value);
        if (!snapshot) {
            return false;
        }
        std::shared_ptr<ppp::tap::TapDarwin::RouteInformationTable> routes;
        if (!ppp::tap::TapDarwin::TryFindAllDefaultGatewayRoutes({}, routes)) {
            return false;
        }
        for (const ppp::net::native::RouteEntry& entry : *routes) {
            const RouteSpec route{
                entry.Destination, entry.NextHop, entry.Prefix, {}
            };
            if (SameDarwinRoute(route, snapshot->route)) {
                return true;
            }
            if (!SameDarwinConflictKey(route, snapshot->route)) {
                continue;
            }
            RouteSnapshotPtr conflict =
                std::make_shared<DarwinRouteSnapshot>(route);
            const ppp::darwin::tun::RouteMutationResult result =
                ppp::darwin::tun::utun_del_route_status(
                    route.network, route.prefix, route.gateway);
            if (result == ppp::darwin::tun::RouteMutationResult::Failed) {
                return false;
            }
            if (result == ppp::darwin::tun::RouteMutationResult::Changed) {
                removed = std::move(conflict);
            }
            return true;
        }
        return true;
    };
    operations.restore_default = [promiscuous](const RouteSnapshotPtr& value) noexcept {
        if (promiscuous) {
            return true;
        }
        auto snapshot = AsDarwinSnapshot(value);
        return snapshot &&
            ppp::darwin::tun::utun_add_route_status(
                snapshot->route.network,
                snapshot->route.prefix,
                snapshot->route.gateway) !=
            ppp::darwin::tun::RouteMutationResult::Failed;
    };
    operations.same_default = [](const RouteSnapshotPtr& left,
        const RouteSnapshotPtr& right) noexcept {
        auto left_snapshot = AsDarwinSnapshot(left);
        auto right_snapshot = AsDarwinSnapshot(right);
        return left_snapshot && right_snapshot &&
            SameDarwinRoute(left_snapshot->route, right_snapshot->route);
    };
#else
    (void)tap_gateway;
    (void)promiscuous;
#endif
    return operations;
}

}
