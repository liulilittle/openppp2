#include <ppp/stdafx.h>
#include <ppp/app/client/route/WindowsRoutePlatform.h>

#if defined(_WIN32)
#include <ppp/net/IPEndPoint.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/win32/network/Router.h>
#endif

namespace ppp::app::client::route {

bool SameWindowsRouteIdentity(
    const WindowsRouteIdentity& left,
    const WindowsRouteIdentity& right) noexcept {
    return left.destination == right.destination &&
        left.mask == right.mask &&
        left.next_hop == right.next_hop &&
        left.interface_index == right.interface_index &&
        left.policy == right.policy;
}

#if defined(_WIN32)
namespace {

class WindowsRouteSnapshot final : public IRouteSnapshot {
public:
    explicit WindowsRouteSnapshot(const MIB_IPFORWARDROW& route) noexcept
        : route(route) {
    }

    MIB_IPFORWARDROW route;
};

class WindowsGatewaySnapshot final : public IRouteSnapshot {
public:
    WindowsGatewaySnapshot(int interface_index, std::string gateway) noexcept
        : interface_index(interface_index), gateway(std::move(gateway)) {
    }

    int interface_index;
    std::string gateway;
};

std::shared_ptr<const WindowsRouteSnapshot> AsWindowsRouteSnapshot(
    const RouteSnapshotPtr& snapshot) noexcept {
    return std::dynamic_pointer_cast<const WindowsRouteSnapshot>(snapshot);
}

std::shared_ptr<const WindowsGatewaySnapshot> AsWindowsGatewaySnapshot(
    const RouteSnapshotPtr& snapshot) noexcept {
    return std::dynamic_pointer_cast<const WindowsGatewaySnapshot>(snapshot);
}

bool SameWindowsRouteIdentity(
    const MIB_IPFORWARDROW& left,
    const MIB_IPFORWARDROW& right) noexcept {
    const WindowsRouteIdentity left_identity{
        left.dwForwardDest,
        left.dwForwardMask,
        left.dwForwardNextHop,
        left.dwForwardIfIndex,
        left.dwForwardPolicy,
    };
    const WindowsRouteIdentity right_identity{
        right.dwForwardDest,
        right.dwForwardMask,
        right.dwForwardNextHop,
        right.dwForwardIfIndex,
        right.dwForwardPolicy,
    };
    return ppp::app::client::route::SameWindowsRouteIdentity(
        left_identity, right_identity);
}

bool SameRestoredWindowsRoute(
    const MIB_IPFORWARDROW& left,
    const MIB_IPFORWARDROW& right) noexcept {
    return SameWindowsRouteIdentity(left, right) &&
        left.dwForwardPolicy == right.dwForwardPolicy &&
        left.dwForwardType == right.dwForwardType &&
        left.dwForwardProto == right.dwForwardProto &&
        left.dwForwardNextHopAS == right.dwForwardNextHopAS &&
        left.dwForwardMetric1 == right.dwForwardMetric1 &&
        left.dwForwardMetric2 == right.dwForwardMetric2 &&
        left.dwForwardMetric3 == right.dwForwardMetric3 &&
        left.dwForwardMetric4 == right.dwForwardMetric4 &&
        left.dwForwardMetric5 == right.dwForwardMetric5;
}

bool TryFindRestoredWindowsRoute(
    const MIB_IPFORWARDROW& route,
    bool& exists) noexcept {
    exists = false;
    auto mib = ppp::win32::network::Router::GetIpForwardTable();
    if (!mib) {
        return false;
    }
    for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
        if (SameRestoredWindowsRoute(mib->table[i], route)) {
            exists = true;
            break;
        }
    }
    return true;
}

bool TryFindWindowsRouteIdentity(
    const MIB_IPFORWARDROW& route,
    bool& exists) noexcept {
    exists = false;
    auto mib = ppp::win32::network::Router::GetIpForwardTable();
    if (!mib) {
        return false;
    }
    for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
        if (SameWindowsRouteIdentity(mib->table[i], route)) {
            exists = true;
            break;
        }
    }
    return true;
}

bool SameWindowsRouteSpec(
    const MIB_IPFORWARDROW& row,
    const RouteSpec& route) noexcept {
    return row.dwForwardDest == route.network &&
        row.dwForwardMask == ppp::net::IPEndPoint::PrefixToNetmask(route.prefix) &&
        row.dwForwardNextHop == route.gateway;
}

bool TryFindWindowsRouteSpec(
    const RouteSpec& route,
    MIB_IPFORWARDROW& found,
    bool& exists) noexcept {
    exists = false;
    auto mib = ppp::win32::network::Router::GetIpForwardTable();
    if (!mib) {
        return false;
    }
    for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
        if (SameWindowsRouteSpec(mib->table[i], route)) {
            found = mib->table[i];
            exists = true;
            break;
        }
    }
    return true;
}

}
#endif

WindowsRoutePlatform::WindowsRoutePlatform(
    uint32_t tap_gateway,
    int underlying_interface_index,
    std::string underlying_gateway) noexcept
    : WindowsRoutePlatform(CreateSystemOperations(
          tap_gateway,
          underlying_interface_index,
          std::move(underlying_gateway))) {
}

WindowsRoutePlatform::WindowsRoutePlatform(WindowsRouteOperations operations) noexcept
    : operations_(std::move(operations)) {
}

DefaultRouteCapture WindowsRoutePlatform::CaptureDefaults() noexcept {
    return operations_.capture_defaults
        ? operations_.capture_defaults()
        : DefaultRouteCapture();
}

bool WindowsRoutePlatform::RemoveDefault(const RouteSnapshotPtr& route) noexcept {
    return operations_.remove_default && operations_.remove_default(route);
}

RouteAddResult WindowsRoutePlatform::Add(const RouteSpec& route) noexcept {
    return operations_.add
        ? operations_.add(route)
        : RouteAddResult::Failed;
}

bool WindowsRoutePlatform::Delete(const RouteSpec& route) noexcept {
    return operations_.remove && operations_.remove(route);
}

bool WindowsRoutePlatform::RestoreDefault(const RouteSnapshotPtr& route) noexcept {
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
    RouteSnapshotPtr removed_conflict;
    if (operations_.remove_conflicting_default &&
        !operations_.remove_conflicting_default(route, removed_conflict)) {
        return false;
    }
    if (!operations_.restore_default) {
        return false;
    }
    if (operations_.restore_default(route)) {
        return true;
    }
    if (removed_conflict) {
        Compensate(route, removed_conflict);
    }
    return false;
}

bool WindowsRoutePlatform::Compensate(
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

bool WindowsRoutePlatform::SameDefault(
    const RouteSnapshotPtr& left,
    const RouteSnapshotPtr& right) noexcept {
    return operations_.same_default
        ? operations_.same_default(left, right)
        : left == right;
}

WindowsRouteOperations WindowsRoutePlatform::CreateSystemOperations(
    uint32_t tap_gateway,
    int underlying_interface_index,
    std::string underlying_gateway) noexcept {
    WindowsRouteOperations operations;
#if defined(_WIN32)
    operations.capture_defaults = [tap_gateway, underlying_interface_index,
        underlying_gateway]() noexcept -> DefaultRouteCapture {
        std::vector<RouteSnapshotPtr> snapshots;
        auto mib = ppp::win32::network::Router::GetIpForwardTable();
        if (NULLPTR == mib) {
            return std::nullopt;
        }
        if (!underlying_gateway.empty()) {
            snapshots.emplace_back(std::make_shared<WindowsGatewaySnapshot>(
                underlying_interface_index, underlying_gateway));
        }

        const uint32_t mid = inet_addr("128.0.0.0");
        for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
            const MIB_IPFORWARDROW& row = mib->table[i];
            const bool is_default =
                (row.dwForwardDest == ppp::net::IPEndPoint::AnyAddress &&
                    (row.dwForwardMask == mid || row.dwForwardMask == ppp::net::IPEndPoint::AnyAddress)) ||
                (row.dwForwardDest == mid && row.dwForwardMask == mid);
            if (is_default && row.dwForwardNextHop != tap_gateway) {
                snapshots.emplace_back(std::make_shared<WindowsRouteSnapshot>(row));
            }
        }
        return snapshots;
    };
    operations.remove_default = [](const RouteSnapshotPtr& value) noexcept {
        if (AsWindowsGatewaySnapshot(value)) {
            return true;
        }
        auto snapshot = AsWindowsRouteSnapshot(value);
        if (!snapshot) {
            return false;
        }
        bool exists = false;
        if (!TryFindRestoredWindowsRoute(snapshot->route, exists)) {
            return false;
        }
        if (!exists) {
            return true;
        }
        MIB_IPFORWARDROW route = snapshot->route;
        if (ppp::win32::network::Router::Delete(route)) {
            return true;
        }
        return TryFindRestoredWindowsRoute(snapshot->route, exists) && !exists;
    };
    operations.add = [](const RouteSpec& route) noexcept {
        MIB_IPFORWARDROW exact;
        bool exact_exists = false;
        if (!TryFindWindowsRouteSpec(route, exact, exact_exists)) {
            return RouteAddResult::Failed;
        }
        if (exact_exists) {
            return RouteAddResult::Unchanged;
        }
        if (ppp::win32::network::Router::Add(
            route.network,
            ppp::net::IPEndPoint::PrefixToNetmask(route.prefix),
            route.gateway,
            1)) {
            return RouteAddResult::Created;
        }
        return TryFindWindowsRouteSpec(route, exact, exact_exists) && exact_exists
            ? RouteAddResult::Unchanged
            : RouteAddResult::Failed;
    };
    operations.remove = [](const RouteSpec& route) noexcept {
        MIB_IPFORWARDROW found;
        bool exists = false;
        if (!TryFindWindowsRouteSpec(route, found, exists)) {
            return false;
        }
        if (!exists) {
            return true;
        }
        if (ppp::win32::network::Router::Delete(found)) {
            return true;
        }
        return TryFindWindowsRouteSpec(route, found, exists) && !exists;
    };
    operations.exact_default_exists = [](const RouteSnapshotPtr& value,
        bool& exists) noexcept {
        exists = false;
        if (AsWindowsGatewaySnapshot(value)) {
            return true;
        }
        auto snapshot = AsWindowsRouteSnapshot(value);
        return snapshot && TryFindRestoredWindowsRoute(snapshot->route, exists);
    };
    operations.remove_conflicting_default = [](const RouteSnapshotPtr& value,
        RouteSnapshotPtr& removed) noexcept {
        removed.reset();
        if (AsWindowsGatewaySnapshot(value)) {
            return true;
        }
        auto snapshot = AsWindowsRouteSnapshot(value);
        if (!snapshot) {
            return false;
        }
        auto mib = ppp::win32::network::Router::GetIpForwardTable();
        if (NULLPTR == mib) {
            return false;
        }
        for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
            const MIB_IPFORWARDROW& row = mib->table[i];
            if (SameRestoredWindowsRoute(row, snapshot->route)) {
                return true;
            }
            if (SameWindowsRouteIdentity(row, snapshot->route)) {
                RouteSnapshotPtr conflict_snapshot =
                    std::make_shared<WindowsRouteSnapshot>(row);
                MIB_IPFORWARDROW conflict = row;
                if (!ppp::win32::network::Router::Delete(conflict)) {
                    bool exists = false;
                    return TryFindWindowsRouteIdentity(snapshot->route, exists) &&
                        !exists;
                }
                removed = std::move(conflict_snapshot);
                return true;
            }
        }
        return true;
    };
    operations.restore_default = [](const RouteSnapshotPtr& value) noexcept {
        if (auto gateway = AsWindowsGatewaySnapshot(value)) {
            return ppp::win32::network::SetDefaultIPGateway(
                gateway->interface_index,
                ppp::vector<ppp::string>{
                    ppp::string(gateway->gateway.data(), gateway->gateway.size()) });
        }
        auto snapshot = AsWindowsRouteSnapshot(value);
        if (!snapshot) {
            return false;
        }
        MIB_IPFORWARDROW route = snapshot->route;
        if (ppp::win32::network::Router::Add(route)) {
            return true;
        }
        bool exists = false;
        return TryFindRestoredWindowsRoute(snapshot->route, exists) && exists;
    };
    operations.same_default = [](const RouteSnapshotPtr& left,
        const RouteSnapshotPtr& right) noexcept {
        auto left_route = AsWindowsRouteSnapshot(left);
        auto right_route = AsWindowsRouteSnapshot(right);
        if (left_route || right_route) {
            return left_route && right_route &&
                SameWindowsRouteIdentity(left_route->route, right_route->route);
        }
        auto left_gateway = AsWindowsGatewaySnapshot(left);
        auto right_gateway = AsWindowsGatewaySnapshot(right);
        if (left_gateway || right_gateway) {
            return left_gateway && right_gateway &&
                left_gateway->interface_index == right_gateway->interface_index &&
                left_gateway->gateway == right_gateway->gateway;
        }
        return false;
    };
#else
    (void)tap_gateway;
    (void)underlying_interface_index;
    (void)underlying_gateway;
#endif
    return operations;
}

}
