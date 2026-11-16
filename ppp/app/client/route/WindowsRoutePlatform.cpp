#include <ppp/stdafx.h>
#include <ppp/app/client/route/WindowsRoutePlatform.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#if defined(_WIN32)
#include <ppp/net/IPEndPoint.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/win32/network/Router.h>
#endif

namespace ppp::app::client::route {

int ResolveWindowsRouteInterfaceIndex(
    uint32_t gateway, uint32_t tap_gateway, int tap_interface_index,
    uint32_t underlying_gateway, int underlying_interface_index,
    const std::function<int(uint32_t)>& lookup) noexcept {
    if (gateway != 0 && gateway == tap_gateway) {
        return tap_interface_index > 0 ? tap_interface_index : -1;
    }
    if (gateway != 0 && gateway == underlying_gateway) {
        return underlying_interface_index > 0 ? underlying_interface_index : -1;
    }
    return lookup ? lookup(gateway) : -1;
}

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
        : route(route), data(CaptureWindowsRouteRowSnapshot(route)) {
    }

    explicit WindowsRouteSnapshot(
        const WindowsRouteRowSnapshot& value) noexcept
        : route{}, data(value) {
        route.dwForwardDest = data.destination;
        route.dwForwardMask = data.mask;
        route.dwForwardPolicy = data.policy;
        route.dwForwardNextHop = data.next_hop;
        route.dwForwardIfIndex = data.interface_index;
        route.dwForwardType = data.type;
        route.dwForwardProto = data.proto;
        route.dwForwardAge = data.age;
        route.dwForwardNextHopAS = data.next_hop_as;
        route.dwForwardMetric1 = data.metric1;
        route.dwForwardMetric2 = data.metric2;
        route.dwForwardMetric3 = data.metric3;
        route.dwForwardMetric4 = data.metric4;
        route.dwForwardMetric5 = data.metric5;
    }

    MIB_IPFORWARDROW route;
    WindowsRouteRowSnapshot data;
};

class WindowsGatewaySnapshot final : public IRouteSnapshot {
public:
    WindowsGatewaySnapshot(int interface_index, std::string gateway) noexcept
        : interface_index(interface_index), gateway(std::move(gateway)),
          data(CaptureWindowsGatewaySnapshotData(
              static_cast<std::uint32_t>(interface_index), this->gateway)) {
    }

    explicit WindowsGatewaySnapshot(
        const WindowsGatewaySnapshotData& value) noexcept
        : interface_index(static_cast<int>(value.interface_index)),
          gateway(value.gateway), data(value) {
    }

    int interface_index;
    std::string gateway;
    WindowsGatewaySnapshotData data;
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

enum class WindowsRouteLookup : std::uint8_t {
    Unavailable,
    Missing,
    Match,
    Conflict,
};

WindowsRouteLookup FindWindowsRoute(
    const MIB_IPFORWARDROW& expected,
    const WindowsRouteRowSnapshot& expected_snapshot) noexcept {
    auto mib = ppp::win32::network::Router::GetIpForwardTable();
    if (!mib) {
        return WindowsRouteLookup::Unavailable;
    }

    bool identity_found = false;
    for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
        const MIB_IPFORWARDROW& row = mib->table[i];
        if (!SameWindowsRouteIdentity(row, expected)) {
            continue;
        }
        identity_found = true;
        // This compare includes all route attributes owned by the snapshot and
        // the stable adapter LUID/GUID.  A changed metric or reused interface
        // index is therefore a conflict, never a route that this process may
        // delete or overwrite.
        if (VerifyWindowsRouteSnapshot(row, expected_snapshot)) {
            return WindowsRouteLookup::Match;
        }
    }
    return identity_found
        ? WindowsRouteLookup::Conflict
        : WindowsRouteLookup::Missing;
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
    bool& exists,
    int interface_index = -1) noexcept {
    exists = false;
    auto mib = ppp::win32::network::Router::GetIpForwardTable();
    if (!mib) {
        return false;
    }
    for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
        if (SameWindowsRouteSpec(mib->table[i], route) &&
            (interface_index < 0 ||
                mib->table[i].dwForwardIfIndex == static_cast<DWORD>(interface_index))) {
            found = mib->table[i];
            exists = true;
            break;
        }
    }
    return true;
}

bool VerifyWindowsGatewayInterfaceIdentity(
    const WindowsGatewaySnapshotData& expected) noexcept {
    auto adapter = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(
        static_cast<int>(expected.interface_index));
    return adapter &&
        static_cast<std::uint32_t>(adapter->InterfaceIndex) ==
            expected.interface_index &&
        _stricmp(adapter->InterfaceLuid.data(), expected.interface_luid.data()) == 0 &&
        _stricmp(adapter->Guid.data(), expected.interface_guid.data()) == 0;
}

}
#endif

WindowsRoutePlatform::WindowsRoutePlatform(
    uint32_t tap_gateway,
    int underlying_interface_index,
    std::string underlying_gateway,
    int tap_interface_index) noexcept
    : WindowsRoutePlatform(CreateSystemOperations(
          tap_gateway,
          underlying_interface_index,
          std::move(underlying_gateway),
          tap_interface_index)) {
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

bool WindowsRoutePlatform::VerifyRouteForRecovery(
    const RouteSpec& route) noexcept {
    // RouteSpec does not contain the MIB row attributes or adapter LUID/GUID
    // required to prove ownership after a restart.  A spec-only lookup is
    // therefore not a recovery verification and must fail closed until the
    // caller supplies a serialized WindowsRouteRowSnapshot.
    (void)route;
    return false;
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

bool WindowsRoutePlatform::SerializeRecoverySnapshot(
    const RouteSnapshotPtr& snapshot, std::string& serialized) noexcept {
#if defined(_WIN32)
    return SerializeWindowsRoutePlatformSnapshot(snapshot, serialized);
#else
    (void)snapshot;
    serialized.clear();
    return false;
#endif
}

bool WindowsRoutePlatform::DeserializeRecoverySnapshot(
    std::string_view serialized, RouteSnapshotPtr& snapshot) noexcept {
#if defined(_WIN32)
    return DeserializeWindowsRoutePlatformSnapshot(serialized, snapshot);
#else
    (void)serialized;
    snapshot.reset();
    return false;
#endif
}

bool WindowsRoutePlatform::PrepareRouteRecoverySnapshot(
    const RouteSpec& route, std::string& serialized) noexcept {
#if defined(_WIN32)
    serialized.clear();
    auto table = ppp::win32::network::Router::GetIpForwardTable();
    if (!table) {
        return false;
    }

    const uint32_t mask = ppp::net::IPEndPoint::PrefixToNetmask(route.prefix);
    const MIB_IPFORWARDROW* match = nullptr;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPFORWARDROW& row = table->table[i];
        if (row.dwForwardDest != route.network ||
            row.dwForwardMask != mask || row.dwForwardNextHop != route.gateway) {
            continue;
        }
        // RouteSpec may carry an interface name.  When it does, require the
        // live row to resolve to that adapter; otherwise a duplicate route on
        // another interface would be an ambiguous ownership record.
        if (!route.interface_name.empty()) {
            const ppp::string name =
                ppp::win32::network::GetInterfaceName(
                    static_cast<int>(row.dwForwardIfIndex));
            if (std::string_view(name.data(), name.size()) !=
                std::string_view(
                    route.interface_name.data(), route.interface_name.size())) {
                continue;
            }
        }
        if (match != nullptr) {
            // More than one row satisfies the route spec.  A spec-only
            // journal entry cannot identify which row OpenPPP2 created.
            serialized.clear();
            return false;
        }
        match = &row;
    }
    if (!match) {
        return false;
    }
    return SerializeWindowsRouteSnapshot(
        CaptureWindowsRouteRowSnapshot(*match), serialized);
#else
    (void)route;
    serialized.clear();
    return false;
#endif
}

bool WindowsRoutePlatform::DeleteRouteRecovery(
    std::string_view serialized) noexcept {
#if defined(_WIN32)
    WindowsRouteRowSnapshot expected;
    if (!DeserializeWindowsRouteSnapshot(serialized, expected)) {
        return false;
    }
    MIB_IPFORWARDROW row{};
    row.dwForwardDest = expected.destination;
    row.dwForwardMask = expected.mask;
    row.dwForwardPolicy = expected.policy;
    row.dwForwardNextHop = expected.next_hop;
    row.dwForwardIfIndex = expected.interface_index;
    row.dwForwardType = expected.type;
    row.dwForwardProto = expected.proto;
    row.dwForwardAge = expected.age;
    row.dwForwardNextHopAS = expected.next_hop_as;
    row.dwForwardMetric1 = expected.metric1;
    row.dwForwardMetric2 = expected.metric2;
    row.dwForwardMetric3 = expected.metric3;
    row.dwForwardMetric4 = expected.metric4;
    row.dwForwardMetric5 = expected.metric5;

    const WindowsRouteLookup before = FindWindowsRoute(row, expected);
    if (before == WindowsRouteLookup::Missing) {
        // The route was already removed.  This is an idempotent successful
        // recovery and lets the journal discard the completed entry.
        return true;
    }
    if (before != WindowsRouteLookup::Match) {
        // Unavailable and conflict both retain the journal for a later retry.
        return false;
    }
    if (!ppp::win32::network::Router::Delete(row)) {
        return FindWindowsRoute(row, expected) == WindowsRouteLookup::Missing;
    }
    return FindWindowsRoute(row, expected) == WindowsRouteLookup::Missing;
#else
    (void)serialized;
    return false;
#endif
}

bool WindowsRoutePlatform::RecoverRouteJournalEntry(
    std::string_view target) noexcept {
#if defined(_WIN32)
    WindowsRoutePlatform platform(0, 0, {});
    if (target.rfind("default:", 0) == 0) {
        RouteSnapshotPtr snapshot;
        if (!platform.DeserializeRecoverySnapshot(target.substr(8), snapshot) ||
            !snapshot) {
            return false;
        }
        return platform.RestoreDefault(snapshot);
    }
    if (target.rfind("created-v2:", 0) == 0) {
        return platform.DeleteRouteRecovery(target.substr(11));
    }
#else
    (void)target;
#endif
    return false;
}

WindowsRouteOperations WindowsRoutePlatform::CreateSystemOperations(
    uint32_t tap_gateway,
    int underlying_interface_index,
    std::string underlying_gateway,
    int tap_interface_index) noexcept {
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
        const auto before = FindWindowsRoute(snapshot->route, snapshot->data);
        if (before == WindowsRouteLookup::Unavailable ||
            before == WindowsRouteLookup::Conflict) {
            return false;
        }
        if (before == WindowsRouteLookup::Missing) {
            return true;
        }
        MIB_IPFORWARDROW route = snapshot->route;
        if (ppp::win32::network::Router::Delete(route)) {
            return FindWindowsRoute(snapshot->route, snapshot->data) ==
                WindowsRouteLookup::Missing;
        }
        return FindWindowsRoute(snapshot->route, snapshot->data) ==
            WindowsRouteLookup::Missing;
    };
    const uint32_t underlying_gateway_address = underlying_gateway.empty()
        ? 0 : inet_addr(underlying_gateway.c_str());
    operations.add = [tap_gateway, tap_interface_index,
        underlying_gateway_address, underlying_interface_index](const RouteSpec& route) noexcept {
        const int interface_index = ResolveWindowsRouteInterfaceIndex(
            route.gateway, tap_gateway, tap_interface_index,
            underlying_gateway_address, underlying_interface_index,
            [](uint32_t gateway) noexcept {
                return ppp::win32::network::Router::GetBestInterface(gateway);
            });
        if (interface_index <= 0) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                "windows_route", "add failed: stage=resolve_interface prefix=%d", route.prefix);
            return RouteAddResult::FailedUnchanged;
        }
        MIB_IPFORWARDROW exact;
        bool exact_exists = false;
        if (!TryFindWindowsRouteSpec(route, exact, exact_exists)) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                "windows_route", "add failed: stage=query_before_add prefix=%d", route.prefix);
            return RouteAddResult::FailedUnchanged;
        }
        if (exact_exists) {
            return RouteAddResult::Unchanged;
        }
        const bool add_succeeded = ppp::win32::network::Router::Add(
            route.network,
            ppp::net::IPEndPoint::PrefixToNetmask(route.prefix),
            route.gateway,
            1,
            interface_index);
        if (!TryFindWindowsRouteSpec(route, exact, exact_exists, interface_index)) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                "windows_route", "add failed: stage=query_after_add api_success=%d prefix=%d",
                add_succeeded ? 1 : 0, route.prefix);
            return RouteAddResult::Failed;
        }
        if (!exact_exists) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                "windows_route", "add failed: stage=route_missing_after_add api_success=%d prefix=%d",
                add_succeeded ? 1 : 0, route.prefix);
            return add_succeeded ? RouteAddResult::Failed : RouteAddResult::FailedUnchanged;
        }
        return add_succeeded ? RouteAddResult::Created :
            RouteAddResult::Unchanged;
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
        if (!snapshot) {
            return false;
        }
        const auto result = FindWindowsRoute(snapshot->route, snapshot->data);
        exists = result == WindowsRouteLookup::Match;
        return result != WindowsRouteLookup::Unavailable;
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
        const auto result = FindWindowsRoute(snapshot->route, snapshot->data);
        if (result == WindowsRouteLookup::Match ||
            result == WindowsRouteLookup::Missing) {
            return true;
        }
        // A route with our address/interface identity but changed attributes,
        // or with a reused interface index and different LUID/GUID, belongs to
        // the current system state.  Keep it in place and leave recovery
        // pending for an explicit, conflict-aware retry.
        return false;
    };
    operations.restore_default = [](const RouteSnapshotPtr& value) noexcept {
        if (auto gateway = AsWindowsGatewaySnapshot(value)) {
            if (!VerifyWindowsGatewayInterfaceIdentity(gateway->data)) {
                return false;
            }
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
        (void)ppp::win32::network::Router::Add(route);
        return FindWindowsRoute(snapshot->route, snapshot->data) ==
            WindowsRouteLookup::Match;
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
    (void)tap_interface_index;
#endif
    return operations;
}

#if defined(_WIN32)
bool SerializeWindowsRoutePlatformSnapshot(
    const RouteSnapshotPtr& snapshot,
    std::string& serialized) noexcept {
    if (auto route = AsWindowsRouteSnapshot(snapshot)) {
        return SerializeWindowsRouteSnapshot(route->data, serialized);
    }
    if (auto gateway = AsWindowsGatewaySnapshot(snapshot)) {
        return SerializeWindowsGatewaySnapshot(gateway->data, serialized);
    }
    serialized.clear();
    return false;
}

bool DeserializeWindowsRoutePlatformSnapshot(
    std::string_view serialized,
    RouteSnapshotPtr& snapshot) noexcept {
    WindowsRouteRowSnapshot route;
    if (DeserializeWindowsRouteSnapshot(serialized, route)) {
        snapshot = std::make_shared<WindowsRouteSnapshot>(route);
        return static_cast<bool>(snapshot);
    }
    WindowsGatewaySnapshotData gateway;
    if (DeserializeWindowsGatewaySnapshot(serialized, gateway)) {
        snapshot = std::make_shared<WindowsGatewaySnapshot>(gateway);
        return static_cast<bool>(snapshot);
    }
    snapshot.reset();
    return false;
}
#endif

}
