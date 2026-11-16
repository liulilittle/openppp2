#include <ppp/stdafx.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>

#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#include <darwin/ppp/tun/utun.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif

namespace ppp::app::client::route {

namespace {

class DarwinRouteSnapshot final : public IRouteSnapshot {
public:
    explicit DarwinRouteSnapshot(RouteSpec route) noexcept
        : route(std::move(route)) {
    }

    explicit DarwinRouteSnapshot(RouteSnapshotRecord record) noexcept
        : route(record.route), record(std::move(record)), stable(true) {
    }

    RouteSpec route;
    RouteSnapshotRecord record;
    bool stable = false;
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

#if defined(_MACOS)
std::string DarwinLinkIdentity(const std::string& name) noexcept {
    if (name.empty()) {
        return {};
    }
    struct ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) {
        return {};
    }
    std::string value;
    for (struct ifaddrs* item = list; item; item = item->ifa_next) {
        if (!item->ifa_name || name != item->ifa_name || !item->ifa_addr ||
            item->ifa_addr->sa_family != AF_LINK) {
            continue;
        }
        const auto* link = reinterpret_cast<const sockaddr_dl*>(item->ifa_addr);
        if (link->sdl_alen == 0) {
            continue;
        }
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(LLADDR(link));
        static constexpr char digits[] = "0123456789abcdef";
        for (unsigned char index = 0; index < link->sdl_alen; ++index) {
            if (!value.empty()) {
                value.push_back(':');
            }
            value.push_back(digits[bytes[index] >> 4]);
            value.push_back(digits[bytes[index] & 0x0f]);
        }
        break;
    }
    freeifaddrs(list);
    return value;
}

bool BuildDarwinRecord(
    RouteSpec route,
    const ppp::tap::TapDarwin::NetworkInterface::Ptr& interface,
    RouteSnapshotRecord& record) noexcept {
    if (!interface || interface->Index <= 0 || interface->Name.empty()) {
        return false;
    }
    const std::string name(interface->Name.begin(), interface->Name.end());
    const std::string link = DarwinLinkIdentity(name);
    if (link.empty()) {
        return false;
    }
    record = RouteSnapshotRecord();
    record.platform = RouteSnapshotPlatform::Darwin;
    route.interface_name = name;
    record.route = std::move(route);
    record.identity.interface_index = static_cast<uint32_t>(interface->Index);
    record.identity.interface_name = name;
    record.identity.link_identity = link;
    return record.Complete();
}

bool FindDarwinRouteInterface(
    const RouteSpec& route,
    const ppp::vector<ppp::tap::TapDarwin::NetworkInterface::Ptr>& interfaces,
    ppp::tap::TapDarwin::NetworkInterface::Ptr& result) noexcept {
    result.reset();
    for (const auto& interface : interfaces) {
        if (!interface) {
            continue;
        }
        for (const auto& gateway : interface->GatewayAddresses) {
            if (gateway.second == route.gateway) {
                result = interface;
                return true;
            }
        }
    }
    return false;
}

#endif
}

DarwinRoutePlatform::DarwinRoutePlatform(uint32_t tap_gateway, bool promiscuous) noexcept
    : DarwinRoutePlatform(CreateSystemOperations(tap_gateway, promiscuous)) {
}

DarwinRoutePlatform::DarwinRoutePlatform(DarwinRouteOperations operations) noexcept
    : operations_(std::move(operations)) {
}

DefaultRouteCapture DarwinRoutePlatform::CaptureDefaults() noexcept {
    if (!operations_.capture_defaults) {
        return DefaultRouteCapture();
    }
    DefaultRouteCapture captured = operations_.capture_defaults();
#if defined(_MACOS)
    if (!captured || captured->empty()) {
        return captured;
    }
    ppp::vector<ppp::tap::TapDarwin::NetworkInterface::Ptr> interfaces;
    if (!ppp::tap::TapDarwin::GetAllNetworkInterfaces(interfaces)) {
        return captured;
    }
    std::vector<RouteSnapshotRecord> records;
    records.reserve(captured->size());
    for (const RouteSnapshotPtr& value : *captured) {
        const auto snapshot = AsDarwinSnapshot(value);
        ppp::tap::TapDarwin::NetworkInterface::Ptr interface;
        RouteSnapshotRecord record;
        if (!snapshot || !FindDarwinRouteInterface(
                snapshot->route, interfaces, interface) ||
            !BuildDarwinRecord(snapshot->route, interface, record)) {
            return captured;
        }
        records.emplace_back(std::move(record));
    }
    std::vector<RouteSnapshotPtr> stable;
    stable.reserve(records.size());
    for (RouteSnapshotRecord& record : records) {
        stable.emplace_back(std::make_shared<DarwinRouteSnapshot>(std::move(record)));
    }
    return stable;
#else
    return captured;
#endif
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

bool DarwinRoutePlatform::VerifyRouteForRecovery(
    const RouteSpec& route) noexcept {
    // RouteSpec does not carry the Darwin interface/link identity needed for
    // a compare-and-delete after restart.  Keep the journal pending until a
    // platform snapshot codec supplies that proof.
    (void)route;
    return false;
}

bool DarwinRoutePlatform::RestoreDefault(const RouteSnapshotPtr& route) noexcept {
    if (pending_compensation_) {
        const PendingCompensation pending = *pending_compensation_;
        if (!Compensate(pending.target, pending.conflict)) {
            return false;
        }
    }

    const auto target_snapshot = AsDarwinSnapshot(route);
    if (!operations_.exact_default_exists &&
        !operations_.remove_conflicting_default) {
        if (target_snapshot && target_snapshot->stable &&
            (!operations_.interface_identity_matches ||
                !operations_.interface_identity_matches(
                    target_snapshot->record.identity))) {
            return false;
        }
        return operations_.restore_default && operations_.restore_default(route);
    }

#if defined(_MACOS)
    if (target_snapshot && target_snapshot->stable && operations_.capture_defaults) {
        const DefaultRouteCapture current = CaptureDefaults();
        if (!current) {
            return false;
        }
        for (const RouteSnapshotPtr& value : *current) {
            const auto current_snapshot = AsDarwinSnapshot(value);
            if (!current_snapshot || !current_snapshot->stable) {
                if (!current->empty()) {
                    // A non-empty query without a stable interface/link
                    // identity cannot prove ownership of the current route.
                    return false;
                }
                continue;
            }
            if (SameDefault(route, value)) {
                return true;
            }
            if (SameDarwinConflictKey(
                    target_snapshot->route, current_snapshot->route)) {
                return false;
            }
        }
    }
#endif

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
#if defined(_MACOS)
    if (target_snapshot && target_snapshot->stable && operations_.capture_defaults) {
        const DefaultRouteCapture verified = CaptureDefaults();
        if (!verified) {
            return false;
        }
        for (const RouteSnapshotPtr& value : *verified) {
            if (SameDefault(route, value)) {
                return true;
            }
        }
        return false;
    }
#endif
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
#if defined(_MACOS)
    const auto left_snapshot = AsDarwinSnapshot(left);
    const auto right_snapshot = AsDarwinSnapshot(right);
    if (left_snapshot && right_snapshot &&
        left_snapshot->stable && right_snapshot->stable) {
        return SameRouteSnapshotRoute(
            left_snapshot->record, right_snapshot->record);
    }
#endif
    return operations_.same_default
        ? operations_.same_default(left, right)
        : left == right;
}

bool DarwinRoutePlatform::TryGetSnapshotRecord(
    const RouteSnapshotPtr& snapshot,
    RouteSnapshotRecord& record) noexcept {
#if defined(_MACOS)
    const auto value = AsDarwinSnapshot(snapshot);
    if (!value || !value->stable || !value->record.Complete()) {
        return false;
    }
    record = value->record;
    return true;
#else
    (void)snapshot;
    (void)record;
    return false;
#endif
}

bool DarwinRoutePlatform::SerializeSnapshot(
    const RouteSnapshotPtr& snapshot,
    std::string& serialized) noexcept {
    serialized.clear();
    RouteSnapshotRecord record;
    return TryGetSnapshotRecord(snapshot, record) &&
        record.platform == RouteSnapshotPlatform::Darwin &&
        SerializeRouteSnapshot(record, serialized);
}

bool DarwinRoutePlatform::DeserializeSnapshot(
    std::string_view serialized,
    RouteSnapshotPtr& snapshot) noexcept {
    snapshot.reset();
    const auto record = DeserializeRouteSnapshot(serialized);
    if (!record ||
        record->platform != RouteSnapshotPlatform::Darwin ||
        !record->Complete()) {
        return false;
    }
    snapshot = std::make_shared<DarwinRouteSnapshot>(*record);
    return static_cast<bool>(snapshot);
}

bool DarwinRoutePlatform::PrepareRouteRecoverySnapshot(
    const RouteSpec& route, std::string& serialized) noexcept {
    serialized.clear();
#if defined(_MACOS)
    ppp::vector<ppp::tap::TapDarwin::NetworkInterface::Ptr> interfaces;
    if (!ppp::tap::TapDarwin::GetAllNetworkInterfaces(interfaces)) {
        return false;
    }
    ppp::tap::TapDarwin::NetworkInterface::Ptr interface;
    if (!FindDarwinRouteInterface(route, interfaces, interface)) {
        return false;
    }
    if (!route.interface_name.empty() &&
        std::string(interface->Name.begin(), interface->Name.end()) !=
            route.interface_name) {
        return false;
    }
    RouteSnapshotRecord record;
    return BuildDarwinRecord(route, interface, record) &&
        SerializeRouteSnapshot(record, serialized);
#else
    (void)route;
    return false;
#endif
}

bool DarwinRoutePlatform::DeleteRouteRecovery(
    std::string_view serialized) noexcept {
#if defined(_MACOS)
    const auto record = DeserializeRouteSnapshot(serialized);
    if (!record || record->platform != RouteSnapshotPlatform::Darwin ||
        !record->Complete() || !operations_.remove) {
        return false;
    }
    if (!operations_.interface_identity_matches ||
        !operations_.interface_identity_matches(record->identity)) {
        return false;
    }
    return operations_.remove(record->route);
#else
    (void)serialized;
    return false;
#endif
}

bool DarwinRoutePlatform::RecoverRouteJournalEntry(
    std::string_view target) noexcept {
#if defined(_MACOS)
    DarwinRoutePlatform platform(0, false);
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
    operations.interface_identity_matches = [](
        const RouteSnapshotIdentity& expected) noexcept {
        if (!expected.Complete()) {
            return false;
        }
        ppp::vector<ppp::tap::TapDarwin::NetworkInterface::Ptr> interfaces;
        if (!ppp::tap::TapDarwin::GetAllNetworkInterfaces(interfaces)) {
            return false;
        }
        for (const auto& interface : interfaces) {
            if (!interface || interface->Index <= 0 ||
                static_cast<uint32_t>(interface->Index) != expected.interface_index ||
                std::string(interface->Name.begin(), interface->Name.end()) !=
                    expected.interface_name) {
                continue;
            }
            const std::string link = DarwinLinkIdentity(expected.interface_name);
            return !link.empty() && link == expected.link_identity;
        }
        return false;
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
