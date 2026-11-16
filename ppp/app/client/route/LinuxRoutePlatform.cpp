#include <ppp/stdafx.h>
#include <ppp/app/client/route/LinuxRoutePlatform.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/net/native/rib.h>

#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
#include <linux/ppp/tap/TapLinux.h>
#include <net/if.h>
#include <fstream>
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

                        explicit LinuxRouteSnapshot(RouteSnapshotRecord record) noexcept
                            : route(record.route), record(std::move(record)), stable(true) {
                        }

                        RouteSpec route;
                        RouteSnapshotRecord record;
                        bool stable = false;
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

#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    std::string LinuxLinkIdentity(const std::string& name) noexcept {
                        if (name.empty()) {
                            return {};
                        }
                        std::ifstream address("/sys/class/net/" + name + "/address");
                        std::string value;
                        if (!address || !(address >> value) || value.empty()) {
                            return {};
                        }
                        return value;
                    }

                    bool BuildLinuxRecord(
                        RouteSpec route,
                        RouteSnapshotRecord& record) noexcept {
                        if (route.interface_name.empty()) {
                            return false;
                        }
                        const unsigned int index = if_nametoindex(
                            route.interface_name.c_str());
                        const std::string link = LinuxLinkIdentity(route.interface_name);
                        if (index == 0 || link.empty()) {
                            return false;
                        }
                        record = RouteSnapshotRecord();
                        record.platform = RouteSnapshotPlatform::Linux;
                        record.route = std::move(route);
                        record.identity.interface_index = index;
                        record.identity.interface_name = record.route.interface_name;
                        record.identity.link_identity = link;
                        return record.Complete();
                    }
#endif

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
                    const std::vector<RouteSpec> specs = BuildRouteSpecs(routes);
                    std::vector<RouteSnapshotRecord> records;
                    records.reserve(specs.size());
                    bool complete = !specs.empty();
                    for (RouteSpec route : specs) {
                        route = Resolve(std::move(route));
                        RouteSnapshotRecord record;
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                        complete = complete && BuildLinuxRecord(route, record);
#else
                        complete = false;
#endif
                        if (complete) {
                            records.emplace_back(std::move(record));
                        }
                        snapshots.emplace_back(
                            std::make_shared<LinuxRouteSnapshot>(std::move(route)));
                    }
                    if (complete && records.size() == snapshots.size()) {
                        snapshots.clear();
                        for (RouteSnapshotRecord& record : records) {
                            snapshots.emplace_back(
                                std::make_shared<LinuxRouteSnapshot>(std::move(record)));
                        }
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
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    if (snapshot->stable) {
                        // An interface name can be reused after a crash. Do
                        // not add a restored route until the current kernel
                        // identity still matches the captured owner.
                        const unsigned int current_index = if_nametoindex(
                            snapshot->record.identity.interface_name.c_str());
                        const std::string current_link = LinuxLinkIdentity(
                            snapshot->record.identity.interface_name);
                        if (current_index == 0 ||
                            current_index != snapshot->record.identity.interface_index ||
                            current_link.empty() ||
                            current_link != snapshot->record.identity.link_identity) {
                            return false;
                        }
                    }
#endif
                    const DefaultRouteCapture current_defaults = CaptureDefaults();
                    if (!current_defaults) {
                        return false;
                    }
                    for (const RouteSnapshotPtr& current : *current_defaults) {
                        if (SameDefault(route, current)) {
                            return true;
                        }
                        const auto target_snapshot = AsLinuxSnapshot(route);
                        const auto current_snapshot = AsLinuxSnapshot(current);
                        if (target_snapshot && target_snapshot->stable &&
                            (!current_snapshot || !current_snapshot->stable)) {
                            // A non-empty query without a stable identity is
                            // not enough evidence to mutate the route table.
                            return false;
                        }
                        if (target_snapshot && current_snapshot &&
                            target_snapshot->stable && current_snapshot->stable &&
                            target_snapshot->route.network == current_snapshot->route.network &&
                            target_snapshot->route.prefix == current_snapshot->route.prefix) {
                            // Preserve a destination/prefix changed by another
                            // actor instead of replacing it with stale state.
                            return false;
                        }
                    }
                    if (!operations_.add ||
                        operations_.add(snapshot->route) == RouteAddResult::Failed) {
                        return false;
                    }
                    if (!snapshot->stable) {
                        return true;
                    }
                    const DefaultRouteCapture verified = CaptureDefaults();
                    if (!verified) {
                        return false;
                    }
                    for (const RouteSnapshotPtr& current : *verified) {
                        if (SameDefault(route, current)) {
                            return true;
                        }
                    }
                    return false;
                }

                bool LinuxRoutePlatform::SameDefault(
                    const RouteSnapshotPtr& left,
                    const RouteSnapshotPtr& right) noexcept {
                    const auto left_snapshot = AsLinuxSnapshot(left);
                    const auto right_snapshot = AsLinuxSnapshot(right);
                    return left_snapshot && right_snapshot &&
                        ((left_snapshot->stable && right_snapshot->stable)
                            ? SameRouteSnapshotRoute(
                                left_snapshot->record, right_snapshot->record)
                            : SameRoute(left_snapshot->route, right_snapshot->route));
                }

                bool LinuxRoutePlatform::TryGetSnapshotRecord(
                    const RouteSnapshotPtr& snapshot,
                    RouteSnapshotRecord& record) noexcept {
                    const auto value = AsLinuxSnapshot(snapshot);
                    if (!value || !value->stable || !value->record.Complete()) {
                        return false;
                    }
                    record = value->record;
                    return true;
                }

                bool LinuxRoutePlatform::SerializeSnapshot(
                    const RouteSnapshotPtr& snapshot,
                    std::string& serialized) noexcept {
                    serialized.clear();
                    RouteSnapshotRecord record;
                    return TryGetSnapshotRecord(snapshot, record) &&
                        record.platform == RouteSnapshotPlatform::Linux &&
                        SerializeRouteSnapshot(record, serialized);
                }

                bool LinuxRoutePlatform::DeserializeSnapshot(
                    std::string_view serialized,
                    RouteSnapshotPtr& snapshot) noexcept {
                    snapshot.reset();
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    const auto record = DeserializeRouteSnapshot(serialized);
                    if (!record ||
                        record->platform != RouteSnapshotPlatform::Linux ||
                        !record->Complete()) {
                        return false;
                    }
                    snapshot = std::make_shared<LinuxRouteSnapshot>(*record);
                    return static_cast<bool>(snapshot);
#else
                    (void)serialized;
                    return false;
#endif
                }

                bool LinuxRoutePlatform::PrepareRouteRecoverySnapshot(
                    const RouteSpec& route,
                    std::string& serialized) noexcept {
                    serialized.clear();
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    RouteSnapshotRecord record;
                    return BuildLinuxRecord(Resolve(route), record) &&
                        SerializeRouteSnapshot(record, serialized);
#else
                    (void)route;
                    return false;
#endif
                }

                bool LinuxRoutePlatform::DeleteRouteRecovery(
                    std::string_view serialized) noexcept {
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    const auto record = DeserializeRouteSnapshot(serialized);
                    if (!record || record->platform != RouteSnapshotPlatform::Linux ||
                        !record->Complete() || !operations_.remove) {
                        return false;
                    }
                    const unsigned int current_index = if_nametoindex(
                        record->identity.interface_name.c_str());
                    const std::string current_link = LinuxLinkIdentity(
                        record->identity.interface_name);
                    if (current_index == 0 ||
                        current_index != record->identity.interface_index ||
                        current_link.empty() ||
                        current_link != record->identity.link_identity) {
                        return false;
                    }
                    return operations_.remove(record->route);
#else
                    (void)serialized;
                    return false;
#endif
                }

                bool LinuxRoutePlatform::RecoverRouteJournalEntry(
                    std::string_view target) noexcept {
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    LinuxRoutePlatform platform(
                        0, {}, {}, {}, false);
                    if (target.rfind("default:", 0) == 0) {
                        RouteSnapshotPtr snapshot;
                        if (!platform.DeserializeRecoverySnapshot(
                                target.substr(8), snapshot) || !snapshot) {
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
