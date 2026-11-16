#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RouteSnapshotContract.h>
#include <ppp/app/client/route/RouteState.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                struct LinuxRouteOperations final {
                    std::function<bool(
                        uint32_t gateway,
                        RouteInformationTablePtr& routes)> capture_defaults;
                    std::function<RouteAddResult(const RouteSpec& route)> add;
                    std::function<bool(const RouteSpec& route)> remove;
                };

                std::string SelectLinuxInterface(
                    uint32_t next_hop,
                    uint32_t tap_gateway,
                    const std::string& tap_interface,
                    const std::string& underlying_interface,
                    const std::unordered_map<uint32_t, std::string>& nics) noexcept;

                class LinuxRoutePlatform final : public IRoutePlatform {
                public:
                    LinuxRoutePlatform(
                        uint32_t tap_gateway,
                        std::string tap_interface,
                        std::string underlying_interface,
                        std::unordered_map<uint32_t, std::string> nics,
                        bool promiscuous) noexcept;

                    LinuxRoutePlatform(
                        uint32_t tap_gateway,
                        std::string tap_interface,
                        std::string underlying_interface,
                        std::unordered_map<uint32_t, std::string> nics,
                        bool promiscuous,
                        LinuxRouteOperations operations) noexcept;

                    DefaultRouteCapture CaptureDefaults() noexcept override;
                    bool RemoveDefault(const RouteSnapshotPtr& route) noexcept override;
                    RouteAddResult Add(const RouteSpec& route) noexcept override;
                    bool Delete(const RouteSpec& route) noexcept override;
                    bool RestoreDefault(const RouteSnapshotPtr& route) noexcept override;
                    bool SameDefault(
                        const RouteSnapshotPtr& left,
                        const RouteSnapshotPtr& right) noexcept override;

                    // Exposes only complete records. Legacy test snapshots
                    // intentionally remain opaque until a host identity is
                    // available.
                    static bool TryGetSnapshotRecord(
                        const RouteSnapshotPtr& snapshot,
                        RouteSnapshotRecord& record) noexcept;
                    // Only complete, host-identity-bearing records may cross
                    // a process boundary. Legacy opaque snapshots are
                    // rejected rather than cast to an implementation type.
                    static bool SerializeSnapshot(
                        const RouteSnapshotPtr& snapshot,
                        std::string& serialized) noexcept;
                    static bool DeserializeSnapshot(
                        std::string_view serialized,
                        RouteSnapshotPtr& snapshot) noexcept;
                    bool SerializeRecoverySnapshot(
                        const RouteSnapshotPtr& snapshot,
                        std::string& serialized) noexcept override {
                        return SerializeSnapshot(snapshot, serialized);
                    }
                    bool DeserializeRecoverySnapshot(
                        std::string_view serialized,
                        RouteSnapshotPtr& snapshot) noexcept override {
                        return DeserializeSnapshot(serialized, snapshot);
                    }
                    bool PrepareRouteRecoverySnapshot(
                        const RouteSpec& route,
                        std::string& serialized) noexcept override;
                    bool DeleteRouteRecovery(
                        std::string_view serialized) noexcept override;

                    // Replays a durable route journal target without a live
                    // connection or RouteCoordinator context.
                    static bool RecoverRouteJournalEntry(
                        std::string_view target) noexcept;

                private:
                    static LinuxRouteOperations CreateSystemOperations() noexcept;
                    RouteSpec Resolve(RouteSpec route) const noexcept;

                    uint32_t tap_gateway_ = 0;
                    std::string tap_interface_;
                    std::string underlying_interface_;
                    std::unordered_map<uint32_t, std::string> nics_;
                    bool promiscuous_ = false;
                    LinuxRouteOperations operations_;
                };

            }
        }
    }
}
