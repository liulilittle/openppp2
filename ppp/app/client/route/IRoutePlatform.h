#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                struct RouteSpec final {
                    uint32_t network = 0;
                    uint32_t gateway = 0;
                    int prefix = 0;
                    std::string interface_name;
                };

                class IRouteSnapshot {
                public:
                    virtual ~IRouteSnapshot() noexcept = default;
                };

                using RouteSnapshotPtr = std::shared_ptr<const IRouteSnapshot>;
                using DefaultRouteCapture =
                    std::optional<std::vector<RouteSnapshotPtr>>;

                enum class RouteAddResult {
                    Failed,
                    Unchanged,
                    Created,
                    // Failure with proof that this invocation left no route
                    // mutation. The coordinator may discard its write-ahead
                    // intent; Failed retains the intent when state is unknown.
                    FailedUnchanged,
                };

                class IRoutePlatform {
                public:
                    virtual ~IRoutePlatform() noexcept = default;

                    virtual DefaultRouteCapture CaptureDefaults() noexcept = 0;
                    virtual bool RemoveDefault(const RouteSnapshotPtr& route) noexcept = 0;
                    virtual RouteAddResult Add(const RouteSpec& route) noexcept = 0;
                    virtual bool Delete(const RouteSpec& route) noexcept = 0;
                    virtual bool RestoreDefault(const RouteSnapshotPtr& route) noexcept = 0;
                    virtual bool SameDefault(
                        const RouteSnapshotPtr& left,
                        const RouteSnapshotPtr& right) noexcept = 0;

                    // Stable snapshot codecs are optional so existing test
                    // doubles remain source compatible.  Production
                    // platforms override these before a durable journal is
                    // enabled.
                    virtual bool SerializeRecoverySnapshot(
                        const RouteSnapshotPtr&, std::string&) noexcept {
                        return false;
                    }
                    virtual bool DeserializeRecoverySnapshot(
                        std::string_view, RouteSnapshotPtr&) noexcept {
                        return false;
                    }
                    // Captures a durable, platform-specific identity for a
                    // route after it has been applied. Recovery must use the
                    // paired compare-and-delete operation instead of
                    // RouteSpec alone.
                    virtual bool PrepareRouteRecoverySnapshot(
                        const RouteSpec&, std::string&) noexcept {
                        return false;
                    }
                    virtual bool DeleteRouteRecovery(
                        std::string_view) noexcept {
                        return false;
                    }
                    // Recovery must prove ownership before deleting a route
                    // after a process restart. Legacy platforms fail closed.
                    virtual bool VerifyRouteForRecovery(
                        const RouteSpec&) noexcept {
                        return false;
                    }
                };

            }
        }
    }
}
