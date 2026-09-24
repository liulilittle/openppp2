#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
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
                };

            }
        }
    }
}
