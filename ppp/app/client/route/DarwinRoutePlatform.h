#pragma once

#include <functional>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

struct DarwinRouteOperations final {
    std::function<DefaultRouteCapture()> capture_defaults;
    std::function<bool(const RouteSnapshotPtr&)> remove_default;
    std::function<RouteAddResult(const RouteSpec&)> add;
    std::function<bool(const RouteSpec&, bool&)> route_exists;
    std::function<bool(const RouteSpec&)> remove;
    std::function<bool(const RouteSnapshotPtr&, bool&)> exact_default_exists;
    std::function<bool(const RouteSnapshotPtr&, RouteSnapshotPtr&)>
        remove_conflicting_default;
    std::function<bool(const RouteSnapshotPtr&)> restore_default;
    std::function<bool(const RouteSnapshotPtr&, const RouteSnapshotPtr&)> same_default;
};

class DarwinRoutePlatform final : public IRoutePlatform {
public:
    DarwinRoutePlatform(uint32_t tap_gateway, bool promiscuous) noexcept;
    explicit DarwinRoutePlatform(DarwinRouteOperations operations) noexcept;

    DefaultRouteCapture CaptureDefaults() noexcept override;
    bool RemoveDefault(const RouteSnapshotPtr& route) noexcept override;
    RouteAddResult Add(const RouteSpec& route) noexcept override;
    bool Delete(const RouteSpec& route) noexcept override;
    bool RestoreDefault(const RouteSnapshotPtr& route) noexcept override;
    bool SameDefault(
        const RouteSnapshotPtr& left,
        const RouteSnapshotPtr& right) noexcept override;

private:
    struct PendingCompensation final {
        RouteSnapshotPtr target;
        RouteSnapshotPtr conflict;
    };

    static DarwinRouteOperations CreateSystemOperations(
        uint32_t tap_gateway,
        bool promiscuous) noexcept;
    bool Compensate(
        const RouteSnapshotPtr& target,
        const RouteSnapshotPtr& conflict) noexcept;

    DarwinRouteOperations operations_;
    std::optional<PendingCompensation> pending_compensation_;
};

}
