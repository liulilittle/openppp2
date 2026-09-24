#pragma once

#include <functional>
#include <string>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

struct WindowsRouteIdentity final {
    uint32_t destination;
    uint32_t mask;
    uint32_t next_hop;
    uint32_t interface_index;
    uint32_t policy;
};

bool SameWindowsRouteIdentity(
    const WindowsRouteIdentity& left,
    const WindowsRouteIdentity& right) noexcept;

struct WindowsRouteOperations final {
    std::function<DefaultRouteCapture()> capture_defaults;
    std::function<bool(const RouteSnapshotPtr&)> remove_default;
    std::function<RouteAddResult(const RouteSpec&)> add;
    std::function<bool(const RouteSpec&)> remove;
    std::function<bool(const RouteSnapshotPtr&, bool&)> exact_default_exists;
    std::function<bool(const RouteSnapshotPtr&, RouteSnapshotPtr&)>
        remove_conflicting_default;
    std::function<bool(const RouteSnapshotPtr&)> restore_default;
    std::function<bool(const RouteSnapshotPtr&, const RouteSnapshotPtr&)> same_default;
};

class WindowsRoutePlatform final : public IRoutePlatform {
public:
    WindowsRoutePlatform(
        uint32_t tap_gateway,
        int underlying_interface_index,
        std::string underlying_gateway) noexcept;
    explicit WindowsRoutePlatform(WindowsRouteOperations operations) noexcept;

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

    static WindowsRouteOperations CreateSystemOperations(
        uint32_t tap_gateway,
        int underlying_interface_index,
        std::string underlying_gateway) noexcept;
    bool Compensate(
        const RouteSnapshotPtr& target,
        const RouteSnapshotPtr& conflict) noexcept;

    WindowsRouteOperations operations_;
    std::optional<PendingCompensation> pending_compensation_;
};

}
