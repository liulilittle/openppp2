#pragma once

#include <functional>
#include <string>
#include <string_view>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/WindowsRouteSnapshot.h>
#if defined(_WIN32)
#include <windows/ppp/win32/network/WindowsRouteSnapshotWin32.h>
#endif

namespace ppp::app::client::route {

#if defined(_WIN32)
bool SerializeWindowsRoutePlatformSnapshot(
    const RouteSnapshotPtr& snapshot,
    std::string& serialized) noexcept;
bool DeserializeWindowsRoutePlatformSnapshot(
    std::string_view serialized,
    RouteSnapshotPtr& snapshot) noexcept;
#endif

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

// Known session gateways must not depend on a live best-route query after
// the default-route transaction has removed the routes used by that query.
int ResolveWindowsRouteInterfaceIndex(
    uint32_t gateway, uint32_t tap_gateway, int tap_interface_index,
    uint32_t underlying_gateway, int underlying_interface_index,
    const std::function<int(uint32_t)>& lookup) noexcept;

struct WindowsRouteOperations final {
    std::function<DefaultRouteCapture()> capture_defaults;
    std::function<bool(const RouteSnapshotPtr&)> remove_default;
    std::function<RouteAddResult(const RouteSpec&)> add;
    std::function<bool(const RouteSpec&)> remove;
    std::function<bool(const RouteSpec&, bool&)> route_exists;
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
        std::string underlying_gateway,
        int tap_interface_index = -1) noexcept;
    explicit WindowsRoutePlatform(WindowsRouteOperations operations) noexcept;

    DefaultRouteCapture CaptureDefaults() noexcept override;
    bool RemoveDefault(const RouteSnapshotPtr& route) noexcept override;
    RouteAddResult Add(const RouteSpec& route) noexcept override;
    bool Delete(const RouteSpec& route) noexcept override;
    bool RestoreDefault(const RouteSnapshotPtr& route) noexcept override;
    bool SameDefault(
        const RouteSnapshotPtr& left,
        const RouteSnapshotPtr& right) noexcept override;
    bool SerializeRecoverySnapshot(
        const RouteSnapshotPtr& snapshot,
        std::string& serialized) noexcept override;
    bool DeserializeRecoverySnapshot(
        std::string_view serialized,
        RouteSnapshotPtr& snapshot) noexcept override;
    bool PrepareRouteRecoverySnapshot(
        const RouteSpec& route,
        std::string& serialized) noexcept override;
    bool DeleteRouteRecovery(std::string_view serialized) noexcept override;
    bool VerifyRouteForRecovery(const RouteSpec& route) noexcept override;
    // Replays a durable route journal target without a live connection.
    static bool RecoverRouteJournalEntry(std::string_view target) noexcept;

private:
    struct PendingCompensation final {
        RouteSnapshotPtr target;
        RouteSnapshotPtr conflict;
    };

    static WindowsRouteOperations CreateSystemOperations(
        uint32_t tap_gateway,
        int underlying_interface_index,
        std::string underlying_gateway,
        int tap_interface_index) noexcept;
    bool Compensate(
        const RouteSnapshotPtr& target,
        const RouteSnapshotPtr& conflict) noexcept;

    WindowsRouteOperations operations_;
    std::optional<PendingCompensation> pending_compensation_;
};

}
