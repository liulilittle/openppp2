#pragma once

#include <functional>
#include <string>
#include <string_view>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RouteSnapshotContract.h>

namespace ppp::app::client::route {

struct DarwinRouteOperations final {
    std::function<DefaultRouteCapture()> capture_defaults;
    std::function<bool(const RouteSnapshotPtr&)> remove_default;
    std::function<RouteAddResult(const RouteSpec&)> add;
    std::function<bool(const RouteSpec&, bool&)> route_exists;
    std::function<bool(const RouteSpec&)> remove;
    std::function<bool(const RouteSnapshotPtr&, bool&)> exact_default_exists;
    std::function<bool(const RouteSnapshotIdentity&)> interface_identity_matches;
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

    static bool TryGetSnapshotRecord(
        const RouteSnapshotPtr& snapshot,
        RouteSnapshotRecord& record) noexcept;
    // Only complete, host-identity-bearing records may cross a process
    // boundary. Legacy opaque snapshots are rejected.
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
        const RouteSpec& route, std::string& serialized) noexcept override;
    bool DeleteRouteRecovery(std::string_view serialized) noexcept override;
    // Replays a durable route journal target without a live connection.
    static bool RecoverRouteJournalEntry(std::string_view target) noexcept;
    bool VerifyRouteForRecovery(const RouteSpec& route) noexcept override;

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
