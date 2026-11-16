#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/NetworkRecoveryJournal.h>
#include <ppp/app/client/route/RouteJournalCodec.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/app/client/routing/HumanRoutingRouteSpecs.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <chrono>
#include <thread>

using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                RouteCoordinator::RouteCoordinator(
                    std::unique_ptr<IRoutePlatform> platform) noexcept
                    : platform_(std::move(platform)),
                      ownership_(NetworkOwnershipLease::Acquire("route-coordinator")) {
                }

                const std::string RouteCoordinator::empty_ownership_token_;

                RouteCoordinator::~RouteCoordinator() noexcept {
                    Stop();
                }

                RouteStateSnapshot RouteCoordinator::Snapshot() const noexcept {
                    return state_.Snapshot();
                }

                void RouteCoordinator::SetRecoveryJournal(
                    NetworkRecoveryJournal* journal) noexcept {
                    std::lock_guard<std::mutex> lock(operation_mutex_);
                    recovery_journal_ = journal;
                }

                bool RouteCoordinator::RecordRouteIntent(
                    const std::string& target,
                    const std::string& before,
                    const std::string& after) noexcept {
                    return !recovery_journal_ || recovery_journal_->RecordIntent(
                        "route", target, before, after, nullptr);
                }

                bool RouteCoordinator::ConfirmRouteIntent(
                    const std::string& target) noexcept {
                    return !recovery_journal_ || recovery_journal_->Confirm(
                        "route", target, nullptr);
                }

                bool RouteCoordinator::RemoveRouteIntent(
                    const std::string& target) noexcept {
                    return !recovery_journal_ || recovery_journal_->Remove(
                        "route", target, nullptr);
                }

                bool RouteCoordinator::RemoveCreatedRouteIntent(
                    const RouteSpec& route) noexcept {
                    if (!recovery_journal_) {
                        return true;
                    }
                    std::string encoded;
                    if (!SerializeRouteSpecForJournal(route, encoded)) {
                        return false;
                    }
                    std::string stable;
                    const bool have_stable = platform_ &&
                        platform_->PrepareRouteRecoverySnapshot(route, stable) &&
                        !stable.empty();
                    bool complete = true;
                    for (const auto& entry : recovery_journal_->PendingFor("route")) {
                        const bool legacy_match =
                            entry.target.rfind("created:", 0) == 0 &&
                            (entry.before == encoded || entry.after == encoded);
                        const bool stable_match = have_stable &&
                            entry.target == "created-v2:" + stable;
                        if (!legacy_match && !stable_match) {
                            continue;
                        }
                        if (!recovery_journal_->Remove(
                                entry.resource, entry.target, nullptr)) {
                            complete = false;
                        }
                    }
                    return complete;
                }

                bool RouteCoordinator::DeleteCreatedRouteForRollback(
                    const RouteSpec& route) noexcept {
                    std::string key;
                    if (!SerializeRouteSpecForJournal(route, key)) {
                        return false;
                    }
                    // This covers the exact failure window where the host
                    // delete succeeded but durable journal removal did not.
                    // Do not touch the host again; only retry journal cleanup.
                    if (deleted_routes_.find(key) != deleted_routes_.end()) {
                        return true;
                    }

                    bool deleted = false;
                    bool attempted_recovery = false;
                    if (recovery_journal_ && platform_) {
                        std::string stable;
                        if (platform_->PrepareRouteRecoverySnapshot(route, stable) &&
                            !stable.empty()) {
                            const std::string target = "created-v2:" + stable;
                            for (const auto& entry :
                                    recovery_journal_->PendingFor("route")) {
                                if (entry.target == target) {
                                    // The platform method must be idempotent:
                                    // missing means already restored, while a
                                    // conflicting row remains pending.
                                    attempted_recovery = true;
                                    deleted = platform_->DeleteRouteRecovery(stable);
                                    break;
                                }
                            }
                        }
                    }
                    if (!deleted && !attempted_recovery && platform_) {
                        // Legacy records and journal-less operation retain the
                        // existing in-process behavior. Once this succeeds,
                        // deleted_routes_ prevents a second destructive call.
                        deleted = platform_->Delete(route);
                    }
                    if (deleted) {
                        deleted_routes_.insert(std::move(key));
                    }
                    return deleted;
                }

                bool RouteCoordinator::JournalDefaultTarget(
                    const RouteSnapshotPtr& route,
                    std::string& target,
                    std::string& serialized) noexcept {
                    if (!recovery_journal_) {
                        return true;
                    }
                    if (!platform_ || !platform_->SerializeRecoverySnapshot(
                            route, serialized) || serialized.empty()) {
                        return false;
                    }
                    target = "default:" + serialized;
                    return true;
                }

                bool RouteCoordinator::JournalCreatedTarget(
                    const RouteSpec& route,
                    std::string& target,
                    std::string& serialized) noexcept {
                    target.clear();
                    serialized.clear();
                    if (!recovery_journal_) {
                        return true;
                    }
                    // The pre-write record must not contain a deletion-capable
                    // snapshot.  A process may exit before Add(), and a
                    // snapshot of an already-existing route would otherwise
                    // authorize deleting a route OpenPPP2 never created.
                    // PromoteCreatedTarget captures the platform row only
                    // after Add() reports Created.
                    std::string legacy;
                    if (!SerializeRouteSpecForJournal(route, legacy)) {
                        return false;
                    }
                    target = "created:" + legacy;
                    serialized = std::move(legacy);
                    return true;
                }

                bool RouteCoordinator::PromoteCreatedTarget(
                    const RouteSpec& route,
                    std::string& target,
                    std::string& serialized) noexcept {
                    if (!recovery_journal_ || !platform_) {
                        return true;
                    }
                    std::string stable;
                    if (!platform_->PrepareRouteRecoverySnapshot(route, stable) ||
                        stable.empty()) {
                        // Test doubles and platforms without a complete row
                        // codec retain the legacy intent, which remains
                        // fail-closed on a later process restart.
                        return true;
                    }
                    const std::string upgraded = "created-v2:" + stable;
                    if (upgraded == target) {
                        serialized = std::move(stable);
                        return true;
                    }
                    if (!recovery_journal_->ReplaceTarget(
                            "route", target, upgraded, stable, nullptr)) {
                        return false;
                    }
                    target = upgraded;
                    serialized = std::move(stable);
                    return true;
                }

                bool RouteCoordinator::RecoverPendingRoutes() noexcept {
                    std::lock_guard<std::mutex> lock(operation_mutex_);
                    return RecoverPendingRoutesLocked();
                }

                bool RouteCoordinator::RecoverPendingRoutesLocked() noexcept {
                    if (!recovery_journal_) {
                        return true;
                    }
                    if (!platform_) {
                        // A restart has no adapter context until the current
                        // connection supplies it. Do not apply new routes
                        // over an unresolved durable route record.
                        return !recovery_journal_->HasPendingFor("route");
                    }
                    return recovery_journal_->RecoverPendingFor(
                        "route",
                        [this](const NetworkRecoveryJournal::Entry& entry) noexcept {
                            if (entry.target.rfind("default:", 0) == 0) {
                                RouteSnapshotPtr snapshot;
                                const std::string_view bytes(
                                    entry.target.data() + 8,
                                    entry.target.size() - 8);
                                return platform_->DeserializeRecoverySnapshot(
                                    bytes, snapshot) && snapshot &&
                                    platform_->RestoreDefault(snapshot);
                            }
                            if (entry.target.rfind("created-v2:", 0) == 0) {
                                return platform_->DeleteRouteRecovery(
                                    std::string_view(entry.target).substr(11));
                            }
                            // A RouteSpec does not carry enough ownership
                            // information to replay a created route after a
                            // restart.  In particular, the platform Delete
                            // operations cannot prove the current interface
                            // identity or the complete route row.  Keep this
                            // record pending until a platform-specific
                            // compare-and-delete codec is available; deleting
                            // by network/gateway alone could remove a route
                            // recreated by the user or another VPN.
                            return false;
                        }, nullptr);
                }

#if defined(OPENPPP2_ROUTE_TEST_MOBILE)
                void RouteCoordinator::SetStopWaiterObserverForTesting(
                    std::function<void()> observer) noexcept {
                    std::lock_guard<std::mutex> stop_lock(stop_mutex_);
                    stop_waiter_observer_ = std::move(observer);
                }
#endif

                bool RouteCoordinator::SetPlatformLocked(
                    std::unique_ptr<IRoutePlatform> platform) noexcept {
                    const RouteStateSnapshot snapshot = state_.Snapshot();
                    if (!platform || stopped_.load(std::memory_order_acquire) ||
                        snapshot.applied || !snapshot.default_routes.empty()) {
                        return false;
                    }
                    platform_ = std::move(platform);
                    return true;
                }

                void RouteCoordinator::ReplaceRib(RouteInformationTablePtr value) noexcept {
                    state_.ReplaceRib(std::move(value));
                }

                void RouteCoordinator::ReplaceFib(ForwardInformationTablePtr value) noexcept {
                    state_.ReplaceFib(std::move(value));
                }

                void RouteCoordinator::ReplacePeerPrefix(
                    RouteInformationTablePtr rib,
                    ForwardInformationTablePtr fib) noexcept {
                    state_.ReplacePeerPrefix(std::move(rib), std::move(fib));
                }

                void RouteCoordinator::AddNic(
                    uint32_t gateway, std::string interface_name) noexcept {
                    state_.AddNic(gateway, std::move(interface_name));
                }

                void RouteCoordinator::MarkApplyReady(bool value) noexcept {
                    state_.MarkApplyReady(value);
                }

                void RouteCoordinator::Clear() noexcept {
                    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                    const RouteStateSnapshot snapshot = state_.Snapshot();
                    if (snapshot.applied || !snapshot.default_routes.empty()) {
                        return;
                    }
                    state_.Clear();
                }

                bool RouteCoordinator::Apply(const std::vector<RouteSpec>& routes) noexcept {
                    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                    return ApplyLocked(routes);
                }

                bool RouteCoordinator::RollbackApplied() noexcept {
                    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                    StopProtection(protection_);
                    const bool rollback_complete = Rollback(applied_);
                    if (rollback_complete) {
                        protection_.reset();
                    }
                    return rollback_complete;
                }

                bool RouteCoordinator::ApplyLocked(
                    const std::vector<RouteSpec>& routes) noexcept {
                    const auto failure = [](const char* stage) noexcept {
                        ppp::telemetry::Log(Level::kInfo, "route_coordinator",
                            "route apply failed: stage=%s", stage);
                        return false;
                    };
                    if (!ownership_ || !ownership_->IsHeld() ||
                        stopped_.load(std::memory_order_acquire) || NULLPTR == platform_) {
                        return failure("ownership_or_stopped_or_platform");
                    }

                    const RouteStateSnapshot before = state_.Snapshot();
                    if (before.applied || !before.default_routes.empty()) {
                        return failure("transaction_already_present");
                    }

                    // A previous process may have died after a route intent
                    // was persisted. Recover it before accepting new state.
                    // EnsureUnderlyingDefault may have already established a
                    // route for this same transaction. Its durable intent is
                    // owned by this coordinator and must not be replayed as
                    // stale state before the hosted route set is applied.
                    if (applied_.empty() && !RecoverPendingRoutesLocked()) {
                        return failure("recover_pending_routes");
                    }

                    const DefaultRouteCapture defaults = platform_->CaptureDefaults();
                    if (!defaults) {
                        return failure("capture_defaults");
                    }
                    for (const RouteSnapshotPtr& route : *defaults) {
                        if (!route) {
                            continue;
                        }
                        std::string journal_target;
                        std::string journal_snapshot;
                        if (!JournalDefaultTarget(
                                route, journal_target, journal_snapshot) ||
                            !RecordRouteIntent(
                                journal_target, journal_snapshot, {})) {
                            // A previous default may already have been
                            // removed in this transaction. Restore it before
                            // reporting the journal failure.
                            Rollback(applied_);
                            return failure("journal_default_intent");
                        }
                        if (!platform_->RemoveDefault(route)) {
                            Rollback(applied_);
                            return failure("remove_default");
                        }
                        // Publish ownership before confirming the durable
                        // intent.  If the confirm write fails, rollback can
                        // still remove the route and restore this default.
                        RememberDefault(platform_, route);
                        if (!ConfirmRouteIntent(journal_target)) {
                            Rollback(applied_);
                            return failure("confirm_default");
                        }
                    }

                    for (const RouteSpec& route : routes) {
                        std::string encoded;
                        std::string journal_target;
                        if (!JournalCreatedTarget(
                                route, journal_target, encoded) ||
                            (recovery_journal_ && !RecordRouteIntent(
                                journal_target, encoded, {}))) {
                            Rollback(applied_);
                            return failure("journal_created_intent");
                        }
                        const RouteAddResult result = platform_->Add(route);
                        if (result == RouteAddResult::Failed ||
                            result == RouteAddResult::FailedUnchanged) {
                            if (result == RouteAddResult::FailedUnchanged) {
                                RemoveRouteIntent(journal_target);
                            }
                            Rollback(applied_);
                            return failure("add_route");
                        }
                        if (result == RouteAddResult::Created) {
                            applied_.emplace_back(route);
                            if (!PromoteCreatedTarget(
                                    route, journal_target, encoded) ||
                                !ConfirmRouteIntent(journal_target)) {
                                Rollback(applied_);
                                return failure("promote_or_confirm_created");
                            }
                        }
                        else if (recovery_journal_) {
                            // The platform reported that no mutation took
                            // place, so its pre-write intent is no longer
                            // needed.
                            RemoveRouteIntent(journal_target);
                        }
                    }

                    state_.MarkApplied(true);
                    return true;
                }

                bool RouteCoordinator::Stop() noexcept {
                    std::promise<bool> completion;
                    std::shared_future<bool> attempt;
                    bool owner = false;
#if defined(OPENPPP2_ROUTE_TEST_MOBILE)
                    std::function<void()> waiter_observer;
#endif
                    {
                        std::lock_guard<std::mutex> stop_lock(stop_mutex_);
                        if (stop_in_progress_) {
                            attempt = stop_attempt_;
#if defined(OPENPPP2_ROUTE_TEST_MOBILE)
                            waiter_observer = stop_waiter_observer_;
#endif
                        }
                        else {
                            stop_in_progress_ = true;
                            stop_attempt_ = completion.get_future().share();
                            owner = true;
                        }
                    }

                    if (!owner) {
#if defined(OPENPPP2_ROUTE_TEST_MOBILE)
                        if (waiter_observer) {
                            waiter_observer();
                        }
#endif
                        return attempt.get();
                    }

                    bool rollback_complete = false;
                    {
                        std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                        stopped_.store(true, std::memory_order_release);
                        StopProtection(protection_);
                        rollback_complete = Rollback(applied_);
                        if (rollback_complete) {
                            protection_.reset();
                        }
                    }

                    {
                        std::lock_guard<std::mutex> stop_lock(stop_mutex_);
                        stop_in_progress_ = false;
                        completion.set_value(rollback_complete);
                    }
                    return rollback_complete;
                }

                void RouteCoordinator::StopProtection(
                    const std::shared_ptr<ProtectionState>& state) noexcept {
                    if (!state) {
                        return;
                    }
                    state->active.store(false, std::memory_order_release);
                    {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->platform.reset();
                    }
                    if (state->worker.joinable()) {
                        state->worker.join();
                    }
                }

                void RouteCoordinator::RememberDefault(
                    const std::shared_ptr<IRoutePlatform>& platform,
                    const RouteSnapshotPtr& route) noexcept {
                    if (!platform || !route) {
                        return;
                    }
                    const std::vector<RouteSnapshotPtr> pending =
                        state_.Snapshot().default_routes;
                    for (const RouteSnapshotPtr& item : pending) {
                        if (platform->SameDefault(item, route)) {
                            return;
                        }
                    }
                    state_.AppendDefaultRoute(route);
                }

                bool RouteCoordinator::Rollback(std::vector<RouteSpec>& applied) noexcept {
                    bool rollback_complete = true;

                    size_t index = applied.size();
                    while (index > 0) {
                        --index;
                    if (platform_ && DeleteCreatedRouteForRollback(applied[index])) {
                            const bool journal_removed =
                            RemoveCreatedRouteIntent(applied[index]);
                            if (journal_removed) {
                                std::string key;
                                if (SerializeRouteSpecForJournal(
                                        applied[index], key)) {
                                    deleted_routes_.erase(key);
                                }
                                applied.erase(applied.begin() + index);
                            }
                            else {
                                rollback_complete = false;
                            }
                        }
                        else {
                            rollback_complete = false;
                        }
                    }
                    state_.MarkApplied(!applied.empty());

                    const RouteStateSnapshot snapshot = state_.Snapshot();
                    size_t default_index = snapshot.default_routes.size();
                    while (default_index > 0) {
                        --default_index;
                        const RouteSnapshotPtr& route =
                            snapshot.default_routes[default_index];
                        if (platform_ && platform_->RestoreDefault(route)) {
                            bool journal_removed = true;
                            if (recovery_journal_) {
                                std::string target;
                                std::string serialized;
                                journal_removed = JournalDefaultTarget(
                                    route, target, serialized) &&
                                    RemoveRouteIntent(target);
                            }
                            if (journal_removed && !state_.RemoveDefaultRoute(route)) {
                                rollback_complete = false;
                            }
                            else if (!journal_removed) {
                                rollback_complete = false;
                            }
                        }
                        else {
                            rollback_complete = false;
                        }
                    }
                    return rollback_complete && state_.ResetAfterRollback(true);
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool RouteCoordinator::AddRoute(const RoutePlanInput& input) noexcept {
                    ppp::telemetry::SpanScope span("client.route.apply");
                    struct ScopedRouteApplyHistogram final {
                        std::chrono::steady_clock::time_point started_at =
                            std::chrono::steady_clock::now();

                        ~ScopedRouteApplyHistogram() noexcept {
                            const auto elapsed = std::chrono::duration_cast<
                                std::chrono::microseconds>(
                                std::chrono::steady_clock::now() - started_at).count();
                            ppp::telemetry::Histogram("client.route.apply.us", elapsed);
                        }
                    } route_apply_histogram;

                    ppp::telemetry::Log(Level::kDebug, "client", "route add");
                    ppp::telemetry::Count("client.route.add", 1);

                    const RouteStateSnapshot snapshot = Snapshot();
                    const std::vector<RouteSpec> rib_specs = BuildRouteSpecs(snapshot.rib);
                    const routing::HumanRoutingRouteSpecPlan human_plan =
                        routing::BuildHumanRoutingRouteSpecs(
                            input,
                            routing::HumanRoutingRouteEnvironment::Desktop);
                    if (human_plan.invalid_count != 0) {
                        ppp::telemetry::Log(Level::kInfo, "route_coordinator",
                            "route apply failed: stage=invalid_human_route_plan");
                        return false;
                    }
                    DnsRouteSpecPlan dns_plan = BuildDnsRouteSpecs(input);
                    const std::vector<RouteSpec> specs = MergeRouteSpecs(
                        rib_specs, human_plan.routes, dns_plan.routes);
                    {
                        std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                        if (!platform_) {
                            std::unique_ptr<IRoutePlatform> platform = NewPlatform(input);
                            if (!SetPlatformLocked(std::move(platform))) {
                                return false;
                            }
                        }
                        if (!ApplyLocked(specs)) {
                            return false;
                        }
                        state_.ClearDnsServers();
                        for (size_t bucket = 0; bucket < dns_plan.servers.size(); ++bucket) {
                            for (uint32_t ip : dns_plan.servers[bucket]) {
                                state_.AddDnsServer(static_cast<int>(bucket), ip);
                            }
                        }
                    }
                    return true;
                }

                bool RouteCoordinator::DeleteRoute() noexcept {
                    ppp::telemetry::Log(Level::kDebug, "client", "route delete");
                    ppp::telemetry::Count("client.route.delete", 1);
                    return Stop();
                }

                bool RouteCoordinator::AddRoute(
                    const RoutePlanInput& input,
                    uint32_t ip,
                    uint32_t gw,
                    int prefix) noexcept {
                    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                    if (!ownership_ || !ownership_->IsHeld() ||
                        stopped_.load(std::memory_order_acquire) || !platform_ ||
                        !state_.Snapshot().applied) {
                        return false;
                    }
                    RouteSpec route = ResolveRouteSpec(
                        input, RouteSpec{ ip, gw, prefix, {} });
                    std::string encoded;
                    std::string journal_target;
                    if (!JournalCreatedTarget(
                            route, journal_target, encoded) ||
                        (recovery_journal_ && !RecordRouteIntent(
                            journal_target, encoded, {}))) {
                        return false;
                    }
                    const RouteAddResult result = platform_->Add(route);
                    if (result == RouteAddResult::Failed ||
                        result == RouteAddResult::FailedUnchanged) {
                        if (result == RouteAddResult::FailedUnchanged) {
                            RemoveRouteIntent(journal_target);
                        }
                        return false;
                    }
                    if (result == RouteAddResult::Created) {
                        applied_.emplace_back(std::move(route));
                        if (!PromoteCreatedTarget(
                                applied_.back(), journal_target, encoded) ||
                            !ConfirmRouteIntent(journal_target)) {
                            return false;
                        }
                    }
                    else if (recovery_journal_) {
                        RemoveRouteIntent(journal_target);
                    }
                    return true;
                }

                bool RouteCoordinator::DeleteRoute(
                    const RoutePlanInput& input,
                    uint32_t ip,
                    uint32_t gw,
                    int prefix) noexcept {
                    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                    if (stopped_.load(std::memory_order_acquire) || !platform_) {
                        return false;
                    }
                    const RouteSpec route = ResolveRouteSpec(
                        input, RouteSpec{ ip, gw, prefix, {} });
                    const auto match = [&route](const RouteSpec& value) noexcept {
                        return value.network == route.network &&
                            value.gateway == route.gateway &&
                            value.prefix == route.prefix &&
                            value.interface_name == route.interface_name;
                    };
                    const auto tail = std::find_if(applied_.rbegin(), applied_.rend(), match);
                    if (tail == applied_.rend()) {
                        return true;
                    }
                    if (!platform_->Delete(route)) {
                        return false;
                    }
                    if (!RemoveCreatedRouteIntent(route)) {
                        return false;
                    }
                    applied_.erase(std::prev(tail.base()));
                    return true;
                }

                bool RouteCoordinator::EnsureUnderlyingDefault(
                    const RoutePlanInput& input) noexcept {
                    const boost::asio::ip::address& gateway =
                        input.underlying_interface.gateway;
                    if (!gateway.is_v4() || gateway.is_loopback() ||
                        gateway.is_unspecified() || gateway.is_multicast() ||
                        gateway.to_v4() == boost::asio::ip::address_v4::broadcast()) {
                        return false;
                    }

                    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                    if (!ownership_ || !ownership_->IsHeld() ||
                        stopped_.load(std::memory_order_acquire)) {
                        return false;
                    }
                    const RouteSpec route{
                        0,
                        htonl(gateway.to_v4().to_uint()),
                        0,
#if defined(_LINUX)
                        // The NIC mapping is loaded later during startup.
                        // An empty interface would resolve this physical
                        // default through the TAP fallback on Linux.
                        input.underlying_interface.name,
#else
                        {},
#endif
                    };
                    const RouteStateSnapshot snapshot = state_.Snapshot();
                    if (snapshot.applied || !snapshot.default_routes.empty()) {
                        return false;
                    }
                    if (!platform_) {
                        std::unique_ptr<IRoutePlatform> platform = NewPlatform(input);
                        if (!SetPlatformLocked(std::move(platform))) {
                            return false;
                        }
                    }
                    if (!platform_) {
                        return false;
                    }
                    // The platform is created from the current interface
                    // context, so durable route intents can now be replayed
                    // before this connection adds another route.
                    if (!RecoverPendingRoutesLocked()) {
                        return false;
                    }
                    const RouteStateSnapshot recovered = state_.Snapshot();
                    if (recovered.applied || !recovered.default_routes.empty()) {
                        return false;
                    }
                    std::string encoded;
                    std::string journal_target;
                    if (!JournalCreatedTarget(
                            route, journal_target, encoded) ||
                        (recovery_journal_ && !RecordRouteIntent(
                            journal_target, encoded, {}))) {
                        return false;
                    }
                    const RouteAddResult result = platform_->Add(route);
                    if (result == RouteAddResult::Failed ||
                        result == RouteAddResult::FailedUnchanged) {
                        if (result == RouteAddResult::FailedUnchanged) {
                            RemoveRouteIntent(journal_target);
                        }
                        return false;
                    }
                    // A route that already existed is not owned by OpenPPP2.
                    // Only remember routes created here so teardown cannot
                    // remove another program's default route.
                    if (result == RouteAddResult::Created) {
                        applied_.emplace_back(route);
                        if (!PromoteCreatedTarget(
                                route, journal_target, encoded) ||
                            !ConfirmRouteIntent(journal_target)) {
                            return false;
                        }
                    }
                    else if (recovery_journal_) {
                        // No OS mutation occurred, so the write-ahead intent
                        // is no longer needed.
                        RemoveRouteIntent(journal_target);
                    }
                    return true;
                }

                bool RouteCoordinator::ProtectDefaultRoute(
                    const RoutePlanInput& input) noexcept {
                    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                    std::shared_ptr<ProtectionState> previous = std::move(protection_);
                    StopProtection(previous);
                    if (input.tap_promiscuous ||
                        stopped_.load(std::memory_order_acquire) || !platform_) {
                        return false;
                    }

                    std::shared_ptr<ProtectionState> current =
                        std::make_shared<ProtectionState>();
                    current->platform = platform_;
                    current->active.store(true, std::memory_order_release);
                    protection_ = current;
                    current->worker = std::thread([this, current]() noexcept {
                        ppp::SetThreadName("protector");
                        while (current->active.load(std::memory_order_acquire)) {
                            const uint64_t start = ppp::GetTickCount();
                            {
                                std::lock_guard<std::mutex> lock(current->mutex);
                                if (!current->active.load(std::memory_order_acquire) ||
                                    !current->platform) {
                                    break;
                                }
                                const DefaultRouteCapture defaults =
                                    current->platform->CaptureDefaults();
                                if (!defaults) {
                                    current->active.store(
                                        false, std::memory_order_release);
                                    break;
                                }
                                for (const RouteSnapshotPtr& route : *defaults) {
                                    if (!route) {
                                        continue;
                                    }
                                    std::string journal_target;
                                    std::string journal_snapshot;
                                    if (!JournalDefaultTarget(
                                            route, journal_target, journal_snapshot) ||
                                        !RecordRouteIntent(
                                            journal_target, journal_snapshot, {})) {
                                        current->active.store(
                                            false, std::memory_order_release);
                                        break;
                                    }
                                    if (!current->platform->RemoveDefault(route)) {
                                        current->active.store(
                                            false, std::memory_order_release);
                                        break;
                                    }
                                    RememberDefault(current->platform, route);
                                    if (!ConfirmRouteIntent(journal_target)) {
                                        current->active.store(
                                            false, std::memory_order_release);
                                        break;
                                    }
                                }
                            }

                            if (!current->active.load(std::memory_order_acquire)) {
                                break;
                            }

                            const uint64_t now = ppp::GetTickCount();
                            const uint64_t delay = now >= start
                                ? 1000 - std::min<uint64_t>(1000, now - start)
                                : 0;
                            ppp::Sleep(delay);
                        }
                    });
                    return true;
                }
#endif

            }
        }
    }
}
