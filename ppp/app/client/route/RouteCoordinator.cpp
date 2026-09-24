#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteCoordinator.h>
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
                    : platform_(std::move(platform)) {
                }

                RouteCoordinator::~RouteCoordinator() noexcept {
                    Stop();
                }

                RouteStateSnapshot RouteCoordinator::Snapshot() const noexcept {
                    return state_.Snapshot();
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

                bool RouteCoordinator::ApplyLocked(
                    const std::vector<RouteSpec>& routes) noexcept {
                    if (stopped_.load(std::memory_order_acquire) || NULLPTR == platform_) {
                        return false;
                    }

                    const RouteStateSnapshot before = state_.Snapshot();
                    if (before.applied || !before.default_routes.empty()) {
                        return false;
                    }

                    const DefaultRouteCapture defaults = platform_->CaptureDefaults();
                    if (!defaults) {
                        return false;
                    }
                    for (const RouteSnapshotPtr& route : *defaults) {
                        if (!route) {
                            continue;
                        }
                        if (!platform_->RemoveDefault(route)) {
                            Rollback(applied_);
                            return false;
                        }
                        RememberDefault(platform_, route);
                    }

                    for (const RouteSpec& route : routes) {
                        const RouteAddResult result = platform_->Add(route);
                        if (result == RouteAddResult::Failed) {
                            Rollback(applied_);
                            return false;
                        }
                        if (result == RouteAddResult::Created) {
                            applied_.emplace_back(route);
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
                        if (platform_ && platform_->Delete(applied[index])) {
                            applied.erase(applied.begin() + index);
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
                            if (!state_.RemoveDefaultRoute(route)) {
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
                    if (stopped_.load(std::memory_order_acquire) || !platform_ ||
                        !state_.Snapshot().applied) {
                        return false;
                    }
                    RouteSpec route = ResolveRouteSpec(
                        input, RouteSpec{ ip, gw, prefix, {} });
                    const RouteAddResult result = platform_->Add(route);
                    if (result == RouteAddResult::Failed) {
                        return false;
                    }
                    if (result == RouteAddResult::Created) {
                        applied_.emplace_back(std::move(route));
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
                    if (stopped_.load(std::memory_order_acquire)) {
                        return false;
                    }
                    std::unique_ptr<IRoutePlatform> platform = NewPlatform(input);
                    return platform && platform->Add(RouteSpec{
                        0,
                        htonl(gateway.to_v4().to_uint()),
                        0,
                        {},
                    }) != RouteAddResult::Failed;
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
                                    if (!current->platform->RemoveDefault(route)) {
                                        current->active.store(
                                            false, std::memory_order_release);
                                        break;
                                    }
                                    RememberDefault(current->platform, route);
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
