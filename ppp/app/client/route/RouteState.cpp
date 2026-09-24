#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteState.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                RouteStateSnapshot RouteState::Snapshot() const noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    return value_;
                }

                void RouteState::ReplaceRib(RouteInformationTablePtr value) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.rib = std::move(value);
                }

                void RouteState::ReplaceFib(ForwardInformationTablePtr value) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.fib = std::move(value);
                }

                void RouteState::ReplacePeerPrefix(
                    RouteInformationTablePtr rib,
                    ForwardInformationTablePtr fib) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.peer_prefix_rib = std::move(rib);
                    value_.peer_prefix_fib = std::move(fib);
                }

                void RouteState::AppendDefaultRoute(RouteSnapshotPtr value) noexcept {
                    if (!value) {
                        return;
                    }
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.default_routes.emplace_back(std::move(value));
                }

                bool RouteState::RemoveDefaultRoute(const RouteSnapshotPtr& value) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    const auto item = std::find(
                        value_.default_routes.begin(), value_.default_routes.end(), value);
                    if (item == value_.default_routes.end()) {
                        return false;
                    }
                    value_.default_routes.erase(item);
                    return true;
                }

                void RouteState::ClearDefaultRoutes() noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.default_routes.clear();
                }

                void RouteState::ReplaceNics(std::unordered_map<uint32_t, std::string> value) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.nics = std::move(value);
                }

                void RouteState::AddNic(uint32_t gateway, std::string interface_name) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.nics[gateway] = std::move(interface_name);
                }

                void RouteState::AddDnsServer(int bucket, uint32_t ip) noexcept {
                    if (bucket < 0 || bucket >= static_cast<int>(value_.dns_servers.size())) {
                        return;
                    }

                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.dns_servers[static_cast<size_t>(bucket)].emplace(ip);
                }

                void RouteState::ClearDnsServers() noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    for (auto& servers : value_.dns_servers) {
                        servers.clear();
                    }
                }

                void RouteState::DeduplicateDnsServers() noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    auto& direct = value_.dns_servers[0];
                    auto& routed = value_.dns_servers[1];
                    for (auto tail = routed.begin(); tail != routed.end();) {
                        if (direct.find(*tail) != direct.end()) {
                            tail = routed.erase(tail);
                        }
                        else {
                            ++tail;
                        }
                    }
                }

                void RouteState::MarkApplied(bool value) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.applied = value;
                }

                void RouteState::MarkApplyReady(bool value) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_.apply_ready = value;
                }

                bool RouteState::ResetAfterRollback(bool rollback_complete) noexcept {
                    if (!rollback_complete) {
                        return false;
                    }

                    std::lock_guard<std::mutex> scope(syncobj_);
                    if (!value_.default_routes.empty()) {
                        return false;
                    }
                    value_.applied = false;
                    return true;
                }

                void RouteState::Clear() noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    value_ = RouteStateSnapshot();
                }

            }
        }
    }
}
