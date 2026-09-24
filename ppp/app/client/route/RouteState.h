#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/net/native/rib_fwd.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                using RouteInformationTablePtr = std::shared_ptr<ppp::net::native::RouteInformationTable>;
                using ForwardInformationTablePtr = std::shared_ptr<ppp::net::native::ForwardInformationTable>;

                struct RouteStateSnapshot final {
                    RouteInformationTablePtr rib;
                    ForwardInformationTablePtr fib;
                    RouteInformationTablePtr peer_prefix_rib;
                    ForwardInformationTablePtr peer_prefix_fib;
                    std::vector<RouteSnapshotPtr> default_routes;
                    std::unordered_map<uint32_t, std::string> nics;
                    std::array<std::unordered_set<uint32_t>, 3> dns_servers;
                    bool applied = false;
                    bool apply_ready = false;
                };

                class RouteState final {
                public:
                    RouteStateSnapshot Snapshot() const noexcept;

                    void ReplaceRib(RouteInformationTablePtr value) noexcept;
                    void ReplaceFib(ForwardInformationTablePtr value) noexcept;
                    void ReplacePeerPrefix(
                        RouteInformationTablePtr rib,
                        ForwardInformationTablePtr fib) noexcept;
                    void AppendDefaultRoute(RouteSnapshotPtr value) noexcept;
                    bool RemoveDefaultRoute(const RouteSnapshotPtr& value) noexcept;
                    void ClearDefaultRoutes() noexcept;
                    void ReplaceNics(std::unordered_map<uint32_t, std::string> value) noexcept;
                    void AddNic(uint32_t gateway, std::string interface_name) noexcept;

                    void AddDnsServer(int bucket, uint32_t ip) noexcept;
                    void ClearDnsServers() noexcept;
                    void DeduplicateDnsServers() noexcept;

                    void MarkApplied(bool value) noexcept;
                    void MarkApplyReady(bool value) noexcept;
                    bool ResetAfterRollback(bool rollback_complete) noexcept;
                    void Clear() noexcept;

                private:
                    mutable std::mutex syncobj_;
                    RouteStateSnapshot value_;
                };

            }
        }
    }
}
