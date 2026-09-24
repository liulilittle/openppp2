#pragma once

/**
 * @file FakeIpPool.h
 * @brief Clash-style fake-ip allocation and hostname mapping (Plan C).
 */

#include <ppp/stdafx.h>
#include <ppp/app/client/routing/HumanRoutingRules.h>

#include <mutex>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                class FakeIpPool final {
                public:
                    struct EntrySnapshot final {
                        ppp::string hostname;
                        uint32_t fake_ip_host = 0;
                        uint32_t real_ip_host = 0;
                        routing::RoutingAction action = routing::RoutingAction::Auto;
                        bool domain_matched = false;
                        bool is_resolving = false;
                        bool is_resolved = false;
                    };

                    struct AllocationResult final {
                        EntrySnapshot entry;
                        bool created = false;
                        bool should_resolve = false;
                    };

                    FakeIpPool() noexcept {}

                    /** @brief Configures the assignable IPv4 range (e.g. "198.18.0.1/16"). */
                    bool Configure(const ppp::string& cidr) noexcept;

                    void Clear() noexcept;

                    bool IsEnabled() const noexcept;

                    /** @brief Returns true when @p ip_host is inside the configured pool. */
                    bool ContainsHostOrder(uint32_t ip_host) const noexcept;

                    AllocationResult Allocate(
                        const ppp::string& hostname,
                        routing::RoutingAction action,
                        bool domain_matched) noexcept;

                    /** @brief Legacy wrapper returning only the allocated fake address. */
                    uint32_t Allocate(const ppp::string& hostname) noexcept;

                    bool SetResolved(
                        const ppp::string& hostname,
                        uint32_t real_ip_host,
                        routing::RoutingAction action) noexcept;
                    void SetResolveFailed(const ppp::string& hostname) noexcept;

                    /** @brief Legacy wrapper preserving the entry's sticky routing action. */
                    void SetRealIp(const ppp::string& hostname, uint32_t real_ip_host) noexcept;

                    bool Lookup(uint32_t fake_ip_host, EntrySnapshot& entry) const noexcept;

                    /** @brief Looks up the real destination if known; 0 when unresolved. */
                    uint32_t LookupRealIpHostOrder(uint32_t fake_ip_host) const noexcept;

                    ppp::string LookupHostname(uint32_t fake_ip_host) const noexcept;

                    bool GetRoute(uint32_t& route_network, int& route_prefix) const noexcept;

                private:
                    struct Entry {
                        ppp::string hostname;
                        uint32_t fake_ip_host = 0;
                        uint32_t real_ip_host = 0;
                        routing::RoutingAction action = routing::RoutingAction::Auto;
                        bool domain_matched = false;
                        bool is_resolving = false;
                        bool is_resolved = false;
                    };

                    static EntrySnapshot Snapshot(const Entry& entry) noexcept;

                    mutable std::mutex sync_;
                    bool enabled_ = false;
                    uint32_t pool_network_host_ = 0;
                    uint32_t pool_mask_host_ = 0;
                    uint32_t pool_start_host_ = 0;
                    uint32_t pool_end_host_ = 0;
                    uint32_t route_network_ = 0;
                    int route_prefix_ = 0;
                    uint32_t cursor_host_ = 0;
                    ppp::unordered_map<uint32_t, Entry> by_fake_ip_;
                    ppp::unordered_map<ppp::string, uint32_t> by_hostname_;
                };

            }
        }
    }
}
