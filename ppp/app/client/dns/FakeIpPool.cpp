#include "FakeIpPool.h"

#include <ppp/net/Ipep.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static bool ParseCidr(
                    const ppp::string& cidr,
                    uint32_t& network_host,
                    uint32_t& mask_host,
                    int& prefix) noexcept {

                    ppp::string text = ATrim(cidr);
                    if (text.empty()) {
                        return false;
                    }

                    std::size_t slash = text.find('/');
                    if (slash == ppp::string::npos) {
                        return false;
                    }

                    ppp::string ip_text = ATrim(text.substr(0, slash));
                    ppp::string prefix_text = ATrim(text.substr(slash + 1));
                    prefix = atoi(prefix_text.data());
                    if (prefix < 1 || prefix > 32) {
                        return false;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address_v4 addr =
                        boost::asio::ip::make_address_v4(ip_text, ec);
                    if (ec) {
                        return false;
                    }

                    network_host = addr.to_uint();
                    if (prefix == 32) {
                        mask_host = 0xFFFFFFFFu;
                    }
                    else {
                        mask_host = (0xFFFFFFFFu << (32 - prefix));
                    }

                    network_host &= mask_host;
                    return true;
                }

                bool FakeIpPool::Configure(const ppp::string& cidr) noexcept {
                    uint32_t network_host = 0;
                    uint32_t mask_host = 0;
                    int prefix = 0;
                    if (!ParseCidr(cidr, network_host, mask_host, prefix)) {
                        Clear();
                        return false;
                    }

                    std::lock_guard<std::mutex> lock(sync_);
                    by_fake_ip_.clear();
                    by_hostname_.clear();
                    enabled_ = true;
                    pool_network_host_ = network_host;
                    pool_mask_host_ = mask_host;
                    pool_start_host_ = network_host + 4;
                    pool_end_host_ = network_host | (~mask_host);
                    if (pool_end_host_ <= pool_start_host_) {
                        pool_start_host_ = network_host + 1;
                    }
                    cursor_host_ = pool_start_host_;
                    route_network_ = htonl(network_host);
                    route_prefix_ = prefix;
                    return true;
                }

                void FakeIpPool::Clear() noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    enabled_ = false;
                    pool_network_host_ = 0;
                    pool_mask_host_ = 0;
                    pool_start_host_ = 0;
                    pool_end_host_ = 0;
                    route_network_ = 0;
                    route_prefix_ = 0;
                    cursor_host_ = 0;
                    by_fake_ip_.clear();
                    by_hostname_.clear();
                }

                bool FakeIpPool::IsEnabled() const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    return enabled_;
                }

                bool FakeIpPool::ContainsHostOrder(uint32_t ip_host) const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_) {
                        return false;
                    }
                    return (ip_host & pool_mask_host_) == pool_network_host_;
                }

                FakeIpPool::EntrySnapshot FakeIpPool::Snapshot(const Entry& entry) noexcept {
                    EntrySnapshot snapshot;
                    snapshot.hostname = entry.hostname;
                    snapshot.fake_ip_host = entry.fake_ip_host;
                    snapshot.real_ip_host = entry.real_ip_host;
                    snapshot.action = entry.action;
                    snapshot.domain_matched = entry.domain_matched;
                    snapshot.is_resolving = entry.is_resolving;
                    snapshot.is_resolved = entry.is_resolved;
                    return snapshot;
                }

                FakeIpPool::AllocationResult FakeIpPool::Allocate(
                    const ppp::string& hostname,
                    routing::RoutingAction action,
                    bool domain_matched) noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    AllocationResult result;
                    if (!enabled_ || hostname.empty()) {
                        return result;
                    }

                    auto found = by_hostname_.find(hostname);
                    if (found != by_hostname_.end()) {
                        Entry& entry = by_fake_ip_[found->second];
                        if (!entry.is_resolved && !entry.is_resolving) {
                            entry.is_resolving = true;
                            result.should_resolve = true;
                        }
                        result.entry = Snapshot(entry);
                        return result;
                    }

                    uint32_t candidate = cursor_host_;
                    bool available = false;
                    for (std::size_t i = 0; i <= (pool_end_host_ - pool_start_host_); ++i) {
                        if (candidate > pool_end_host_) {
                            candidate = pool_start_host_;
                        }
                        if (by_fake_ip_.find(candidate) == by_fake_ip_.end()) {
                            available = true;
                            break;
                        }
                        ++candidate;
                    }

                    if (!available) {
                        return result;
                    }

                    cursor_host_ = candidate + 1;
                    if (cursor_host_ > pool_end_host_) {
                        cursor_host_ = pool_start_host_;
                    }

                    Entry entry;
                    entry.hostname = hostname;
                    entry.fake_ip_host = candidate;
                    entry.action = action;
                    entry.domain_matched = domain_matched;
                    entry.is_resolving = true;
                    by_fake_ip_[candidate] = entry;
                    by_hostname_[hostname] = candidate;
                    result.entry = Snapshot(entry);
                    result.created = true;
                    result.should_resolve = true;
                    return result;
                }

                uint32_t FakeIpPool::Allocate(const ppp::string& hostname) noexcept {
                    return Allocate(hostname, routing::RoutingAction::Auto, false).entry.fake_ip_host;
                }

                bool FakeIpPool::SetResolved(
                    const ppp::string& hostname,
                    uint32_t real_ip_host,
                    routing::RoutingAction action) noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_ || hostname.empty() || real_ip_host == 0) {
                        return false;
                    }

                    auto found = by_hostname_.find(hostname);
                    if (found == by_hostname_.end()) {
                        return false;
                    }

                    Entry& entry = by_fake_ip_[found->second];
                    entry.real_ip_host = real_ip_host;
                    if (!entry.domain_matched) {
                        entry.action = action;
                    }
                    entry.is_resolving = false;
                    entry.is_resolved = true;
                    return true;
                }

                void FakeIpPool::SetResolveFailed(const ppp::string& hostname) noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    auto found = by_hostname_.find(hostname);
                    if (found != by_hostname_.end()) {
                        by_fake_ip_[found->second].is_resolving = false;
                    }
                }

                void FakeIpPool::SetRealIp(const ppp::string& hostname, uint32_t real_ip_host) noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_ || hostname.empty() || real_ip_host == 0) {
                        return;
                    }
                    auto found = by_hostname_.find(hostname);
                    if (found == by_hostname_.end()) {
                        return;
                    }
                    Entry& entry = by_fake_ip_[found->second];
                    entry.real_ip_host = real_ip_host;
                    entry.is_resolving = false;
                    entry.is_resolved = true;
                }

                bool FakeIpPool::Lookup(uint32_t fake_ip_host, EntrySnapshot& entry) const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    auto found = by_fake_ip_.find(fake_ip_host);
                    if (found == by_fake_ip_.end()) {
                        entry = EntrySnapshot{};
                        return false;
                    }
                    entry = Snapshot(found->second);
                    return true;
                }

                uint32_t FakeIpPool::LookupRealIpHostOrder(uint32_t fake_ip_host) const noexcept {
                    EntrySnapshot entry;
                    return Lookup(fake_ip_host, entry) && entry.is_resolved ? entry.real_ip_host : 0;
                }

                ppp::string FakeIpPool::LookupHostname(uint32_t fake_ip_host) const noexcept {
                    EntrySnapshot entry;
                    return Lookup(fake_ip_host, entry) ? entry.hostname : ppp::string{};
                }

                bool FakeIpPool::GetRoute(uint32_t& route_network, int& route_prefix) const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_) {
                        route_network = 0;
                        route_prefix = 0;
                        return false;
                    }

                    route_network = route_network_;
                    route_prefix = route_prefix_;
                    return true;
                }

            }
        }
    }
}
