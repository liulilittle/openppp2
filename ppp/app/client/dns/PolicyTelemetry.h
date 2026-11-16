#pragma once

#include <ppp/app/client/dns/DurableFakeIpStore.h>
#include <ppp/app/client/policy/PolicyModel.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ppp::app::client::dns {

// DNS fields count requests/events. Policy fields count terminal DNS decisions
// per query and routed-flow decisions per new flow; fake_ip_pending is a live
// request gauge. The snapshot contains no query or hostname data.
struct PolicyTelemetrySnapshot final {
    uint64_t dns_cache_hits = 0;
    uint64_t dns_cache_misses = 0;
    uint64_t dns_cache_coalesced = 0;
    uint64_t dns_timeout_attempts = 0;
    uint64_t dns_timeouts = 0;
    uint64_t dns_upstream_failures = 0;
    uint64_t dns_cancelled = 0;
    uint64_t fake_ip_mappings = 0;
    uint64_t fake_ip_exhaustions = 0;
    uint64_t fake_ip_persistence_errors = 0;
    uint64_t fake_ip_pending = 0;
    uint64_t policy_direct = 0;
    uint64_t policy_proxy = 0;
    uint64_t policy_reject = 0;
};

// One instance belongs to one client session/service. It has no process-global state.
class PolicyTelemetry final {
public:
    void RecordDnsCacheHit() noexcept { dns_cache_hits_.fetch_add(1, std::memory_order_relaxed); }
    void RecordDnsCacheMiss() noexcept { dns_cache_misses_.fetch_add(1, std::memory_order_relaxed); }
    void RecordDnsCacheCoalesced() noexcept { dns_cache_coalesced_.fetch_add(1, std::memory_order_relaxed); }
    void RecordDnsTimeoutAttempt() noexcept { dns_timeout_attempts_.fetch_add(1, std::memory_order_relaxed); }
    void RecordDnsTimeout() noexcept { dns_timeouts_.fetch_add(1, std::memory_order_relaxed); }
    void RecordDnsUpstreamFailure() noexcept { dns_upstream_failures_.fetch_add(1, std::memory_order_relaxed); }
    void RecordDnsCancelled() noexcept { dns_cancelled_.fetch_add(1, std::memory_order_relaxed); }
    void RecordPolicyDirect() noexcept { policy_direct_.fetch_add(1, std::memory_order_relaxed); }
    void RecordPolicyProxy() noexcept { policy_proxy_.fetch_add(1, std::memory_order_relaxed); }
    void RecordPolicyReject() noexcept { policy_reject_.fetch_add(1, std::memory_order_relaxed); }
    void RecordPolicyDecision(policy::PolicyAction action) noexcept {
        switch (action) {
        case policy::PolicyAction::Direct: RecordPolicyDirect(); break;
        case policy::PolicyAction::Proxy: RecordPolicyProxy(); break;
        case policy::PolicyAction::Reject: RecordPolicyReject(); break;
        }
    }

    void AddFakeIpPending(std::ptrdiff_t delta) noexcept {
        int64_t current = fake_ip_pending_.load(std::memory_order_relaxed);
        for (;;) {
            int64_t next = current;
            if (delta > 0) {
                const auto amount = static_cast<uint64_t>(delta);
                next = amount > static_cast<uint64_t>(INT64_MAX - current)
                    ? INT64_MAX : current + static_cast<int64_t>(amount);
            } else if (delta < 0) {
                const auto amount = static_cast<uint64_t>(-(delta + 1)) + 1;
                next = amount >= static_cast<uint64_t>(current) ? 0 : current - static_cast<int64_t>(amount);
            }
            if (fake_ip_pending_.compare_exchange_weak(current, next,
                    std::memory_order_relaxed, std::memory_order_relaxed)) return;
        }
    }

    PolicyTelemetrySnapshot Snapshot(const DurableFakeIpStore::Stats& store = {}) const noexcept {
        PolicyTelemetrySnapshot result;
        result.dns_cache_hits = dns_cache_hits_.load(std::memory_order_relaxed);
        result.dns_cache_misses = dns_cache_misses_.load(std::memory_order_relaxed);
        result.dns_cache_coalesced = dns_cache_coalesced_.load(std::memory_order_relaxed);
        result.dns_timeout_attempts = dns_timeout_attempts_.load(std::memory_order_relaxed);
        result.dns_timeouts = dns_timeouts_.load(std::memory_order_relaxed);
        result.dns_upstream_failures = dns_upstream_failures_.load(std::memory_order_relaxed);
        result.dns_cancelled = dns_cancelled_.load(std::memory_order_relaxed);
        result.fake_ip_mappings = store.fake_ip_mappings;
        result.fake_ip_exhaustions = store.fake_ip_exhaustions;
        result.fake_ip_persistence_errors = store.fake_ip_persistence_errors;
        result.fake_ip_pending = static_cast<uint64_t>(fake_ip_pending_.load(std::memory_order_relaxed));
        result.policy_direct = policy_direct_.load(std::memory_order_relaxed);
        result.policy_proxy = policy_proxy_.load(std::memory_order_relaxed);
        result.policy_reject = policy_reject_.load(std::memory_order_relaxed);
        return result;
    }

private:
    std::atomic<uint64_t> dns_cache_hits_{0};
    std::atomic<uint64_t> dns_cache_misses_{0};
    std::atomic<uint64_t> dns_cache_coalesced_{0};
    std::atomic<uint64_t> dns_timeout_attempts_{0};
    std::atomic<uint64_t> dns_timeouts_{0};
    std::atomic<uint64_t> dns_upstream_failures_{0};
    std::atomic<uint64_t> dns_cancelled_{0};
    std::atomic<int64_t> fake_ip_pending_{0};
    std::atomic<uint64_t> policy_direct_{0};
    std::atomic<uint64_t> policy_proxy_{0};
    std::atomic<uint64_t> policy_reject_{0};
};

} // namespace ppp::app::client::dns
