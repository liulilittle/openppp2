#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ppp::app::client::policy {

struct PolicyUpdateStatus;

struct PolicyStatusCounters final {
    std::uint64_t dns_cache_hits = 0;
    std::uint64_t dns_cache_misses = 0;
    std::uint64_t dns_cache_coalesced = 0;
    std::uint64_t dns_timeout_attempts = 0;
    std::uint64_t dns_timeouts = 0;
    std::uint64_t dns_upstream_failures = 0;
    std::uint64_t dns_cancelled = 0;
    std::uint64_t fake_ip_mappings = 0;
    std::uint64_t fake_ip_exhaustions = 0;
    std::uint64_t fake_ip_persistence_errors = 0;
    std::uint64_t fake_ip_pending = 0;
    std::uint64_t policy_direct = 0;
    std::uint64_t policy_proxy = 0;
    std::uint64_t policy_reject = 0;
};

struct PolicyStatusSource final {
    std::string name;
    std::string url_redacted;
    std::string etag;
    std::string last_modified;
    std::string sha256;
    std::uint64_t bytes = 0;
    std::int64_t validated_at_ms = 0;
};

struct PolicyStatusRecord final {
    std::uint32_t schema = 1;
    std::string identity;
    std::uint64_t pid = 0;
    std::string process_start;
    std::int64_t updated_at_ms = 0;
    std::uint64_t session_generation = 0;
    std::uint64_t active_version = 0;
    std::uint64_t prepared_version = 0;
    std::string prepared_digest;
    std::string durable_current;
    std::string durable_previous;
    std::int64_t last_attempt_ms = 0;
    std::int64_t last_success_ms = 0;
    std::int64_t next_attempt_ms = 0;
    std::string last_result;
    std::string last_diagnostic;
    bool offline = false;
    PolicyStatusCounters counters;
    std::vector<PolicyStatusSource> sources;
};

enum class PolicyStatusState {
    Online,
    Offline,
    Stale,
    Unverified
};

struct PolicyStatusResult final {
    PolicyStatusState state = PolicyStatusState::Offline;
    PolicyStatusRecord record;
    std::string reason;
};

PolicyStatusRecord MakePolicyStatusRecord(const PolicyUpdateStatus& status,
    std::uint64_t pid, const std::string& processStart, std::uint64_t sessionGeneration,
    std::int64_t updatedAtMs, bool offline);
PolicyStatusRecord MakePolicyStatusRecord(const PolicyUpdateStatus& status,
    const PolicyStatusCounters& counters, std::uint64_t pid, const std::string& processStart,
    std::uint64_t sessionGeneration, std::int64_t updatedAtMs, bool offline);

class PolicyStatusWriterLease final {
public:
    PolicyStatusWriterLease() noexcept;
    ~PolicyStatusWriterLease();
    PolicyStatusWriterLease(PolicyStatusWriterLease&& other) noexcept;
    PolicyStatusWriterLease& operator=(PolicyStatusWriterLease&& other) noexcept;
    PolicyStatusWriterLease(const PolicyStatusWriterLease&) = delete;
    PolicyStatusWriterLease& operator=(const PolicyStatusWriterLease&) = delete;

    bool TryAcquire(const std::string& statusPath, const std::string& expectedIdentity,
        std::string& error);
    bool Write(const PolicyStatusRecord& status, std::string& error) const;
    bool OwnsLease() const noexcept;
    void Release() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

bool WriteStatusAtomically(const std::string& path, const std::string& expectedIdentity,
    const PolicyStatusRecord& status, std::string& error);

// Unsupported platforms return the "unverified" token; readers never mark it online.
bool GetCurrentProcessIdentity(std::uint64_t& pid, std::string& processStart,
    std::string& error);

PolicyStatusResult ReadStatus(const std::string& path, const std::string& expectedIdentity,
    std::int64_t nowMs, std::int64_t staleAfterMs = 120000);

const char* PolicyStatusStateName(PolicyStatusState state) noexcept;

} // namespace ppp::app::client::policy
