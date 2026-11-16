#pragma once

#include "DurablePolicyBundle.h"
#include "PolicyModel.h"
#include "PolicyRuntime.h"
#include "PolicySourceLoader.h"
#include "PolicyUpdateFetcher.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace ppp::app::client::policy {

enum class PolicyUpdateMode { CommitRuntime, PrepareOnly };
enum class PolicyUpdateResultCode { Updated, Unchanged, Prepared, Failed, RequiresReconnect, Closed };

struct PolicyUpdateResult final {
    PolicyUpdateResultCode code = PolicyUpdateResultCode::Failed;
    std::uint64_t version = 0;
    std::string diagnostic;
    bool Ok() const noexcept {
        return code == PolicyUpdateResultCode::Updated || code == PolicyUpdateResultCode::Unchanged ||
            code == PolicyUpdateResultCode::Prepared;
    }
};

enum class PolicyBootstrapState { Closed, Ready, Failed };

class PolicyBootstrapGate final {
public:
    PolicyBootstrapState State() const noexcept;
    bool AllowsBusiness() const noexcept;
    void Open() noexcept;
    void Fail() noexcept;
    void Close() noexcept;

private:
    std::atomic<PolicyBootstrapState> state_{PolicyBootstrapState::Closed};
};

struct PolicyUpdateSourceStatus final {
    std::string name;
    std::string url_redacted;
    std::string etag;
    std::string last_modified;
    std::string sha256;
    std::size_t bytes = 0;
    std::int64_t validated_at_ms = 0;
};

struct PolicyUpdateStatus final {
    std::uint64_t active_version = 0;
    std::string identity_fingerprint;
    bool durable_current = false;
    bool durable_previous = false;
    bool prepared_pending_commit = false;
    std::uint64_t prepared_version = 0;
    std::string prepared_digest;
    bool offline = false;
    std::int64_t last_attempt_ms = 0;
    std::int64_t last_success_ms = 0;
    std::int64_t next_attempt_ms = 0;
    std::string last_result;
    std::string last_diagnostic;
    std::vector<PolicyUpdateSourceStatus> sources;
};

class PolicyUpdateClock {
public:
    virtual ~PolicyUpdateClock() = default;
    virtual std::chrono::system_clock::time_point Now() const = 0;
    virtual void WaitUntil(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
        std::chrono::system_clock::time_point deadline, const std::function<bool()>& interrupted) = 0;
};

class SystemPolicyUpdateClock final : public PolicyUpdateClock {
public:
    std::chrono::system_clock::time_point Now() const override;
    void WaitUntil(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
        std::chrono::system_clock::time_point deadline, const std::function<bool()>& interrupted) override;
};

class PolicyUpdateService final {
public:
    PolicyUpdateService(PolicyRuntime& runtime, PolicySource declared_source,
        std::shared_ptr<DurablePolicyBundleStore> store,
        std::shared_ptr<PolicyUpdateFetcher> fetcher,
        std::shared_ptr<PolicyUpdateClock> clock = std::make_shared<SystemPolicyUpdateClock>(),
        std::function<PolicyLoadResult()> declaration_loader = {});
    ~PolicyUpdateService();

    PolicyUpdateResult RestoreAndPrepare();
    PolicyUpdateResult BootstrapUpdate();
    PolicyUpdateResult RunOnce(PolicyUpdateMode mode = PolicyUpdateMode::CommitRuntime);
    PolicyUpdateResult CheckImmutableConfiguration(const PolicySource& candidate) const;
    bool Start();
    void Trigger();
    void Close() noexcept;
    PolicyUpdateStatus Status() const;
    // Sink callbacks run without the status mutex and must not re-enter this service.
    void SetStatusSink(std::function<void(const PolicyUpdateStatus&)> sink);
    void SetFetcher(std::shared_ptr<PolicyUpdateFetcher> fetcher);
    PolicyBootstrapGate& Gate() noexcept { return gate_; }
    const std::string& IdentityFingerprint() const noexcept { return identity_fingerprint_; }

    static std::string ImmutableFingerprint(const PolicySource& source);

private:
    struct Materialized;
    PolicyUpdateResult RunOnceLocked(PolicyUpdateMode mode);
    PolicyUpdateResult RestoreBundle(const DurablePolicyLoad& loaded, bool fallback, const PolicySource& declaration);
    bool LoadDeclaration(PolicySource& source, std::string& error) const;
    void Worker();
    void RecordResult(const PolicyUpdateResult& result, bool attempt);
    void PublishStatus();

    PolicyRuntime& runtime_;
    const PolicySource declared_source_;
    const std::shared_ptr<DurablePolicyBundleStore> store_;
    std::shared_ptr<PolicyUpdateFetcher> fetcher_;
    const std::shared_ptr<PolicyUpdateClock> clock_;
    const std::function<PolicyLoadResult()> declaration_loader_;
    const std::string identity_fingerprint_;
    mutable std::mutex operation_mutex_;
    mutable std::mutex fetcher_mutex_;
    std::mutex lifecycle_mutex_;
    std::mutex publication_mutex_;
    mutable std::mutex status_mutex_;
    std::mutex worker_mutex_;
    std::condition_variable worker_cv_;
    std::thread worker_;
    std::shared_ptr<std::atomic_bool> cancellation_;
    std::atomic_bool closed_{false};
    bool started_ = false;
    bool triggered_ = false;
    std::chrono::system_clock::time_point next_attempt_{};
    std::chrono::seconds backoff_{60};
    PolicyUpdateStatus status_;
    std::function<void(const PolicyUpdateStatus&)> status_sink_;
    PolicyBootstrapGate gate_;
};

} // namespace ppp::app::client::policy
