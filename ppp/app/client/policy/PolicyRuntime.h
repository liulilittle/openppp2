#pragma once

#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <json/json.h>
#include <mutex>

namespace ppp::app::client::policy {

class PolicyRuntime;

struct PolicyPreparedPolicy {
    std::shared_ptr<const PolicySnapshot> snapshot;
    std::vector<PolicyDiagnostic> diagnostics;
    bool Ok() const noexcept;
private:
    std::shared_ptr<const void> owner_;
    std::shared_ptr<const PolicySnapshot> prepared_snapshot_;
    friend class PolicyRuntime;
};

class PolicyRuntime final {
public:
    PolicyRuntime();
    // Preparation reserves a version; failures may leave gaps but never publish.
    PolicyPreparedPolicy Prepare(const PolicySource& source);
    PolicyPreparedPolicy Prepare(const Json::Value& config, const std::string& config_path);
    PolicyPreparedPolicy PrepareFile(const std::string& config_path);
    bool Commit(const PolicyPreparedPolicy& candidate);
    std::shared_ptr<const PolicySnapshot> GetSnapshot() const noexcept;
    PolicyDecision Evaluate(const std::string& domain, const std::string& ipv4 = "") const;
    PolicyDnsPlan PlanDns(const std::string& domain) const;

private:
    std::shared_ptr<const void> owner_;
    std::shared_ptr<const PolicySnapshot> snapshot_;
    std::mutex publish_mutex_;
    std::uint64_t next_version_ = 1;
};

} // namespace ppp::app::client::policy
