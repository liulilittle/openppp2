#include <ppp/app/client/policy/PolicyRuntime.h>
#include <ppp/app/client/policy/PolicySourceLoader.h>

#include <algorithm>
#include <atomic>
#include <limits>

namespace ppp::app::client::policy {
namespace {
PolicyPreparedPolicy Loaded(PolicyRuntime& runtime, PolicyLoadResult loaded) {
    PolicyPreparedPolicy result;
    if (loaded.Ok()) result = runtime.Prepare(loaded.source);
    result.diagnostics.insert(result.diagnostics.begin(),
        loaded.diagnostics.begin(), loaded.diagnostics.end());
    return result;
}
}

bool PolicyPreparedPolicy::Ok() const noexcept {
    return snapshot && std::none_of(diagnostics.begin(), diagnostics.end(),
        [](const auto& diagnostic) { return diagnostic.severity == "error"; });
}

PolicyRuntime::PolicyRuntime() : owner_(std::make_shared<const unsigned char>(0)) {}

PolicyPreparedPolicy PolicyRuntime::Prepare(const PolicySource& source) {
    PolicyPreparedPolicy candidate;
    candidate.owner_ = owner_;
    std::uint64_t version;
    {
        std::lock_guard<std::mutex> lock(publish_mutex_);
        if (next_version_ == std::numeric_limits<std::uint64_t>::max()) {
            PolicyDiagnostic diagnostic;
            diagnostic.code = "E_POLICY_VERSION_EXHAUSTED";
            diagnostic.message = "Policy version counter is exhausted.";
            candidate.diagnostics.push_back(std::move(diagnostic));
            return candidate;
        }
        version = next_version_++;
    }
    auto compiled = PolicyCompiler::Compile(source, version);
    candidate.snapshot = std::move(compiled.snapshot);
    candidate.prepared_snapshot_ = candidate.snapshot;
    candidate.diagnostics = std::move(compiled.diagnostics);
    return candidate;
}

PolicyPreparedPolicy PolicyRuntime::Prepare(const Json::Value& config, const std::string& config_path) {
    return Loaded(*this, PolicySourceLoader::Load(config, config_path));
}

PolicyPreparedPolicy PolicyRuntime::PrepareFile(const std::string& config_path) {
    return Loaded(*this, PolicySourceLoader::LoadFile(config_path));
}

bool PolicyRuntime::Commit(const PolicyPreparedPolicy& candidate) {
    if (!candidate.Ok() || candidate.owner_ != owner_ || candidate.snapshot != candidate.prepared_snapshot_) return false;
    std::lock_guard<std::mutex> lock(publish_mutex_);
    auto current = GetSnapshot();
    if (current && candidate.snapshot->Version() <= current->Version()) return false;
    std::atomic_store_explicit(&snapshot_, candidate.snapshot, std::memory_order_release);
    return true;
}

std::shared_ptr<const PolicySnapshot> PolicyRuntime::GetSnapshot() const noexcept {
    return std::atomic_load_explicit(&snapshot_, std::memory_order_acquire);
}

PolicyDecision PolicyRuntime::Evaluate(const std::string& domain, const std::string& ipv4) const {
    auto snapshot = GetSnapshot();
    PolicyDecision decision;
    decision.action = PolicyAction::Reject;
    if (!snapshot) { decision.reason = "policy_unavailable"; return decision; }
    return PolicyEvaluator::Evaluate(*snapshot, domain, ipv4);
}

PolicyDnsPlan PolicyRuntime::PlanDns(const std::string& domain) const {
    auto snapshot = GetSnapshot();
    if (snapshot) return PolicyEvaluator::PlanDns(*snapshot, domain);
    PolicyDnsPlan plan;
    plan.action = PolicyAction::Reject;
    plan.rejected = true;
    return plan;
}

} // namespace ppp::app::client::policy
