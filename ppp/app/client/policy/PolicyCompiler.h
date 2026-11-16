#pragma once

#include <ppp/app/client/policy/PolicyModel.h>
#include <memory>

namespace ppp::app::client::policy {

class PolicyEvaluator;
class PolicySnapshot final {
public:
    struct Index;
    std::uint64_t Version() const noexcept;
    std::size_t RuleCount() const noexcept;
    std::size_t SkippedIpv6() const noexcept;
    const std::vector<PolicyRule>& Rules() const noexcept;
    const std::map<std::string, PolicyResolver>& Resolvers() const noexcept;
    const std::string& DnsMode() const noexcept;
    const std::string& FakeIpRange() const noexcept;
    const std::string& FakeIpStorage() const noexcept;
    const std::string& FakeIpIdentity() const noexcept;
    const std::string& DnsResolverForAction(PolicyAction action) const noexcept;
    bool TcpDomainSniff() const noexcept;
private:
    explicit PolicySnapshot(std::shared_ptr<const Index> index);
    std::shared_ptr<const Index> index_;
    friend class PolicyCompiler;
    friend class PolicyEvaluator;
};

struct PolicyCompileResult {
    std::shared_ptr<const PolicySnapshot> snapshot;
    std::vector<PolicyDiagnostic> diagnostics;
    bool Ok() const noexcept { return snapshot != nullptr; }
};

class PolicyCompiler final {
public:
    static PolicyCompileResult Compile(const PolicySource& source, std::uint64_t version = 1);
};

} // namespace ppp::app::client::policy
