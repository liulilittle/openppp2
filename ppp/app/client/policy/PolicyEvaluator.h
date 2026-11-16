#pragma once

#include <ppp/app/client/policy/PolicyCompiler.h>

namespace ppp::app::client::policy {

struct PolicyDecision {
    PolicyAction action = PolicyAction::Proxy;
    bool matched = false;
    bool needs_ip_resolution = false;
    std::string rule_id;
    std::string source;
    std::string file;
    std::size_t line = 0;
    std::string reason;
    std::uint64_t version = 0;
};

struct PolicyDnsPlan {
    PolicyAction action = PolicyAction::Proxy;
    PolicyAction via = PolicyAction::Proxy;
    std::string resolver;
    bool rejected = false;
    std::string rule_id;
    std::string source;
    std::string file;
    std::size_t line = 0;
    std::uint64_t version = 0;
};

class PolicyEvaluator final {
public:
    static PolicyDecision Evaluate(const PolicySnapshot& snapshot,
        const std::string& domain, const std::string& ipv4 = "");
    static PolicyDnsPlan PlanDns(const PolicySnapshot& snapshot, const std::string& domain);
};

} // namespace ppp::app::client::policy
