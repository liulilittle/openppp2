#pragma once

#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <boost/asio/ip/address.hpp>

namespace ppp::app::client::policy {

enum class PolicyTcpDisposition { Reject, Direct, Proxy };

struct PolicyTcpFlowInput {
    std::string hostname;
    std::string ipv4;
    bool ipv6 = false;
    bool is_fake_ip = false;
    bool is_resolved = true;
    bool direct_supported = true;
};

struct PolicyTcpFlowDecision {
    PolicyTcpDisposition disposition = PolicyTcpDisposition::Reject;
    PolicyDecision policy;
    std::string reason;
    bool needs_dns_resolution = false;
};

inline PolicyTcpFlowDecision EvaluatePolicyTcpFlow(
    const std::shared_ptr<const PolicySnapshot>& snapshot, const PolicyTcpFlowInput& input) {
    PolicyTcpFlowDecision result;
    if (!snapshot) { result.reason = "policy_unavailable"; return result; }
    if (input.ipv6) { result.reason = "unsupported_ipv6"; return result; }
    if (input.is_fake_ip && input.hostname.empty()) {
        result.reason = "unresolved_fake_ip"; return result;
    }
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(input.ipv4, error);
    if (error || !address.is_v4()) {
        result.reason = !error ? "unsupported_ipv6" : "unresolved_destination";
        return result;
    }
    if (input.is_fake_ip && !input.is_resolved) {
        result.policy = PolicyEvaluator::Evaluate(*snapshot, input.hostname);
        if (!result.policy.matched && !result.policy.needs_ip_resolution) {
            result.reason = "unresolved_fake_ip"; return result;
        }
        if (result.policy.matched && result.policy.action == PolicyAction::Reject) {
            result.reason = "policy_reject"; return result;
        }
        if (result.policy.matched && result.policy.action == PolicyAction::Direct && !input.direct_supported) {
            result.reason = "unsupported_direct"; return result;
        }
        result.reason = "needs_policy_resolution";
        result.needs_dns_resolution = true;
        return result;
    }
    result.policy = PolicyEvaluator::Evaluate(*snapshot, input.hostname, input.ipv4);
    result.reason = result.policy.reason;
    if (result.policy.reason == "invalid_ipv4" || result.policy.needs_ip_resolution) {
        result.reason = "unresolved_destination"; return result;
    }
    if (result.policy.action == PolicyAction::Reject) {
        result.reason = "policy_reject"; return result;
    }
    if (result.policy.action == PolicyAction::Direct) {
        if (!input.direct_supported) { result.reason = "unsupported_direct"; return result; }
        result.disposition = PolicyTcpDisposition::Direct;
    } else result.disposition = PolicyTcpDisposition::Proxy;
    return result;
}

} // namespace ppp::app::client::policy
