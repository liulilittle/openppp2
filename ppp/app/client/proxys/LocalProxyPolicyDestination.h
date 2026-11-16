#pragma once

#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <ppp/app/client/routing/ResolvedDestination.h>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

namespace ppp::app::client::proxys {

struct LocalProxyPolicyDestination {
    std::string original_domain;
    boost::asio::ip::address address;
    policy::PolicyAction action = policy::PolicyAction::Reject;
    bool policy_rejected = false;
};

struct SocksUdpReplyEndpoints {
    boost::asio::ip::udp::endpoint source;
    boost::asio::ip::udp::endpoint destination;
};

inline SocksUdpReplyEndpoints MakeSocksUdpReplyEndpoints(
    const boost::asio::ip::udp::endpoint& client_relay,
    const boost::asio::ip::udp::endpoint& remote) {
    return {remote, client_relay};
}

inline policy::PolicyDecision PlanLocalProxyUdpDestination(
    const std::shared_ptr<const policy::PolicySnapshot>& snapshot,
    const std::string& domain, const boost::asio::ip::address& address, bool original_is_fake) {
    if (snapshot) return policy::PolicyEvaluator::Evaluate(*snapshot, domain,
        original_is_fake ? "" : address.to_string());
    policy::PolicyDecision decision;
    decision.action = policy::PolicyAction::Reject;
    return decision;
}

// Keep one snapshot and the original domain across the DNS and IPv4 phases.
template<class TResolve>
bool ResolveLocalProxyPolicyDestination(
    const std::shared_ptr<const policy::PolicySnapshot>& snapshot,
    const std::string& host, bool require_address, const TResolve& resolve,
    LocalProxyPolicyDestination& destination) {
    destination = {};
    if (!snapshot || host.empty()) return false;
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(host, ec);
    if (!ec && (!address.is_v4() || address.is_unspecified())) return false;
    if (ec) destination.original_domain = host;
    else destination.address = address;
    auto decision = policy::PolicyEvaluator::Evaluate(*snapshot, destination.original_domain,
        ec ? "" : address.to_string());
    if (ec && !decision.matched && !decision.needs_ip_resolution) {
        destination.policy_rejected = decision.action == policy::PolicyAction::Reject;
        return false;
    }
    if (decision.action == policy::PolicyAction::Reject && !decision.needs_ip_resolution) {
        destination.policy_rejected = true;
        return false;
    }
    if (ec && (require_address || decision.needs_ip_resolution || decision.action == policy::PolicyAction::Direct)) {
        if (!resolve(destination.original_domain, destination.address) || !destination.address.is_v4() ||
            destination.address.is_unspecified()) return false;
        decision = policy::PolicyEvaluator::Evaluate(*snapshot, destination.original_domain, destination.address.to_string());
    }
    destination.action = decision.action;
    destination.policy_rejected = decision.action == policy::PolicyAction::Reject && !decision.needs_ip_resolution;
    return !decision.needs_ip_resolution && decision.action != policy::PolicyAction::Reject;
}

} // namespace ppp::app::client::proxys
