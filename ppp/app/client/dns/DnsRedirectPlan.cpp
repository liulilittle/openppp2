#include "DnsRedirectPlan.h"

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                bool DnsRedirectPlan::IsGatewayDnsServer(uint32_t destination, uint32_t gateway, uint32_t mask) noexcept {
                    if (destination == gateway) {
                        return true;
                    }
                    return htonl((ntohl(gateway) & ntohl(mask)) + 1) == destination;
                }

                static DnsRedirectPlanResult MakeUdpRelay(
                    const boost::asio::ip::address& target,
                    const boost::asio::ip::address& destination,
                    bool defer_same_destination_to_tunnel) noexcept {

                    DnsRedirectPlanResult result;
                    result.udp_relay_target = target;
                    if (defer_same_destination_to_tunnel && target == destination) {
                        result.action = DnsRouteAction::kDeferToTunnel;
                    }
                    else {
                        result.action = DnsRouteAction::kUdpRelay;
                    }
                    return result;
                }

                DnsRedirectPlanResult DnsRedirectPlan::Decide(const DnsRedirectPlanInput& input) noexcept {
                    DnsRedirectPlanResult result;

                    if (input.qtype == DnsQueryType::kAAAA &&
                        ((input.has_resolver && !input.allow_ipv6_response) ||
                         (input.has_human_action &&
                          input.human_action != routing::RoutingAction::Auto))) {
                        result.action = DnsRouteAction::kBlockAAAA;
                        return result;
                    }

                    if (input.has_human_action &&
                        input.human_action != routing::RoutingAction::Auto) {
                        if (!input.has_resolver || input.human_provider.empty()) {
                            result.action = DnsRouteAction::kDrop;
                            return result;
                        }
                        result.action = DnsRouteAction::kResolveProvider;
                        result.provider_name = input.human_provider;
                        result.provider_domestic =
                            input.human_action == routing::RoutingAction::Direct;
                        return result;
                    }

                    // Rule-first: gateway queries no longer bypass dns-rules (Plan B).
                    if (NULLPTR != input.rule) {
                        if (!input.rule->ProviderName.empty()) {
                            if (!input.has_resolver) {
                                result.action = DnsRouteAction::kDrop;
                                return result;
                            }
                            result.action = DnsRouteAction::kResolveProvider;
                            result.provider_name = input.rule->ProviderName;
                            result.provider_domestic = input.rule->Nic;
                            return result;
                        }

                        return MakeUdpRelay(
                            input.rule->Server,
                            input.destination,
                            input.defer_same_destination_to_tunnel);
                    }

                    // Unified resolver path for unmatched and gateway queries (Plan B/D).
                    if (input.has_resolver &&
                        (input.intercept_unmatched || input.is_gateway_query)) {
                        result.action = DnsRouteAction::kResolveUnmatched;
                        return result;
                    }

                    // Legacy gateway UDP relay when resolver is unavailable.
                    if (input.is_gateway_query) {
                        if (input.gateway_upstream_available &&
                            !input.gateway_upstream.is_unspecified()) {
                            return MakeUdpRelay(
                                input.gateway_upstream,
                                input.destination,
                                input.defer_same_destination_to_tunnel);
                        }
                        result.action = DnsRouteAction::kDrop;
                        return result;
                    }

                    return MakeUdpRelay(
                        input.destination,
                        input.destination,
                        input.defer_same_destination_to_tunnel);
                }

            }
        }
    }
}
