#pragma once

/**
 * @file DnsRedirectPlan.h
 * @brief Pure DNS routing decisions for intercepted UDP/53 queries.
 */

#include <ppp/stdafx.h>
#include <ppp/app/client/dns/Rule.h>
#include <ppp/app/client/routing/HumanRoutingRules.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                enum class DnsQueryType : uint16_t {
                    kA = 1,
                    kAAAA = 28,
                };

                enum class DnsRouteAction {
                    kBlockAAAA,
                    kResolveProvider,
                    kResolveUnmatched,
                    kUdpRelay,
                    kDeferToTunnel,
                    kDrop,
                };

                struct DnsRedirectPlanInput {
                    DnsQueryType qtype = DnsQueryType::kA;
                    boost::asio::ip::address destination;
                    bool is_gateway_query = false;
                    bool gateway_upstream_available = false;
                    boost::asio::ip::address gateway_upstream;
                    bool intercept_unmatched = true;
                    bool has_resolver = true;
                    bool allow_ipv6_response = true;
                    bool has_human_action = false;
                    routing::RoutingAction human_action = routing::RoutingAction::Auto;
                    ppp::string human_provider;
                    Rule::Ptr rule;
                    /** When true (desktop), UDP relay to the original destination defers to tunnel fallback. */
                    bool defer_same_destination_to_tunnel = false;
                };

                struct DnsRedirectPlanResult {
                    DnsRouteAction action = DnsRouteAction::kDrop;
                    boost::asio::ip::address udp_relay_target;
                    bool provider_domestic = false;
                    ppp::string provider_name;
                };

                class DnsRedirectPlan final {
                public:
                    static DnsRedirectPlanResult Decide(const DnsRedirectPlanInput& input) noexcept;

                    /** Returns whether the destination identifies the tunnel gateway DNS endpoint. */
                    static bool IsGatewayDnsServer(uint32_t destination, uint32_t gateway, uint32_t mask) noexcept;
                };

            }
        }
    }
}
