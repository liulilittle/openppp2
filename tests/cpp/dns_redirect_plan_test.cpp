#define BOOST_TEST_MODULE dns_redirect_plan_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsRedirectPlan.h>
#include <ppp/app/client/dns/Rule.h>

namespace client_dns = ppp::app::client::dns;

namespace {

boost::asio::ip::address MakeAddress(const char* text) {
    boost::system::error_code ec;
    boost::asio::ip::address address = boost::asio::ip::make_address(text, ec);
    BOOST_REQUIRE(!ec);
    return address;
}

client_dns::DnsRedirectPlanInput BaseInput() {
    client_dns::DnsRedirectPlanInput input;
    input.destination = MakeAddress("8.8.8.8");
    input.intercept_unmatched = true;
    input.has_resolver = true;
    input.allow_ipv6_response = true;
    return input;
}

}  // namespace

BOOST_AUTO_TEST_CASE(gateway_query_resolves_via_resolver_when_upstream_available) {
    auto input = BaseInput();
    input.is_gateway_query = true;
    input.gateway_upstream_available = true;
    input.gateway_upstream = MakeAddress("1.1.1.1");

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kResolveUnmatched));
}

BOOST_AUTO_TEST_CASE(gateway_query_resolves_when_upstream_missing_but_resolver_available) {
    auto input = BaseInput();
    input.is_gateway_query = true;
    input.gateway_upstream_available = false;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kResolveUnmatched));
}

BOOST_AUTO_TEST_CASE(gateway_query_falls_back_to_upstream_without_resolver) {
    auto input = BaseInput();
    input.is_gateway_query = true;
    input.has_resolver = false;
    input.gateway_upstream_available = true;
    input.gateway_upstream = MakeAddress("1.1.1.1");

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kUdpRelay));
    BOOST_TEST(result.udp_relay_target == input.gateway_upstream);
}

BOOST_AUTO_TEST_CASE(gateway_query_drops_when_upstream_missing_and_no_resolver) {
    auto input = BaseInput();
    input.is_gateway_query = true;
    input.has_resolver = false;
    input.gateway_upstream_available = false;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kDrop));
}

BOOST_AUTO_TEST_CASE(gateway_query_honors_provider_rule) {
    auto input = BaseInput();
    input.is_gateway_query = true;
    input.gateway_upstream_available = true;
    input.gateway_upstream = MakeAddress("1.1.1.1");
    input.rule = std::make_shared<client_dns::Rule>();
    input.rule->ProviderName = "doh.pub";
    input.rule->Nic = true;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kResolveProvider));
    BOOST_TEST(result.provider_name == "doh.pub");
    BOOST_TEST(result.provider_domestic == true);
}

BOOST_AUTO_TEST_CASE(unmatched_query_resolves_when_intercept_enabled) {
    auto input = BaseInput();
    input.rule = nullptr;
    input.intercept_unmatched = true;
    input.has_resolver = true;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kResolveUnmatched));
}

BOOST_AUTO_TEST_CASE(unmatched_query_relays_when_intercept_disabled) {
    auto input = BaseInput();
    input.rule = nullptr;
    input.intercept_unmatched = false;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kUdpRelay));
    BOOST_TEST(result.udp_relay_target == input.destination);
}

BOOST_AUTO_TEST_CASE(provider_rule_resolves_via_resolver) {
    auto input = BaseInput();
    input.rule = std::make_shared<client_dns::Rule>();
    input.rule->ProviderName = "cloudflare";
    input.rule->Nic = false;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kResolveProvider));
    BOOST_TEST(result.provider_name == "cloudflare");
    BOOST_TEST(result.provider_domestic == false);
}

BOOST_AUTO_TEST_CASE(provider_rule_drops_without_resolver) {
    auto input = BaseInput();
    input.rule = std::make_shared<client_dns::Rule>();
    input.rule->ProviderName = "cloudflare";
    input.has_resolver = false;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kDrop));
}

BOOST_AUTO_TEST_CASE(ip_rule_relays_to_rule_server) {
    auto input = BaseInput();
    input.rule = std::make_shared<client_dns::Rule>();
    input.rule->Server = MakeAddress("9.9.9.9");

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kUdpRelay));
    BOOST_TEST(result.udp_relay_target == input.rule->Server);
}

BOOST_AUTO_TEST_CASE(desktop_defers_same_destination_to_tunnel) {
    auto input = BaseInput();
    input.rule = nullptr;
    input.intercept_unmatched = false;
    input.defer_same_destination_to_tunnel = true;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kDeferToTunnel));
}

BOOST_AUTO_TEST_CASE(aaaa_blocked_when_ipv6_disallowed) {
    auto input = BaseInput();
    input.qtype = client_dns::DnsQueryType::kAAAA;
    input.allow_ipv6_response = false;
    input.has_resolver = true;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) == static_cast<int>(client_dns::DnsRouteAction::kBlockAAAA));
}

BOOST_AUTO_TEST_CASE(is_gateway_dns_server_matches_gateway_and_network_plus_one) {
    const uint32_t mask = htonl(0xFFFFFF00u);
    const uint32_t gateway = htonl(0x0A000002u);  // 10.0.0.2
    const uint32_t network_plus_one = htonl(0x0A000001u);  // 10.0.0.1 on /24

    BOOST_TEST(client_dns::DnsRedirectPlan::IsGatewayDnsServer(gateway, gateway, mask));
    BOOST_TEST(client_dns::DnsRedirectPlan::IsGatewayDnsServer(network_plus_one, gateway, mask));
    BOOST_TEST(!client_dns::DnsRedirectPlan::IsGatewayDnsServer(htonl(0x08080808u), gateway, mask));
}

BOOST_AUTO_TEST_CASE(human_direct_action_uses_domestic_provider_before_legacy_rule) {
    auto input = BaseInput();
    input.has_human_action = true;
    input.human_action = ppp::app::client::routing::RoutingAction::Direct;
    input.human_provider = "doh.pub";
    input.rule = std::make_shared<client_dns::Rule>();
    input.rule->ProviderName = "cloudflare";
    input.rule->Nic = false;

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) ==
        static_cast<int>(client_dns::DnsRouteAction::kResolveProvider));
    BOOST_TEST(result.provider_name == "doh.pub");
    BOOST_TEST(result.provider_domestic);
}

BOOST_AUTO_TEST_CASE(human_proxy_action_uses_foreign_provider) {
    auto input = BaseInput();
    input.has_human_action = true;
    input.human_action = ppp::app::client::routing::RoutingAction::Proxy;
    input.human_provider = "cloudflare";

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) ==
        static_cast<int>(client_dns::DnsRouteAction::kResolveProvider));
    BOOST_TEST(result.provider_name == "cloudflare");
    BOOST_TEST(!result.provider_domestic);
}

BOOST_AUTO_TEST_CASE(human_action_without_provider_fails_closed) {
    auto input = BaseInput();
    input.has_human_action = true;
    input.human_action = ppp::app::client::routing::RoutingAction::Direct;
    input.human_provider.clear();

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) ==
        static_cast<int>(client_dns::DnsRouteAction::kDrop));
}

BOOST_AUTO_TEST_CASE(human_action_blocks_aaaa_even_when_ipv6_is_allowed) {
    auto input = BaseInput();
    input.qtype = client_dns::DnsQueryType::kAAAA;
    input.has_human_action = true;
    input.human_action = ppp::app::client::routing::RoutingAction::Proxy;
    input.human_provider = "cloudflare";

    const auto result = client_dns::DnsRedirectPlan::Decide(input);
    BOOST_TEST(static_cast<int>(result.action) ==
        static_cast<int>(client_dns::DnsRouteAction::kBlockAAAA));
}
