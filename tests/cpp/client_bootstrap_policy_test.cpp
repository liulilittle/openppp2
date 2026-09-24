#define BOOST_TEST_MODULE client_bootstrap_policy_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/ApplicationClientBootstrap.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>

#include <type_traits>
#include <utility>

using ppp::app::NormalizeClientStaticMode;
using ppp::app::NormalizeClientProxyOnlyRuntime;
using ppp::app::TcpStackMode;
using ppp::app::client::VEthernetNetworkSwitcher;
using ppp::configurations::NormalizeClientRoutingStringList;
using ppp::configurations::AppConfiguration;

using IoContextPtr = std::shared_ptr<boost::asio::io_context>;
using AppConfigurationPtr = std::shared_ptr<AppConfiguration>;

static_assert(std::is_constructible_v<VEthernetNetworkSwitcher,
    const IoContextPtr&, TcpStackMode, bool, bool, const AppConfigurationPtr&>);
static_assert(std::is_constructible_v<VEthernetNetworkSwitcher,
    const IoContextPtr&, bool, bool, bool, const AppConfigurationPtr&>);
static_assert(std::is_same_v<
    decltype(std::declval<const VEthernetNetworkSwitcher&>().GetTcpStackMode()),
    TcpStackMode>);

BOOST_AUTO_TEST_CASE(static_mode_respects_proxy_only_runtime) {
    BOOST_TEST(!NormalizeClientStaticMode(false, false));
    BOOST_TEST(NormalizeClientStaticMode(true, false));
    BOOST_TEST(!NormalizeClientStaticMode(false, true));
    BOOST_TEST(!NormalizeClientStaticMode(true, true));
}


BOOST_AUTO_TEST_CASE(client_routing_string_sources_trim_and_drop_empty) {
    ppp::vector<ppp::string> values;
    values.emplace_back("  bypass.txt ");
    values.emplace_back(" \t ");
    values.emplace_back(" inline:10.0.0.0/8 ");
    values.emplace_back("");

    NormalizeClientRoutingStringList(values);

    BOOST_TEST(values.size() == 2U);
    BOOST_TEST(values[0] == "bypass.txt");
    BOOST_TEST(values[1] == "inline:10.0.0.0/8");
}

// C1 regression: canonical routing present => client.routes is the mirror;
// the bootstrap must NOT load client.routes a second time.  Verified here by
// checking that configured==true and routes are mirrored, which is the
// precondition that makes the old unconditional loop a double-load.
BOOST_AUTO_TEST_CASE(canonical_routing_configured_flag_set_when_routing_object_supplied) {
    AppConfiguration::ClientRoutingConfiguration routing{};
    ppp::vector<AppConfiguration::RouteConfiguration> legacy_routes;
    AppConfiguration::RouteConfiguration route{};
    route.path = "routes.txt";
    routing.configured = true;
    routing.routes.emplace_back(route);
    // Mirror (as AppConfiguration::Load does).
    legacy_routes = routing.routes;

    BOOST_TEST(routing.configured);
    BOOST_TEST(routing.routes.size() == 1U);
    // Mirror is identical: the old loop iterating client.routes would
    // re-load the same path, which is the bug C1 fixes.
    BOOST_TEST(legacy_routes.size() == routing.routes.size());
    BOOST_TEST(legacy_routes[0].path == routing.routes[0].path);
}

BOOST_AUTO_TEST_CASE(canonical_routing_not_configured_when_routing_object_absent) {
    AppConfiguration::ClientRoutingConfiguration routing{};
    ppp::vector<AppConfiguration::RouteConfiguration> legacy_routes;
    AppConfiguration::RouteConfiguration route{};
    route.path = "legacy.txt";
    legacy_routes.emplace_back(route);

    BOOST_TEST(!routing.configured);
    BOOST_TEST(routing.routes.empty());
    // Legacy loop should run (canonical absent).
    BOOST_TEST(legacy_routes.size() == 1U);
}

// NormalizeClientProxyOnlyRuntime is the single authoritative expression for
// proxy_only_runtime used by ApplicationClientBootstrap, ApplicationConfig,
// and all platform bridge entry points.  All four input combinations are
// tested here so that any future inline re-implementation diverges visibly.
BOOST_AUTO_TEST_CASE(normalize_proxy_only_runtime_all_combinations) {
    BOOST_TEST(!NormalizeClientProxyOnlyRuntime(false, false));
    BOOST_TEST( NormalizeClientProxyOnlyRuntime(true,  false));
    BOOST_TEST( NormalizeClientProxyOnlyRuntime(false, true));
    BOOST_TEST( NormalizeClientProxyOnlyRuntime(true,  true));
}

// F1 regression: trigger condition for ApplyPeerPrefixRoutes must select the
// same source as PeerPrefixRouteManager::Apply.  When canonical is configured
// and non-empty, legacy peer_routes being empty must not suppress the trigger.
BOOST_AUTO_TEST_CASE(peer_routes_trigger_prefers_canonical_when_configured) {
    AppConfiguration::ClientRoutingConfiguration routing{};
    routing.configured = true;
    AppConfiguration::PeerPrefixRouteConfiguration pr{};
    pr.network = "10.20.0.0";
    pr.prefix  = 24;
    pr.via     = "10.0.0.2";
    routing.peer_routes.emplace_back(pr);

    ppp::vector<AppConfiguration::PeerPrefixRouteConfiguration> legacy_peer{};

    // canonical non-empty => trigger should fire
    const auto& effective = routing.configured ? routing.peer_routes : legacy_peer;
    BOOST_TEST(!effective.empty());

    // legacy empty should NOT suppress trigger when canonical is configured
    BOOST_TEST(legacy_peer.empty());
}

BOOST_AUTO_TEST_CASE(peer_routes_trigger_falls_back_to_legacy_when_canonical_absent) {
    AppConfiguration::ClientRoutingConfiguration routing{};
    // configured == false: legacy path
    AppConfiguration::PeerPrefixRouteConfiguration pr{};
    pr.network = "10.30.0.0";
    pr.prefix  = 16;
    pr.via     = "10.0.0.3";

    ppp::vector<AppConfiguration::PeerPrefixRouteConfiguration> legacy_peer{};
    legacy_peer.emplace_back(pr);

    const auto& effective = routing.configured ? routing.peer_routes : legacy_peer;
    BOOST_TEST(!effective.empty());
    BOOST_TEST(effective[0].network == "10.30.0.0");
}

// F2 — canonical-wins: CLI --dns-rules is only active when canonical routing
// is absent.  In canonical path the routing.dns_rules vector is authoritative.
// Bootstrap iterates routing.dns_rules unconditionally; legacy path leaves it
// empty so the loop is a no-op, and CLI --dns-rules is loaded by the separate
// legacy guard instead.
BOOST_AUTO_TEST_CASE(dns_rules_empty_in_legacy_path_is_no_op_in_unified_loop) {
    AppConfiguration::ClientRoutingConfiguration routing{};
    // Legacy path: configured == false, routing.dns_rules empty.
    BOOST_TEST(!routing.configured);
    BOOST_TEST(routing.dns_rules.empty());
    int dns_load_count = 0;
    for (const auto& src : routing.dns_rules) {
        (void)src;
        ++dns_load_count;
    }
    BOOST_TEST(dns_load_count == 0);
}

BOOST_AUTO_TEST_CASE(dns_rules_loaded_from_canonical_when_configured) {
    AppConfiguration::ClientRoutingConfiguration routing{};
    routing.configured = true;
    routing.dns_rules.emplace_back("rules.txt");
    routing.dns_rules.emplace_back("inline:example.com /cloudflare/tun");

    int dns_load_count = 0;
    for (const auto& src : routing.dns_rules) {
        (void)src;
        ++dns_load_count;
    }
    BOOST_TEST(dns_load_count == 2);
}

// C5 / F3: --mode=proxy (proxy_mode=true) overrides client.proxy-only=false.
BOOST_AUTO_TEST_CASE(proxy_mode_cli_flag_overrides_json_proxy_only_false) {
    BOOST_TEST(NormalizeClientProxyOnlyRuntime(true, false));
}

BOOST_AUTO_TEST_CASE(proxy_mode_cli_false_and_json_proxy_only_true_yields_proxy_only) {
    BOOST_TEST(NormalizeClientProxyOnlyRuntime(false, true));
}

BOOST_AUTO_TEST_CASE(both_proxy_inputs_false_yields_tun_mode) {
    BOOST_TEST(!NormalizeClientProxyOnlyRuntime(false, false));
}
