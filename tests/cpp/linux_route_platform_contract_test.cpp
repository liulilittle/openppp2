#define BOOST_TEST_MODULE linux_route_platform_contract_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/LinuxRoutePlatform.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/net/native/rib.h>
#include <linux/ppp/tap/TapLinux.h>

namespace route = ppp::app::client::route;

namespace linux_route_platform_test {
    void ConfigureRouteAdd(
        int error,
        bool query_succeeded,
        bool exact_exists) noexcept;
    int ExactRouteProbes() noexcept;
    int RouteDeletes() noexcept;
}

BOOST_AUTO_TEST_CASE(interface_selection_uses_tap_known_nic_then_tap_fallback) {
    const std::unordered_map<uint32_t, std::string> nics = {
        { 20u, "wlan0" },
    };

    BOOST_TEST(route::SelectLinuxInterface(10u, 10u, "tap0", "eth0", nics) == "tap0");
    BOOST_TEST(route::SelectLinuxInterface(20u, 10u, "tap0", "eth0", nics) == "wlan0");
    BOOST_TEST(route::SelectLinuxInterface(30u, 10u, "tap0", "eth0", nics) == "tap0");
}

BOOST_AUTO_TEST_CASE(production_route_add_result_requires_exact_eexist) {
    using Result = ppp::tap::TapLinux::RouteMutationResult;

    BOOST_TEST(static_cast<int>(ppp::tap::TapLinux::ClassifyRouteAddResult(
        0, false, false)) == static_cast<int>(Result::Changed));
    BOOST_TEST(static_cast<int>(ppp::tap::TapLinux::ClassifyRouteAddResult(
        EEXIST, true, true)) == static_cast<int>(Result::Unchanged));
    BOOST_TEST(static_cast<int>(ppp::tap::TapLinux::ClassifyRouteAddResult(
        EEXIST, true, false)) == static_cast<int>(Result::Failed));
    BOOST_TEST(static_cast<int>(ppp::tap::TapLinux::ClassifyRouteAddResult(
        EEXIST, false, true)) == static_cast<int>(Result::Failed));
    BOOST_TEST(static_cast<int>(ppp::tap::TapLinux::ClassifyRouteAddResult(
        EPERM, true, true)) == static_cast<int>(Result::Failed));
}

BOOST_AUTO_TEST_CASE(captured_defaults_are_stable_itemized_routes) {
    ppp::vector<ppp::string> calls;
    int capture_count = 0;
    auto defaults = std::make_shared<ppp::net::native::RouteInformationTable>();
    defaults->GetAllRoutes()[1u] = {
        { 1u, 0, 20u },
        { 1u, 1, 10u },
    };

    route::LinuxRouteOperations operations;
    operations.capture_defaults =
        [&calls, &capture_count, defaults](uint32_t gateway,
            route::RouteInformationTablePtr& routes) noexcept {
            calls.emplace_back("capture:" + std::to_string(gateway));
            routes = ++capture_count <= 2
                ? defaults
                : route::RouteInformationTablePtr();
            return true;
        };
    operations.add = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("add:" + std::to_string(spec.network) + ":" +
            std::to_string(spec.prefix) + ":" + spec.interface_name);
        return route::RouteAddResult::Created;
    };
    operations.remove = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("delete:" + std::to_string(spec.network) + ":" +
            std::to_string(spec.prefix) + ":" + spec.interface_name);
        return true;
    };

    route::LinuxRoutePlatform platform(
        10u,
        "tap0",
        "eth0",
        { { 20u, "wlan0" } },
        false,
        std::move(operations));

    route::RouteSpec spec;
    spec.network = 7u;
    spec.gateway = 20u;
    spec.prefix = 32;
    const route::DefaultRouteCapture captured = platform.CaptureDefaults();
    const route::DefaultRouteCapture recapture = platform.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    BOOST_REQUIRE(recapture.has_value());
    const std::vector<route::RouteSnapshotPtr>& snapshots = *captured;
    const std::vector<route::RouteSnapshotPtr>& recaptured = *recapture;
    BOOST_REQUIRE(snapshots.size() == 2u);
    BOOST_REQUIRE(recaptured.size() == 2u);
    BOOST_TEST(platform.SameDefault(snapshots[0], recaptured[0]));
    BOOST_TEST(platform.SameDefault(snapshots[1], recaptured[1]));
    BOOST_TEST(!platform.SameDefault(snapshots[0], snapshots[1]));
    BOOST_TEST(platform.RemoveDefault(snapshots[0]));
    BOOST_TEST(platform.RemoveDefault(snapshots[1]));
    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Created));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(platform.RestoreDefault(snapshots[1]));
    BOOST_TEST(platform.RestoreDefault(snapshots[0]));

    const ppp::vector<ppp::string> expected = {
        "capture:10", "capture:10",
        "delete:1:1:tap0", "delete:1:0:wlan0",
        "add:7:32:wlan0", "delete:7:32:wlan0",
        "capture:10", "add:1:0:wlan0",
        "capture:10", "add:1:1:tap0"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(promiscuous_mode_does_not_remove_or_restore_defaults) {
    int default_mutations = 0;
    route::LinuxRouteOperations operations;
    operations.capture_defaults = [](uint32_t,
        route::RouteInformationTablePtr&) noexcept {
        return false;
    };
    operations.add = [&default_mutations](const route::RouteSpec&) noexcept {
        ++default_mutations;
        return route::RouteAddResult::Created;
    };
    operations.remove = [&default_mutations](const route::RouteSpec&) noexcept {
        ++default_mutations;
        return true;
    };

    route::LinuxRoutePlatform platform(10u, "tap0", "eth0", {}, true, std::move(operations));
    const route::DefaultRouteCapture captured = platform.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    BOOST_TEST(captured->empty());
    BOOST_TEST(platform.RemoveDefault(nullptr));
    BOOST_TEST(platform.RestoreDefault(nullptr));
    BOOST_TEST(default_mutations == 0);
}

BOOST_AUTO_TEST_CASE(restore_succeeds_when_the_default_route_already_exists) {
    bool route_present = true;
    int add_attempts = 0;
    auto defaults = std::make_shared<ppp::net::native::RouteInformationTable>();
    defaults->GetAllRoutes()[1u] = { { 1u, 0, 20u } };

    route::LinuxRouteOperations operations;
    operations.capture_defaults = [&route_present, defaults](uint32_t,
        route::RouteInformationTablePtr& routes) noexcept {
        routes = route_present ? defaults : route::RouteInformationTablePtr();
        return true;
    };
    operations.remove = [&route_present](const route::RouteSpec&) noexcept {
        route_present = false;
        return true;
    };
    operations.add = [&add_attempts](const route::RouteSpec&) noexcept {
        ++add_attempts;
        return route::RouteAddResult::Failed;
    };

    route::LinuxRoutePlatform platform(
        10u, "tap0", "eth0", { { 20u, "wlan0" } }, false,
        std::move(operations));
    const route::DefaultRouteCapture captured = platform.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    const std::vector<route::RouteSnapshotPtr>& snapshots = *captured;
    BOOST_REQUIRE(snapshots.size() == 1u);
    BOOST_REQUIRE(platform.RemoveDefault(snapshots[0]));

    route_present = true;
    BOOST_TEST(platform.RestoreDefault(snapshots[0]));
    BOOST_TEST(add_attempts == 0);
}

BOOST_AUTO_TEST_CASE(restore_failure_is_reported_when_the_route_is_still_absent) {
    bool route_present = true;
    auto defaults = std::make_shared<ppp::net::native::RouteInformationTable>();
    defaults->GetAllRoutes()[1u] = { { 1u, 0, 20u } };

    route::LinuxRouteOperations operations;
    operations.capture_defaults = [&route_present, defaults](uint32_t,
        route::RouteInformationTablePtr& routes) noexcept {
        routes = route_present ? defaults : route::RouteInformationTablePtr();
        return true;
    };
    operations.remove = [&route_present](const route::RouteSpec&) noexcept {
        route_present = false;
        return true;
    };
    operations.add = [](const route::RouteSpec&) noexcept {
        return route::RouteAddResult::Failed;
    };

    route::LinuxRoutePlatform platform(
        10u, "tap0", "eth0", { { 20u, "wlan0" } }, false,
        std::move(operations));
    const route::DefaultRouteCapture captured = platform.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    const std::vector<route::RouteSnapshotPtr>& snapshots = *captured;
    BOOST_REQUIRE(snapshots.size() == 1u);
    BOOST_REQUIRE(platform.RemoveDefault(snapshots[0]));
    BOOST_TEST(!platform.RestoreDefault(snapshots[0]));
}

BOOST_AUTO_TEST_CASE(capture_failure_is_distinct_from_a_successful_empty_query) {
    route::LinuxRouteOperations failed_operations;
    failed_operations.capture_defaults = [](uint32_t,
        route::RouteInformationTablePtr&) noexcept {
        return false;
    };
    route::LinuxRoutePlatform failed(
        10u, "tap0", "eth0", {}, false, std::move(failed_operations));
    BOOST_TEST(!failed.CaptureDefaults().has_value());

    route::LinuxRouteOperations empty_operations;
    empty_operations.capture_defaults = [](uint32_t,
        route::RouteInformationTablePtr& routes) noexcept {
        routes.reset();
        return true;
    };
    route::LinuxRoutePlatform empty(
        10u, "tap0", "eth0", {}, false, std::move(empty_operations));
    const route::DefaultRouteCapture captured = empty.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    BOOST_TEST(captured->empty());
}

BOOST_AUTO_TEST_CASE(add_preserves_created_unchanged_and_failed_status) {
    std::vector<route::RouteAddResult> results = {
        route::RouteAddResult::Created,
        route::RouteAddResult::Unchanged,
        route::RouteAddResult::Failed,
    };
    route::LinuxRouteOperations operations;
    operations.add = [&results](const route::RouteSpec&) noexcept {
        const route::RouteAddResult result = results.front();
        results.erase(results.begin());
        return result;
    };
    route::LinuxRoutePlatform platform(
        10u, "tap0", "eth0", {}, false, std::move(operations));
    const route::RouteSpec spec{ 1u, 2u, 32, {} };

    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Created));
    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Unchanged));
    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Failed));
}

BOOST_AUTO_TEST_CASE(system_add_eexist_requires_exact_route_match_without_deleting_conflicts) {
    route::LinuxRoutePlatform platform(
        10u, "tap0", "eth0", {}, false);
    const route::RouteSpec spec{ 1u, 2u, 24, "eth0" };

    linux_route_platform_test::ConfigureRouteAdd(EEXIST, true, true);
    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Unchanged));
    BOOST_TEST(linux_route_platform_test::ExactRouteProbes() == 1);
    BOOST_TEST(linux_route_platform_test::RouteDeletes() == 0);

    linux_route_platform_test::ConfigureRouteAdd(EEXIST, true, false);
    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Failed));
    BOOST_TEST(linux_route_platform_test::ExactRouteProbes() == 1);
    BOOST_TEST(linux_route_platform_test::RouteDeletes() == 0);

    linux_route_platform_test::ConfigureRouteAdd(EEXIST, false, false);
    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Failed));
    BOOST_TEST(linux_route_platform_test::ExactRouteProbes() == 1);
    BOOST_TEST(linux_route_platform_test::RouteDeletes() == 0);
}

BOOST_AUTO_TEST_CASE(delete_reports_the_missing_route_postcondition_as_success) {
    int attempts = 0;
    route::LinuxRouteOperations operations;
    operations.remove = [&attempts](const route::RouteSpec&) noexcept {
        ++attempts;
        return true;
    };
    route::LinuxRoutePlatform platform(
        10u, "tap0", "eth0", {}, false, std::move(operations));
    const route::RouteSpec spec{ 1u, 2u, 32, {} };

    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(attempts == 2);
}

BOOST_AUTO_TEST_CASE(rib_is_converted_to_route_specs_without_host_dependencies) {
    auto rib = std::make_shared<ppp::net::native::RouteInformationTable>();
    auto& routes = rib->GetAllRoutes();
    routes[0x0a000000u] = {
        { 0x0a000000u, 24, 30u },
        { 0x0a000000u, 16, 10u },
        { 0x0a000000u, 8, 10u },
    };
    routes[0xc0a80000u] = {
        { 0xc0a80000u, 16, 20u },
    };

    const std::vector<route::RouteSpec> specs = route::BuildRouteSpecs(rib);
    BOOST_REQUIRE(specs.size() == 4u);
    BOOST_TEST(specs[0].network == 0x0a000000u);
    BOOST_TEST(specs[0].prefix == 8);
    BOOST_TEST(specs[0].gateway == 10u);
    BOOST_TEST(specs[0].interface_name.empty());
    BOOST_TEST(specs[1].network == 0x0a000000u);
    BOOST_TEST(specs[1].prefix == 16);
    BOOST_TEST(specs[1].gateway == 10u);
    BOOST_TEST(specs[2].network == 0x0a000000u);
    BOOST_TEST(specs[2].prefix == 24);
    BOOST_TEST(specs[2].gateway == 30u);
    BOOST_TEST(specs[3].network == 0xc0a80000u);
    BOOST_TEST(specs[3].prefix == 16);
    BOOST_TEST(specs[3].gateway == 20u);
}

BOOST_AUTO_TEST_CASE(dns_route_specs_are_deduplicated_and_deterministic) {
    route::RoutePlanInput input;
    input.tap_gateway = 10u;
    input.underlying_interface.gateway =
        boost::asio::ip::make_address("192.0.2.1");
    input.tunnel_dns = { 30u, 20u };
    input.underlying_dns = { 40u, 20u };
    input.has_fake_ip_route = true;
    input.fake_ip_route = route::RouteSpec{ 20u, 10u, 32, {} };

    const route::DnsRouteSpecPlan plan = route::BuildDnsRouteSpecs(input);

    BOOST_REQUIRE(plan.routes.size() == 3u);
    BOOST_TEST(plan.routes[0].network == 20u);
    BOOST_TEST(plan.routes[0].gateway == 10u);
    BOOST_TEST(plan.routes[0].prefix == 32);
    BOOST_TEST(plan.routes[1].network == 30u);
    BOOST_TEST(plan.routes[1].gateway == 10u);
    BOOST_TEST(plan.routes[2].network == 40u);
    BOOST_TEST(plan.routes[2].gateway ==
        htonl(input.underlying_interface.gateway.to_v4().to_uint()));
    BOOST_TEST(plan.servers[0].count(20u) == 1u);
    BOOST_TEST(plan.servers[0].count(30u) == 1u);
    BOOST_TEST(plan.servers[1].count(20u) == 0u);
    BOOST_TEST(plan.servers[1].count(40u) == 1u);
}
