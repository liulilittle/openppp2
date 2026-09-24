#define BOOST_TEST_MODULE route_platform_adapters_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/WindowsRoutePlatform.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>
#include <ppp/app/client/route/MobileRoutePlatform.h>
#include <ppp/net/IPEndPoint.h>
#include <darwin/ppp/tap/TapDarwin.h>

namespace route = ppp::app::client::route;

namespace {

class Snapshot final : public route::IRouteSnapshot {
public:
    explicit Snapshot(int id) noexcept : id(id) {}
    int id;
};

template <typename Operations, typename Platform>
void VerifyDesktopAdapter() {
    std::vector<std::string> calls;
    auto baseline = std::make_shared<Snapshot>(7);
    auto equivalent = std::make_shared<Snapshot>(7);
    Operations operations;
    operations.capture_defaults = [baseline, &calls]() noexcept {
        calls.emplace_back("capture");
        return std::vector<route::RouteSnapshotPtr>{ baseline };
    };
    operations.remove_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("remove-default");
        return true;
    };
    operations.add = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("add:" + std::to_string(spec.network));
        return route::RouteAddResult::Created;
    };
    operations.remove = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("delete:" + std::to_string(spec.network));
        return true;
    };
    operations.restore_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("restore");
        return true;
    };
    operations.same_default = [](const route::RouteSnapshotPtr& left,
        const route::RouteSnapshotPtr& right) noexcept {
        const auto left_snapshot = std::dynamic_pointer_cast<const Snapshot>(left);
        const auto right_snapshot = std::dynamic_pointer_cast<const Snapshot>(right);
        return left_snapshot && right_snapshot &&
            left_snapshot->id == right_snapshot->id;
    };

    Platform platform(std::move(operations));
    route::RouteSpec spec;
    spec.network = 7;
    const route::DefaultRouteCapture captured = platform.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    const std::vector<route::RouteSnapshotPtr>& snapshots = *captured;
    BOOST_REQUIRE(snapshots.size() == 1u);
    BOOST_TEST(snapshots[0] == baseline);
    BOOST_TEST(platform.SameDefault(snapshots[0], equivalent));
    BOOST_TEST(platform.RemoveDefault(snapshots[0]));
    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Created));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(platform.RestoreDefault(snapshots[0]));
    const std::vector<std::string> expected = {
        "capture", "remove-default", "add:7", "delete:7", "restore"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

}

BOOST_AUTO_TEST_CASE(windows_adapter_owns_platform_operation_boundary) {
    VerifyDesktopAdapter<route::WindowsRouteOperations, route::WindowsRoutePlatform>();
}

BOOST_AUTO_TEST_CASE(darwin_adapter_owns_platform_operation_boundary) {
    VerifyDesktopAdapter<route::DarwinRouteOperations, route::DarwinRoutePlatform>();
}

BOOST_AUTO_TEST_CASE(darwin_production_route_identity_matches_address_prefix_and_gateway) {
    const uint32_t mask24 = ppp::net::IPEndPoint::PrefixToNetmask(24);
    const uint32_t mask25 = ppp::net::IPEndPoint::PrefixToNetmask(25);

    BOOST_TEST(ppp::tap::TapDarwin::IsExactRoute(
        1u, 24, 2u, 1u, mask24, 2u));
    BOOST_TEST(!ppp::tap::TapDarwin::IsExactRoute(
        1u, 24, 2u, 1u, mask24, 3u));
    BOOST_TEST(!ppp::tap::TapDarwin::IsExactRoute(
        1u, 24, 2u, 1u, mask25, 2u));
}

BOOST_AUTO_TEST_CASE(darwin_capture_distinguishes_failure_from_empty) {
    route::DarwinRouteOperations failed_operations;
    failed_operations.capture_defaults = []() noexcept {
        return route::DefaultRouteCapture();
    };
    route::DarwinRoutePlatform failed(std::move(failed_operations));
    BOOST_TEST(!failed.CaptureDefaults().has_value());

    route::DarwinRouteOperations empty_operations;
    empty_operations.capture_defaults = []() noexcept {
        return route::DefaultRouteCapture(std::vector<route::RouteSnapshotPtr>());
    };
    route::DarwinRoutePlatform empty(std::move(empty_operations));
    const route::DefaultRouteCapture captured = empty.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    BOOST_TEST(captured->empty());
}

BOOST_AUTO_TEST_CASE(darwin_add_and_delete_preserve_postcondition_status) {
    int deletes = 0;
    route::DarwinRouteOperations operations;
    operations.add = [](const route::RouteSpec&) noexcept {
        return route::RouteAddResult::Unchanged;
    };
    operations.route_exists = [](const route::RouteSpec&, bool& exists) noexcept {
        exists = true;
        return true;
    };
    operations.remove = [&deletes](const route::RouteSpec&) noexcept {
        ++deletes;
        return true;
    };
    route::DarwinRoutePlatform platform(std::move(operations));
    const route::RouteSpec spec{ 1u, 2u, 32, {} };

    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Unchanged));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(deletes == 2);
}

BOOST_AUTO_TEST_CASE(darwin_add_unchanged_requires_exact_route_without_replacement) {
    struct Scenario final {
        bool query_succeeded;
        bool exact_exists;
        route::RouteAddResult expected;
    };
    const Scenario scenarios[] = {
        { true, true, route::RouteAddResult::Unchanged },
        { true, false, route::RouteAddResult::Failed },
        { false, false, route::RouteAddResult::Failed },
    };
    const route::RouteSpec spec{ 1u, 2u, 24, {} };

    for (const Scenario& scenario : scenarios) {
        int probes = 0;
        int removes = 0;
        int replacements = 0;
        route::DarwinRouteOperations operations;
        operations.add = [](const route::RouteSpec&) noexcept {
            return route::RouteAddResult::Unchanged;
        };
        operations.route_exists = [&scenario, &probes](
            const route::RouteSpec&, bool& exists) noexcept {
            ++probes;
            exists = scenario.exact_exists;
            return scenario.query_succeeded;
        };
        operations.remove = [&removes](const route::RouteSpec&) noexcept {
            ++removes;
            return true;
        };
        operations.remove_conflicting_default =
            [&replacements](const route::RouteSnapshotPtr&,
                route::RouteSnapshotPtr&) noexcept {
                ++replacements;
                return true;
            };

        route::DarwinRoutePlatform platform(std::move(operations));
        BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
            static_cast<int>(scenario.expected));
        BOOST_TEST(probes == 1);
        BOOST_TEST(removes == 0);
        BOOST_TEST(replacements == 0);
    }
}

BOOST_AUTO_TEST_CASE(darwin_restore_returns_immediately_when_exact_route_exists) {
    int mutations = 0;
    auto target = std::make_shared<Snapshot>(20);
    route::DarwinRouteOperations operations;
    operations.exact_default_exists = [](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        exists = true;
        return true;
    };
    operations.remove_conflicting_default =
        [&mutations](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr&) noexcept {
            ++mutations;
            return true;
        };
    operations.restore_default =
        [&mutations](const route::RouteSnapshotPtr&) noexcept {
            ++mutations;
            return true;
        };

    route::DarwinRoutePlatform platform(std::move(operations));
    BOOST_TEST(platform.RestoreDefault(target));
    BOOST_TEST(mutations == 0);
}

BOOST_AUTO_TEST_CASE(darwin_restore_replaces_conflict_and_confirms_exact_target) {
    std::vector<std::string> calls;
    int query_count = 0;
    auto target = std::make_shared<Snapshot>(21);
    auto conflict = std::make_shared<Snapshot>(22);
    route::DarwinRouteOperations operations;
    operations.exact_default_exists =
        [&calls, &query_count](const route::RouteSnapshotPtr&,
            bool& exists) noexcept {
            calls.emplace_back(++query_count == 1 ? "query-before" : "query-after");
            exists = query_count == 2;
            return true;
        };
    operations.remove_conflicting_default =
        [&calls, conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            calls.emplace_back("delete-conflict");
            removed = conflict;
            return true;
        };
    operations.restore_default =
        [&calls](const route::RouteSnapshotPtr&) noexcept {
            calls.emplace_back("add-target");
            return true;
        };

    route::DarwinRoutePlatform platform(std::move(operations));
    BOOST_TEST(platform.RestoreDefault(target));
    const std::vector<std::string> expected = {
        "query-before", "delete-conflict", "add-target", "query-after"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(darwin_restore_compensates_when_target_add_fails) {
    std::vector<std::string> calls;
    auto target = std::make_shared<Snapshot>(23);
    auto conflict = std::make_shared<Snapshot>(24);
    route::DarwinRouteOperations operations;
    operations.exact_default_exists = [&calls](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        calls.emplace_back("query");
        exists = false;
        return true;
    };
    operations.remove_conflicting_default =
        [&calls, conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            calls.emplace_back("delete-conflict");
            removed = conflict;
            return true;
        };
    operations.remove_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("remove-target");
        return true;
    };
    operations.restore_default =
        [&calls, target](const route::RouteSnapshotPtr& value) noexcept {
            if (value == target) {
                calls.emplace_back("add-target");
                return false;
            }
            calls.emplace_back("restore-conflict");
            return true;
        };

    route::DarwinRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(target));
    const std::vector<std::string> expected = {
        "query", "delete-conflict", "add-target",
        "remove-target", "restore-conflict"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(darwin_restore_compensates_when_exact_confirmation_fails) {
    std::vector<std::string> calls;
    int query_count = 0;
    auto target = std::make_shared<Snapshot>(25);
    auto conflict = std::make_shared<Snapshot>(26);
    route::DarwinRouteOperations operations;
    operations.exact_default_exists =
        [&calls, &query_count](const route::RouteSnapshotPtr&,
            bool& exists) noexcept {
            calls.emplace_back(++query_count == 1 ? "query-before" : "query-after");
            exists = false;
            return true;
        };
    operations.remove_conflicting_default =
        [&calls, conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            calls.emplace_back("delete-conflict");
            removed = conflict;
            return true;
        };
    operations.remove_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("remove-target");
        return true;
    };
    operations.restore_default =
        [&calls, target](const route::RouteSnapshotPtr& value) noexcept {
            calls.emplace_back(value == target ? "add-target" : "restore-conflict");
            return true;
        };

    route::DarwinRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(target));
    const std::vector<std::string> expected = {
        "query-before", "delete-conflict", "add-target", "query-after",
        "remove-target", "restore-conflict"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(darwin_failed_compensation_is_retried_before_new_restore_work) {
    std::vector<std::string> calls;
    int conflict_restore_attempts = 0;
    int query_attempts = 0;
    auto target = std::make_shared<Snapshot>(27);
    auto conflict = std::make_shared<Snapshot>(28);
    route::DarwinRouteOperations operations;
    operations.exact_default_exists =
        [&calls, &query_attempts](const route::RouteSnapshotPtr&,
            bool& exists) noexcept {
            calls.emplace_back("query");
            exists = false;
            return ++query_attempts == 1;
        };
    operations.remove_conflicting_default =
        [&calls, conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            calls.emplace_back("delete-conflict");
            removed = conflict;
            return true;
        };
    operations.remove_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("remove-target");
        return true;
    };
    operations.restore_default =
        [&calls, &conflict_restore_attempts, target](
            const route::RouteSnapshotPtr& value) noexcept {
            if (value == target) {
                calls.emplace_back("add-target");
                return false;
            }
            calls.emplace_back("restore-conflict");
            return ++conflict_restore_attempts == 2;
        };

    route::DarwinRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(target));
    BOOST_TEST(!platform.RestoreDefault(target));
    const std::vector<std::string> expected = {
        "query", "delete-conflict", "add-target",
        "remove-target", "restore-conflict",
        "remove-target", "restore-conflict", "query"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(darwin_query_failure_has_no_mutation_and_returns_false) {
    int mutations = 0;
    auto target = std::make_shared<Snapshot>(29);
    route::DarwinRouteOperations operations;
    operations.exact_default_exists = [](const route::RouteSnapshotPtr&,
        bool&) noexcept {
        return false;
    };
    operations.remove_conflicting_default =
        [&mutations](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr&) noexcept {
            ++mutations;
            return true;
        };
    operations.restore_default =
        [&mutations](const route::RouteSnapshotPtr&) noexcept {
            ++mutations;
            return true;
        };

    route::DarwinRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(target));
    BOOST_TEST(mutations == 0);
}

BOOST_AUTO_TEST_CASE(windows_route_identity_includes_policy) {
    const route::WindowsRouteIdentity original{ 1u, 2u, 3u, 4u, 5u };
    route::WindowsRouteIdentity different_policy = original;
    different_policy.policy = 6u;

    BOOST_TEST(!route::SameWindowsRouteIdentity(original, different_policy));
}

BOOST_AUTO_TEST_CASE(windows_capture_distinguishes_failure_from_empty) {
    route::WindowsRouteOperations failed_operations;
    failed_operations.capture_defaults = []() noexcept {
        return route::DefaultRouteCapture();
    };
    route::WindowsRoutePlatform failed(std::move(failed_operations));
    BOOST_TEST(!failed.CaptureDefaults().has_value());

    route::WindowsRouteOperations empty_operations;
    empty_operations.capture_defaults = []() noexcept {
        return route::DefaultRouteCapture(std::vector<route::RouteSnapshotPtr>());
    };
    route::WindowsRoutePlatform empty(std::move(empty_operations));
    const route::DefaultRouteCapture captured = empty.CaptureDefaults();
    BOOST_REQUIRE(captured.has_value());
    BOOST_TEST(captured->empty());
}

BOOST_AUTO_TEST_CASE(windows_add_and_delete_preserve_postcondition_status) {
    int deletes = 0;
    route::WindowsRouteOperations operations;
    operations.add = [](const route::RouteSpec&) noexcept {
        return route::RouteAddResult::Unchanged;
    };
    operations.remove = [&deletes](const route::RouteSpec&) noexcept {
        ++deletes;
        return true;
    };
    route::WindowsRoutePlatform platform(std::move(operations));
    const route::RouteSpec spec{ 1u, 2u, 32, {} };

    BOOST_TEST(static_cast<int>(platform.Add(spec)) ==
        static_cast<int>(route::RouteAddResult::Unchanged));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(deletes == 2);
}

BOOST_AUTO_TEST_CASE(windows_restore_removes_conflicting_identity_before_create) {
    std::vector<std::string> calls;
    auto snapshot = std::make_shared<Snapshot>(9);
    auto conflict = std::make_shared<Snapshot>(90);
    route::WindowsRouteOperations operations;
    operations.exact_default_exists = [&calls](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        calls.emplace_back("exact");
        exists = false;
        return true;
    };
    operations.remove_conflicting_default =
        [&calls, conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            calls.emplace_back("remove-conflict");
            removed = conflict;
            return true;
        };
    operations.restore_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("create");
        return true;
    };

    route::WindowsRoutePlatform platform(std::move(operations));
    BOOST_TEST(platform.RestoreDefault(snapshot));
    const std::vector<std::string> expected = {
        "exact", "remove-conflict", "create"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(windows_restore_never_deletes_an_exact_row) {
    int conflicting_removes = 0;
    int creates = 0;
    auto snapshot = std::make_shared<Snapshot>(10);
    route::WindowsRouteOperations operations;
    operations.exact_default_exists = [](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        exists = true;
        return true;
    };
    operations.remove_conflicting_default =
        [&conflicting_removes](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr&) noexcept {
            ++conflicting_removes;
            return true;
        };
    operations.restore_default = [&creates](const route::RouteSnapshotPtr&) noexcept {
        ++creates;
        return true;
    };

    route::WindowsRoutePlatform platform(std::move(operations));
    BOOST_TEST(platform.RestoreDefault(snapshot));
    BOOST_TEST(conflicting_removes == 0);
    BOOST_TEST(creates == 0);
}

BOOST_AUTO_TEST_CASE(windows_restore_keeps_pending_when_conflict_removal_fails) {
    int creates = 0;
    auto snapshot = std::make_shared<Snapshot>(11);
    route::WindowsRouteOperations operations;
    operations.exact_default_exists = [](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        exists = false;
        return true;
    };
    operations.remove_conflicting_default =
        [](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr&) noexcept { return false; };
    operations.restore_default = [&creates](const route::RouteSnapshotPtr&) noexcept {
        ++creates;
        return true;
    };

    route::WindowsRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(snapshot));
    BOOST_TEST(creates == 0);
}

BOOST_AUTO_TEST_CASE(windows_restore_rolls_back_conflict_when_target_create_fails) {
    std::vector<std::string> calls;
    auto target = std::make_shared<Snapshot>(12);
    auto conflict = std::make_shared<Snapshot>(120);
    route::WindowsRouteOperations operations;
    operations.exact_default_exists = [&calls](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        calls.emplace_back("exact");
        exists = false;
        return true;
    };
    operations.remove_conflicting_default =
        [&calls, conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            calls.emplace_back("delete-conflict");
            removed = conflict;
            return true;
        };
    operations.remove_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("remove-target");
        return true;
    };
    operations.restore_default =
        [&calls, target](const route::RouteSnapshotPtr& value) noexcept {
            if (value == target) {
                calls.emplace_back("add-target");
                return false;
            }
            calls.emplace_back("restore-conflict");
            return true;
        };

    route::WindowsRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(target));
    const std::vector<std::string> expected = {
        "exact", "delete-conflict", "add-target",
        "remove-target", "restore-conflict"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(windows_restore_reports_failed_conflict_rollback) {
    int rollback_attempts = 0;
    auto target = std::make_shared<Snapshot>(13);
    auto conflict = std::make_shared<Snapshot>(130);
    route::WindowsRouteOperations operations;
    operations.exact_default_exists = [](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        exists = false;
        return true;
    };
    operations.remove_conflicting_default =
        [conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            removed = conflict;
            return true;
        };
    operations.remove_default = [](const route::RouteSnapshotPtr&) noexcept {
        return true;
    };
    operations.restore_default =
        [&rollback_attempts, target](const route::RouteSnapshotPtr& value) noexcept {
            if (value == target) {
                return false;
            }
            ++rollback_attempts;
            return false;
        };

    route::WindowsRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(target));
    BOOST_TEST(rollback_attempts == 1);
}

BOOST_AUTO_TEST_CASE(windows_failed_compensation_is_retried_before_new_restore_work) {
    std::vector<std::string> calls;
    int conflict_restore_attempts = 0;
    int query_attempts = 0;
    auto target = std::make_shared<Snapshot>(14);
    auto conflict = std::make_shared<Snapshot>(140);
    route::WindowsRouteOperations operations;
    operations.exact_default_exists =
        [&calls, &query_attempts](const route::RouteSnapshotPtr&,
            bool& exists) noexcept {
            calls.emplace_back("query");
            exists = false;
            return ++query_attempts == 1;
        };
    operations.remove_conflicting_default =
        [&calls, conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            calls.emplace_back("delete-conflict");
            removed = conflict;
            return true;
        };
    operations.remove_default = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("remove-target");
        return true;
    };
    operations.restore_default =
        [&calls, &conflict_restore_attempts, target](
            const route::RouteSnapshotPtr& value) noexcept {
            if (value == target) {
                calls.emplace_back("add-target");
                return false;
            }
            calls.emplace_back("restore-conflict");
            return ++conflict_restore_attempts == 2;
        };

    route::WindowsRoutePlatform platform(std::move(operations));
    BOOST_TEST(!platform.RestoreDefault(target));
    BOOST_TEST(!platform.RestoreDefault(target));
    const std::vector<std::string> expected = {
        "query", "delete-conflict", "add-target",
        "remove-target", "restore-conflict",
        "remove-target", "restore-conflict", "query"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(mobile_adapter_builds_deduplicated_all_route_plan) {
    route::MobileRoutePlan plan;
    plan.tap_network = 0x0a000000u;
    plan.tap_prefix = 24;
    plan.tap_gateway = 0x0a000001u;
    plan.loopback_gateway = 0x7f000001u;
    plan.tunnel_dns = { 1u, 2u };
    plan.underlying_dns = { 2u, 3u };

    std::vector<route::RouteSpec> specs = route::BuildMobileRouteSpecs(plan);
    BOOST_REQUIRE(specs.size() == 4u);
    BOOST_TEST(specs[0].network == 0x0a000000u);
    BOOST_TEST(specs[0].prefix == 24);
    BOOST_TEST(specs[0].gateway == plan.tap_gateway);
    BOOST_TEST(specs[1].gateway == plan.tap_gateway);
    BOOST_TEST(specs[2].gateway == plan.tap_gateway);
    BOOST_TEST(specs[3].network == 3u);
    BOOST_TEST(specs[3].gateway == plan.loopback_gateway);

    std::vector<uint32_t> applied;
    route::MobileRoutePlatform platform(
        [&applied](const route::RouteSpec& spec) noexcept {
            applied.emplace_back(spec.network);
            return true;
        });
    BOOST_TEST(platform.ApplyAll(specs));
    BOOST_TEST(applied.size() == specs.size());
}
