#define BOOST_TEST_MODULE route_snapshot_contract_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/RouteSnapshotContract.h>

namespace route = ppp::app::client::route;

namespace {

route::RouteSnapshotRecord MakeRecord() {
    route::RouteSnapshotRecord record;
    record.platform = route::RouteSnapshotPlatform::Linux;
    record.route = route::RouteSpec{ 0u, 0x01020304u, 0, "eth0" };
    record.identity.interface_index = 7;
    record.identity.interface_name = "eth0";
    record.identity.link_identity = "02:00:00:00:00:07";
    record.route.interface_name = record.identity.interface_name;
    return record;
}

}

BOOST_AUTO_TEST_CASE(versioned_records_round_trip_without_pointer_state) {
    const route::RouteSnapshotRecord source = MakeRecord();
    std::string wire;
    BOOST_REQUIRE(route::SerializeRouteSnapshot(source, wire));
    BOOST_REQUIRE(!wire.empty());

    const auto parsed = route::DeserializeRouteSnapshot(wire);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_TEST(parsed->version == route::RouteSnapshotRecord::kVersion);
    BOOST_TEST(route::SameRouteSnapshotRoute(source, *parsed));
}

BOOST_AUTO_TEST_CASE(incomplete_identity_is_rejected_before_persistence) {
    route::RouteSnapshotRecord record = MakeRecord();
    record.identity.interface_index = 0;
    std::string wire;
    BOOST_TEST(!route::SerializeRouteSnapshot(record, wire));

    record = MakeRecord();
    record.identity.link_identity.clear();
    BOOST_TEST(!route::SerializeRouteSnapshot(record, wire));
}

BOOST_AUTO_TEST_CASE(unknown_version_platform_and_truncation_fail_closed) {
    const route::RouteSnapshotRecord source = MakeRecord();
    std::string wire;
    BOOST_REQUIRE(route::SerializeRouteSnapshot(source, wire));

    std::string unknown_version = wire;
    unknown_version[6] = static_cast<char>(
        route::RouteSnapshotRecord::kVersion + 1);
    BOOST_TEST(!route::DeserializeRouteSnapshot(unknown_version).has_value());

    std::string unknown_platform = wire;
    unknown_platform[7] = static_cast<char>(0xff);
    BOOST_TEST(!route::DeserializeRouteSnapshot(unknown_platform).has_value());

    wire.pop_back();
    BOOST_TEST(!route::DeserializeRouteSnapshot(wire).has_value());
}

BOOST_AUTO_TEST_CASE(darwin_identity_is_distinct_from_linux_identity) {
    route::RouteSnapshotRecord source = MakeRecord();
    source.platform = route::RouteSnapshotPlatform::Darwin;
    source.identity.interface_index = 4;
    source.identity.interface_name = "en0";
    source.identity.link_identity = "00:11:22:33:44:55";
    source.route.interface_name = source.identity.interface_name;

    std::string wire;
    BOOST_REQUIRE(route::SerializeRouteSnapshot(source, wire));
    const auto parsed = route::DeserializeRouteSnapshot(wire);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(static_cast<int>(parsed->platform) ==
        static_cast<int>(route::RouteSnapshotPlatform::Darwin));
    BOOST_TEST(parsed->identity.interface_index == 4u);
    BOOST_TEST(parsed->identity.interface_name == "en0");
}
