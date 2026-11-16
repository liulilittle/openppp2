#define BOOST_TEST_MODULE windows_route_snapshot_test
#include <boost/test/included/unit_test.hpp>

#include <array>
#include <string>

#include <ppp/app/client/route/WindowsRouteSnapshot.h>

namespace route = ppp::app::client::route;

namespace {

route::WindowsRouteRowSnapshot Row() {
    route::WindowsRouteRowSnapshot value;
    value.destination = 0x01020304u;
    value.mask = 0xffffff00u;
    value.policy = 7u;
    value.next_hop = 0x05060708u;
    value.interface_index = 12u;
    value.type = 4u;
    value.proto = 3u;
    value.age = 19u;
    value.next_hop_as = 64512u;
    value.metric1 = 10u;
    value.metric2 = 11u;
    value.metric3 = 12u;
    value.metric4 = 13u;
    value.metric5 = 14u;
    value.interface_luid = "123456789";
    value.interface_guid = "{01234567-89ab-cdef-0123-456789abcdef}";
    return value;
}

route::WindowsGatewaySnapshotData Gateway() {
    route::WindowsGatewaySnapshotData value;
    value.interface_index = 9u;
    value.interface_luid = "987654321";
    value.interface_guid = "{fedcba98-7654-3210-fedc-ba9876543210}";
    value.gateway = "192.0.2.1";
    return value;
}

} // namespace

BOOST_AUTO_TEST_CASE(route_row_round_trip_preserves_all_fields) {
    const auto original = Row();
    std::string encoded;
    BOOST_REQUIRE(route::SerializeWindowsRouteSnapshot(original, encoded));
    BOOST_TEST(encoded.size() > 12u);

    route::WindowsRouteRowSnapshot decoded;
    BOOST_REQUIRE(route::DeserializeWindowsRouteSnapshot(encoded, decoded));
    BOOST_TEST(route::VerifyWindowsRouteSnapshot(original, decoded));

    decoded.age++;
    BOOST_TEST(route::VerifyWindowsRouteSnapshot(original, decoded));
    decoded.metric5++;
    BOOST_TEST(!route::VerifyWindowsRouteSnapshot(original, decoded));
}

BOOST_AUTO_TEST_CASE(gateway_round_trip_preserves_interface_identity) {
    const auto original = Gateway();
    std::string encoded;
    BOOST_REQUIRE(route::SerializeWindowsGatewaySnapshot(original, encoded));

    route::WindowsGatewaySnapshotData decoded;
    BOOST_REQUIRE(route::DeserializeWindowsGatewaySnapshot(encoded, decoded));
    BOOST_TEST(route::VerifyWindowsGatewaySnapshot(original, decoded));

    decoded.interface_luid = "other";
    BOOST_TEST(!route::VerifyWindowsGatewaySnapshot(original, decoded));
}

BOOST_AUTO_TEST_CASE(codec_rejects_unknown_version_kind_and_trailing_data) {
    std::string encoded;
    BOOST_REQUIRE(route::SerializeWindowsRouteSnapshot(Row(), encoded));

    route::WindowsRouteRowSnapshot decoded;
    std::string unknown_version = encoded;
    unknown_version[7] = 2;
    BOOST_TEST(!route::DeserializeWindowsRouteSnapshot(unknown_version, decoded));

    std::string wrong_kind = encoded;
    wrong_kind[8] = static_cast<char>(route::WindowsRouteSnapshotKind::Gateway);
    BOOST_TEST(!route::DeserializeWindowsRouteSnapshot(wrong_kind, decoded));

    std::string nonzero_reserved = encoded;
    nonzero_reserved[9] = 1;
    BOOST_TEST(!route::DeserializeWindowsRouteSnapshot(nonzero_reserved, decoded));

    std::string trailing = encoded;
    trailing.push_back('\0');
    BOOST_TEST(!route::DeserializeWindowsRouteSnapshot(trailing, decoded));
}

BOOST_AUTO_TEST_CASE(codec_rejects_truncated_and_oversized_strings) {
    std::string encoded;
    BOOST_REQUIRE(route::SerializeWindowsGatewaySnapshot(Gateway(), encoded));
    route::WindowsGatewaySnapshotData decoded;

    BOOST_TEST(!route::DeserializeWindowsGatewaySnapshot(
        std::string_view(encoded.data(), encoded.size() - 1), decoded));

    // The first string length starts at offset 16 (header + interface index).
    std::string oversized = encoded;
    oversized[16] = static_cast<char>(0x7f);
    oversized[17] = static_cast<char>(0xff);
    oversized[18] = static_cast<char>(0xff);
    oversized[19] = static_cast<char>(0xff);
    BOOST_TEST(!route::DeserializeWindowsGatewaySnapshot(oversized, decoded));
}

BOOST_AUTO_TEST_CASE(empty_identity_is_not_a_wildcard_for_verification) {
    auto expected = Row();
    auto actual = expected;
    actual.interface_luid.clear();
    BOOST_TEST(!route::VerifyWindowsRouteSnapshot(expected, actual));

    expected.interface_guid.clear();
    actual = Row();
    BOOST_TEST(!route::VerifyWindowsRouteSnapshot(expected, actual));

    expected = Row();
    actual = expected;
    actual.interface_luid.clear();
    actual.interface_guid.clear();
    BOOST_TEST(!route::VerifyWindowsRouteSnapshot(expected, actual));
}

BOOST_AUTO_TEST_CASE(gateway_identity_is_required_for_verification) {
    const auto expected = Gateway();
    auto actual = expected;
    actual.interface_guid.clear();
    BOOST_TEST(!route::VerifyWindowsGatewaySnapshot(expected, actual));

    actual = expected;
    actual.interface_luid.clear();
    actual.interface_guid.clear();
    BOOST_TEST(!route::VerifyWindowsGatewaySnapshot(expected, actual));
}
