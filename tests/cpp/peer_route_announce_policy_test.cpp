#define BOOST_TEST_MODULE peer_route_announce_policy_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/PeerPrefixRoute.h>
#include <ppp/app/server/PeerRouteAnnouncePolicy.h>

namespace server = ppp::app::server;
namespace protocol = ppp::app::protocol;

static server::PeerRouteAnnounceEntry entry(const char* network, int prefix) {
    server::PeerRouteAnnounceEntry e;
    e.network = network;
    e.prefix = prefix;
    return e;
}

static server::PeerRouteAllowEntry allow(const char* guid, const char* network, int prefix) {
    server::PeerRouteAllowEntry r;
    r.guid = guid;
    r.network = network;
    r.prefix = prefix;
    return r;
}

BOOST_AUTO_TEST_CASE(empty_allowlist_rejects_everything) {
    ppp::vector<server::PeerRouteAllowEntry> allowed;
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(
        allowed, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", entry("10.20.0.0", 24)));
}

BOOST_AUTO_TEST_CASE(exact_match_allows) {
    ppp::vector<server::PeerRouteAllowEntry> allowed;
    allowed.emplace_back(allow("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "10.20.0.0", 24));
    BOOST_TEST(server::IsPeerRouteAnnouncementAllowed(
        allowed, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", entry("10.20.0.0", 24)));
}

BOOST_AUTO_TEST_CASE(guid_case_and_braces_normalize) {
    ppp::vector<server::PeerRouteAllowEntry> allowed;
    allowed.emplace_back(allow("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", "10.20.0.0", 24));
    // Host bits in the announce are masked; 10.20.0.7/24 == 10.20.0.0/24.
    BOOST_TEST(server::IsPeerRouteAnnouncementAllowed(
        allowed, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", entry("10.20.0.7", 24)));
}

BOOST_AUTO_TEST_CASE(prefix_or_network_mismatch_rejects) {
    ppp::vector<server::PeerRouteAllowEntry> allowed;
    allowed.emplace_back(allow("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "10.20.0.0", 24));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(
        allowed, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", entry("10.20.0.0", 16)));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(
        allowed, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", entry("10.21.0.0", 24)));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(
        allowed, "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee", entry("10.20.0.0", 24)));
}

BOOST_AUTO_TEST_CASE(empty_guid_allow_entry_never_matches) {
    ppp::vector<server::PeerRouteAllowEntry> allowed;
    allowed.emplace_back(allow("", "10.20.0.0", 24));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(
        allowed, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", entry("10.20.0.0", 24)));
}

BOOST_AUTO_TEST_CASE(dangerous_prefixes_rejected_even_if_listed) {
    ppp::vector<server::PeerRouteAllowEntry> allowed;
    const char* guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    allowed.emplace_back(allow(guid, "0.0.0.0", 8));
    allowed.emplace_back(allow(guid, "127.0.0.0", 8));
    allowed.emplace_back(allow(guid, "169.254.0.0", 16));
    allowed.emplace_back(allow(guid, "224.0.0.0", 4));
    allowed.emplace_back(allow(guid, "240.0.0.0", 4));

    BOOST_TEST(server::IsDangerousPeerPrefix(0x7f000000u, 8));
    BOOST_TEST(server::IsDangerousPeerPrefix(0xa9fe0000u, 16));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(allowed, guid, entry("0.0.0.0", 8)));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(allowed, guid, entry("127.0.0.0", 8)));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(allowed, guid, entry("169.254.0.0", 16)));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(allowed, guid, entry("224.0.0.0", 4)));
    BOOST_TEST(!server::IsPeerRouteAnnouncementAllowed(allowed, guid, entry("240.0.0.0", 4)));
}

BOOST_AUTO_TEST_CASE(parse_masks_host_bits) {
    uint32_t network = 0;
    BOOST_REQUIRE(server::ParsePeerPrefixNetwork("10.20.1.5", 24, network));
    // 10.20.1.5/24 -> 10.20.1.0
    BOOST_TEST(network == 0x0a140100u);
}

BOOST_AUTO_TEST_CASE(snapshot_gateway_replaces_client_controlled_via) {
    protocol::PeerPrefixRouteEntry announced;
    announced.network = "10.20.0.0";
    announced.prefix = 24;
    announced.via = "10.0.0.99";

    const protocol::PeerPrefixRouteEntry snapshot =
        server::BindPeerRouteGateway(announced, htonl(0x0a000007u));

    BOOST_TEST(snapshot.network == "10.20.0.0");
    BOOST_TEST(snapshot.prefix == 24);
    BOOST_TEST(snapshot.via == "10.0.0.7");
}
