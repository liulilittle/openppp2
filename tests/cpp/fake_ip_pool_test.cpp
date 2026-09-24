#define BOOST_TEST_MODULE fake_ip_pool_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/FakeIpPool.h>

namespace client_dns = ppp::app::client::dns;

BOOST_AUTO_TEST_CASE(configure_and_allocate) {
    client_dns::FakeIpPool pool;
    BOOST_TEST(pool.Configure("198.18.0.1/16"));
    BOOST_TEST(pool.IsEnabled());

    boost::system::error_code ec;
    const uint32_t sample_host =
        boost::asio::ip::make_address_v4("198.18.0.5", ec).to_uint();
    BOOST_REQUIRE(!ec);
    BOOST_TEST(pool.ContainsHostOrder(sample_host));

    const uint32_t first = pool.Allocate("example.com");
    const uint32_t second = pool.Allocate("example.com");
    BOOST_TEST(first != 0);
    BOOST_TEST(first == second);

    const uint32_t other = pool.Allocate("other.example");
    BOOST_TEST(other != 0);
    BOOST_TEST(other != first);
}

BOOST_AUTO_TEST_CASE(set_and_lookup_real_ip) {
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));

    const uint32_t fake_host = pool.Allocate("api.example.com");
    BOOST_REQUIRE(fake_host != 0);
    BOOST_TEST(pool.LookupRealIpHostOrder(fake_host) == 0);

    pool.SetRealIp("api.example.com", 0x08080808u); // 8.8.8.8
    BOOST_TEST(pool.LookupRealIpHostOrder(fake_host) == 0x08080808u);
    BOOST_TEST(pool.LookupHostname(fake_host) == "api.example.com");
}

BOOST_AUTO_TEST_CASE(pool_exhaustion_rejects_new_hostnames) {
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.0/30"));

    const uint32_t first = pool.Allocate("first.example.com");
    const uint32_t second = pool.Allocate("second.example.com");
    const uint32_t third = pool.Allocate("third.example.com");
    BOOST_REQUIRE(first != 0);
    BOOST_REQUIRE(second != 0);
    BOOST_REQUIRE(third != 0);

    BOOST_TEST(pool.Allocate("overflow.example.com") == 0u);
    BOOST_TEST(pool.Allocate("first.example.com") == first);
}

BOOST_AUTO_TEST_CASE(invalid_cidr_disables_pool) {
    client_dns::FakeIpPool pool;
    BOOST_TEST(!pool.Configure("not-a-cidr"));
    BOOST_TEST(!pool.IsEnabled());
}

BOOST_AUTO_TEST_CASE(invalid_cidr_clears_existing_pool) {
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));
    const uint32_t fake_host = pool.Allocate("api.example.com");
    BOOST_REQUIRE(fake_host != 0);

    BOOST_TEST(!pool.Configure("not-a-cidr"));
    BOOST_TEST(!pool.IsEnabled());
    BOOST_TEST(pool.LookupHostname(fake_host).empty());

    uint32_t route_network = 123;
    int route_prefix = 45;
    BOOST_TEST(!pool.GetRoute(route_network, route_prefix));
    BOOST_TEST(route_network == 0u);
    BOOST_TEST(route_prefix == 0);
}

BOOST_AUTO_TEST_CASE(route_snapshot_reports_configured_route) {
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));

    uint32_t route_network = 0;
    int route_prefix = 0;
    BOOST_TEST(pool.GetRoute(route_network, route_prefix));
    BOOST_TEST(route_network == htonl(0xC6120000u));
    BOOST_TEST(route_prefix == 16);
}

BOOST_AUTO_TEST_CASE(domain_action_is_sticky_after_real_ip_resolution) {
    using Action = ppp::app::client::routing::RoutingAction;
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));

    const auto allocation = pool.Allocate("direct.example", Action::Direct, true);
    BOOST_REQUIRE(allocation.created);
    BOOST_REQUIRE(allocation.should_resolve);
    BOOST_TEST(allocation.entry.is_resolving);
    BOOST_TEST(!allocation.entry.is_resolved);

    BOOST_REQUIRE(pool.SetResolved("direct.example", 0xCB007107u, Action::Proxy));
    client_dns::FakeIpPool::EntrySnapshot entry;
    BOOST_REQUIRE(pool.Lookup(allocation.entry.fake_ip_host, entry));
    BOOST_TEST(entry.real_ip_host == 0xCB007107u);
    BOOST_TEST(static_cast<int>(entry.action) == static_cast<int>(Action::Direct));
    BOOST_TEST(entry.domain_matched);
    BOOST_TEST(!entry.is_resolving);
    BOOST_TEST(entry.is_resolved);
}

BOOST_AUTO_TEST_CASE(ip_action_applies_when_domain_did_not_match) {
    using Action = ppp::app::client::routing::RoutingAction;
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));

    const auto allocation = pool.Allocate("ip-policy.example", Action::Auto, false);
    BOOST_REQUIRE(allocation.should_resolve);
    BOOST_REQUIRE(pool.SetResolved("ip-policy.example", 0x08080808u, Action::Proxy));

    client_dns::FakeIpPool::EntrySnapshot entry;
    BOOST_REQUIRE(pool.Lookup(allocation.entry.fake_ip_host, entry));
    BOOST_TEST(static_cast<int>(entry.action) == static_cast<int>(Action::Proxy));
    BOOST_TEST(!entry.domain_matched);
}

BOOST_AUTO_TEST_CASE(repeated_allocation_coalesces_resolution_and_failure_allows_retry) {
    using Action = ppp::app::client::routing::RoutingAction;
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));

    const auto first = pool.Allocate("retry.example", Action::Proxy, true);
    const auto concurrent = pool.Allocate("retry.example", Action::Direct, true);
    BOOST_REQUIRE(first.should_resolve);
    BOOST_TEST(!concurrent.should_resolve);
    BOOST_TEST(first.entry.fake_ip_host == concurrent.entry.fake_ip_host);
    BOOST_TEST(static_cast<int>(concurrent.entry.action) == static_cast<int>(Action::Proxy));

    pool.SetResolveFailed("retry.example");
    const auto retry = pool.Allocate("retry.example", Action::Direct, false);
    BOOST_TEST(retry.should_resolve);
    BOOST_TEST(!retry.created);
    BOOST_TEST(static_cast<int>(retry.entry.action) == static_cast<int>(Action::Proxy));
}
