#define BOOST_TEST_MODULE dns_udp_flow_registry_test
#include <boost/test/included/unit_test.hpp>

#include <chrono>

#include <ppp/dns/DnsUdpFlowRegistry.h>

namespace {

boost::asio::ip::udp::endpoint MakeEndpoint(const char* address, uint16_t port) {
    boost::system::error_code ec;
    const boost::asio::ip::address ip = boost::asio::ip::make_address(address, ec);
    BOOST_REQUIRE(!ec);
    return boost::asio::ip::udp::endpoint(ip, port);
}

}  // namespace

BOOST_AUTO_TEST_CASE(registered_flow_is_consumed_once) {
    ppp::dns::DnsUdpFlowRegistry registry;
    const auto remote = MakeEndpoint("1.1.1.1", 53);

    BOOST_TEST(registry.Register(53000, remote, std::chrono::seconds(1)));
    BOOST_TEST(registry.Consume(53000, remote));
    BOOST_TEST(!registry.Consume(53000, remote));
}

BOOST_AUTO_TEST_CASE(flow_match_requires_local_port_and_remote_endpoint) {
    ppp::dns::DnsUdpFlowRegistry registry;
    const auto remote = MakeEndpoint("1.1.1.1", 53);

    BOOST_TEST(registry.Register(53000, remote, std::chrono::seconds(1)));
    BOOST_TEST(!registry.Consume(53001, remote));
    BOOST_TEST(!registry.Consume(53000, MakeEndpoint("1.1.1.1", 5353)));
    BOOST_TEST(!registry.Consume(53000, MakeEndpoint("1.0.0.1", 53)));
    BOOST_TEST(registry.Consume(53000, remote));
}

BOOST_AUTO_TEST_CASE(flow_rejects_invalid_lifetime) {
    ppp::dns::DnsUdpFlowRegistry registry;
    BOOST_TEST(!registry.Register(53000, MakeEndpoint("1.1.1.1", 53), std::chrono::milliseconds(0)));
}
