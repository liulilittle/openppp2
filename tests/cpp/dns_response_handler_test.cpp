#define BOOST_TEST_MODULE dns_response_handler_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/net/packet/IPFrame.h>

namespace client_dns = ppp::app::client::dns;

namespace {

boost::asio::ip::udp::endpoint MakeEndpoint(const char* address, uint16_t port) {
    boost::system::error_code ec;
    return boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address(address, ec), port);
}

std::shared_ptr<ppp::net::packet::BufferSegment> MakeQuerySegment(const char* payload) {
  auto segment = ppp::make_shared_object<ppp::net::packet::BufferSegment>();
  const std::size_t length = std::strlen(payload);
  segment->Buffer = std::shared_ptr<ppp::Byte>(new ppp::Byte[length], std::default_delete<ppp::Byte[]>());
  std::memcpy(segment->Buffer.get(), payload, length);
  segment->Length = static_cast<int>(length);
  return segment;
}

client_dns::DnsResponseHandlerPorts MakePorts(
    bool inject_ok,
    bool& inject_called,
    bool& tunnel_called,
  int& tunnel_bytes) {

    client_dns::DnsResponseHandlerPorts ports;
    ports.enable_dns_cache = false;
    ports.datagram_output =
        [inject_ok, &inject_called](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const std::shared_ptr<ppp::Byte>&,
            void*,
            int,
            bool) noexcept {
            inject_called = true;
            return inject_ok;
        };
    ports.tunnel_send =
        [&tunnel_called, &tunnel_bytes](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const void*,
            int packet_size) noexcept {
            tunnel_called = true;
            tunnel_bytes = packet_size;
            return true;
        };
    return ports;
}

}  // namespace

BOOST_AUTO_TEST_CASE(inject_success_skips_tunnel_fallback) {
    bool inject_called = false;
    bool tunnel_called = false;
    int tunnel_bytes = 0;

    client_dns::DnsResponseHandlerPorts ports;
    ports.datagram_output =
        [&inject_called](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const std::shared_ptr<ppp::Byte>&,
            void*,
            int,
            bool) noexcept {
            inject_called = true;
            return true;
        };
    ports.tunnel_send =
        [&tunnel_called, &tunnel_bytes](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const void*,
            int packet_size) noexcept {
            tunnel_called = true;
            tunnel_bytes = packet_size;
            return true;
        };

    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    auto query = MakeQuerySegment("query");
    ppp::vector<ppp::Byte> response = { 0x12, 0x34, 0x81, 0x80 };

    client_dns::DnsResponseHandler::HandleWithPorts(
        ports, query, source, dest, std::move(response));

    BOOST_TEST(inject_called);
    BOOST_TEST(!tunnel_called);
    BOOST_TEST(tunnel_bytes == 0);
}

BOOST_AUTO_TEST_CASE(inject_failure_falls_back_to_tunnel) {
    bool inject_called = false;
    bool tunnel_called = false;
    int tunnel_bytes = 0;
    auto ports = MakePorts(false, inject_called, tunnel_called, tunnel_bytes);

    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    auto query = MakeQuerySegment("fallback-query");
    ppp::vector<ppp::Byte> response = { 0xab, 0xcd, 0x81, 0x80 };

    client_dns::DnsResponseHandler::HandleWithPorts(
        ports, query, source, dest, std::move(response));

    BOOST_TEST(inject_called);
    BOOST_TEST(tunnel_called);
    BOOST_TEST(tunnel_bytes == static_cast<int>(std::strlen("fallback-query")));
}

BOOST_AUTO_TEST_CASE(empty_response_without_query_is_dropped) {
    client_dns::DnsResponseHandlerPorts ports;
    bool tunnel_called = false;
    ports.tunnel_send =
        [&tunnel_called](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const void*,
            int) noexcept {
            tunnel_called = true;
            return true;
        };

    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    ppp::vector<ppp::Byte> response;

    client_dns::DnsResponseHandler::HandleWithPorts(
        ports, nullptr, source, dest, std::move(response));

    BOOST_TEST(!tunnel_called);
}

BOOST_AUTO_TEST_CASE(empty_response_with_query_still_tunnels) {
    bool tunnel_called = false;
    int tunnel_bytes = 0;
    client_dns::DnsResponseHandlerPorts ports;
    ports.tunnel_send =
        [&tunnel_called, &tunnel_bytes](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const void*,
            int packet_size) noexcept {
            tunnel_called = true;
            tunnel_bytes = packet_size;
            return true;
        };

    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    auto query = MakeQuerySegment("tunnel-only");
    ppp::vector<ppp::Byte> response;

    client_dns::DnsResponseHandler::HandleWithPorts(
        ports, query, source, dest, std::move(response));

    BOOST_TEST(tunnel_called);
    BOOST_TEST(tunnel_bytes == static_cast<int>(std::strlen("tunnel-only")));
}

BOOST_AUTO_TEST_CASE(cache_write_runs_before_inject) {
    bool inject_called = false;
    bool tunnel_called = false;
    int cache_bytes = 0;

    client_dns::DnsResponseHandlerPorts ports;
    ports.enable_dns_cache = true;
    ports.write_cache = [&cache_bytes](const ppp::Byte* packet, int packet_size) noexcept {
        cache_bytes = packet_size;
        BOOST_TEST(packet != nullptr);
    };
    ports.datagram_output =
        [&inject_called](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const std::shared_ptr<ppp::Byte>&,
            void*,
            int,
            bool) noexcept {
            inject_called = true;
            return true;
        };
    ports.tunnel_send =
        [&tunnel_called](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            const void*,
            int) noexcept {
            tunnel_called = true;
            return true;
        };

    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    auto query = MakeQuerySegment("query");
    ppp::vector<ppp::Byte> response = { 0x12, 0x34, 0x81, 0x80 };

    client_dns::DnsResponseHandler::HandleWithPorts(
        ports, query, source, dest, std::move(response));

    BOOST_TEST(cache_bytes == 4);
    BOOST_TEST(inject_called);
    BOOST_TEST(!tunnel_called);
}
