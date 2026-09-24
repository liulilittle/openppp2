#define BOOST_TEST_MODULE dns_session_context_test
#include <boost/test/included/unit_test.hpp>

#include <atomic>
#include <thread>

#include <ppp/app/client/dns/DnsSessionContext.h>

namespace dns = ppp::app::client::dns;

namespace {

class FakeTransport final : public dns::IDnsTunnelTransport {
public:
    std::atomic_int sends{0};

    bool SendDnsDatagram(
        const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&,
        const void*,
        int) noexcept override {
        ++sends;
        return true;
    }
};

}

BOOST_AUTO_TEST_CASE(expired_transport_and_close_disable_sends) {
    auto transport = std::make_shared<FakeTransport>();
    dns::DnsSessionContext session(transport, 7);
    boost::asio::ip::udp::endpoint endpoint;
    const uint8_t packet = 1;

    BOOST_TEST(session.Generation() == 7u);
    BOOST_TEST(session.Send(endpoint, endpoint, &packet, 1));
    BOOST_TEST(transport->sends.load() == 1);

    transport.reset();
    BOOST_TEST(!session.Send(endpoint, endpoint, &packet, 1));
    session.Close();
    BOOST_TEST(!session.IsActive());
    BOOST_TEST(!session.Send(endpoint, endpoint, &packet, 1));
}

BOOST_AUTO_TEST_CASE(concurrent_close_is_safe_and_idempotent) {
    auto transport = std::make_shared<FakeTransport>();
    auto session = std::make_shared<dns::DnsSessionContext>(transport, 9);
    std::atomic_bool start{false};
    std::thread sender([&]() {
        boost::asio::ip::udp::endpoint endpoint;
        const uint8_t packet = 1;
        while (!start.load(std::memory_order_acquire)) {}
        for (int i = 0; i < 1000; ++i) {
            session->Send(endpoint, endpoint, &packet, 1);
        }
    });
    std::thread closer([&]() {
        start.store(true, std::memory_order_release);
        for (int i = 0; i < 1000; ++i) {
            session->Close();
        }
    });
    sender.join();
    closer.join();
    BOOST_TEST(!session->IsActive());
}
