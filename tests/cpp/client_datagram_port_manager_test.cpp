#define BOOST_TEST_MODULE client_datagram_port_manager_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>

#include "support/datagram_manager_stubs.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace udp_client = ppp::app::client::udp;
namespace spy_ns = ppp::app::client::udp::test;

namespace {

boost::asio::ip::udp::endpoint Ep(const char* address, unsigned short port) noexcept {
    return boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(address), port);
}

udp_client::VEthernetDatagramPortPtr MakeStubPort(const udp_client::ITransmissionPtr& transmission,
                                                  const boost::asio::ip::udp::endpoint& source) noexcept {
    return std::make_shared<ppp::app::client::VEthernetDatagramPort>(
        std::shared_ptr<ppp::app::client::VEthernetExchanger>(), udp_client::UdpRelayHostPorts(), transmission, source);
}

udp_client::UdpRelayHostPorts MakeFilledPorts() noexcept {
    udp_client::UdpRelayHostPorts ports;
    ports.get_tap = []() noexcept { return std::shared_ptr<ppp::tap::ITap>(); };
    ports.get_configuration = []() noexcept { return std::shared_ptr<ppp::configurations::AppConfiguration>(); };
    ports.datagram_output = [](const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&,
                               const std::shared_ptr<ppp::Byte>&, void*, int, bool) noexcept { return true; };
    ports.rewrite_fakeip = [](const boost::asio::ip::address& address) noexcept { return address; };
    ports.do_send_to = [](const udp_client::ITransmissionPtr&, const boost::asio::ip::udp::endpoint&,
                          const boost::asio::ip::udp::endpoint&, ppp::Byte*, int,
                          ppp::coroutines::YieldContext&) noexcept { return true; };
    ports.release_port = [](
        const boost::asio::ip::udp::endpoint&, const ppp::app::client::VEthernetDatagramPort*) noexcept {};
    ports.emplace_timeout = [](int64_t, ppp::function<void()>) noexcept {};
    ports.get_transmission = []() noexcept {
        // Non-null aliasing handle: SendTo only null-checks it before handing it to create_port,
        // and the stub create_port never dereferences it.
        static int transmission_marker = 0;
        return udp_client::ITransmissionPtr(std::shared_ptr<void>(),
            reinterpret_cast<ppp::transmissions::ITransmission*>(&transmission_marker));
    };
    ports.create_port = [](const udp_client::ITransmissionPtr& transmission,
                           const boost::asio::ip::udp::endpoint& source) noexcept { return MakeStubPort(transmission, source); };
    ports.is_disposed = []() noexcept { return false; };
    return ports;
}

}  // namespace

BOOST_AUTO_TEST_CASE(default_ports_is_invalid) {
    udp_client::UdpRelayHostPorts ports;
    BOOST_TEST(!ports.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_ports_is_valid) {
    BOOST_TEST(MakeFilledPorts().IsValid());
}

BOOST_AUTO_TEST_CASE(manager_reflects_ports_validity) {
    udp_client::ClientDatagramPortManager invalid((udp_client::UdpRelayHostPorts()));
    BOOST_TEST(!invalid.IsValid());
    udp_client::ClientDatagramPortManager valid(MakeFilledPorts());
    BOOST_TEST(valid.IsValid());
}

BOOST_AUTO_TEST_CASE(make_udp_relay_host_ports_null_backend_is_invalid) {
    BOOST_TEST(!udp_client::MakeUdpRelayHostPorts(nullptr).IsValid());
}

BOOST_AUTO_TEST_CASE(add_new_datagram_port_dedups_by_source) {
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    int create_calls = 0;
    ports.create_port = [&create_calls](const udp_client::ITransmissionPtr& transmission,
                                        const boost::asio::ip::udp::endpoint& source) noexcept {
        ++create_calls;
        return MakeStubPort(transmission, source);
    };
    udp_client::ClientDatagramPortManager m(ports);

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.1", 5000);
    udp_client::VEthernetDatagramPortPtr a = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    udp_client::VEthernetDatagramPortPtr b = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);

    BOOST_TEST((a != nullptr));
    BOOST_TEST((a == b));
    BOOST_TEST(create_calls == 1);
}

BOOST_AUTO_TEST_CASE(concurrent_same_source_create_returns_one_winner) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    std::mutex mutex;
    std::condition_variable entered_cv;
    std::condition_variable release_cv;
    int entered = 0;
    bool release = false;
    std::atomic<int> self_release_calls{0};
    std::atomic<int> removed_winners{0};
    udp_client::ClientDatagramPortManager* manager = nullptr;
    ports.release_port = [&](const boost::asio::ip::udp::endpoint& source,
                             const ppp::app::client::VEthernetDatagramPort* expected) noexcept {
        ++self_release_calls;
        if (manager->ReleaseDatagramPortIf(source, expected)) {
            ++removed_winners;
        }
    };
    ports.create_port = [&](const udp_client::ITransmissionPtr& transmission,
                            const boost::asio::ip::udp::endpoint& source) noexcept {
        {
            std::unique_lock<std::mutex> lock(mutex);
            ++entered;
            entered_cv.notify_all();
            release_cv.wait(lock, [&]() noexcept { return release; });
        }
        return std::make_shared<ppp::app::client::VEthernetDatagramPort>(
            std::shared_ptr<ppp::app::client::VEthernetExchanger>(), ports, transmission, source);
    };
    udp_client::ClientDatagramPortManager m(ports);
    manager = &m;
    const auto src = Ep("10.0.0.2", 6000);
    udp_client::VEthernetDatagramPortPtr first;
    udp_client::VEthernetDatagramPortPtr second;

    std::thread first_thread([&]() { first = m.AddNewDatagramPort({}, src); });
    std::thread second_thread([&]() { second = m.AddNewDatagramPort({}, src); });
    {
        std::unique_lock<std::mutex> lock(mutex);
        entered_cv.wait(lock, [&]() noexcept { return entered == 2; });
        release = true;
    }
    release_cv.notify_all();
    first_thread.join();
    second_thread.join();

    BOOST_TEST((first != nullptr));
    BOOST_TEST((first == second));
    BOOST_TEST((m.GetDatagramPort(src) == first));
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().construct == 2);
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().finalize == 1);
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 1);
    BOOST_TEST(self_release_calls.load() == 1);
    BOOST_TEST(removed_winners.load() == 0);
}

BOOST_AUTO_TEST_CASE(release_closes_gate_while_create_is_blocked) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    std::mutex mutex;
    std::condition_variable entered_cv;
    std::condition_variable release_cv;
    bool entered = false;
    bool release = false;
    ports.create_port = [&](const udp_client::ITransmissionPtr& transmission,
                            const boost::asio::ip::udp::endpoint& source) noexcept {
        {
            std::unique_lock<std::mutex> lock(mutex);
            entered = true;
            entered_cv.notify_one();
            release_cv.wait(lock, [&]() noexcept { return release; });
        }
        return MakeStubPort(transmission, source);
    };
    udp_client::ClientDatagramPortManager m(ports);
    const auto src = Ep("10.0.0.12", 1600);
    udp_client::VEthernetDatagramPortPtr result;
    std::thread creator([&]() { result = m.AddNewDatagramPort({}, src); });
    {
        std::unique_lock<std::mutex> lock(mutex);
        entered_cv.wait(lock, [&]() noexcept { return entered; });
    }

    m.Release();
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    release_cv.notify_one();
    creator.join();

    BOOST_TEST((result == nullptr));
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().finalize == 1);
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 1);
}

BOOST_AUTO_TEST_CASE(get_and_release_roundtrip) {
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.2", 6000);
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));

    udp_client::VEthernetDatagramPortPtr p = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    BOOST_TEST((p != nullptr));
    BOOST_TEST((m.GetDatagramPort(src) == p));
    BOOST_TEST((m.ReleaseDatagramPort(src) == p));
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));
}

BOOST_AUTO_TEST_CASE(send_to_creates_port_and_forwards) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());
    const auto source = Ep("10.0.0.3", 7000);

    unsigned char buf[4] = {1, 2, 3, 4};
    const bool sent = m.SendTo(source, Ep("8.8.8.8", 53), buf, static_cast<int>(sizeof(buf)));
    BOOST_TEST(sent);
    BOOST_TEST((m.GetDatagramPort(source) != nullptr));
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().sendto == 1);
}

BOOST_AUTO_TEST_CASE(send_to_forwards_each_datagram_routing_action) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());
    const auto source = Ep("10.0.0.13", 1700);
    const auto destination = Ep("8.8.8.8", 53);
    unsigned char packet = 1;
    auto& spy = spy_ns::DatagramPortSpyInstance();

    BOOST_REQUIRE(m.SendTo(source, destination, &packet, 1,
        ppp::app::client::routing::RoutingAction::Direct));
    const auto port = m.GetDatagramPort(source);
    BOOST_REQUIRE((port != nullptr));
    BOOST_TEST(spy.last_action.load() ==
        static_cast<int>(ppp::app::client::routing::RoutingAction::Direct));

    BOOST_REQUIRE(m.SendTo(source, destination, &packet, 1,
        ppp::app::client::routing::RoutingAction::Proxy));
    BOOST_TEST((m.GetDatagramPort(source) == port));
    BOOST_TEST(spy.last_action.load() ==
        static_cast<int>(ppp::app::client::routing::RoutingAction::Proxy));

    BOOST_REQUIRE(m.SendTo(source, destination, &packet, 1));
    BOOST_TEST((m.GetDatagramPort(source) == port));
    BOOST_TEST(spy.last_action.load() ==
        static_cast<int>(ppp::app::client::routing::RoutingAction::Auto));
    BOOST_TEST(spy.sendto.load() == 3);
}

BOOST_AUTO_TEST_CASE(receive_empty_packet_finalizes_port) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.4", 8000);
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    BOOST_TEST(m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), nullptr, 0));

    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 1);   // finalize signal = MarkFinalize + Dispose
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().onmessage == 0);
}

BOOST_AUTO_TEST_CASE(receive_with_port_delivers_onmessage) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.5", 9000);
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    unsigned char buf[4] = {1, 2, 3, 4};
    m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf)));

    BOOST_TEST(spy_ns::DatagramPortSpyInstance().onmessage == 1);
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 0);
}

BOOST_AUTO_TEST_CASE(receive_without_port_reinjects_to_tun) {
    int reinjected = 0;
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    ports.datagram_output = [&reinjected](const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&,
                                          const std::shared_ptr<ppp::Byte>&, void*, int, bool) noexcept { ++reinjected; return true; };
    udp_client::ClientDatagramPortManager m(ports);

    unsigned char buf[4] = {1, 2, 3, 4};
    m.ReceiveFromDestination(Ep("10.0.0.6", 1000), Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf)));
    BOOST_TEST(reinjected == 1);
}

BOOST_AUTO_TEST_CASE(datagram_handler_register_dispatch_release) {
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.7", 1100);
    int handled = 0;
    BOOST_TEST(m.RegisterDatagramHandler(src,
        [&handled](const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&,
                   void*, int) noexcept { ++handled; return true; }));

    unsigned char buf[4] = {1, 2, 3, 4};
    BOOST_TEST(m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf))));
    BOOST_TEST(handled == 1);

    BOOST_TEST(m.ReleaseDatagramHandler(src));
    m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf)));
    BOOST_TEST(handled == 1);   // handler no longer dispatched after release
}

BOOST_AUTO_TEST_CASE(tick_disposes_aging_ports) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.8", 1200);
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    BOOST_TEST((m.GetDatagramPort(src) != nullptr));

    m.Tick(1000);   // stub port has timeout_ == 0, so IsPortAging(1000) is true

    BOOST_TEST((m.GetDatagramPort(src) == nullptr));              // aged out of the table
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 1);   // disposed outside the lock
}

BOOST_AUTO_TEST_CASE(tick_on_empty_table_is_noop) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());
    m.Tick(1000);
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 0);
}

BOOST_AUTO_TEST_CASE(rebind_retained_ports_switches_carrier) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());
    static int old_marker = 0;
    static int new_marker = 0;
    udp_client::ITransmissionPtr old_transmission(std::shared_ptr<void>(),
        reinterpret_cast<ppp::transmissions::ITransmission*>(&old_marker));
    udp_client::ITransmissionPtr new_transmission(std::shared_ptr<void>(),
        reinterpret_cast<ppp::transmissions::ITransmission*>(&new_marker));
    const auto source = Ep("10.0.0.9", 1300);
    m.AddNewDatagramPort(old_transmission, source);

    BOOST_TEST(m.RebindTransmission(udp_client::ITransmissionPtr()));
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().transmission == nullptr);
    BOOST_TEST(m.RebindTransmission(new_transmission));

    unsigned char packet = 1;
    BOOST_TEST(m.SendTo(source, Ep("8.8.8.8", 53), &packet, 1));
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().transmission == new_transmission.get());
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().rebind == 2);
}

BOOST_AUTO_TEST_CASE(reset_ports_preserves_registered_handlers) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());
    const auto source = Ep("10.0.0.10", 1400);
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), source);
    int handled = 0;
    BOOST_REQUIRE(m.RegisterDatagramHandler(source,
        [&handled](const boost::asio::ip::udp::endpoint&,
                   const boost::asio::ip::udp::endpoint&, void*, int) noexcept {
            ++handled;
            return true;
        }));

    m.ResetPorts();

    BOOST_TEST((m.GetDatagramPort(source) == nullptr));
    unsigned char packet = 1;
    BOOST_TEST(m.ReceiveFromDestination(source, Ep("1.1.1.1", 53), &packet, 1));
    BOOST_TEST(handled == 1);
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 1);
}

BOOST_AUTO_TEST_CASE(release_disposes_all_and_clears_tables) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), Ep("10.0.0.9", 1300));
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), Ep("10.0.0.10", 1400));

    m.Release();

    BOOST_TEST((m.GetDatagramPort(Ep("10.0.0.9", 1300)) == nullptr));
    BOOST_TEST((m.GetDatagramPort(Ep("10.0.0.10", 1400)) == nullptr));
    BOOST_TEST((m.AddNewDatagramPort({}, Ep("10.0.0.11", 1500)) == nullptr));
    BOOST_TEST(!m.RegisterDatagramHandler(Ep("10.0.0.11", 1500),
        [](const auto&, const auto&, void*, int) noexcept { return true; }));
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 2);
}

BOOST_AUTO_TEST_CASE(concurrent_send_receive_tick_no_uaf) {
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());
    std::atomic<int> sent{0};

    auto sender = [&]() {
        for (int i = 0; i < 4000; ++i) {
            int payload = i;
            m.SendTo(Ep("10.1.0.1", static_cast<unsigned short>(2000 + (i % 128))),
                     Ep("8.8.8.8", 53), &payload, static_cast<int>(sizeof(payload)));
            sent.fetch_add(1, std::memory_order_relaxed);
        }
    };
    auto receiver = [&]() {
        for (int i = 0; i < 4000; ++i) {
            int payload = i;
            m.ReceiveFromDestination(Ep("10.1.0.1", static_cast<unsigned short>(2000 + (i % 128))),
                                     Ep("1.1.1.1", 53), reinterpret_cast<ppp::Byte*>(&payload),
                                     static_cast<int>(sizeof(payload)));
        }
    };
    auto sweeper = [&]() {
        for (int i = 0; i < 4000; ++i) {
            m.Tick(static_cast<std::uint64_t>(1000 + i));
        }
    };

    std::thread t1(sender), t2(sender), t3(receiver), t4(sweeper);
    t1.join();
    t2.join();
    t3.join();
    t4.join();

    BOOST_TEST(sent.load() == 8000);   // both senders completed without a crash under ASan
}
