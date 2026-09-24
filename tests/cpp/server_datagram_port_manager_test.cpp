#define BOOST_TEST_MODULE server_datagram_port_manager_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/server/udp/ServerDatagramPortManager.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>

#include "support/server_datagram_manager_stubs.h"

namespace udp_server = ppp::app::server::udp;
namespace spy_ns = ppp::app::server::udp::test;

namespace {

boost::asio::ip::udp::endpoint Ep(const char* address, unsigned short port) noexcept {
    return boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(address), port);
}

udp_server::VirtualEthernetDatagramPortPtr MakeStubPort(const udp_server::ITransmissionPtr& transmission,
                                                        const boost::asio::ip::udp::endpoint& source) noexcept {
    return std::make_shared<ppp::app::server::VirtualEthernetDatagramPort>(
        std::shared_ptr<ppp::app::server::VirtualEthernetExchanger>(), udp_server::ServerUdpRelayHostPorts(), transmission, source);
}

udp_server::ServerUdpRelayHostPorts MakeFilledPorts() noexcept {
    udp_server::ServerUdpRelayHostPorts ports;
    ports.create_port = [](const udp_server::ITransmissionPtr& transmission,
                           const boost::asio::ip::udp::endpoint& source) noexcept { return MakeStubPort(transmission, source); };
    ports.on_port_opened = [](const udp_server::ITransmissionPtr&,
                              const udp_server::VirtualEthernetDatagramPortPtr&) noexcept {};
    ports.get_configuration = []() noexcept { return std::shared_ptr<ppp::configurations::AppConfiguration>(); };
    ports.do_send_to = [](const udp_server::ITransmissionPtr&, const boost::asio::ip::udp::endpoint&,
                          const boost::asio::ip::udp::endpoint&, ppp::Byte*, int,
                          ppp::coroutines::YieldContext&) noexcept { return true; };
    ports.release_port = [](const boost::asio::ip::udp::endpoint&) noexcept {};
    ports.get_interface_ip = []() noexcept { return boost::asio::ip::address(); };
    ports.namespace_query = [](const void*, int) noexcept { return true; };
    return ports;
}

}  // namespace

BOOST_AUTO_TEST_CASE(default_ports_is_invalid) {
    udp_server::ServerUdpRelayHostPorts ports;
    BOOST_TEST(!ports.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_ports_is_valid) {
    BOOST_TEST(MakeFilledPorts().IsValid());
}

BOOST_AUTO_TEST_CASE(manager_reflects_ports_validity) {
    udp_server::ServerDatagramPortManager invalid((udp_server::ServerUdpRelayHostPorts()));
    BOOST_TEST(!invalid.IsValid());
    udp_server::ServerDatagramPortManager valid(MakeFilledPorts());
    BOOST_TEST(valid.IsValid());
}

BOOST_AUTO_TEST_CASE(make_server_udp_relay_host_ports_null_backend_is_invalid) {
    BOOST_TEST(!udp_server::MakeServerUdpRelayHostPorts(nullptr).IsValid());
}

BOOST_AUTO_TEST_CASE(add_new_datagram_port_dedups_and_opens) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerUdpRelayHostPorts ports = MakeFilledPorts();
    int create_calls = 0;
    int opened_calls = 0;
    ports.create_port = [&create_calls](const udp_server::ITransmissionPtr& transmission,
                                        const boost::asio::ip::udp::endpoint& source) noexcept {
        ++create_calls;
        return MakeStubPort(transmission, source);
    };
    ports.on_port_opened = [&opened_calls](const udp_server::ITransmissionPtr&,
                                           const udp_server::VirtualEthernetDatagramPortPtr&) noexcept { ++opened_calls; };
    udp_server::ServerDatagramPortManager m(ports);

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.1", 5000);
    udp_server::VirtualEthernetDatagramPortPtr a = m.AddNewDatagramPort(udp_server::ITransmissionPtr(), src);
    udp_server::VirtualEthernetDatagramPortPtr b = m.AddNewDatagramPort(udp_server::ITransmissionPtr(), src);

    BOOST_TEST((a != nullptr));
    BOOST_TEST((a == b));
    BOOST_TEST(create_calls == 1);
    BOOST_TEST(opened_calls == 1);                                  // notified once, on first open
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().open == 1);  // socket opened once
}

BOOST_AUTO_TEST_CASE(get_and_release_roundtrip) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.2", 6000);
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));

    udp_server::VirtualEthernetDatagramPortPtr p = m.AddNewDatagramPort(udp_server::ITransmissionPtr(), src);
    BOOST_TEST((p != nullptr));
    BOOST_TEST((m.GetDatagramPort(src) == p));
    BOOST_TEST((m.ReleaseDatagramPort(src) == p));                     // returns the removed port
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));                   // gone from the table
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().dispose == 1);  // released port disposed
}

BOOST_AUTO_TEST_CASE(send_to_destination_opens_port_and_forwards) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());

    unsigned char buf[4] = {1, 2, 3, 4};
    BOOST_TEST(m.SendToDestination(udp_server::ITransmissionPtr(), Ep("10.0.0.3", 7000), Ep("8.8.8.8", 53),
                                   reinterpret_cast<ppp::Byte*>(buf), static_cast<int>(sizeof(buf)), false));
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().open == 1);
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().sendto == 1);
}

BOOST_AUTO_TEST_CASE(send_to_destination_reuses_existing_port) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.4", 8000);
    m.AddNewDatagramPort(udp_server::ITransmissionPtr(), src);
    unsigned char buf[4] = {1, 2, 3, 4};
    BOOST_TEST(m.SendToDestination(udp_server::ITransmissionPtr(), src, Ep("8.8.8.8", 53),
                                   reinterpret_cast<ppp::Byte*>(buf), static_cast<int>(sizeof(buf)), false));

    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().open == 1);    // not reopened
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().sendto == 1);
}

BOOST_AUTO_TEST_CASE(send_to_destination_fin_on_existing_finalizes) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.5", 9000);
    m.AddNewDatagramPort(udp_server::ITransmissionPtr(), src);
    BOOST_TEST(m.SendToDestination(udp_server::ITransmissionPtr(), src, Ep("8.8.8.8", 53), nullptr, 0, true));

    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().dispose == 1);  // MarkFinalize + Dispose
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().sendto == 0);   // no payload sent on fin
}

BOOST_AUTO_TEST_CASE(send_to_destination_fin_without_port_returns_false) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());

    BOOST_TEST(!m.SendToDestination(udp_server::ITransmissionPtr(), Ep("10.0.0.6", 1000), Ep("8.8.8.8", 53),
                                    nullptr, 0, true));
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().open == 0);     // fin never opens a fresh port
}

BOOST_AUTO_TEST_CASE(rebind_updates_every_retained_port) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());
    m.AddNewDatagramPort(udp_server::ITransmissionPtr(), Ep("10.0.0.10", 1400));
    m.AddNewDatagramPort(udp_server::ITransmissionPtr(), Ep("10.0.0.11", 1500));

    m.RebindTransmission(udp_server::ITransmissionPtr());

    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().rebind == 2);
}

BOOST_AUTO_TEST_CASE(tick_disposes_aging_ports) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.7", 1100);
    m.AddNewDatagramPort(udp_server::ITransmissionPtr(), src);
    BOOST_TEST((m.GetDatagramPort(src) != nullptr));

    m.Tick(1000);   // stub port has timeout_ == 0, so IsPortAging(1000) is true

    BOOST_TEST((m.GetDatagramPort(src) == nullptr));                  // aged out of the table
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().dispose == 1); // disposed by the sweep
}

BOOST_AUTO_TEST_CASE(tick_on_empty_table_is_noop) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());
    m.Tick(1000);
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().dispose == 0);
}

BOOST_AUTO_TEST_CASE(release_disposes_all_and_clears_table) {
    spy_ns::ServerDatagramPortSpyInstance().Reset();
    udp_server::ServerDatagramPortManager m(MakeFilledPorts());
    m.AddNewDatagramPort(udp_server::ITransmissionPtr(), Ep("10.0.0.8", 1200));
    m.AddNewDatagramPort(udp_server::ITransmissionPtr(), Ep("10.0.0.9", 1300));

    m.Release();

    BOOST_TEST((m.GetDatagramPort(Ep("10.0.0.8", 1200)) == nullptr));
    BOOST_TEST((m.GetDatagramPort(Ep("10.0.0.9", 1300)) == nullptr));
    BOOST_TEST(spy_ns::ServerDatagramPortSpyInstance().dispose == 2);
}
