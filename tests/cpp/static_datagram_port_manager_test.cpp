#define BOOST_TEST_MODULE static_datagram_port_manager_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/server/udp/StaticDatagramPortManager.h>
#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>

#include "support/static_datagram_manager_stubs.h"

#include <atomic>
#include <thread>

namespace udp_server = ppp::app::server::udp;
namespace spy_ns = ppp::app::server::udp::test;

namespace {

std::shared_ptr<boost::asio::io_context> TestContext() noexcept {
    static std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
    return context;
}

udp_server::VirtualEthernetDatagramPortStaticPtr MakeStubPort(uint32_t source_ip, int source_port) noexcept {
    return std::make_shared<ppp::app::server::VirtualEthernetDatagramPortStatic>(
        std::shared_ptr<ppp::app::server::VirtualEthernetExchanger>(), TestContext(), source_ip, source_port);
}

udp_server::StaticUdpRelayHostPorts MakeFilledPorts() noexcept {
    udp_server::StaticUdpRelayHostPorts ports;
    ports.create_port = [](uint32_t source_ip, int source_port) noexcept { return MakeStubPort(source_ip, source_port); };
    ports.on_port_opened = [](const udp_server::VirtualEthernetDatagramPortStaticPtr&) noexcept {};
    return ports;
}

}  // namespace

BOOST_AUTO_TEST_CASE(default_ports_is_invalid) {
    udp_server::StaticUdpRelayHostPorts ports;
    BOOST_TEST(!ports.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_ports_is_valid) {
    BOOST_TEST(MakeFilledPorts().IsValid());
}

BOOST_AUTO_TEST_CASE(manager_reflects_ports_validity) {
    udp_server::StaticDatagramPortManager invalid((udp_server::StaticUdpRelayHostPorts()));
    BOOST_TEST(!invalid.IsValid());
    udp_server::StaticDatagramPortManager valid(MakeFilledPorts());
    BOOST_TEST(valid.IsValid());
}

BOOST_AUTO_TEST_CASE(make_static_udp_relay_host_ports_null_backend_is_invalid) {
    BOOST_TEST(!udp_server::MakeStaticUdpRelayHostPorts(nullptr).IsValid());
}

BOOST_AUTO_TEST_CASE(get_or_add_dedups_and_opens) {
    spy_ns::StaticDatagramPortSpyInstance().Reset();
    udp_server::StaticUdpRelayHostPorts ports = MakeFilledPorts();
    int create_calls = 0;
    int opened_calls = 0;
    ports.create_port = [&create_calls](uint32_t source_ip, int source_port) noexcept {
        ++create_calls;
        return MakeStubPort(source_ip, source_port);
    };
    ports.on_port_opened = [&opened_calls](const udp_server::VirtualEthernetDatagramPortStaticPtr&) noexcept { ++opened_calls; };
    udp_server::StaticDatagramPortManager m(ports);

    udp_server::VirtualEthernetDatagramPortStaticPtr a = m.GetOrAddDatagramPort(42, 0x0A000001, 5000);
    udp_server::VirtualEthernetDatagramPortStaticPtr b = m.GetOrAddDatagramPort(42, 0x0A000001, 5000);

    BOOST_TEST((a != nullptr));
    BOOST_TEST((a == b));
    BOOST_TEST(create_calls == 1);                                        // second call hit the fast path
    BOOST_TEST(opened_calls == 1);                                        // notified once, on first open
    BOOST_TEST(spy_ns::StaticDatagramPortSpyInstance().open == 1);        // socket opened once
}

BOOST_AUTO_TEST_CASE(release_port_removes_and_disposes) {
    spy_ns::StaticDatagramPortSpyInstance().Reset();
    udp_server::StaticDatagramPortManager m(MakeFilledPorts());

    udp_server::VirtualEthernetDatagramPortStaticPtr p = m.GetOrAddDatagramPort(7, 0x0A000002, 6000);
    BOOST_TEST((p != nullptr));
    BOOST_TEST((m.ReleaseDatagramPort(7) == p));                          // returns the removed port
    BOOST_TEST(spy_ns::StaticDatagramPortSpyInstance().dispose == 1);     // released port disposed
    BOOST_TEST((m.GetOrAddDatagramPort(7, 0x0A000002, 6000) != p));       // gone; a fresh port is created
}

BOOST_AUTO_TEST_CASE(release_port_missing_returns_null) {
    spy_ns::StaticDatagramPortSpyInstance().Reset();
    udp_server::StaticDatagramPortManager m(MakeFilledPorts());
    BOOST_TEST((m.ReleaseDatagramPort(999) == nullptr));
    BOOST_TEST(spy_ns::StaticDatagramPortSpyInstance().dispose == 0);
}

BOOST_AUTO_TEST_CASE(tick_disposes_aging_ports) {
    spy_ns::StaticDatagramPortSpyInstance().Reset();
    udp_server::StaticDatagramPortManager m(MakeFilledPorts());

    m.GetOrAddDatagramPort(11, 0x0A000003, 7000);
    m.Tick(1000);   // stub port has timeout_ == 0, so IsPortAging(1000) is true

    BOOST_TEST(spy_ns::StaticDatagramPortSpyInstance().dispose == 1);     // aged out and disposed
    BOOST_TEST((m.ReleaseDatagramPort(11) == nullptr));                  // already gone from the table
}

BOOST_AUTO_TEST_CASE(tick_on_empty_table_is_noop) {
    spy_ns::StaticDatagramPortSpyInstance().Reset();
    udp_server::StaticDatagramPortManager m(MakeFilledPorts());
    m.Tick(1000);
    BOOST_TEST(spy_ns::StaticDatagramPortSpyInstance().dispose == 0);
}

BOOST_AUTO_TEST_CASE(release_disposes_all_and_clears_table) {
    spy_ns::StaticDatagramPortSpyInstance().Reset();
    udp_server::StaticDatagramPortManager m(MakeFilledPorts());
    m.GetOrAddDatagramPort(21, 0x0A000004, 8000);
    m.GetOrAddDatagramPort(22, 0x0A000005, 8100);

    m.Release();

    BOOST_TEST(spy_ns::StaticDatagramPortSpyInstance().dispose == 2);
    BOOST_TEST((m.ReleaseDatagramPort(21) == nullptr));
    BOOST_TEST((m.ReleaseDatagramPort(22) == nullptr));
}

BOOST_AUTO_TEST_CASE(concurrent_get_or_add_release_tick_no_uaf) {
    udp_server::StaticDatagramPortManager m(MakeFilledPorts());
    std::atomic<int> ops{0};

    // Two adders contend on the same 64 keys (exercising the create-outside-lock / recheck-under-lock
    // race), while a sweeper and a releaser churn the table concurrently.
    auto adder = [&](uint32_t base) {
        for (int i = 0; i < 4000; ++i) {
            m.GetOrAddDatagramPort(1000 + (i % 64), base, 2000 + (i % 64));
            ops.fetch_add(1, std::memory_order_relaxed);
        }
    };
    auto releaser = [&]() {
        for (int i = 0; i < 4000; ++i) {
            m.ReleaseDatagramPort(1000 + (i % 64));
        }
    };
    auto sweeper = [&]() {
        for (int i = 0; i < 4000; ++i) {
            m.Tick(static_cast<std::uint64_t>(1000 + i));
        }
    };

    std::thread t1([&] { adder(0x0A010001); });
    std::thread t2([&] { adder(0x0A010002); });
    std::thread t3(releaser);
    std::thread t4(sweeper);
    t1.join();
    t2.join();
    t3.join();
    t4.join();

    BOOST_TEST(ops.load() == 8000);   // both adders completed without a crash under ASan
}
