#include <ppp/app/client/policy/PolicyTunnelUpdateConnector.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
namespace asio = boost::asio;
using Tcp = asio::ip::tcp;
using Udp = asio::ip::udp;
using namespace std::chrono_literals;
using ppp::app::client::policy::PolicyTunnelUpdateConnector;
using ppp::app::client::policy::PolicyUpdateEndpoint;
using ppp::app::client::policy::PolicyUpdateVia;

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void ResolvesHostAndKeepsProxyEgress() {
    const std::vector<Udp::endpoint> bootstrap{
        Udp::endpoint(asio::ip::make_address("192.0.2.53"), 5300)};
    std::atomic_int resolved{0};
    std::atomic_int tunneled{0};
    std::atomic_bool hook_inputs_valid{true};
    PolicyTunnelUpdateConnector::TestHooks hooks;
    hooks.resolve_bootstrap = [&](const std::string& hostname,
        const std::vector<Udp::endpoint>& servers, PolicyTunnelUpdateConnector::Clock::time_point deadline,
        const std::shared_ptr<std::atomic_bool>& cancelled, asio::ip::address& address, std::string&) {
        if (hostname != "rules.example" || servers != bootstrap ||
            std::chrono::steady_clock::now() >= deadline || cancelled)
            hook_inputs_valid.store(false, std::memory_order_relaxed);
        address = asio::ip::make_address("198.51.100.27");
        resolved.fetch_add(1, std::memory_order_relaxed);
        return true;
    };
    hooks.connect_tunnel = [&](const PolicyUpdateEndpoint& endpoint, Tcp::socket& socket,
        const PolicyTunnelUpdateConnector::TunnelActiveCheck& active,
        const PolicyTunnelUpdateConnector::TunnelCompletion& completion) {
        if (endpoint.host != "198.51.100.27" || endpoint.port != 443 ||
            endpoint.via != PolicyUpdateVia::Proxy || !active())
            hook_inputs_valid.store(false, std::memory_order_relaxed);
        completion({});
        tunneled.fetch_add(1, std::memory_order_relaxed);
    };

    PolicyTunnelUpdateConnector connector(bootstrap, std::move(hooks));
    asio::io_context io;
    Tcp::socket socket(io);
    std::string error;
    const bool connected = connector.Connect({"rules.example", 443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 1s, {}, socket, error);
    Require(connected, (std::string("proxy policy connector should complete through the fake exchanger: ") + error).c_str());
    Require(resolved.load(std::memory_order_relaxed) == 1 && tunneled.load(std::memory_order_relaxed) == 1,
        "hostname resolution and tunnel exchange should each run once");
    Require(hook_inputs_valid.load(std::memory_order_relaxed), "bootstrap and tunnel hooks should receive valid inputs");
}

void NumericHostDoesNotRequireBootstrapAndDirectIsRejected() {
    std::atomic_int resolved{0};
    std::atomic_int tunneled{0};
    PolicyTunnelUpdateConnector::TestHooks hooks;
    hooks.resolve_bootstrap = [&](const std::string&, const std::vector<Udp::endpoint>&,
        PolicyTunnelUpdateConnector::Clock::time_point, const std::shared_ptr<std::atomic_bool>&,
        asio::ip::address&, std::string&) {
        resolved.fetch_add(1, std::memory_order_relaxed);
        return false;
    };
    hooks.connect_tunnel = [&](const PolicyUpdateEndpoint& endpoint, Tcp::socket& socket,
        const PolicyTunnelUpdateConnector::TunnelActiveCheck&,
        const PolicyTunnelUpdateConnector::TunnelCompletion& completion) {
        Require(endpoint.host == "198.51.100.9" && endpoint.via == PolicyUpdateVia::Proxy,
            "numeric proxy destination should pass directly to the control tunnel");
        completion({});
        tunneled.fetch_add(1, std::memory_order_relaxed);
    };
    PolicyTunnelUpdateConnector connector({}, std::move(hooks));
    asio::io_context io;
    Tcp::socket socket(io);
    std::string error;
    Require(connector.Connect({"198.51.100.9", 8443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 1s, {}, socket, error),
        "numeric policy source should not need direct bootstrap DNS");
    Require(resolved.load(std::memory_order_relaxed) == 0 && tunneled.load(std::memory_order_relaxed) == 1,
        "numeric source should skip DNS and use the tunnel once");

    Tcp::socket rejected(io);
    error.clear();
    Require(!connector.Connect({"198.51.100.9", 8443, PolicyUpdateVia::Direct},
        std::chrono::steady_clock::now() + 1s, {}, rejected, error),
        "runtime control connector must reject direct egress requests");
    Require(error.find("proxy egress") != std::string::npos,
        "direct egress rejection should be explicit");
}

void MissingBootstrapAndPreCancelledRequestsFailClosed() {
    std::atomic_int tunnel_calls{0};
    PolicyTunnelUpdateConnector::TestHooks hooks;
    hooks.resolve_bootstrap = [](const std::string&, const std::vector<Udp::endpoint>&,
        PolicyTunnelUpdateConnector::Clock::time_point, const std::shared_ptr<std::atomic_bool>&,
        asio::ip::address&, std::string&) { return false; };
    hooks.connect_tunnel = [&](const PolicyUpdateEndpoint&, Tcp::socket&,
        const PolicyTunnelUpdateConnector::TunnelActiveCheck&,
        const PolicyTunnelUpdateConnector::TunnelCompletion& completion) {
        tunnel_calls.fetch_add(1, std::memory_order_relaxed);
        completion({});
    };
    PolicyTunnelUpdateConnector no_bootstrap({}, std::move(hooks));
    asio::io_context io;
    Tcp::socket socket(io);
    std::string error;
    Require(!no_bootstrap.Connect({"rules.example", 443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 1s, {}, socket, error),
        "hostname proxy update without bootstrap must fail");
    Require(error.find("bootstrap DNS") != std::string::npos && tunnel_calls.load() == 0,
        "missing bootstrap must fail before creating a tunnel connection");

    const auto bootstrap = std::vector<Udp::endpoint>{
        Udp::endpoint(asio::ip::make_address("192.0.2.53"), 5300)};
    PolicyTunnelUpdateConnector::TestHooks cancelled_hooks;
    cancelled_hooks.resolve_bootstrap = [](const std::string&, const std::vector<Udp::endpoint>&,
        PolicyTunnelUpdateConnector::Clock::time_point, const std::shared_ptr<std::atomic_bool>&,
        asio::ip::address&, std::string&) { return false; };
    cancelled_hooks.connect_tunnel = [&](const PolicyUpdateEndpoint&, Tcp::socket&,
        const PolicyTunnelUpdateConnector::TunnelActiveCheck&,
        const PolicyTunnelUpdateConnector::TunnelCompletion& completion) {
        tunnel_calls.fetch_add(1, std::memory_order_relaxed);
        completion({});
    };
    PolicyTunnelUpdateConnector connector(bootstrap, std::move(cancelled_hooks));
    auto cancelled = std::make_shared<std::atomic_bool>(true);
    error.clear();
    Require(!connector.Connect({"198.51.100.9", 443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 1s, cancelled, socket, error),
        "pre-cancelled update must fail before tunnel setup");
    Require(error.find("cancelled") != std::string::npos && tunnel_calls.load() == 0,
        "pre-cancelled request must not invoke the fake exchanger");
}

void LateTunnelCompletionIsSafeAfterDeadline() {
    std::thread late_completion;
    PolicyTunnelUpdateConnector::TestHooks hooks;
    hooks.connect_tunnel = [&](const PolicyUpdateEndpoint&, Tcp::socket&,
        const PolicyTunnelUpdateConnector::TunnelActiveCheck&,
        const PolicyTunnelUpdateConnector::TunnelCompletion& completion) {
        late_completion = std::thread([completion] {
            std::this_thread::sleep_for(80ms);
            completion({});
        });
    };
    PolicyTunnelUpdateConnector connector({}, std::move(hooks));
    asio::io_context io;
    Tcp::socket socket(io);
    std::string error;
    const bool connected = connector.Connect({"198.51.100.9", 443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 20ms, {}, socket, error);
    late_completion.join();
    Require(!connected && error.find("timed out") != std::string::npos,
        "late tunnel completion must not revive a timed-out connect");
}

void CancellationBeforeBootstrapResponseDoesNotStartTunnel() {
    const std::vector<Udp::endpoint> bootstrap{
        Udp::endpoint(asio::ip::make_address("192.0.2.53"), 5300)};
    auto cancelled = std::make_shared<std::atomic_bool>(false);
    std::atomic_bool resolver_started{false};
    std::atomic_int tunnel_calls{0};
    PolicyTunnelUpdateConnector::TestHooks hooks;
    hooks.resolve_bootstrap = [&](const std::string&, const std::vector<Udp::endpoint>&,
        PolicyTunnelUpdateConnector::Clock::time_point,
        const std::shared_ptr<std::atomic_bool>& token, asio::ip::address&, std::string&) {
        resolver_started.store(true, std::memory_order_release);
        while (!token->load(std::memory_order_acquire)) std::this_thread::sleep_for(1ms);
        return false;
    };
    hooks.connect_tunnel = [&](const PolicyUpdateEndpoint&, Tcp::socket&,
        const PolicyTunnelUpdateConnector::TunnelActiveCheck&,
        const PolicyTunnelUpdateConnector::TunnelCompletion& completion) {
        tunnel_calls.fetch_add(1, std::memory_order_relaxed);
        completion({});
    };
    PolicyTunnelUpdateConnector connector(bootstrap, std::move(hooks));
    asio::io_context io;
    Tcp::socket socket(io);
    std::string error;
    bool connected = true;
    std::thread request([&] {
        connected = connector.Connect({"rules.example", 443, PolicyUpdateVia::Proxy},
            std::chrono::steady_clock::now() + 2s, cancelled, socket, error);
    });
    while (!resolver_started.load(std::memory_order_acquire)) std::this_thread::yield();
    cancelled->store(true, std::memory_order_release);
    request.join();
    Require(!connected && error.find("cancelled") != std::string::npos,
        "cancellation before the bootstrap response must abort hostname resolution");
    Require(tunnel_calls.load(std::memory_order_relaxed) == 0,
        "cancellation before bootstrap response must not start the control tunnel");
}

void MulticastDatagramsDoNotFailSharedTunnel() {
    using Link = ppp::app::protocol::VirtualEthernetLinklayer;
    auto context = std::make_shared<asio::io_context>();
    Link link({}, context, {});
    ppp::Byte payload[] = {0x01};
    const Udp::endpoint source(asio::ip::make_address("192.0.2.10"), 1024);
    // No carrier is supplied: these datagrams must be consumed before any
    // transport access. A false result makes the UDP port dispose its carrier.
    const Udp::endpoint destinations[] = {
        {asio::ip::make_address("224.0.0.252"), 5355},
        {asio::ip::make_address("224.0.0.251"), 5353},
        {asio::ip::make_address("239.255.255.250"), 1900},
        {asio::ip::make_address("ff02::fb"), 5353},
    };
    for (const auto& destination : destinations) {
        Require(link.DoSendTo({}, source, destination, payload, 1,
            ppp::nullof<Link::YieldContext>()),
            "multicast drop must not report a shared-carrier write failure");
    }
    Require(!link.DoSendTo({}, source, destinations[0], nullptr, 1,
        ppp::nullof<Link::YieldContext>()), "malformed datagrams must still fail");
}

} // namespace

int main() {
    try {
        MulticastDatagramsDoNotFailSharedTunnel();
        ResolvesHostAndKeepsProxyEgress();
        NumericHostDoesNotRequireBootstrapAndDirectIsRejected();
        MissingBootstrapAndPreCancelledRequestsFailClosed();
        LateTunnelCompletionIsSafeAfterDeadline();
        CancellationBeforeBootstrapResponseDoesNotStartTunnel();
        std::cout << "policy_tunnel_update_connector_test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "policy_tunnel_update_connector_test failed: " << error.what() << '\n';
        return 1;
    }
}
