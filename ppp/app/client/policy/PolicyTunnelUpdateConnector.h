#pragma once

#include "PolicyUpdateFetcher.h"

#include <atomic>
#include <functional>
#include <memory>
#include <vector>

namespace ppp::app::client {
class VEthernetExchanger;
}

namespace ppp::app::client::policy {

class PolicyTunnelUpdateConnector final : public PolicyUpdateSocketConnector {
public:
    using Clock = std::chrono::steady_clock;
    using Udp = boost::asio::ip::udp;
    using Tcp = boost::asio::ip::tcp;
    using SocketProtector = std::function<bool(Udp::socket::native_handle_type)>;
    using ResolveBootstrap = std::function<bool(const std::string& hostname,
        const std::vector<Udp::endpoint>& bootstrap, Clock::time_point deadline,
        const std::shared_ptr<std::atomic_bool>& cancelled,
        boost::asio::ip::address& address, std::string& error)>;
    using TunnelActiveCheck = std::function<bool()>;
    using TunnelCompletion = std::function<void(boost::system::error_code)>;
    using ConnectTunnel = std::function<void(const PolicyUpdateEndpoint& endpoint,
        Tcp::socket& socket, const TunnelActiveCheck& active, const TunnelCompletion& completion)>;

    struct TestHooks final {
        ResolveBootstrap resolve_bootstrap;
        ConnectTunnel connect_tunnel;
    };

    PolicyTunnelUpdateConnector(std::shared_ptr<VEthernetExchanger> exchanger,
        std::vector<Udp::endpoint> bootstrap, SocketProtector protect_socket);
    PolicyTunnelUpdateConnector(std::vector<Udp::endpoint> bootstrap, TestHooks test_hooks);

    bool Connect(const PolicyUpdateEndpoint& endpoint,
        Clock::time_point deadline,
        const std::shared_ptr<std::atomic_bool>& cancelled,
        Tcp::socket& socket, std::string& error) override;

private:
    bool ConnectThroughTunnel(const PolicyUpdateEndpoint& endpoint, Clock::time_point deadline,
        const std::shared_ptr<std::atomic_bool>& cancelled,
        Tcp::socket& socket, std::string& error);

    std::vector<Udp::endpoint> bootstrap_;
    TestHooks test_hooks_;
};

} // namespace ppp::app::client::policy
