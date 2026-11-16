#pragma once

#include <functional>
#include <memory>
#include <cstdint>
#include <string>
#include <boost/asio/ip/tcp.hpp>

namespace ppp::app::client {
class VEthernetExchanger;
namespace dns {

// Host-side TCP bridge adapter used by DNS and policy-update transport wiring.
// The completion must retain the query's socket until it is called.
class PolicyTunnelDnsStream final {
public:
    using Completion = std::function<void(boost::system::error_code)>;
    using ActiveCheck = std::function<bool()>;
    static void Connect(const std::shared_ptr<VEthernetExchanger>& exchanger,
        boost::asio::ip::tcp::socket& socket,
        const boost::asio::ip::tcp::endpoint& upstream,
        const ActiveCheck& active,
        const Completion& completion) noexcept;
    static void Connect(const std::shared_ptr<VEthernetExchanger>& exchanger,
        boost::asio::ip::tcp::socket& socket,
        const std::string& host, std::uint16_t port,
        const ActiveCheck& active,
        const Completion& completion) noexcept;
};

} // namespace dns
} // namespace ppp::app::client
