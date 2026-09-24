#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <ppp/dns/DnsUdpFlowRegistry.h>
#include <ppp/stdafx.h>

namespace ppp {
namespace configurations { class AppConfiguration; }
namespace tap { class ITap; }
namespace threading { class BufferswapAllocator; class Timer; }
namespace net {
namespace packet { class BufferSegment; }
#if defined(_LINUX)
class ProtectorNetwork;
#endif
}
}

namespace ppp::app::client::dns {

struct DnsQueryContext final {
    using TimeoutRegistrationHandle = void*;

    std::function<bool(
        const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&,
        const std::shared_ptr<Byte>&,
        void*, int, bool)> datagram_output;

    std::shared_ptr<ppp::tap::ITap> tap;
    std::shared_ptr<ppp::configurations::AppConfiguration> configuration;
    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator;
    std::shared_ptr<boost::asio::io_context> io_context;

    std::function<bool(
        TimeoutRegistrationHandle,
        const std::shared_ptr<std::function<void(ppp::threading::Timer*)>>&)> emplace_timeout;
    std::function<bool(TimeoutRegistrationHandle)> delete_timeout;
    std::function<void(const Byte*, int)> write_cache;
    std::shared_ptr<ppp::dns::DnsUdpFlowRegistry> udp_flow_registry;

#if defined(_LINUX)
    std::shared_ptr<ppp::net::ProtectorNetwork> protector_network;
#endif

    std::function<void(
        const std::shared_ptr<ppp::net::packet::BufferSegment>&,
        const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&,
        ppp::vector<Byte>)> handle_resolver_response;

    bool IsValid() const noexcept {
        return datagram_output && tap && configuration && io_context &&
            emplace_timeout && delete_timeout && handle_resolver_response;
    }
};

}
