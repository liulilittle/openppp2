#pragma once

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <functional>

namespace ppp::app::client::dns {

class IDnsTunnelTransport {
public:
    using DatagramPacketHandler = std::function<bool(const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&, void*, int)>;
    virtual ~IDnsTunnelTransport() noexcept = default;

    virtual bool SendDnsDatagram(
        const boost::asio::ip::udp::endpoint& source,
        const boost::asio::ip::udp::endpoint& destination,
        const void* packet,
        int packet_size) noexcept = 0;

    virtual bool RegisterDatagramHandler(const boost::asio::ip::udp::endpoint&,
        const DatagramPacketHandler&) noexcept { return false; }
    virtual bool ReleaseDatagramHandler(const boost::asio::ip::udp::endpoint&) noexcept { return false; }
    virtual void ConnectDnsStream(boost::asio::ip::tcp::socket&,
        const boost::asio::ip::tcp::endpoint&,
        const std::function<bool()>&,
        const std::function<void(boost::system::error_code)>& callback) noexcept {
        callback(boost::asio::error::operation_not_supported);
    }
};

}
