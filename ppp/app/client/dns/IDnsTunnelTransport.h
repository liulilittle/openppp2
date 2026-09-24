#pragma once

#include <boost/asio/ip/udp.hpp>

namespace ppp::app::client::dns {

class IDnsTunnelTransport {
public:
    virtual ~IDnsTunnelTransport() noexcept = default;

    virtual bool SendDnsDatagram(
        const boost::asio::ip::udp::endpoint& source,
        const boost::asio::ip::udp::endpoint& destination,
        const void* packet,
        int packet_size) noexcept = 0;
};

}
