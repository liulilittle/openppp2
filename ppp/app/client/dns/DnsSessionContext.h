#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

#include <ppp/app/client/dns/IDnsTunnelTransport.h>

namespace ppp::app::client::dns {

class DnsSessionContext final {
public:
    DnsSessionContext(
        std::weak_ptr<IDnsTunnelTransport> transport,
        uint64_t generation) noexcept;

    bool Send(
        const boost::asio::ip::udp::endpoint& source,
        const boost::asio::ip::udp::endpoint& destination,
        const void* packet,
        int packet_size) const noexcept;
    void Close() noexcept;
    bool IsActive() const noexcept;
    uint64_t Generation() const noexcept;

private:
    std::weak_ptr<IDnsTunnelTransport> transport_;
    uint64_t generation_ = 0;
    std::atomic_bool active_{true};
};

}
