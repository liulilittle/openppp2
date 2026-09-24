#include <ppp/app/client/dns/DnsSessionContext.h>

#include <utility>

namespace ppp::app::client::dns {

DnsSessionContext::DnsSessionContext(
    std::weak_ptr<IDnsTunnelTransport> transport,
    uint64_t generation) noexcept
    : transport_(std::move(transport)),
      generation_(generation) {
}

bool DnsSessionContext::Send(
    const boost::asio::ip::udp::endpoint& source,
    const boost::asio::ip::udp::endpoint& destination,
    const void* packet,
    int packet_size) const noexcept {
    if (!active_.load(std::memory_order_acquire)) {
        return false;
    }
    std::shared_ptr<IDnsTunnelTransport> transport = transport_.lock();
    return nullptr != transport &&
        transport->SendDnsDatagram(source, destination, packet, packet_size);
}

void DnsSessionContext::Close() noexcept {
    active_.store(false, std::memory_order_release);
}

bool DnsSessionContext::IsActive() const noexcept {
    return active_.load(std::memory_order_acquire);
}

uint64_t DnsSessionContext::Generation() const noexcept {
    return generation_;
}

}
