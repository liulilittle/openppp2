// vdns stub for offline test binaries that link Ipep.cpp (which references the
// vdns resolver globals) without the real vdns runtime. ResolveAsync reports
// failure and the globals stay empty, so hostname resolution falls back to the
// caller's synchronous path.

#include <ppp/net/asio/vdns.h>

namespace ppp::net::asio::vdns {

IPEndPointVectorPtr servers;
std::atomic<int> ttl{0};
std::atomic<bool> enabled{false};

bool ResolveAsync(
    boost::asio::io_context&,
    const char*,
    int,
    const ppp::vector<boost::asio::ip::udp::endpoint>&,
    const ppp::function<void(const boost::asio::ip::address&)>&) noexcept {
    return false;
}

} // namespace ppp::net::asio::vdns
