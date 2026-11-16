// Windows socket platform-guard stubs for offline test binaries that do not
// link ppp/net/Socket.cpp. These guards are no-ops on non-POSIX platforms in
// production; the stubs keep that behavior for MSVC-only builds.

#include <ppp/stdafx.h>

#if defined(_WIN32)

#include <ppp/net/Socket.h>

namespace ppp {
namespace net {

bool Socket::SetTypeOfService(int, int) noexcept {
    return false;
}

bool Socket::SetSignalPipeline(int, bool) noexcept {
    return false;
}

bool Socket::ReuseSocketAddress(int, bool) noexcept {
    return false;
}

void Socket::AdjustDefaultSocketOptional(int, bool) noexcept {}

bool Socket::Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>&) noexcept {
    return false;
}

bool Socket::Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>&) noexcept {
    return false;
}

} // namespace net
} // namespace ppp

#endif // _WIN32
