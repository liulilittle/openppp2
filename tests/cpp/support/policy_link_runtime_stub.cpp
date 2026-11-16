// Link-only stubs for policy/transport offline test binaries that pull in
// chnroutes2.cpp / HttpClient.cpp / DnsResolver.cpp through the shared
// transport_auth_configuration_test fixture. These symbols live in real
// runtime translation units (Executors.cpp, Timer.cpp, VNetstack.cpp,
// Socket.cpp, BufferswapAllocator.cpp) that drag the native network stack
// into offline tests. The definitions are inert: executors resolve to null,
// timers produce zero durations, and cancel/allocator calls are no-ops.
//
// This file is intentionally separate from windows_composition_stub.cpp:
// policy_dns_transport_test and policy_tunnel_update_connector_test link the
// real implementations, so the symbols must not be defined there twice.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#if defined(_WIN32)
#include <windows.h>

#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/net/Socket.h>
#include <common/libtcpip/netstack.h>

namespace ppp {
namespace threading {

std::shared_ptr<boost::asio::io_context> Executors::GetDefault() noexcept {
    return nullptr;
}

void Executors::Awaitable::Processed() noexcept {
}

bool Executors::Awaitable::Await() noexcept {
    return true;
}

#ifndef PPP_STUB_NO_DURATIONTIME
boost::asio::steady_timer::duration Timer::DurationTime(long long int interval, DurationType durationType) noexcept {
    (void)interval;
    (void)durationType;
    return boost::asio::steady_timer::duration(0);
}
#endif // PPP_STUB_NO_DURATIONTIME

#ifndef PPP_STUB_NO_GETTICKCOUNT
uint64_t Executors::GetTickCount() noexcept {
    return 0;
}
#endif // PPP_STUB_NO_GETTICKCOUNT
#ifndef PPP_STUB_NO_GETCURRENT
std::shared_ptr<boost::asio::io_context> Executors::GetCurrent(bool) noexcept {
    return nullptr;
}
#endif // PPP_STUB_NO_GETCURRENT
#ifndef PPP_STUB_NO_EXECUTORS_NOW
DateTime Executors::Now() noexcept {
    return DateTime();
}
#endif // PPP_STUB_NO_EXECUTORS_NOW
} // namespace threading

} // namespace ppp

namespace lwip {

std::shared_ptr<boost::asio::io_context> netstack::Executor;

} // namespace lwip


#ifndef PPP_STUB_NO_SOCKET_CANCEL
namespace ppp {
namespace net {

void Socket::Cancel(const boost::asio::steady_timer&) noexcept {
}

void Socket::Cancel(const boost::asio::ip::udp::socket&) noexcept {
}

void Socket::Cancel(const boost::asio::ip::tcp::socket&) noexcept {
}

void Socket::Cancel(const boost::asio::ip::tcp::acceptor&) noexcept {
}

void Socket::Cancel(const boost::asio::ip::udp::resolver&) noexcept {
}

void Socket::Cancel(const boost::asio::ip::tcp::resolver&) noexcept {
}

void Socket::Cancel(const std::shared_ptr<boost::asio::ip::udp::socket>&) noexcept {
}

void Socket::Cancel(const std::shared_ptr<boost::asio::ip::tcp::socket>&) noexcept {
}

void Socket::Cancel(const std::shared_ptr<boost::asio::ip::tcp::acceptor>&) noexcept {
}

} // namespace net
} // namespace ppp
#endif // PPP_STUB_NO_SOCKET_CANCEL
#endif // _WIN32
