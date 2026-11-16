// Windows composition stubs for policy/transport offline test binaries.
//
// These targets link ppp/stdafx.cpp, whose global bootstrap (ppp::global::cctor)
// references the full runtime composition (lwip netstack, executor hooks, vdns,
// ICMP, HTTP proxy connection registry). The real implementations drag the
// native network stack into offline tests, so this translation unit provides
// inert definitions. They are only compiled under MSVC where the linker does
// not discard unreferenced sections the way --gc-sections does on Linux CI.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <memory>
#include <ppp/coroutines/YieldContext.h>

#if defined(_WIN32)
#include <windows.h>

#include <ppp/net/asio/vdns.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/ssl/SSL.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/net/QoSS.h>
#include <openssl/ssl.h>

namespace lwip {

void netstack_cctor() noexcept {}

} // namespace lwip

namespace ppp {

namespace threading {

void Executors_cctor() noexcept {}

void Executors::SetSecondTickHandler(const SecondTickHandler&) noexcept {}

void Executors::SetWorkersStoppedHandler(const WorkersStoppedHandler&) noexcept {}

std::shared_ptr<boost::asio::io_context> Executors::GetExecutor() noexcept {
    return nullptr;
}

std::shared_ptr<boost::asio::io_context> Executors::GetScheduler() noexcept {
    return nullptr;
}

Executors::Awaitable::Awaitable() noexcept = default;

} // namespace threading

#ifndef PPP_STUB_NO_YIELD_SPAWN
namespace coroutines {

bool YieldContext::Spawn(ppp::threading::BufferswapAllocator*, boost::asio::io_context&, boost::asio::strand<boost::asio::io_context::executor_type>*, SpawnHander&&, int) noexcept {
    return false;
}

} // namespace coroutines
#endif // PPP_STUB_NO_YIELD_SPAWN


namespace net {

namespace asio {

namespace vdns {

void vdns_ctor() noexcept {}

void UpdateAsync() noexcept {}

} // namespace vdns

void InternetControlMessageProtocol_DoEvents() noexcept {}

} // namespace asio

std::shared_ptr<QoSS> QoSS::New(int, const boost::asio::ip::address&, int, bool) noexcept {
    return nullptr;
}

} // namespace net

namespace app {

namespace client {

namespace proxys {

void VEthernetHttpProxyConnection_cctor() noexcept {}

} // namespace proxys

} // namespace client

} // namespace app

namespace ethernet {

bool NetstackTryExit() noexcept {
    return false;
}

} // namespace ethernet

} // namespace ppp

namespace ppp::win32 {

bool Win32Native::CloseHandle(const void*) noexcept {
    return false;
}

bool Win32Native::IsUserAnAdministrator() noexcept {
    return false;
}

bool Win32Native::SetThreadDescription(const std::string&) noexcept {
    return false;
}

ppp::string Win32Native::GetFullPath(const char* path) noexcept {
    if (path == NULLPTR || *path == 0) {
        return ppp::string();
    }
    char fullpath[MAX_PATH];
    DWORD size = GetFullPathNameA(path, MAX_PATH, fullpath, NULLPTR);
    if (size == 0 || size >= MAX_PATH) {
        return ppp::string();
    }
    return ppp::string(fullpath, size);
}

} // namespace ppp::win32

namespace ppp::win32::network {

bool SetDnsAddresses(int, const ppp::vector<ppp::string>&) noexcept {
    return false;
}

} // namespace ppp::win32::network

#endif // _WIN32
