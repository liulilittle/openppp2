// Link-only fallbacks for offline test binaries that compile
// common/chnroutes2/chnroutes2.cpp directly.
//
// chnroutes2_getiplist() / http_easy_get() reference the coroutine, executor,
// timer and socket runtime. Plain Linux builds drop those references through
// -ffunction-sections/--gc-sections, but ASan/UBSan instrumentation keeps the
// download path alive and the link fails. No offline test calls the download
// path, so these definitions are inert.
//
// Every definition is weak: targets that also link the real implementation
// (Socket.cpp, Timer.cpp, YieldContext.cpp, ...) keep the strong symbol, and
// no duplicate definitions are introduced in non-sanitizer builds. MSVC builds
// use windows_composition_stub.cpp / policy_link_runtime_stub.cpp instead.

#if !defined(_WIN32)

#include <ppp/stdafx.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>
#include <common/libtcpip/netstack.h>

#define OPENPPP2_TEST_WEAK __attribute__((weak))

namespace lwip {

OPENPPP2_TEST_WEAK std::shared_ptr<boost::asio::io_context> netstack::Executor;

} // namespace lwip

namespace ppp {
namespace threading {

OPENPPP2_TEST_WEAK std::shared_ptr<boost::asio::io_context> Executors::GetExecutor() noexcept {
    return nullptr;
}

OPENPPP2_TEST_WEAK std::shared_ptr<boost::asio::io_context> Executors::GetDefault() noexcept {
    return nullptr;
}

OPENPPP2_TEST_WEAK Executors::Awaitable::Awaitable() noexcept = default;

OPENPPP2_TEST_WEAK void Executors::Awaitable::Processed() noexcept {
}

OPENPPP2_TEST_WEAK bool Executors::Awaitable::Await() noexcept {
    return false;
}

OPENPPP2_TEST_WEAK boost::asio::steady_timer::duration Timer::DurationTime(long long int, DurationType) noexcept {
    return boost::asio::steady_timer::duration(0);
}

} // namespace threading

namespace coroutines {

OPENPPP2_TEST_WEAK bool YieldContext::Spawn(ppp::threading::BufferswapAllocator*, boost::asio::io_context&,
    boost::asio::strand<boost::asio::io_context::executor_type>*, SpawnHander&&, int) noexcept {
    return false;
}

} // namespace coroutines

namespace net {

OPENPPP2_TEST_WEAK bool Socket::Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>&) noexcept {
    return false;
}

} // namespace net
} // namespace ppp

#endif // !_WIN32
