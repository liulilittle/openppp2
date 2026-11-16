// Windows QoS stub for offline test binaries that reference
// IWebsocketTransmission's Windows QoS path without linking
// windows/ppp/net/QoSS.cpp. Returns nullptr so no QoS tuning is applied,
// matching the disabled-QoS runtime behavior.

#include <ppp/stdafx.h>

#if defined(_WIN32)

#include <windows/ppp/net/QoSS.h>

namespace ppp {
namespace net {

std::shared_ptr<QoSS> QoSS::New(int, const boost::asio::ip::address&, int, bool) noexcept {
    return nullptr;
}

} // namespace net
} // namespace ppp

#endif // _WIN32
