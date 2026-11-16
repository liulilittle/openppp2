// Netstack bootstrap stubs for offline test binaries that link ppp/stdafx.cpp
// (whose global bootstrap references lwip::netstack_cctor and
// ppp::ethernet::NetstackTryExit) without linking the lwip network stack.

#include <ppp/stdafx.h>

#if defined(_WIN32)

namespace lwip {

void netstack_cctor() noexcept {}

} // namespace lwip

namespace ppp {

namespace ethernet {

bool NetstackTryExit() noexcept {
    return false;
}

} // namespace ethernet

} // namespace ppp

#endif // _WIN32
