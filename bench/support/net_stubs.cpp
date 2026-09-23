// Stub for benchmarks that link checksum.cpp or rib.cpp directly.
// Provides Socket::GetDefaultTTL() and Socket::SOCKET_RESTRICTIONS_ (needed by
// checksum.cpp's static init of ip_hdr::IP_DFT_TTL) and StringToAddress (needed
// by rib.cpp's AddRoute(const ppp::string&, ...)), without pulling in the full
// Socket.cpp / stdafx.cpp dependency chain.
//
// This file deliberately does NOT define ip_standard_chksum, ip_hdr::IP_HLEN,
// ip_hdr::NewId, or ip_hdr::Parse — those come from checksum.cpp itself.
// Therefore it is safe to link alongside checksum.cpp (unlike packet_stubs.cpp).
#include <ppp/stdafx.h>
#include <ppp/net/Socket.h>
#include <ppp/io/File.h>

namespace ppp::net {
    Socket::SOCKET_RESTRICTIONS::SOCKET_RESTRICTIONS() noexcept
        : IPV6_TCLASS_ON(true), IP_TOS_ON(true), IP_TOS_DEFAULT_FLASH(false) {}

    Socket::SOCKET_RESTRICTIONS Socket::SOCKET_RESTRICTIONS_;

    int Socket::GetDefaultTTL() noexcept { return 64; }
} // namespace ppp::net

// StringToAddress is declared in stdafx.h but defined in stdafx.cpp (too heavy
// to link entirely). Provide a minimal implementation for rib.cpp's CIDR parser.
namespace ppp {
    boost::asio::ip::address StringToAddress(const char* s, boost::system::error_code& ec) noexcept {
        return boost::asio::ip::make_address(s, ec);
    }
} // namespace ppp

// rib.cpp's AddAllRoutesByIPList() calls File::Exists and File::ReadAllText to
// load IP-list files. In benchmarks these paths are never used, so return
// false / empty to short-circuit the file-loading branch.
namespace ppp::io {
    bool File::Exists(const char* path) noexcept { return false; }
    ppp::string File::ReadAllText(const char* path) noexcept { return ppp::string(); }
} // namespace ppp::io
