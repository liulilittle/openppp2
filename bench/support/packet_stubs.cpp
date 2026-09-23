#include <ppp/stdafx.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/Socket.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/native/ip.h>

#include <atomic>

namespace ppp::net {
Socket::SOCKET_RESTRICTIONS::SOCKET_RESTRICTIONS() noexcept
    : IPV6_TCLASS_ON(true), IP_TOS_ON(true), IP_TOS_DEFAULT_FLASH(false) {}
Socket::SOCKET_RESTRICTIONS Socket::SOCKET_RESTRICTIONS_;

int Socket::GetDefaultTTL() noexcept { return 64; }

namespace native {
const int ip_hdr::IP_HLEN = sizeof(ip_hdr);
const unsigned char ip_hdr::IP_DFT_TTL = 64;

unsigned short ip_hdr::NewId() noexcept {
    static std::atomic<unsigned int> id{0};
    unsigned short next = 0;
    while (next == 0) next = static_cast<unsigned short>(++id);
    return next;
}

ip_hdr* ip_hdr::Parse(const void* packet, int& length) noexcept {
    auto* header = static_cast<ip_hdr*>(const_cast<void*>(packet));
    if (!header || IPH_V(header) != IP_VER) return nullptr;
    const int header_length = IPH_HL(header) << 2;
    if (header_length < IP_HLEN || header_length > length) return nullptr;
    const int wire_length = ntohs(header->len);
    if (wire_length < header_length || wire_length > length) return nullptr;
    length = wire_length;
    return header;
}

unsigned short ip_standard_chksum(void* data, int length) noexcept {
    auto* bytes = static_cast<unsigned char*>(data);
    unsigned int sum = 0;
    while (length > 1) {
        sum += static_cast<unsigned int>(bytes[0] << 8 | bytes[1]);
        bytes += 2;
        length -= 2;
    }
    if (length) sum += static_cast<unsigned int>(bytes[0] << 8);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return htons(static_cast<unsigned short>(sum));
}
} // namespace native
}
