#pragma once

/**
 * @file TapUserspaceRoute.h
 * @brief Packet classification for the proxy-only in-process adapter.
 */

#include <cstdint>
#include <cstring>

namespace ppp {
    namespace tap {
        enum class TapUserspaceRoute {
            Drop,       ///< Not IPv4, malformed, or unrelated to the local virtual IP.
            Host,       ///< From a peer to the local virtual IP: deliver to the in-process stack.
            HostSyn,    ///< A peer opening a TCP connection to the local virtual IP (SYN without ACK).
            Tunnel,     ///< From the in-process stack: raise as adapter input toward the tunnel.
        };

        /**
         * @brief Classifies a packet written to the in-process adapter.
         * @param local_ip Local virtual IPv4 address in network byte order.
         *
         * HostSyn is reported separately so the adapter can admit only forwarded ports.
         */
        inline TapUserspaceRoute ClassifyTapUserspacePacket(const void* packet, int packet_size, uint32_t local_ip) noexcept {
            constexpr int kIPv4MinHeader = 20;
            constexpr unsigned char kProtoTcp = 6;
            constexpr unsigned char kTcpSyn = 0x02;
            constexpr unsigned char kTcpAck = 0x10;

            if (nullptr == packet || packet_size < kIPv4MinHeader) {
                return TapUserspaceRoute::Drop;
            }

            const unsigned char* bytes = static_cast<const unsigned char*>(packet);
            if ((bytes[0] >> 4) != 4) {
                return TapUserspaceRoute::Drop;
            }

            const int header_length = (bytes[0] & 0x0f) * 4;
            if (header_length < kIPv4MinHeader || header_length > packet_size) {
                return TapUserspaceRoute::Drop;
            }

            uint32_t source = 0;
            uint32_t destination = 0;
            memcpy(&source, bytes + 12, sizeof(source));
            memcpy(&destination, bytes + 16, sizeof(destination));

            if (destination == local_ip) {
                if (bytes[9] == kProtoTcp && packet_size >= header_length + 14) {
                    const unsigned char flags = bytes[header_length + 13];
                    if ((flags & kTcpSyn) != 0 && (flags & kTcpAck) == 0) {
                        return TapUserspaceRoute::HostSyn;
                    }
                }
                return TapUserspaceRoute::Host;
            }

            return source == local_ip ? TapUserspaceRoute::Tunnel : TapUserspaceRoute::Drop;
        }

        /** @brief TCP destination port in host order, or 0 when the packet is not a complete IPv4/TCP header. */
        inline uint16_t TapUserspaceTcpDestinationPort(const void* packet, int packet_size) noexcept {
            if (nullptr == packet || packet_size < 20) {
                return 0;
            }

            const unsigned char* bytes = static_cast<const unsigned char*>(packet);
            const int header_length = (bytes[0] & 0x0f) * 4;
            if ((bytes[0] >> 4) != 4 || bytes[9] != 6 || header_length < 20 || packet_size < header_length + 4) {
                return 0;
            }

            return static_cast<uint16_t>((bytes[header_length + 2] << 8) | bytes[header_length + 3]);
        }
    }
}
