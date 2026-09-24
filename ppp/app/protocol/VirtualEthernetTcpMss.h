#pragma once

/**
 * @file VirtualEthernetTcpMss.h
 * @brief Helpers for computing and clamping TCP MSS in tunneled IPv4/IPv6 packets.
 */

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/app/protocol/VirtualEthernetPathMtu.h>
#include <ppp/app/protocol/VirtualEthernetIPv6.h>
#include <ppp/ipv6/IPv6Packet.h>

namespace ppp {
    namespace app {
        namespace protocol {
            /** @brief Minimum TCP MSS value for IPv4 (RFC 879). */
            static constexpr int kTcpMssIPv4Min = 1200;
            /** @brief Maximum TCP MSS value for IPv4 (MTU - IPv4 header - TCP header). */
            static constexpr int kTcpMssIPv4Max = 1460;
            /** @brief Minimum TCP MSS value for IPv6. */
            static constexpr int kTcpMssIPv6Min = 1220;
            /** @brief Maximum TCP MSS value for IPv6 (MTU - IPv6 header - TCP header). */
            static constexpr int kTcpMssIPv6Max = 1440;
            /** @brief Virtual ethernet tunnel encapsulation overhead in bytes. */
            static constexpr int kVEthernetTunnelOverhead = 80;

            /**
             * @brief Computes a dynamic TCP MSS value from tunnel overhead and an optional learned PMTU.
             * @param ipv4 True to use IPv4 header sizing and clamp range; false for IPv6.
             * @param tunnel_overhead Extra encapsulation overhead in bytes.
             * @param path_mtu Learned MTU for the inner IP path, or zero when unknown.
             * @return A bounded MSS value suitable for SYN option clamping.
             */
            static inline unsigned short ComputeDynamicTcpMss(bool ipv4, int tunnel_overhead, int path_mtu) noexcept {
                tunnel_overhead = std::max<int>(0, tunnel_overhead);
                int base_mtu = ppp::tap::ITap::Mtu - tunnel_overhead;
                if (path_mtu > 0) {
                    base_mtu = std::min<int>(base_mtu, path_mtu);
                }

                /** @brief IP header size: 20 bytes for IPv4 (ip_hdr::IP_HLEN), 40 bytes for IPv6 (IPv6_HEADER_MIN_SIZE). */
                int ip_header = ipv4 ? ppp::net::native::ip_hdr::IP_HLEN : ppp::ipv6::IPv6_HEADER_MIN_SIZE;
                /** @brief TCP header minimum size without options (tcp_hdr::TCP_HLEN = 20 bytes). */
                int tcp_header = ppp::net::native::tcp_hdr::TCP_HLEN;
                int mss = base_mtu - ip_header - tcp_header;

                if (ipv4) {
                    mss = std::max<int>(kTcpMssIPv4Min, std::min<int>(kTcpMssIPv4Max, mss));
                }
                else {
                    mss = std::max<int>(kTcpMssIPv6Min, std::min<int>(kTcpMssIPv6Max, mss));
                }
                return (unsigned short)mss;
            }

            /** @brief Computes the static-safe TCP MSS when no PMTU observation is available. */
            static inline unsigned short ComputeDynamicTcpMss(bool ipv4, int tunnel_overhead) noexcept {
                return ComputeDynamicTcpMss(ipv4, tunnel_overhead, 0);
            }

            /**
             * @brief Clamps the MSS option in an IPv4 TCP SYN packet.
             * @param packet Raw packet buffer containing an IPv4 packet.
             * @param packet_length Packet length in bytes.
             * @param mss_value Maximum MSS value allowed after clamping.
             * @return True if MSS is changed and checksums are updated; otherwise false.
             */
            static inline bool ClampTcpMssIPv4(Byte* packet, int packet_length, unsigned short mss_value) noexcept {
                if (NULLPTR == packet || packet_length < (int)sizeof(ppp::net::native::ip_hdr)) {
                    return false;
                }

                int ip_length = packet_length;
                ppp::net::native::ip_hdr* iphdr = ppp::net::native::ip_hdr::Parse(packet, ip_length);
                if (NULLPTR == iphdr || ((iphdr->v_hl & 0x0f) << 2) < ppp::net::native::ip_hdr::IP_HLEN || iphdr->proto != ppp::net::native::ip_hdr::IP_PROTO_TCP) {
                    return false;
                }

                int ip_header_length = (iphdr->v_hl & 0x0f) << 2;
                int tcp_length = ip_length - ip_header_length;
                if (tcp_length < ppp::net::native::tcp_hdr::TCP_HLEN) {
                    return false;
                }

                ppp::net::native::tcp_hdr* tcphdr = reinterpret_cast<ppp::net::native::tcp_hdr*>(packet + ip_header_length);
                int tcp_header_length = ppp::net::native::tcp_hdr::TCPH_HDRLEN_BYTES(tcphdr);
                if (tcp_header_length <= ppp::net::native::tcp_hdr::TCP_HLEN || tcp_header_length > tcp_length) {
                    return false;
                }

                if ((ppp::net::native::tcp_hdr::TCPH_FLAGS(tcphdr) & ppp::net::native::tcp_hdr::TCP_SYN) == 0) {
                    return false;
                }

                Byte* options = reinterpret_cast<Byte*>(tcphdr) + ppp::net::native::tcp_hdr::TCP_HLEN;
                int options_length = tcp_header_length - ppp::net::native::tcp_hdr::TCP_HLEN;
                bool changed = false;

                /**
                 * @brief Walks TCP options until EOL, malformed entry, or MSS option.
                 */
                for (int i = 0; i < options_length;) {
                    Byte kind = options[i];
                    if (kind == 0) {
                        break;
                    }
                    if (kind == 1) {
                        i++;
                        continue;
                    }
                    if (i + 1 >= options_length) {
                        break;
                    }

                    Byte length = options[i + 1];
                    if (length < 2 || i + length > options_length) {
                        break;
                    }

                    if (kind == 2 && length == 4) {
                        unsigned short* mss = reinterpret_cast<unsigned short*>(options + i + 2);
                        unsigned short current = ntohs(*mss);
                        if (current > mss_value) {
                            *mss = htons(mss_value);
                            changed = true;
                        }
                        break;
                    }

                    i += length;
                }

                if (!changed) {
                    return false;
                }

                iphdr->chksum = 0;
                iphdr->chksum = ppp::net::native::inet_chksum(iphdr, ip_header_length);
                tcphdr->chksum = 0;
                tcphdr->chksum = ppp::net::native::inet_chksum_pseudo(reinterpret_cast<unsigned char*>(tcphdr), IPPROTO_TCP, tcp_length, iphdr->src, iphdr->dest);
                return true;
            }

            /**
             * @brief Clamps the MSS option in an IPv6 TCP SYN packet.
             * @param packet Raw packet buffer containing an IPv6 packet.
             * @param packet_length Packet length in bytes.
             * @param mss_value Maximum MSS value allowed after clamping.
             * @return True if MSS is changed and TCP checksum is updated; otherwise false.
             */
            static inline bool ClampTcpMssIPv6(Byte* packet, int packet_length, unsigned short mss_value) noexcept {
                /** @brief Minimum IPv6 packet size: 40-byte fixed header + 20-byte TCP header minimum. */
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE + ppp::net::native::tcp_hdr::TCP_HLEN) {
                    return false;
                }

                ppp::app::protocol::VirtualEthernetIPv6MinimalHeader* ipv6 = reinterpret_cast<ppp::app::protocol::VirtualEthernetIPv6MinimalHeader*>(packet);
                if ((ipv6->VersionTrafficClass >> 4) != 6 || ipv6->NextHeader != IPPROTO_TCP) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::app::protocol::ParseVirtualEthernetIPv6Header(packet, packet_length, source, destination)) {
                    return false;
                }

                /** @brief IPv6 fixed header size (40 bytes per RFC 8200). */
                ppp::net::native::tcp_hdr* tcphdr = reinterpret_cast<ppp::net::native::tcp_hdr*>(packet + ppp::ipv6::IPv6_HEADER_MIN_SIZE);
                int tcp_length = packet_length - ppp::ipv6::IPv6_HEADER_MIN_SIZE;
                int tcp_header_length = ppp::net::native::tcp_hdr::TCPH_HDRLEN_BYTES(tcphdr);
                if (tcp_header_length <= ppp::net::native::tcp_hdr::TCP_HLEN || tcp_header_length > tcp_length) {
                    return false;
                }

                if ((ppp::net::native::tcp_hdr::TCPH_FLAGS(tcphdr) & ppp::net::native::tcp_hdr::TCP_SYN) == 0) {
                    return false;
                }

                Byte* options = reinterpret_cast<Byte*>(tcphdr) + ppp::net::native::tcp_hdr::TCP_HLEN;
                int options_length = tcp_header_length - ppp::net::native::tcp_hdr::TCP_HLEN;
                bool changed = false;

                /**
                 * @brief Walks TCP options until EOL, malformed entry, or MSS option.
                 */
                for (int i = 0; i < options_length;) {
                    Byte kind = options[i];
                    if (kind == 0) {
                        break;
                    }
                    if (kind == 1) {
                        i++;
                        continue;
                    }
                    if (i + 1 >= options_length) {
                        break;
                    }

                    Byte length = options[i + 1];
                    if (length < 2 || i + length > options_length) {
                        break;
                    }

                    if (kind == 2 && length == 4) {
                        unsigned short* mss = reinterpret_cast<unsigned short*>(options + i + 2);
                        unsigned short current = ntohs(*mss);
                        if (current > mss_value) {
                            *mss = htons(mss_value);
                            changed = true;
                        }
                        break;
                    }

                    i += length;
                }

                if (!changed) {
                    return false;
                }

                tcphdr->chksum = 0;
                tcphdr->chksum = ppp::app::protocol::VirtualEthernetIPv6PseudoChecksum(reinterpret_cast<unsigned char*>(tcphdr), tcp_length, source, destination, IPPROTO_TCP);
                return true;
            }
        }
    }
}
