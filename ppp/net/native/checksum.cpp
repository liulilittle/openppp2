#include <stdio.h>
#include <stdint.h>
#include <atomic>
#include <ppp/diagnostics/Error.h>

/**
 * @file checksum.cpp
 * @brief Packet parsing and Internet checksum implementations (RIB/FIB moved to rib.cpp).
 */

#include <ppp/io/File.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/eth.h>
#include <ppp/net/native/rib.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/threading/Executors.h>

#if defined(__SIMD__)
#include <immintrin.h>
#endif

namespace ppp
{
    namespace net
    {
        namespace native
        {
            /** @brief Cached IPv4 header size in bytes. */
            const int           ip_hdr::IP_HLEN    = sizeof(struct ip_hdr);
            /** @brief Cached TCP header size in bytes. */
            const int           tcp_hdr::TCP_HLEN  = sizeof(struct tcp_hdr);
            /** @brief Default TTL value used for new IPv4 headers. */
            const unsigned char ip_hdr::IP_DFT_TTL = Socket::GetDefaultTTL();

            /** @brief Generates a monotonic non-zero IPv4 identification value. */
            unsigned short ip_hdr::NewId() noexcept
            {
                static std::atomic<unsigned int> aid = ATOMIC_FLAG_INIT;

                for (;;)
                {
                    unsigned short r = ++aid;
                    if (r != 0)
                    {
                        return r;
                    }
                }
            }

            /**
             * @brief Validates and parses an IPv4 header from raw packet bytes.
             * @param packet Packet start pointer.
             * @param len In/out packet length; may be adjusted to header-reported length.
             * @return Parsed header pointer on success, otherwise `NULLPTR`.
             */
            struct ip_hdr* ip_hdr::Parse(const void* packet, int& len) noexcept
            {
                struct ip_hdr* iphdr = (struct ip_hdr*)packet;
                if (NULLPTR == iphdr)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumIpParseNullPacket);
                    return NULLPTR;
                }

                int iphdr_ver = IPH_V(iphdr);
                if (iphdr_ver != ip_hdr::IP_VER)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                int iphdr_hlen = IPH_HL(iphdr) << 2;
                if (iphdr_hlen > len)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                if (iphdr_hlen < IP_HLEN)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                int ttl = IPH_TTL(iphdr);
                if (ttl < 1)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                int reft = ntohs(iphdr->len);
                if (len != reft)
                {
                    /* Truncate the size of the IP messages. */
                    if (reft > len)
                    {
                        iphdr->len = htons(len);
                    }
                    else
                    {
                        len = reft;
                    }
                }

                /* All ones (broadcast) or all zeroes (old skool broadcast). */
                if (iphdr->dest == IP_ADDR_ANY_VALUE)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return NULLPTR;
                }

                /* ~iphdr->dest == IP_ADDR_ANY_VALUE */
                if (iphdr->src == IP_ADDR_ANY_VALUE || iphdr->src == IP_ADDR_BROADCAST_VALUE)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return NULLPTR;
                }

                // if ((IPH_OFFSET(iphdr) & ntohs((UInt16)(ip_hdr::IP_OFFMASK | ip_hdr::IP_MF))))
                // {
                //     return NULLPTR;
                // }

#if defined(PACKET_CHECKSUM)
                if (iphdr->chksum != 0)
                {
                    int checksum = inet_chksum(iphdr, iphdr_hlen);
                    if (checksum != 0)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                        return NULLPTR;
                    }
                }
#endif

                int proto = IPH_PROTO(iphdr);
                if (proto == IP_PROTO_UDP || proto == IP_PROTO_TCP || proto == IP_PROTO_ICMP)
                {
                    return iphdr;
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumIpParseProtocolUnsupported);
                return NULLPTR;
            }

            /**
             * @brief Validates and parses a TCP header from an IPv4 payload.
             * @param iphdr Parsed IPv4 header.
             * @param packet TCP segment start pointer.
             * @param size TCP segment size in bytes.
             * @return Parsed TCP header pointer on success, otherwise `NULLPTR`.
             */
            struct tcp_hdr* tcp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept
            {
                if (NULLPTR == iphdr || size < 1)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumTcpParseInvalidArguments);
                    return NULLPTR;
                }

                struct tcp_hdr* tcphdr = (struct tcp_hdr*)packet;
                if (NULLPTR == tcphdr)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumTcpParseNullHeader);
                    return NULLPTR;
                }

                int hdrlen_bytes = TCPH_HDRLEN_BYTES(tcphdr);
                if (hdrlen_bytes < TCP_HLEN || hdrlen_bytes > size) // Malformed datagram
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                int len = size - hdrlen_bytes;
                if (len < 0)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

#if defined(PACKET_CHECKSUM)
                if (tcphdr->chksum != 0)
                {
                    unsigned int pseudo_checksum = inet_chksum_pseudo((unsigned char*)tcphdr,
                        (unsigned int)IPPROTO_TCP,
                        (unsigned int)size,
                        iphdr->src,
                        iphdr->dest);
                    if (pseudo_checksum != 0)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                        return NULLPTR;
                    }
                }
#endif
                return tcphdr;
            }

            /**
             * @brief Validates and parses a UDP header from an IPv4 payload.
             * @param iphdr Parsed IPv4 header.
             * @param packet UDP datagram start pointer.
             * @param size UDP datagram size in bytes.
             * @return Parsed UDP header pointer on success, otherwise `NULLPTR`.
             */
            struct udp_hdr* udp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept {
                if (NULLPTR == iphdr || size < 1)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumUdpParseInvalidArguments);
                    return NULLPTR;
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)packet;
                if (NULLPTR == udphdr)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumUdpParseNullHeader);
                    return NULLPTR;
                }

                /**
                 * @brief Validate UDP length field before using it.
                 * @note udphdr->len is network byte order; convert with ntohs.
                 *       Minimum valid UDP length is sizeof(struct udp_hdr) = 8 bytes.
                 */
                int udp_total_len = ntohs(udphdr->len);
                if (udp_total_len < static_cast<int>(sizeof(struct udp_hdr)))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                if (size != udp_total_len) // Invalid datagram: size mismatch
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                int hdrlen_bytes = sizeof(struct udp_hdr);
                int len = size - hdrlen_bytes;
                if (len < 0)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

#if defined(PACKET_CHECKSUM)
                if (udphdr->chksum != 0)
                {
                    unsigned int pseudo_checksum = inet_chksum_pseudo((unsigned char*)udphdr,
                        (unsigned int)IPPROTO_UDP,
                        (unsigned int)size,
                        iphdr->src,
                        iphdr->dest);
                    if (pseudo_checksum != 0)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                        return NULLPTR;
                    }
                }
#endif
                return udphdr;
            }

            /**
             * @brief Validates and parses an ICMP header from an IPv4 payload.
             * @param iphdr Parsed IPv4 header.
             * @param packet ICMP payload start pointer.
             * @param size ICMP payload size in bytes.
             * @return Parsed ICMP header pointer on success, otherwise `NULLPTR`.
             */
            struct icmp_hdr* icmp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept
            {
                if (NULLPTR == iphdr || size < 1)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumIcmpParseInvalidArguments);
                    return NULLPTR;
                }

                struct icmp_hdr* icmphdr = (struct icmp_hdr*)packet;
                if (NULLPTR == icmphdr)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ChecksumIcmpParseNullHeader);
                    return NULLPTR;
                }

#if defined(PACKET_CHECKSUM)
                if (icmphdr->icmp_chksum != 0)
                {
                    unsigned short cksum = inet_chksum(icmphdr, size);
                    if (cksum != 0)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                        return NULLPTR;
                    }
                }
#endif

                int len = size - sizeof(struct icmp_hdr);
                if (len < 0)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }
                return icmphdr;
            }

            /** @brief Converts current MAC address object to text. */
            ppp::string eth_addr::ToString() noexcept
            {
                return ToString(*this);
            }

            /** @brief Converts provided MAC address to `xx:xx:xx:xx:xx:xx` text. */
            ppp::string eth_addr::ToString(const struct eth_addr& mac) noexcept
            {
                char sz[1000];
                int len = snprintf(sz, sizeof(sz), "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac.s_data[0],
                    mac.s_data[1],
                    mac.s_data[2],
                    mac.s_data[3],
                    mac.s_data[4],
                    mac.s_data[5]);

                if (len > 0)
                {
                    return sz;
                }

                return "00:00:00:00:00:00";
            }

            /** @brief Parses MAC text in colon or dash format into binary bytes. */
            bool eth_addr::TryParse(const char* mac_string, struct eth_addr& mac) noexcept
            {
                if (NULLPTR == mac_string || *mac_string == '\x0')
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                int addr[6];
                int count = sscanf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
                    &addr[0],
                    &addr[1],
                    &addr[2],
                    &addr[3],
                    &addr[4],
                    &addr[5]);

                if (count != 6)
                {
                    count = sscanf(mac_string, "%02x-%02x-%02x-%02x-%02x-%02x",
                        &addr[0],
                        &addr[1],
                        &addr[2],
                        &addr[3],
                        &addr[4],
                        &addr[5]);

                    if (count != 6)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                        return false;
                    }
                }

                mac = { (uint8_t)addr[0], (uint8_t)addr[1], (uint8_t)addr[2], (uint8_t)addr[3], (uint8_t)addr[4], (uint8_t)addr[5] };
                return true;
            }

#if defined(__SIMD__)
            /**
             * @brief Computes standard Internet checksum with SIMD acceleration.
             * @param dataptr Pointer to contiguous bytes.
             * @param len Buffer size in bytes.
             * @return 16-bit folded sum value (before one's complement inversion).
             */
            unsigned short                                                              ip_standard_chksum(void* dataptr, int len) noexcept /* MARCO C/C++: __SSE2__ */
            {
                uint8_t* data = (uint8_t*)dataptr;
                if (len == 0)
                {
                    return 0;
                }

                uint32_t acc = 0; // Use a 32-bit accumulator to match the original implementation
                size_t i = 0;

                // Use SSE2 to process 16-byte blocks
                if (len >= 16)
                {
                    __m128i accumulator = _mm_setzero_si128();
                    const size_t simd_bytes = len & ~0x0F; // Align to 16 bytes

                    for (; i < simd_bytes; i += 16)
                    {
                        // Load unaligned data
                        __m128i chunk = _mm_loadu_si128(
                            reinterpret_cast<const __m128i*>(data + i));

                        // Key point: simulate scalar processing logic
                        // Split 16 bytes into 8 16-bit big-endian words
                        __m128i high_bytes = _mm_slli_epi16(chunk, 8);
                        __m128i low_bytes = _mm_srli_epi16(chunk, 8);

                        // Create masks to clear unnecessary bits
                        __m128i mask = _mm_set1_epi16(0x00FF);
                        __m128i word1 = _mm_and_si128(high_bytes, _mm_slli_epi32(mask, 8));
                        __m128i word2 = _mm_and_si128(low_bytes, mask);

                        // Combine into correct 16-bit words
                        __m128i words = _mm_or_si128(word1, word2);

                        // Split 16-bit words into low and high 64 bits
                        __m128i low64 = _mm_unpacklo_epi16(words, _mm_setzero_si128());
                        __m128i high64 = _mm_unpackhi_epi16(words, _mm_setzero_si128());

                        // Accumulate into 32-bit accumulator
                        accumulator = _mm_add_epi32(accumulator, low64);
                        accumulator = _mm_add_epi32(accumulator, high64);
                    }

                    // Horizontal sum: accumulate all 32-bit values
                    alignas(16) uint32_t tmp[4];
                    _mm_store_si128(reinterpret_cast<__m128i*>(tmp), accumulator);
                    acc += tmp[0] + tmp[1] + tmp[2] + tmp[3];
                }

                // Process remaining bytes
                uint8_t* octetptr = data + i;
                int remaining = len - i;
                while (remaining > 1)
                {
                    uint32_t src = (static_cast<uint32_t>(octetptr[0]) << 8) | octetptr[1];
                    acc += src;
                    octetptr += 2;
                    remaining -= 2;
                }

                // Handle the last odd byte if length is odd
                if (remaining > 0)
                {
                    acc += static_cast<uint32_t>(*octetptr) << 8;
                }

                // Fold in carries
                acc = (acc >> 16) + (acc & 0xFFFF);
                if (acc > 0xFFFF)
                {
                    acc = (acc >> 16) + (acc & 0xFFFF);
                }

                // Return the result
                return ntohs(static_cast<uint16_t>(acc));
            }
#else
            /**
             * @brief Computes standard Internet checksum using scalar arithmetic.
             * @param dataptr Pointer to contiguous bytes.
             * @param len Buffer size in bytes.
             * @return 16-bit folded sum value (before one's complement inversion).
             */
            unsigned short                                                              ip_standard_chksum(void* dataptr, int len) noexcept
            {
                unsigned int acc;
                unsigned short src;
                unsigned char* octetptr;

                acc = 0;
                /* dataptr may be at odd or even addresses */
                octetptr = (unsigned char*)dataptr;
                while (len > 1)
                {
                    /* declare first octet as most significant
                       thus assume network order, ignoring host order */
                    src = (unsigned short)((*octetptr) << 8);
                    octetptr++;
                    /* declare second octet as least significant */
                    src |= (*octetptr);
                    octetptr++;
                    acc += src;
                    len -= 2;
                }

                if (len > 0)
                {
                    /* accumulate remaining octet */
                    src = (unsigned short)((*octetptr) << 8);
                    acc += src;
                }

                /* add deferred carry bits */
                acc = (unsigned int)((acc >> 16) + (acc & 0x0000ffffUL));
                if ((acc & 0xffff0000UL) != 0)
                {
                    acc = (unsigned int)((acc >> 16) + (acc & 0x0000ffffUL));
                }

                /* This maybe a little confusing: reorder sum using htons()
                   instead of ntohs() since it has a little less call overhead.
                   The caller must invert bits for Internet sum ! */
                return ntohs((unsigned short)acc);
            }
#endif


            /** @brief Formats raw bytes as uppercase MAC text with zero padding. */
            ppp::string eth_addr::BytesToMacAddress(const void* data, int size) noexcept
            {
                if ((size < 1) || (NULLPTR != data && size < 1))
                {
                    data = NULLPTR;
                    size = 0;
                }

                // Set default MAC address
                unsigned char default_byte_arr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                int num_of_bytes_to_copy = (size <= 6) ? size : 6;
                if (NULLPTR != data)
                {
                    memcpy(default_byte_arr, data, num_of_bytes_to_copy);
                }

                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    default_byte_arr[0], default_byte_arr[1], default_byte_arr[2],
                    default_byte_arr[3], default_byte_arr[4], default_byte_arr[5]);
                return mac_str;
            }
        }
    }
}
