#include <stdio.h>
#include <stdint.h>
#include <atomic>

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
            const int           ip_hdr::IP_HLEN    = sizeof(struct ip_hdr);
            const int           tcp_hdr::TCP_HLEN  = sizeof(struct tcp_hdr);
            const unsigned char ip_hdr::IP_DFT_TTL = Socket::GetDefaultTTL();

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

            struct ip_hdr* ip_hdr::Parse(const void* packet, int& len) noexcept
            {
                struct ip_hdr* iphdr = (struct ip_hdr*)packet;
                if (NULL == iphdr)
                {
                    return NULL;
                }

                int iphdr_ver = IPH_V(iphdr);
                if (iphdr_ver != ip_hdr::IP_VER)
                {
                    return NULL;
                }

                int iphdr_hlen = IPH_HL(iphdr) << 2;
                if (iphdr_hlen > len)
                {
                    return NULL;
                }

                if (iphdr_hlen < IP_HLEN)
                {
                    return NULL;
                }

                int ttl = IPH_TTL(iphdr);
                if (ttl < 1)
                {
                    return NULL;
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
                    return NULL;
                }

                /* ~iphdr->dest == IP_ADDR_ANY_VALUE */ 
                if (iphdr->src == IP_ADDR_ANY_VALUE || iphdr->src == IP_ADDR_BROADCAST_VALUE) 
                {
                    return NULL;
                }

                // if ((IPH_OFFSET(iphdr) & ntohs((UInt16)(ip_hdr::IP_OFFMASK | ip_hdr::IP_MF)))) 
                // {
                //     return NULL;
                // }

#if defined(PACKET_CHECKSUM)
                if (iphdr->chksum != 0)
                {
                    int checksum = inet_chksum(iphdr, iphdr_hlen);
                    if (checksum != 0)
                    {
                        return NULL;
                    }
                }
#endif

                int proto = IPH_PROTO(iphdr);
                return proto == IP_PROTO_UDP || proto == IP_PROTO_TCP || proto == IP_PROTO_ICMP ? iphdr : NULL;
            }

            struct tcp_hdr* tcp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept
            {
                if (NULL == iphdr || size < 1)
                {
                    return NULL;
                }

                struct tcp_hdr* tcphdr = (struct tcp_hdr*)packet;
                if (NULL == tcphdr)
                {
                    return NULL;
                }

                int hdrlen_bytes = TCPH_HDRLEN_BYTES(tcphdr);
                if (hdrlen_bytes < TCP_HLEN || hdrlen_bytes > size) // 错误的数据报
                {
                    return NULL;
                }

                int len = size - hdrlen_bytes;
                if (len < 0)
                {
                    return NULL;
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
                        return NULL;
                    }
                }
#endif
                return tcphdr;
            }

            struct udp_hdr* udp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept {
                if (NULL == iphdr || size < 1)
                {
                    return NULL;
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)packet;
                if (NULL == udphdr)
                {
                    return NULL;
                }

                if (size != ntohs(udphdr->len)) // 错误的数据报
                {
                    return NULL;
                }

                int hdrlen_bytes = sizeof(struct udp_hdr);
                int len = size - hdrlen_bytes;
                if (len < 1)
                {
                    return NULL;
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
                        return NULL;
                    }
                }
#endif
                return udphdr;
            }

            struct icmp_hdr* icmp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept
            {
                if (NULL == iphdr || size < 1)
                {
                    return NULL;
                }

                struct icmp_hdr* icmphdr = (struct icmp_hdr*)packet;
                if (NULL == icmphdr)
                {
                    return NULL;
                }

#if defined(PACKET_CHECKSUM)
                if (icmphdr->icmp_chksum != 0)
                {
                    unsigned short cksum = inet_chksum(icmphdr, size);
                    if (cksum != 0)
                    {
                        return NULL;
                    }
                }
#endif

                int len = size - sizeof(struct icmp_hdr);
                if (len < 0)
                {
                    return NULL;
                }
                return icmphdr;
            }

            ppp::string eth_addr::ToString() noexcept
            {
                return ToString(*this);
            }

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
            
            bool eth_addr::TryParse(const char* mac_string, struct eth_addr& mac) noexcept
            {
                if (NULL == mac_string || *mac_string == '\x0')
                {
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
                        return false;
                    }
                }

                mac = { (uint8_t)addr[0], (uint8_t)addr[1], (uint8_t)addr[2], (uint8_t)addr[3], (uint8_t)addr[4], (uint8_t)addr[5] };
                return true;
            }

#if defined(__SIMD__)
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

            bool RouteInformationTable::AddAllRoutesByIPList(const ppp::string& path, uint32_t gw) noexcept
            {
                if (path.empty())
                {
                    return false;
                }

                if (!ppp::io::File::Exists(path.data()))
                {
                    return false;
                }

                ppp::string cidrs = ppp::io::File::ReadAllText(path.data());
                if (cidrs.empty())
                {
                    return true;
                }

                return AddAllRoutes(cidrs, gw);
            }

            bool RouteInformationTable::AddAllRoutes(const ppp::string& cidrs, uint32_t gw) noexcept
            {
                if (cidrs.empty())
                {
                    return false;
                }

                ppp::vector<ppp::string> routes;
                if (Tokenize<ppp::string>(cidrs, routes, "\r\n") < 1)
                {
                    return false;
                }

                bool any = false;
                for (ppp::string& route : routes)
                {
                    any |= AddRoute(route, gw);
                }
                return any;
            }

            bool RouteInformationTable::AddRoute(const ppp::string& cidr, uint32_t gw) noexcept
            {
                if (cidr.empty())
                {
                    return false;
                }

                std::string host;
                int prefix = -1;
                bool prefix_f = false;

                std::size_t i = cidr.find('/');
                if (i == ppp::string::npos)
                {
                    host = cidr;
                }
                else
                {
                    if (i == 0)
                    {
                        return false;
                    }

                    host = cidr.substr(0, i);
                    prefix_f = true;
                    prefix = atoi(cidr.data() + (i + 1));
                }

                boost::system::error_code ec;
                boost::asio::ip::address ip = StringToAddress(host, ec);
                if (ec)
                {
                    return false;
                }

                if (ip.is_v4())
                {
                    if (!prefix_f)
                    {
                        prefix = 32;
                    }
                    elif(prefix < 0 || prefix > 32)
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }

                boost::asio::ip::address_v4 in = ip.to_v4();
                return AddRoute(htonl(in.to_uint()), prefix, gw);
            }

            bool RouteInformationTable::AddRoute(uint32_t ip, int prefix, uint32_t gw) noexcept
            {
                if (prefix < MIN_PREFIX_VALUE || prefix > MAX_PREFIX_VALUE)
                {
                    return false;
                }

                if (IPEndPoint::NoneAddress == ip)
                {
                    return false;
                }

                if (IPEndPoint::AnyAddress == gw || IPEndPoint::NoneAddress == gw)
                {
                    return false;
                }

                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                if ((ip & mask) != ip)
                {
                    return false;
                }

                RouteEntries& entries = routes[ip];
                auto tail = std::find_if(entries.begin(), entries.end(),
                    [prefix](RouteEntry& route) noexcept -> bool
                    {
                        return route.Prefix == prefix;
                    });
                if (tail != entries.end())
                {
                    tail->NextHop = gw;
                }
                else
                {
                    RouteEntry entry;
                    entry.NextHop = gw;
                    entry.Destination = ip;
                    entry.Prefix = prefix;
                    entries.emplace_back(entry);
                }
                return true;
            }

            bool RouteInformationTable::DeleteRoute(uint32_t ip) noexcept
            {
                auto tail = routes.find(ip);
                auto endl = routes.end();
                if (tail == endl)
                {
                    return false;
                }

                routes.erase(tail);
                return true;
            }

            bool RouteInformationTable::DeleteRoute(uint32_t ip, uint32_t gw) noexcept
            {
                auto tail = routes.find(ip);
                auto endl = routes.end();
                if (tail == endl)
                {
                    return false;
                }

                ppp::vector<int> prefixes;
                auto& entries = tail->second;
                for (auto&& route : entries)
                {
                    if (route.NextHop == gw)
                    {
                        prefixes.emplace_back(route.Prefix);
                    }
                }

                for (int prefix : prefixes)
                {
                    DeleteRoute(ip, prefix, gw);
                }
                return prefixes.size() > 0;
            }

            bool RouteInformationTable::DeleteRoute(uint32_t ip, int prefix, uint32_t gw) noexcept
            {
                auto tail = routes.find(ip);
                auto endl = routes.end();
                if (tail == endl)
                {
                    return false;
                }

                auto& entries = tail->second;
                auto entry_tail = std::find_if(entries.begin(), entries.end(),
                    [prefix, gw](RouteEntry& route) noexcept -> bool
                    {
                        return route.Prefix == prefix && route.NextHop == gw;
                    });

                if (entry_tail == entries.end())
                {
                    return false;
                }

                entries.erase(entry_tail);
                if (entries.empty())
                {
                    routes.erase(tail);
                }
                return true;
            }

            RouteEntriesTable& RouteInformationTable::GetAllRoutes() noexcept
            {
                return routes;
            }

            void RouteInformationTable::Clear() noexcept
            {
                routes.clear();
            }

            ForwardInformationTable::ForwardInformationTable(RouteInformationTable& rib) noexcept
            {
                Fill(rib);
            }

            uint32_t ForwardInformationTable::GetNextHop(uint32_t ip, RouteEntriesTable& routes) noexcept 
            {
                return GetNextHop(ip, MIN_PREFIX_VALUE, MAX_PREFIX_VALUE, routes);
            }

            uint32_t ForwardInformationTable::GetNextHop(uint32_t ip, int min_prefix_value, int max_prefix_value, RouteEntriesTable& routes) noexcept
            {
                for (int prefix = max_prefix_value; prefix >= min_prefix_value; prefix--)
                {
                    uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                    uint32_t dest = ip & mask;
                    auto tail = routes.find(dest);
                    auto endl = routes.end();
                    if (tail == endl)
                    {
                        continue;
                    }

                    for (auto&& entry : tail->second)
                    {
                        if (prefix >= entry.Prefix)
                        {
                            return entry.NextHop;
                        }
                    }
                }
                return IPEndPoint::NoneAddress;
            }

            uint32_t ForwardInformationTable::GetNextHop(uint32_t ip) noexcept
            {
                return GetNextHop(ip, routes);
            }

            RouteEntriesTable& ForwardInformationTable::GetAllRoutes() noexcept
            {
                return routes;
            }

            void ForwardInformationTable::Fill(RouteInformationTable& rib) noexcept
            {
                routes = rib.GetAllRoutes();
                for (auto&& kv : routes)
                {
                    auto& entries = kv.second;
                    std::sort(entries.begin(), entries.end(),
                        [](RouteEntry& x, RouteEntry& y) noexcept
                        {
                            return x.Prefix > y.Prefix;
                        });
                }
            }

            void ForwardInformationTable::Clear() noexcept
            {
                routes.clear();
            }

            ppp::string eth_addr::BytesToMacAddress(const void* data, int size) noexcept
            {
                if ((size < 1) || (NULL != data && size < 1))
                {
                    data = NULL;
                    size = 0;
                }

                // Set default MAC address
                unsigned char default_byte_arr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                int num_of_bytes_to_copy = (size <= 6) ? size : 6;
                if (NULL != data)
                {
                    memcpy(default_byte_arr, data, num_of_bytes_to_copy);
                }

                char mac_str[18];
                sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                    default_byte_arr[0], default_byte_arr[1], default_byte_arr[2],
                    default_byte_arr[3], default_byte_arr[4], default_byte_arr[5]);
                return mac_str;
            }

            namespace dns
            {
                static bool ExtractName(char* szEncodedStr, uint16_t* pusEncodedStrLen, char* szDotStr, uint16_t nDotStrSize, char* szPacketStartPos, char* szPacketEndPos, char** ppDecodePos) noexcept
                {
                    if (NULL == szEncodedStr || NULL == pusEncodedStrLen || NULL == szDotStr || szEncodedStr >= szPacketEndPos)
                    {
                        return false;
                    }

                    char*& pDecodePos = *ppDecodePos;
                    pDecodePos = szEncodedStr;

                    uint16_t usPlainStrLen = 0;
                    uint8_t nLabelDataLen = 0;
                    *pusEncodedStrLen = 0;

                    while ((nLabelDataLen = *pDecodePos) != 0x00)
                    {
                        // Normal Format，LabelDataLen + Label
                        if ((nLabelDataLen & 0xc0) == 0) 
                        {
                            if ((usPlainStrLen + nLabelDataLen + 1) > nDotStrSize || (pDecodePos + nLabelDataLen + 1) >= szPacketEndPos)
                            {
                                return false;
                            }

                            memcpy(szDotStr + usPlainStrLen, pDecodePos + 1, nLabelDataLen);
                            memcpy(szDotStr + usPlainStrLen + nLabelDataLen, ".", 1);

                            pDecodePos += (nLabelDataLen + 1);
                            usPlainStrLen += (nLabelDataLen + 1);
                            *pusEncodedStrLen += (nLabelDataLen + 1);
                        }
                        else  
                        {
                            // Message compression format is 11000000 00000000, consisting of two bytes. 
                            // The first two bits are the jump flag, and the last 14 bits are the offset of the jump。
                            if (NULL == szPacketStartPos)
                            {
                                return false;
                            }

                            uint16_t usJumpPos = ntohs(*(uint16_t*)(pDecodePos)) & 0x3fff;
                            uint16_t nEncodeStrLen = 0;
                            if (!ExtractName(szPacketStartPos + usJumpPos, &nEncodeStrLen, szDotStr + usPlainStrLen, nDotStrSize - usPlainStrLen, szPacketStartPos, szPacketEndPos, ppDecodePos))
                            {
                                return false;
                            }
                            else
                            {
                                *pusEncodedStrLen += 2;
                                return true;
                            }
                        }
                    }

                    ++pDecodePos;
                    szDotStr[usPlainStrLen - 1] = '\0';
                    *pusEncodedStrLen += 1;
                    return true;
                }

                static bool ExtractHost_DefaultPredicateB(dns_hdr* h) noexcept
                {
                    uint16_t usFlags = htons(h->usFlags) & htons(DNS_TYPE_A);
                    return usFlags != 0;
                }

                ppp::string ExtractHost(const Byte* szPacketStartPos, int nPacketLength) noexcept
                {
                    ppp::function<bool(dns_hdr*)> predicate = ExtractHost_DefaultPredicateB;
                    return ExtractHostX(szPacketStartPos, nPacketLength, predicate);
                }

                ppp::string ExtractHostX(const Byte* szPacketStartPos, int nPacketLength, const ppp::function<bool(dns_hdr*)>& fPredicateB) noexcept
                {
                    ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)> fPredicateE =
                        [](dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool
                        {
                            return true;
                        };
                    return ExtractHostZ(szPacketStartPos, nPacketLength, fPredicateB, fPredicateE);
                }

                ppp::string ExtractHostY(const Byte* szPacketStartPos, int nPacketLength, const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>& fPredicateE) noexcept
                {
                    ppp::function<bool(dns_hdr*)> fPredicateB = ExtractHost_DefaultPredicateB;
                    return ExtractHostZ(szPacketStartPos, nPacketLength, fPredicateB, fPredicateE);
                }

                ppp::string ExtractHostZ(const Byte*                                        szPacketStartPos, 
                    int                                                                     nPacketLength, 
                    const ppp::function<bool(dns_hdr*)>&                                    fPredicateB, 
                    const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>&  fPredicateE) noexcept
                {
                    static constexpr int MAX_DOMAINNAME_LEN_STR = MAX_DOMAINNAME_LEN + 1;

                    if (NULL == fPredicateB || NULL == fPredicateE)
                    {
                        return ppp::string();
                    }

                    struct dns_hdr* pDNSHeader = (struct dns_hdr*)szPacketStartPos;
                    if (NULL == pDNSHeader || nPacketLength < sizeof(pDNSHeader))
                    {
                        return ppp::string();
                    }

                    if (!fPredicateB(pDNSHeader))
                    {
                        return ppp::string();
                    }

                    int nQuestionCount = htons(pDNSHeader->usQuestionCount);
                    if (nQuestionCount < 1)
                    {
                        return ppp::string();
                    }

                    std::shared_ptr<Byte> pioBuffers = make_shared_alloc<Byte>(MAX_DOMAINNAME_LEN_STR);
                    if (NULL == pioBuffers) 
                    {
                        return ppp::string();
                    }

                    uint16_t pusEncodedStrLen = 0;
                    char* pDecodePos = NULL;
                    char* szDomainDotStr = (char*)pioBuffers.get();

                    if (!ExtractName((char*)(pDNSHeader + 1), &pusEncodedStrLen, szDomainDotStr,
                        (uint16_t)MAX_DOMAINNAME_LEN_STR, (char*)szPacketStartPos, (char*)szPacketStartPos + nPacketLength, &pDecodePos))
                    {
                        return ppp::string();
                    }

                    while (pusEncodedStrLen > 0 && szDomainDotStr[pusEncodedStrLen - 1] == '\x0')
                    {
                        pusEncodedStrLen--;
                    }

                    if (pusEncodedStrLen == 0)
                    {
                        return ppp::string();
                    }

                    uint16_t* pusDecodePos = (uint16_t*)pDecodePos;
                    uint16_t usQueriesType = ntohs(pusDecodePos[0]);
                    uint16_t usQueriesClass = ntohs(pusDecodePos[1]);

                    ppp::string strDomianStr(szDomainDotStr, pusEncodedStrLen);
                    if (!fPredicateE(pDNSHeader, strDomianStr, usQueriesType, usQueriesClass))
                    {
                        return ppp::string();
                    }

                    return strDomianStr.data();
                }
            }
        }
    }
}