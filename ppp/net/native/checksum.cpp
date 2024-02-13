#include <stdio.h>
#include <stdint.h>
#include <atomic>

#include <ppp/io/File.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/rib.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/threading/Executors.h>

namespace ppp
{
    namespace net
    {
        namespace native
        {
            const int ip_hdr::IP_HLEN = sizeof(struct ip_hdr);
            const int tcp_hdr::TCP_HLEN = sizeof(struct tcp_hdr);
            const unsigned char ip_hdr::IP_DFT_TTL = Socket::GetDefaultTTL();

            unsigned short ip_hdr::NewId() noexcept
            {
                static std::atomic<unsigned int> aid = ATOMIC_FLAG_INIT;

                unsigned short r = 0;
                do
                {
                    r = ++aid;
                } while (r == 0);
                return r;
            }

            struct ip_hdr* ip_hdr::Parse(const void* packet, int len) noexcept
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
                if (iphdr_hlen >= len)
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

                if (len != ntohs(iphdr->len))
                {
                    return NULL;
                }

                /* all ones (broadcast) or all zeroes (old skool broadcast) */
                if ((~iphdr->dest == IP_ADDR_ANY_VALUE) || (iphdr->dest == IP_ADDR_ANY_VALUE))
                {
                    return NULL;
                }

                if ((~iphdr->src == IP_ADDR_ANY_VALUE) || (iphdr->src == IP_ADDR_ANY_VALUE))
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
                    int cksum = inet_chksum(iphdr, iphdr_hlen);
                    if (cksum != 0)
                    {
                        return NULL;
                    }
                }
#endif

                int ip_proto = IPH_PROTO(iphdr);
                if (ip_proto == IP_PROTO_UDP ||
                    ip_proto == IP_PROTO_TCP ||
                    ip_proto == IP_PROTO_ICMP)
                {
                    return iphdr;
                }
                return NULL;
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
                boost::asio::ip::address ip = boost::asio::ip::address::from_string(host, ec);
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

            namespace dns
            {
#pragma pack(push, 1)
                struct dns_hdr
                {
                    uint16_t usTransID;         // 标识符
                    uint16_t usFlags;           // 各种标志位
                    uint16_t usQuestionCount;   // Question字段个数 
                    uint16_t usAnswerCount;     // Answer字段个数
                    uint16_t usAuthorityCount;  // Authority字段个数
                    uint16_t usAdditionalCount; // Additional字段个数
                };
#pragma pack(pop)

                static constexpr int MAX_DOMAINNAME_LEN = 255;
                static constexpr int DNS_PORT = 53;
                static constexpr int DNS_TYPE_SIZE = 2;
                static constexpr int DNS_CLASS_SIZE = 2;
                static constexpr int DNS_TTL_SIZE = 4;
                static constexpr int DNS_DATALEN_SIZE = 2;
                static constexpr int DNS_TYPE_A = 0x0001; //1 a host address
                static constexpr int DNS_TYPE_CNAME = 0x0005; //5 the canonical name for an alias
                static constexpr int DNS_PACKET_MAX_SIZE = (sizeof(struct dns_hdr) + MAX_DOMAINNAME_LEN + DNS_TYPE_SIZE + DNS_CLASS_SIZE);

                static bool ExtractName(char* szEncodedStr, uint16_t* pusEncodedStrLen, char* szDotStr, uint16_t nDotStrSize, char* szPacketStartPos, char* szPacketEndPos) noexcept
                {
                    if (NULL == szEncodedStr || NULL == pusEncodedStrLen || NULL == szDotStr || szEncodedStr >= szPacketEndPos)
                    {
                        return false;
                    }

                    char* pDecodePos = szEncodedStr;
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
                            if (!ExtractName(szPacketStartPos + usJumpPos, &nEncodeStrLen, szDotStr + usPlainStrLen, nDotStrSize - usPlainStrLen, szPacketStartPos, szPacketEndPos))
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

                    szDotStr[usPlainStrLen - 1] = '\0';
                    *pusEncodedStrLen += 1;
                    return true;
                }

                ppp::string ExtractHost(const Byte* szPacketStartPos, int nPacketLength) noexcept
                {
                    struct dns_hdr* pDNSHeader = (struct dns_hdr*)szPacketStartPos;
                    if (NULL == pDNSHeader || nPacketLength < sizeof(pDNSHeader))
                    {
                        return ppp::string();
                    }

                    uint16_t usFlags = htons(pDNSHeader->usFlags) & htons(DNS_TYPE_A);
                    if (usFlags == 0)
                    {
                        return ppp::string();
                    }

                    int nQuestionCount = htons(pDNSHeader->usQuestionCount);
                    if (nQuestionCount < 1)
                    {
                        return ppp::string();
                    }

                    auto pioContext = ppp::threading::Executors::GetCurrent();
                    if (NULL == pioContext)
                    {
                        return ppp::string();
                    }

                    auto pioBuffers = ppp::threading::Executors::GetCachedBuffer(pioContext.get());
                    if (NULL == pioBuffers)
                    {
                        pioBuffers = make_shared_alloc<Byte>(PPP_BUFFER_SIZE);
                        if (NULL == pioBuffers)
                        {
                            return ppp::string();
                        }
                    }

                    uint16_t pusEncodedStrLen = 0;
                    char* szDomainDotStr = (char*)pioBuffers.get();

                    if (!ExtractName((char*)(pDNSHeader + 1), &pusEncodedStrLen, szDomainDotStr,
                        (uint16_t)std::min<int>(UINT16_MAX, PPP_BUFFER_SIZE), (char*)szPacketStartPos, (char*)szPacketStartPos + nPacketLength))
                    {
                        return ppp::string();
                    }

                    while (pusEncodedStrLen > 0 && szDomainDotStr[pusEncodedStrLen - 1] == '\x0')
                    {
                        pusEncodedStrLen--;
                    }

                    return pusEncodedStrLen == 0 ? ppp::string() : ppp::string(szDomainDotStr, pusEncodedStrLen);
                }
            }
        }
    }
}