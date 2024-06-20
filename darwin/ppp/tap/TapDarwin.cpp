#include <darwin/ppp/tap/TapDarwin.h>
#include <darwin/ppp/tun/utun.h>

#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/collections/Dictionary.h>

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <cstring>
#include <iostream>

using namespace ppp::tap;
using namespace ppp::darwin::tun;

using ppp::net::native::ip_hdr;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::collections::Dictionary;

#if !defined(ROUNDUP)
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

namespace ppp
{
    namespace tap
    {
        typedef TapDarwin::NetworkInterface             NetworkInterface;
        typedef NetworkInterface::Ptr                   NetworkInterfacePtr;

        static int FetchAllRouteNtreeStuff(const ppp::function<bool(int interface_index, uint32_t ip, uint32_t gw, uint32_t mask)>& predicate) noexcept /* sysctlbyname("net.route.0.0.dump", buf, &len, NULL, 0) */
        {
            if (NULL == predicate)
            {
                return -1;
            }

            int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY };
            size_t needed = 0;
            if (sysctl(mib, arraysizeof(mib), NULL, &needed, NULL, 0) < 0)
            {
                return -1;
            }

            std::shared_ptr<Byte> buffer_managed = ppp::make_shared_alloc<Byte>(needed);
            if (NULL == buffer_managed)
            {
                return -1;
            }

            char* buffer = (char*)buffer_managed.get();
            if (sysctl(mib, arraysizeof(mib), buffer, &needed, NULL, 0) < 0)
            {
                return -1;
            }

            struct rt_msghdr* rtm = NULL;
            char* buffer_needed = buffer + needed;

            for (char* i = buffer; i < buffer_needed; i += rtm->rtm_msglen)
            {
                rtm = (struct rt_msghdr*)(i); /* RTAX_NETMASK */
                if (rtm->rtm_type != RTM_GET)
                {
                    continue;
                }

                /* inet_ntop(AF_INET, &sa->sin_addr.s_addr, line, sizeof(line) - 1); */
                if (!(rtm->rtm_flags & RTF_UP))
                {
                    continue;
                }

                /* MAXHOSTNAMELEN; */
                if (!(rtm->rtm_flags & RTF_GATEWAY))
                {
                    continue;
                }

                struct sockaddr* sa_tab[RTAX_MAX];
                struct sockaddr* sa = (struct sockaddr*)(rtm + 1); 
                if (NULL != sa)
                {
                    for (int j = 0; j < RTAX_MAX; j++)
                    {
                        if (rtm->rtm_addrs & (1 << j))
                        {
                            sa_tab[j] = sa;
                            sa = (struct sockaddr*)((char*)sa + ROUNDUP(sa->sa_len));
                        }
                        else
                        {
                            sa_tab[j] = NULL;
                        }
                    }
                }

                uint32_t ip = IPEndPoint::AnyAddress;
                uint32_t gw = IPEndPoint::AnyAddress;
                uint32_t mask = IPEndPoint::AnyAddress;
                if (rtm->rtm_addrs & (1 << RTAX_DST))
                {
                    struct sockaddr_in* sa = (struct sockaddr_in*)(sa_tab[RTAX_DST]);
                    if (sa->sin_family != AF_INET)
                    {
                        continue;
                    }

                    ip = sa->sin_addr.s_addr;
                }

                if (rtm->rtm_addrs & (1 << RTAX_GATEWAY))
                {
                    struct sockaddr_in* sa = (struct sockaddr_in*)(sa_tab[RTAX_GATEWAY]);
                    if (sa->sin_family != AF_INET)
                    {
                        continue;
                    }

                    gw = sa->sin_addr.s_addr;
                }

                if (rtm->rtm_addrs & (1 << RTAX_NETMASK))
                {
                    struct sockaddr_in* sa = (struct sockaddr_in*)(sa_tab[RTAX_NETMASK]);
                    mask = sa->sin_addr.s_addr;
                }

                if (predicate(rtm->rtm_index, ip, gw, mask))
                {
                    break;
                }
            }

            return 0;
        }

        static bool FetchAllNetworkInterfaceNative(ppp::unordered_map<int, NetworkInterfacePtr>& interfaces) noexcept
        {
            struct ifaddrs* ifList = NULL;
            if (getifaddrs(&ifList))
            {
                return false;
            }

            for (struct ifaddrs* ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
            {
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr; // ifa_dstaddr
                if (NULL == sin || sin->sin_family != AF_INET)
                {
                    continue;
                }

                UInt32 ip = sin->sin_addr.s_addr;
                sin = (struct sockaddr_in*)ifa->ifa_netmask;
                if (NULL == sin || (sin->sin_family != AF_INET && (sin->sin_family != AF_UNSPEC || sin->sin_len != '\a')))
                {
                    continue;
                }

                UInt32 mask = sin->sin_addr.s_addr;
                ppp::string name = ifa->ifa_name;
                if (name.empty())
                {
                    continue;
                }

                NetworkInterfacePtr ni = ppp::make_shared_object<NetworkInterface>();
                if (NULL == ni)
                {
                    break;
                }

                ni->Name = name;
                ni->Index = TapDarwin::GetInterfaceIndex(name);
                ni->IPAddress = Ipep::ToAddress(ip).to_string();
                ni->SubnetmaskAddress = Ipep::ToAddress(mask).to_string();
                interfaces[ni->Index] = ni;
            }

            freeifaddrs(ifList);
            return true;
        }

        static inline bool IsDefaultGatewayRouteOSX(uint32_t ip, uint32_t mid, uint32_t mask) noexcept
        {
            int prefix = IPEndPoint::NetmaskToPrefix(mask);
            return (ip == ppp::net::IPEndPoint::AnyAddress && mask == mid) ||
                (ip == ppp::net::IPEndPoint::AnyAddress && prefix == 8) || // 0.0.0.0/8 (only os-x ≈ 0.0.0.0/0)
                (ip == ppp::net::IPEndPoint::AnyAddress && mask == ppp::net::IPEndPoint::AnyAddress) ||
                (ip == mid && mask == mid) ||
                (ip == mid && prefix == 8); // 128.0.0.0/8 (only os-x ≈ 128.0.0.0/0)
        }

        static bool FetchAllNetworkInterfaces(ppp::vector<NetworkInterfacePtr>& nis) noexcept
        {
            typedef ppp::unordered_map<uint32_t, int> BestGatewayTable;

            ppp::unordered_map<int, NetworkInterfacePtr> interfaces;
            if (!FetchAllNetworkInterfaceNative(interfaces))
            {
                return false;
            }

            ppp::unordered_map<int, BestGatewayTable> best_gws;
            ppp::unordered_map<int, uint32_t> best_anys;

            uint32_t mid = inet_addr("128.0.0.0");
            FetchAllRouteNtreeStuff(
                [&best_gws, &best_anys, &interfaces, mid](int interface_index, uint32_t ip, uint32_t gw, uint32_t mask) noexcept
                {
                    NetworkInterfacePtr ni;
                    if (ip == IPEndPoint::AnyAddress)
                    {
                        best_anys[interface_index] = gw;
                    }

                    best_gws[interface_index][gw]++;
                    if (!Dictionary::TryGetValue(interfaces, interface_index, ni))
                    {
                        return false;
                    }

                    if (NULL == ni)
                    {
                        return false;
                    }

                    bool ok = IsDefaultGatewayRouteOSX(ip, mid, mask);
                    if (ok)
                    {
                        ni->GatewayAddresses[ip] = gw;
                    }

                    return false;
                });

            ppp::unordered_map<int, uint32_t> bests;
            for (auto&& [interface_index, m] : best_gws)
            {
                NetworkInterfacePtr ni;
                if (!Dictionary::TryGetValue(interfaces, interface_index, ni) || NULL == ni)
                {
                    continue;
                }

                uint32_t gw = IPEndPoint::AnyAddress;
                if (!Dictionary::TryGetValue(best_anys, interface_index, gw))
                {
                    bool gw_has = false;
                    int gw_best = 0;
                    for (auto&& [iterator_gw, best_count] : m)
                    {
                        if (!gw_has || best_count > gw_best)
                        {
                            gw_has = true;
                            gw = iterator_gw;
                            gw_best = best_count;
                        }
                    }
                }

                ni->GatewayServer = Ipep::ToAddress(gw).to_string();
            }

            for (auto&& [_, ni] : interfaces)
            {
                if (NULL == ni || ni->Index == -1)
                {
                    continue;
                }

                bool fixed_gw = false;
                do
                {
                    ppp::string gw_string = ni->GatewayServer;
                    if (gw_string.empty())
                    {
                        fixed_gw = true;
                        break;
                    }
                    else
                    {
                        boost::system::error_code ec;
                        boost::asio::ip::address gw_address = StringToAddress(gw_string.data(), ec);
                        if (ec)
                        {
                            fixed_gw = true;
                            break;
                        }

                        if (IPEndPoint::IsInvalid(gw_address))
                        {
                            fixed_gw = true;
                            break;
                        }
                    }
                } while (false);

                while (fixed_gw)
                {
                    boost::system::error_code ec;
                    boost::asio::ip::address ip_address = StringToAddress(ni->IPAddress.data(), ec);
                    if (ec || !ip_address.is_v4())
                    {
                        break;
                    }

                    if (IPEndPoint::IsInvalid(ip_address))
                    {
                        break;
                    }

                    boost::asio::ip::address mask_address = StringToAddress(ni->SubnetmaskAddress.data(), ec);
                    if (ec || !mask_address.is_v4())
                    {
                        break;
                    }

                    uint32_t mask = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(mask_address, IPEndPoint::MinPort)).GetAddress();
                    uint32_t ip = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(ip_address, IPEndPoint::MinPort)).GetAddress();
                    uint32_t gw = htonl(ntohl(mask & ip) + 1);
                    ni->GatewayServer = Ipep::ToAddress(gw).to_string();
                    break;
                }

                nis.emplace_back(ni);
            }
            return true;
        }

        static NetworkInterface::Ptr Darwin_GetPreferredNetworkInterface2(const ppp::vector<NetworkInterface::Ptr>& interfaces, const ppp::string& nic) noexcept
        {
            boost::system::error_code ec;
            if (interfaces.empty())
            {
                return NULL;
            }

            ppp::string nic_lower = ToLower(ATrim(nic));
            for (NetworkInterfacePtr ni : interfaces)
            {
                ppp::string& interface_name = ni->Name;
                if (strncmp(interface_name.data(), "lo", 2) == 0 || strncmp(interface_name.data(), "utun", 4) == 0)
                {
                    continue;
                }

                boost::asio::ip::address ip = StringToAddress(ni->IPAddress.data(), ec);
                if (ec || !ip.is_v4())
                {
                    continue;
                }

                boost::asio::ip::address gw = StringToAddress(ni->GatewayServer.data(), ec);
                if (ec || !gw.is_v4())
                {
                    continue;
                }

                boost::asio::ip::address mask = StringToAddress(ni->SubnetmaskAddress.data(), ec);
                if (ec || !mask.is_v4())
                {
                    continue;
                }

                bool continued = false;
                boost::asio::ip::address addresses[] = { ip, gw };
                for (boost::asio::ip::address& i : addresses)
                {
                    uint32_t address = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(i, IPEndPoint::MinPort)).GetAddress();
                    if (address == IPEndPoint::LoopbackAddress ||
                        address == IPEndPoint::AnyAddress ||
                        address == IPEndPoint::NoneAddress || IPEndPoint::IsInvalid(i))
                    {
                        continued = true;
                        break;
                    }
                }

                if (continued)
                {
                    continue;
                }

                if (nic.size() > 0) 
                {
                    ppp::string interface_lower = ToLower(ATrim(interface_name));
                    if (interface_lower != nic_lower && interface_lower.find(nic_lower) == std::string::npos) 
                    {
                        continue;
                    }
                }

                return ni;
            }
            return NULL;
        }

        NetworkInterface::Ptr TapDarwin::GetPreferredNetworkInterface(const ppp::vector<NetworkInterface::Ptr>& interfaces) noexcept
        {
            ppp::string nic;
            return Darwin_GetPreferredNetworkInterface2(interfaces, nic);
        }

        NetworkInterface::Ptr TapDarwin::GetPreferredNetworkInterface2(const ppp::vector<NetworkInterface::Ptr>& interfaces, const ppp::string& nic) noexcept 
        {
            NetworkInterface::Ptr ni = Darwin_GetPreferredNetworkInterface2(interfaces, nic);
            if (NULL != ni)
            {
                return ni;
            }
            else
            {
                return GetPreferredNetworkInterface(interfaces);
            }
        }

        std::shared_ptr<TapDarwin::RouteInformationTable> TapDarwin::FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>& bypass_gws) noexcept
        {
            std::shared_ptr<TapDarwin::RouteInformationTable> rib = make_shared_object<TapDarwin::RouteInformationTable>();
            if (NULL == rib) 
            {
                return NULL;
            }

            bool any = false;
            uint32_t mid = inet_addr("128.0.0.0");

            FetchAllRouteNtreeStuff(
                [&bypass_gws, &any, &rib, mid](int interface_index, uint32_t ip, uint32_t gw, uint32_t mask) noexcept 
                {
                    bool ok = IsDefaultGatewayRouteOSX(ip, mid, mask);
                    if (!ok) 
                    {
                        return false;
                    }

                    if (bypass_gws.find(gw) != bypass_gws.end()) 
                    {
                        return false;
                    }

                    boost::asio::ip::address gw_address = Ipep::ToAddress(gw);
                    if (gw_address.is_multicast()) 
                    {
                        return false;
                    }

                    if (gw_address.is_loopback()) 
                    {
                        return false;
                    }

                    if (IPEndPoint::IsInvalid(gw_address)) 
                    {
                        return false;
                    }

                    auto r = rib->emplace(ip, gw);
                    any |= r.second;
                    return false;
                });

            if (any)
            {
                return rib;
            }
            else
            {
                return NULL;
            }
        }

        bool TapDarwin::GetAllNetworkInterfaces(ppp::vector<NetworkInterface::Ptr>& interfaces) noexcept
        {
            interfaces.clear();
            return FetchAllNetworkInterfaces(interfaces);
        }

        int TapDarwin::GetInterfaceIndex(const ppp::string& ifrName) noexcept
        {
            if (ifrName.empty())
            {
                return -1;
            }

            int interface_index = (int)if_nametoindex(ifrName.data());
            if (interface_index == 0 || interface_index == -1)
            {
                return -1;
            }

            return interface_index;
        }

        bool TapDarwin::GetInterfaceName(int interface_index, ppp::string& ifrName) noexcept
        {
            ifrName.clear();
            if (interface_index == 0 || interface_index == -1)
            {
                return false;
            }

            char buf[255];
            if (if_indextoname((unsigned int)interface_index, buf))
            {
                char ch = *buf;
                if (ch == '\x0')
                {
                    return false;
                }

                ifrName = buf;
                return true;
            }
            else
            {
                return false;
            }
        }

        TapDarwin::TapDarwin(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network) noexcept
            : ITap(context, dev, tun, address, gw, mask, hosted_network)
            , promisc_(false)
        {

        }

        std::shared_ptr<TapDarwin> TapDarwin::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept
        {
            if (NULL == context)
            {
                return NULL;
            }

            if (dev.empty())
            {
                return NULL;
            }

            IPEndPoint ipEP(ip, 0);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                return NULL;
            }

            IPEndPoint gwEP(ip, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                return NULL;
            }

            IPEndPoint maskEP(ip, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                return NULL;
            }

            // Try to open the utun virtual network adapter. 
            // If the utun virtual network adapter cannot be opened, 
            // Try to open the Utun virtual network adapter with different utunnum 255 times. 
            // If the Utun virtual network adapter driver handle still cannot be opened, a failure is returned.
            int utunnum = utun_utunnum(dev);
            int tun = utun_open(utunnum, ip, gw, mask);
            if (tun == -1)
            {
                // Try looping open the utun driver to see see.
                for (int i = 0; i < UINT8_MAX; i++)
                {
                    if (i == utunnum)
                    {
                        continue;
                    }

                    utunnum = i;
                    tun = utun_open(utunnum, ip, gw, mask);
                    if (tun != -1)
                    {
                        break;
                    }
                }

                // The vnic still cannot be opened, indicating that the current OS X system may not have the Apple driver for utun.
                if (tun == -1)
                {
                    return NULL;
                }
            }

            ppp::vector<boost::asio::ip::address> dns_servers;
            Ipep::ToAddresses(dns_addresses, dns_servers);

            // On OS X, the utun virtual NIC is not allowed to set an alias and can only be in the format of utun%d. 
            // Therefore, the interface name of the utun virtual NIC is obtained through the handle of the utun vnic, 
            // And this name is used to complete the following operations, instead of the default NIC name ppp.
            ppp::string interface_name;
            if (!utun_get_if_name(tun, interface_name))
            {
                close(tun);
                return NULL;
            }

            return CreateInternal(context, ip, gw, mask, promisc, hosted_network, tun, interface_name, dns_servers);
        }

        std::shared_ptr<TapDarwin> TapDarwin::CreateInternal(const std::shared_ptr<boost::asio::io_context>& context, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, int tun, ppp::string interface_name, const ppp::vector<boost::asio::ip::address>& dns_addresses) noexcept
        {
            int interface_index = TapDarwin::GetInterfaceIndex(interface_name);
            if (interface_index == -1)
            {
                ::close(tun);
                return NULL;
            }

            std::shared_ptr<TapDarwin> tap = make_shared_object<TapDarwin>(context, interface_name, reinterpret_cast<void*>(tun), ip, gw, mask, hosted_network);
            if (NULL == tap)
            {
                ::close(tun);
                return NULL;
            }

            tap->promisc_ = promisc;
            tap->dns_addresses_ = dns_addresses;

            ITap* my = tap.get(); 
            if (NULL != my) 
            {
                my->GetInterfaceIndex() = interface_index;
            }

            return tap;
        }

        // When you turn on optimized compilation, try to ask the CXX compiler to embed the following functions into the caller.
        static inline bool WritePacketToKernelNio(TapDarwin* my, const std::shared_ptr<boost::asio::posix::stream_descriptor>& stream, const void* packet, int packet_size) noexcept
        {
            // Windows virtual nics need to use Event to write to the kernel asynchronously, 
            // MacOS virtual nics can directly write to the kernel ::write function,
            // Can reduce a memory allocation and replication, improve throughput efficiency.
            if (NULL == packet || packet_size < 1 || NULL == stream)
            {
                return false;
            }

            // Check whether the IP packet protocol output by the VPN protocol stack is AF_INET.
            struct ip_hdr* iphdr = (struct ip_hdr*)packet;
            if (ip_hdr::IPH_V(iphdr) != ip_hdr::IP_VER)
            {
                return false;
            }

            // Copy to the current thread or coroutine stack, reduce memory fragmentation and write to the kernel, 
            // Discarding the report if it exceeds the MTU size.
            int tun = (int)reinterpret_cast<std::intptr_t>(my->GetHandle());
            if (packet_size > ITap::Mtu)
            {
                return false;
            }
            else
            {
                Byte chunk[ITap::Mtu + sizeof(uint32_t)];
                size_t chunk_size = packet_size + sizeof(uint32_t);

                *(uint32_t*)chunk = htonl(AF_INET);
                memcpy(chunk + sizeof(uint32_t), packet, packet_size);

                ssize_t bytes_transferred = ::write(tun, chunk, chunk_size);
                return bytes_transferred > -1;
            }
        }

        bool TapDarwin::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept
        {
            return WritePacketToKernelNio(this, GetStream(), packet.get(), packet_size);
        }

        bool TapDarwin::Output(const void* packet, int packet_size) noexcept
        {
            return WritePacketToKernelNio(this, GetStream(), packet, packet_size);
        }

        void TapDarwin::OnInput(PacketInputEventArgs& e) noexcept
        {
            // According to the low-level interface documentation of the operating system (obscure location), 
            // OSX utun packets need to add four bytes to the frame header to indicate the AF_INET and AF_INET6 protocol types.
            int packet_length = e.PacketLength;
            if (packet_length > sizeof(uint32_t))
            {
                Byte* packet = (Byte*)e.Packet;
                Byte protocol = (Byte)ntohl(*(uint32_t*)packet);
                if (protocol == AF_INET)
                {
                    e.Packet = packet + sizeof(uint32_t);
                    e.PacketLength = packet_length - sizeof(uint32_t);
                    ITap::OnInput(e);
                }
            }
        }

        static bool DeleteAddAllRoutes(const std::shared_ptr<ppp::net::native::RouteInformationTable>& rib, bool operate_add_or_delete) noexcept
        {
            if (NULL == rib)
            {
                return false;
            }

            bool any = false;
            for (auto&& [_, entries] : rib->GetAllRoutes())
            {
                for (auto&& entry : entries)
                {
                    if (operate_add_or_delete)
                    {
                        any |= utun_add_route(entry.Destination, entry.Prefix, entry.NextHop);
                    }
                    else
                    {
                        any |= utun_del_route(entry.Destination, entry.Prefix, entry.NextHop);
                    }
                }
            }
            return any;
        }

        bool TapDarwin::AddAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept
        {
            return DeleteAddAllRoutes(rib, true);
        }

        bool TapDarwin::DeleteAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept
        {
            return DeleteAddAllRoutes(rib, false);
        }

        bool TapDarwin::SetInterfaceMtu(int mtu) noexcept
        {
            int tun = (int)reinterpret_cast<std::intptr_t>(GetHandle());
            return utun_set_mtu(tun, mtu);
        }
    }
}