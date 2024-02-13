// https://stackoverflow.com/questions/2300149/how-can-i-determine-the-default-gateway-on-iphone/8095530#8095530
// https://stackoverflow.com/questions/5390164/getting-routing-table-on-macosx-programmatically/11265543#11265543
// https://bugzilla.mozilla.org/show_bug.cgi?id=1579424
// https://gist.github.com/etodd/d8184b91c02306b889c13eb03f81fb6d
// https://github.com/songgao/water/issues/3#issuecomment-158704536
// https://build.openvpn.net/doxygen/route_8c_source.html
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tun.c#L3250

#include <darwin/ppp/tap/TapDarwin.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/collections/Dictionary.h>

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <sys/ioctl.h>          // ioctl
#include <sys/kern_control.h>   // struct socketaddr_ctl
#include <net/if_utun.h>        // UTUN_CONTROL_NAME
#include <sys/sys_domain.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <cstring>
#include <iostream>
#include <ppp/net/native/ip.h>

using ppp::net::native::ip_hdr;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::collections::Dictionary;

// networksetup -setmanual Ethernet 192.168.0.22 255.255.255.0 192.168.0.1
// route add -net 9.9.9.9/32 10.0.0.1
// route delete -net 9.9.9.9/32 10.0.0.1
// netstat -rn
// ifconfig utun1 mtu 2000
// ifconfig utun1 inet 10.0.0.2 10.0.0.1 netmask 255.255.255.0 up

#if !defined(ROUNDUP)
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

#if !defined(ETH_HWADDR_LEN)
#if defined(ETHARP_HWADDR_LEN)
#define ETH_HWADDR_LEN    ETHARP_HWADDR_LEN /* compatibility mode */
#else
#define ETH_HWADDR_LEN    6
#endif
#endif

#pragma pack(push, 1)
struct eth_addr
{
    union
    {
        uint8_t                                         s_data[ETH_HWADDR_LEN];
        struct
        {
            uint32_t                                    dw;
            uint16_t                                    w;
        }                                               s_zero;
    };
};
#pragma pack(pop)

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
                if (struct sockaddr* sa = (struct sockaddr*)(rtm + 1); NULL != sa)
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
                    if (Dictionary::TryGetValue(interfaces, interface_index, ni) && NULL != ni)
                    {
                        if (ip == mid || ip == IPEndPoint::AnyAddress)
                        {
                            ni->GatewayAddresses[ip] = gw;
                        }
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
                        boost::asio::ip::address gw_address = boost::asio::ip::address::from_string(gw_string.data(), ec);
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
                    boost::asio::ip::address ip_address = boost::asio::ip::address::from_string(ni->IPAddress.data(), ec);
                    if (ec || !ip_address.is_v4())
                    {
                        break;
                    }

                    if (IPEndPoint::IsInvalid(ip_address))
                    {
                        break;
                    }

                    boost::asio::ip::address mask_address = boost::asio::ip::address::from_string(ni->SubnetmaskAddress.data(), ec);
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

        bool utun_set_cloexec(int fd) noexcept
        {
            int flags = fcntl(fd, F_GETFD, 0);
            if (flags == -1)
            {
                return false;
            }

            flags |= FD_CLOEXEC;
            if (fcntl(fd, F_SETFD, flags) < 0)
            {
                return false;
            }

            return true;
        }

        /* Helper functions that tries to open utun device
         * return -2 on early initialization failures (utun not supported
         * at all (old OS X) and -1 on initlization failure of utun
         * device (utun works but utunX is already used */
        int utun_open(int utunnum) noexcept
        {
            if (utunnum < 0 || utunnum > UINT8_MAX)
            {
                return -1;
            }

            struct ctl_info ctlInfo;
            memset(&ctlInfo, 0, sizeof(ctlInfo));
            strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));

            int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if (fd == -1)
            {
                return fd;
            }

            if (ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0)
            {
                close(fd);
                return -1;
            }

            struct sockaddr_ctl sc;
            memset(&sc, 0, sizeof(sc));

            sc.sc_id = ctlInfo.ctl_id;
            sc.sc_len = sizeof(sc);
            sc.sc_family = AF_SYSTEM;
            sc.ss_sysaddr = AF_SYS_CONTROL;
            sc.sc_unit = utunnum + 1;

            if (connect(fd, (struct sockaddr*)&sc, sizeof(sc)) < 0)
            {
                close(fd);
                return -1;
            }

            int flags = fcntl(fd, F_GETFL, 0);
            if (flags == -1)
            {
                close(fd);
                return -1;
            }
            
            if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
            {
                close(fd);
                return -1;
            }
            
            utun_set_cloexec(fd);
            return fd;
        }

        bool utun_set_mtu(int tun, int mtu) noexcept
        {
            if (tun == -1)
            {
                return false;
            }

            // MTU: 68 ~ 65535 RANGE.
            if (mtu < 68)
            {
                mtu = ITap::Mtu;
            }

            ppp::string name;
            if (!utun_get_if_name(tun, name))
            {
                return false;
            }

            char buf[1000];
            snprintf(buf, sizeof(buf), "ifconfig %s mtu %d > /dev/null 2>&1", name.data(), mtu);

            int status = system(buf);
            return status == 0;
        }

        bool utun_get_if_name(int tun, ppp::string& ifrName) noexcept
        {
            ifrName.clear();
            if (tun == -1)
            {
                return false;
            }

            /* Retrieve the assigned interface name. */
            char utunname[1000];
            socklen_t utunname_len = sizeof(utunname);
            if (getsockopt(tun, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len) < 0)
            {
                return false;
            }

            ifrName = utunname;
            return true;
        }

        bool utun_set_if_ip_gw_and_mask(int tun, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask) noexcept
        {
            if (tun == -1 || ip.empty() || mask.empty())
            {
                return false;
            }

            ppp::string name;
            if (!utun_get_if_name(tun, name))
            {
                return false;
            }

            char cmd[1000];
            snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s %s netmask %s up", name.data(), ip.data(), gw.data(), mask.data());

            int status = system(cmd);
            return status == 0;
        }

        void utun_close(int fd) noexcept
        {
            if (fd != -1)
            {
                close(fd);
            }
        }

        bool utun_set_mac(int tun, const ppp::string& mac) noexcept
        {
            if (tun == -1 || mac.empty())
            {
                return false;
            }

            ppp::string name;
            if (!utun_get_if_name(tun, name))
            {
                return false;
            }

            char buf[1000];
            snprintf(buf, sizeof(buf), "ifconfig %s ether %s > /dev/null 2>&1", name.data(), mac.data());

            int status = system(buf);
            return status == 0;
        }

        static ppp::string utun_mac_to_string(const struct eth_addr& mac) noexcept
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

        // 10.0.0.2 10.0.0.1 255.255.255.0
        int utun_open(int utunnum, uint32_t ip, uint32_t gw, uint32_t mask) noexcept
        {
            if (ip == gw)
            {
                return -1;
            }

            uint32_t first = gw & mask;
            if ((ip & mask) != first)
            {
                return -1;
            }

            boost::asio::ip::address addresses[] = { Ipep::ToAddress(ip), Ipep::ToAddress(gw) };
            for (boost::asio::ip::address& i : addresses)
            {
                uint32_t address = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(i, IPEndPoint::MinPort)).GetAddress();
                if (address == IPEndPoint::LoopbackAddress ||
                    address == IPEndPoint::AnyAddress ||
                    address == IPEndPoint::NoneAddress || IPEndPoint::IsInvalid(i))
                {
                    return -1;
                }
            }

            int fd = utun_open(utunnum);
            if (fd == -1)
            {
                return -1;
            }

            ppp::string tun_name;
            if (!utun_get_if_name(fd, tun_name))
            {
                close(fd);
                return -1;
            }

            if (!utun_set_mtu(fd, ITap::Mtu))
            {
                close(fd);
                return -1;
            }

            std::string strings[] = { addresses[0].to_string(), addresses[1].to_string(), Ipep::ToAddress(ip).to_string() };
            if (!utun_set_if_ip_gw_and_mask(fd,
                strings[0].data(),  // ip
                strings[1].data(),  // gw
                strings[2].data())) // mask
            {
                close(fd);
                return -1;
            }

            utun_set_mac(fd, utun_mac_to_string({ 0x02,0x00,0x17,0x01,0xa6,0xd9 })); // 02:00:17:01:a6:d9
            return fd;
        }

        static bool utun_ctl_add_or_delete_route(UInt32 address, int prefix, UInt32 gw, bool operate_add_or_delete) noexcept
        {
            if (prefix < 0 || prefix > 32)
            {
                prefix = 32;
            }

            ppp::string address_string = IPEndPoint::ToAddressString(address);
            ppp::string gw_string = IPEndPoint::ToAddressString(gw);

            char cmd[1000];
            int len = snprintf(cmd,
                sizeof(cmd),
                "route %s -net %s/%d %s > /dev/null 2>&1",
                operate_add_or_delete ? "add" : "delete",
                address_string.data(),
                prefix,
                gw_string.data());

            if (len < 1)
            {
                return false;
            }

            int status = system(cmd);
            return status == 0;
        }

        static inline bool utun_ctl_add_or_delete_route2(UInt32 address, UInt32 mask, UInt32 gw, bool operate_add_or_delete) noexcept
        {
            int prefix = IPEndPoint::NetmaskToPrefix(mask);
            return utun_ctl_add_or_delete_route(address, prefix, gw, operate_add_or_delete);
        }

        static bool utun_ctl_add_or_delete_route(UInt32 address, UInt32 gw, bool operate_add_or_delete) noexcept
        {
            ppp::string address_string = IPEndPoint::ToAddressString(address);
            ppp::string gw_string = IPEndPoint::ToAddressString(gw);

            char cmd[1000];
            int len = snprintf(cmd,
                sizeof(cmd),
                "route %s -net %s %s > /dev/null 2>&1",
                operate_add_or_delete ? "add" : "delete",
                address_string.data(),
                gw_string.data());

            if (len < 1)
            {
                return false;
            }

            int status = system(cmd);
            return status == 0;
        }

        bool utun_add_route(UInt32 address, int prefix, UInt32 gw) noexcept
        {
            return utun_ctl_add_or_delete_route(address, prefix, gw, true);
        }

        bool utun_del_route(UInt32 address, int prefix, UInt32 gw) noexcept
        {
            return utun_ctl_add_or_delete_route(address, prefix, gw, false);
        }

        bool utun_add_route2(UInt32 address, UInt32 mask, UInt32 gw) noexcept
        {
            return utun_ctl_add_or_delete_route2(address, mask, gw, true);
        }

        bool utun_del_route2(UInt32 address, UInt32 mask, UInt32 gw) noexcept
        {
            return utun_ctl_add_or_delete_route2(address, mask, gw, false);
        }

        bool utun_add_route(UInt32 address, UInt32 gw) noexcept
        {
            return utun_ctl_add_or_delete_route(address, gw, true);
        }

        bool utun_del_route(UInt32 address, UInt32 gw) noexcept
        {
            return utun_ctl_add_or_delete_route(address, gw, false);
        }

        int utun_utunnum(const ppp::string& dev) noexcept
        {
            int v = 0;
            if (dev.empty())
            {
                return v;
            }

            ppp::string s;
            for (char ch : dev)
            {
                if (ch >= '0' && ch <= '9')
                {
                    s.append(1, ch);
                    continue;
                }
            }

            v = atoi(s.data());
            if (v < 0)
            {
                v = 0;
            }
            elif(v > UINT8_MAX)
            {
                v = UINT8_MAX;
            }

            return v;
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

                boost::asio::ip::address ip = boost::asio::ip::address::from_string(ni->IPAddress.data(), ec);
                if (ec || !ip.is_v4())
                {
                    continue;
                }

                boost::asio::ip::address gw = boost::asio::ip::address::from_string(ni->GatewayServer.data(), ec);
                if (ec || !gw.is_v4())
                {
                    continue;
                }

                boost::asio::ip::address mask = boost::asio::ip::address::from_string(ni->SubnetmaskAddress.data(), ec);
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

            if (ITap* my = tap.get(); NULL != my) {

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
    }
}