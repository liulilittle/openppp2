// https://stackoverflow.com/questions/2300149/how-can-i-determine-the-default-gateway-on-iphone/8095530#8095530
// https://stackoverflow.com/questions/5390164/getting-routing-table-on-macosx-programmatically/11265543#11265543
// https://bugzilla.mozilla.org/show_bug.cgi?id=1579424
// https://gist.github.com/etodd/d8184b91c02306b889c13eb03f81fb6d
// https://github.com/songgao/water/issues/3#issuecomment-158704536
// https://build.openvpn.net/doxygen/route_8c_source.html
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tun.c#L3250

#include <darwin/ppp/tap/TapDarwin.h>
#include <darwin/ppp/tun/utun.h>

#include <ppp/tap/ITap.h>
#include <ppp/net/native/eth.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>

#include <common/unix/UnixAfx.h>

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

// networksetup -setmanual Ethernet 192.168.0.22 255.255.255.0 192.168.0.1
// route add -net 9.9.9.9/32 10.0.0.1
// route delete -net 9.9.9.9/32 10.0.0.1
// netstat -rn
// ifconfig utun1 mtu 2000
// ifconfig utun1 inet 10.0.0.2 10.0.0.1 netmask 255.255.255.0 up

using ppp::net::Ipep;
using ppp::net::IPEndPoint;

namespace ppp 
{
    namespace darwin 
    {
        namespace tun 
        {
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

                utun_set_cloexec(fd);
                ppp::net::Socket::SetNonblocking(fd, true);
                return fd;
            }

            bool utun_set_cloexec(int fd) noexcept
            {
                return ppp::unix__::UnixAfx::set_fd_cloexec(fd);
            }

            bool utun_set_mtu(int tun, int mtu) noexcept
            {
                if (tun == -1)
                {
                    return false;
                }
                else
                {
                    // MTU: 68 ~ 65535 RANGE.
                    mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);
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

                if (!utun_set_mtu(fd, ppp::tap::ITap::Mtu))
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

                utun_set_mac(fd, ppp::net::native::eth_addr::ToString({ 0x02,0x00,0x17,0x01,0xa6,0xd9 })); // 02:00:17:01:a6:d9
                return fd;
            }

            static bool utun_ctl_add_or_delete_route_sys_abi(int action, uint32_t dst, uint32_t mask, uint32_t nexthop) noexcept 
            {
            #pragma pack(push, 1)
                struct 
                {
                    struct rt_msghdr    msghdr;
                    struct sockaddr_in  addr[3];
                } packet{};
            #pragma pack(pop)

                packet.msghdr.rtm_msglen  = sizeof(packet);
                packet.msghdr.rtm_version = RTM_VERSION;
                packet.msghdr.rtm_type    = action;
                packet.msghdr.rtm_addrs   = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
                packet.msghdr.rtm_flags   = RTF_UP | RTA_GATEWAY;

                for (int i = 0; i < arraysizeof(packet.addr); i++) 
                {
                    auto& r      = packet.addr[i];
                    r.sin_len    = sizeof(*packet.addr);
                    r.sin_family = AF_INET;
                }

                packet.addr[0].sin_addr.s_addr = dst;
                packet.addr[1].sin_addr.s_addr = nexthop;
                packet.addr[2].sin_addr.s_addr = mask;

                int route_fd = socket(AF_ROUTE, SOCK_RAW, 0);
                if (route_fd < 0) 
                {
                    return false;
                }

                int message_flags = 0;
            #if defined(MSG_NOSIGNAL)
                message_flags = MSG_NOSIGNAL;
            #endif

                int err = send(route_fd, &packet, sizeof(packet), message_flags);
                close(route_fd);

                return err != -1;
            }

            static inline bool utun_ctl_add_or_delete_route2(UInt32 address, UInt32 mask, UInt32 gw, bool operate_add_or_delete) noexcept
            {
                int action = operate_add_or_delete ? RTM_ADD : RTM_DELETE;
                return utun_ctl_add_or_delete_route_sys_abi(action, address, mask, gw);
            }

            static bool utun_ctl_add_or_delete_route(UInt32 address, int prefix, UInt32 gw, bool operate_add_or_delete) noexcept
            {
                if (prefix < 0 || prefix > 32)
                {
                    prefix = 32;
                }

                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                return utun_ctl_add_or_delete_route2(address, mask, gw, operate_add_or_delete);
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
                return utun_add_route(address, 32, gw);
            }

            bool utun_del_route(UInt32 address, UInt32 gw) noexcept
            {
                return utun_del_route(address, 32, gw);
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
        }
    }
}