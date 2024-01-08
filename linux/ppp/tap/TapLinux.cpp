// https://android.googlesource.com/platform/frameworks/base.git/+/android-4.3_r2.1/services/jni/com_android_server_connectivity_Vpn.cpp
// https://android.googlesource.com/platform/system/core/+/master/libnetutils/ifc_utils.c
// https://www.androidos.net.cn/android/6.0.1_r16/xref/bionic/libc/bionic/if_nametoindex.c
// https://android.googlesource.com/platform/frameworks/native/+/master/include/android/multinetwork.h
// https://android.googlesource.com/platform/cts/+/fed9991/tests/tests/net/jni/NativeMultinetworkJni.c

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

#ifdef ANDROID 
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#else
#include <net/if.h>
#include <net/route.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <limits>
#include <exception>

#include <linux/ppp/tap/TapLinux.h>

#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>

// ip tuntap add mode tun dev tun0
// ip addr add 10.0.0.1/24 dev tun0
// ip link set dev tun0 up

#define SYSTEM_ERROR (-1)

#if (defined(ANDROID) || defined(__ANDROID__))
/* SIOCKILLADDR is an Android extension. */
#define SIOCKILLADDR 0x8939
#endif

using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;

namespace ppp {
    namespace tap {
        static class IfcctlSocket {
        public:
            int                                 sock_v4;
            bool                                compatible_route;

        public:
            IfcctlSocket() noexcept
                : sock_v4(-1)
                , compatible_route(false) {
                int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (fd == -1) {
                    fd = socket(AF_INET, SOCK_DGRAM, 0);
                }

                sock_v4 = fd;
            }
            ~IfcctlSocket() noexcept {
                int fd = sock_v4;
                if (fd != -1) {
                    close(fd);
                }

                sock_v4 = -1;
            }
        }                                       ifc_ctl_sock; // ifc_ctl_sock6

        static constexpr const char*            DNS_RESOLV_CONFIGURATION_FILE_PATH = "/etc/resolv.conf";

        TapLinux::TapLinux(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network)
            : ITap(context, dev, tun, address, gw, mask, hosted_network)
            , promisc_(false) {
            
        }

        ppp::vector<boost::asio::ip::address>& TapLinux::GetDnsAddresses() noexcept {
            return dns_addresses_;
        }

        int TapLinux::OpenDriver(const char* ifrName) noexcept {
            if (NULL == ifrName || *ifrName == '\x0') {
                ifrName = "tun%d";
            }

            int tun = open("/dev/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
            if (tun == -1) {
                tun = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
            }

            if (tun == -1) {
                return -1;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
            strncpy(ifr.ifr_name, ifrName, IFNAMSIZ);

            bool fails = ioctl(tun, TUNSETIFF, &ifr) < 0;
            if (fails) {
                close(tun);
                return -1;
            }
            else {
                return tun;
            }
        }

        bool TapLinux::IsPromisc() noexcept {
            return promisc_;
        }

        UInt32 TapLinux::GetDefaultNetworkInterface() noexcept {
            std::unordered_map<UInt32, int> bests;
            for (const char* address_string : PPP_PUBLIC_DNS_SERVER_LIST) {
                boost::system::error_code ec;
                boost::asio::ip::address address = boost::asio::ip::address::from_string(address_string, ec);
                if (ec) {
                    continue;
                }

                if (address.is_multicast()) {
                    continue;
                }

                UInt32 ip = GetDefaultNetworkInterface(address_string);
                if (ip == IPEndPoint::NoneAddress ||
                    ip == IPEndPoint::LoopbackAddress ||
                    ip == IPEndPoint::AnyAddress) {
                    continue;
                }

                bests[ip]++;
            }

            bool preferred_has = false;
            if (bests.empty()) {
                return 0;
            }

            uint32_t preferred = IPEndPoint::NoneAddress;
            for (auto&& kv : bests) {
                if (!preferred_has) {
                    preferred_has = true;
                    preferred = kv.first;
                    continue;
                }

                if (kv.second > bests[preferred]) {
                    preferred_has = true;
                    preferred = kv.first;
                    continue;
                }
            }

            return preferred_has ? preferred : IPEndPoint::NoneAddress;
        }

        UInt32 TapLinux::GetDefaultNetworkInterface(const char* address_string) noexcept {
            if (NULL == address_string || *address_string == '\x0') {
                return IPEndPoint::NoneAddress;
            }

            int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (fd == -1) {
                return IPEndPoint::NoneAddress;
            }

            if (!Socket::SetNonblocking(fd, true)) {
                Socket::Closesocket(fd);
                return IPEndPoint::NoneAddress;
            }

            struct sockaddr_in connect_addr;
            memset(&connect_addr, 0, sizeof(connect_addr));

            connect_addr.sin_addr.s_addr = inet_addr(address_string);
            connect_addr.sin_port = 53;
            connect_addr.sin_family = AF_INET;

            int err = connect(fd, (struct sockaddr*)&connect_addr, sizeof(connect_addr));
            if (err < 0) {
                err = errno;
                if (err != EINPROGRESS) {
                    Socket::Closesocket(fd);
                    return IPEndPoint::NoneAddress;
                }
            }

            struct sockaddr_in sock_addr;
            memset(&sock_addr, 0, sizeof(sock_addr));

            int sock_len = sizeof(sock_addr);
            err = getsockname(fd, (struct sockaddr*)&sock_addr, (socklen_t*)&sock_len);
            if (err < 0) {
                Socket::Closesocket(fd);
                return IPEndPoint::NoneAddress;
            }

            Socket::Closesocket(fd);
            if (sock_addr.sin_family != AF_INET) {
                return IPEndPoint::NoneAddress;
            }
            else {
                return sock_addr.sin_addr.s_addr;
            }
        }

        void TapLinux::CompatibleRoute(bool compatible) noexcept {
            ifc_ctl_sock.compatible_route = compatible;
        }

        bool TapLinux::SetIPAddress(const ppp::string& ifrName, const ppp::string& addressIP, const ppp::string& mask) noexcept {
            if (ifrName.empty()) {
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, ifrName.data());

            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_addr);
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = inet_addr(addressIP.data());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCSIFADDR, &ifr)) {
                return false;
            }

            memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));

            struct sockaddr_in maskAddr;
            memset(&maskAddr, 0, sizeof(maskAddr));

            maskAddr.sin_family = AF_INET;
            maskAddr.sin_addr.s_addr = inet_addr(mask.data());

            memcpy(&ifr.ifr_netmask, &maskAddr, sizeof(ifr.ifr_netmask));
            return ioctl(ifc_ctl_sock.sock_v4, SIOCSIFNETMASK, &ifr) == 0;
        }

        ppp::string TapLinux::GetIPAddress(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return "";
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, ifrName.data());

            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_addr);
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = 0;

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCGIFADDR, &ifr)) {
                return "";
            }

            char ip_buf[UINT8_MAX];
            strcpy(ip_buf, inet_ntoa(addr->sin_addr));
            return ip_buf;
        }

        ppp::string TapLinux::GetMaskAddress(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return "";
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, ifrName.data());

            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_netmask);
            addr->sin_family = AF_INET;

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCGIFNETMASK, &ifr)) {
                return "";
            }

            char ip_buf[UINT8_MAX];
            strcpy(ip_buf, inet_ntoa(addr->sin_addr));
            return ip_buf;
        }

        ppp::string TapLinux::GetHardwareAddress(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return "";
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifrName.data(), ifrName.size());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCGIFHWADDR, &ifr)) {
                return "";
            }
            return ppp::string((char*)ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        int TapLinux::GetInterfaceIndex(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return SYSTEM_ERROR;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifrName.data(), ifrName.size());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOGIFINDEX, &ifr)) {
                return SYSTEM_ERROR;
            }
            return ifr.ifr_ifindex;
        }

        void TapLinux::InitialSockAddrIn(struct sockaddr* sa, in_addr_t addr) noexcept {
            struct sockaddr_in* sin = (struct sockaddr_in*)sa;
            sin->sin_family = AF_INET;
            sin->sin_port = 0;
            sin->sin_addr.s_addr = addr;
        }

        int TapLinux::SetRoute(int action, const ppp::string& ifrName, struct in_addr dst, int prefix, struct in_addr gw) noexcept {
            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            struct rtentry rt;
            memset(&rt, 0, sizeof(rt));

            rt.rt_dst.sa_family = AF_INET;
            if (ifrName.empty()) {
                rt.rt_dev = NULL;
            }
            else {
                rt.rt_dev = (char*)ifrName.data();
            }

            in_addr_t netmask = IPEndPoint::PrefixToNetmask(prefix);
            InitialSockAddrIn(&rt.rt_genmask, netmask);
            InitialSockAddrIn(&rt.rt_dst, dst.s_addr);

            rt.rt_metric = 0;
            rt.rt_flags = RTF_UP;
            if (prefix == 32) {
                rt.rt_flags |= RTF_HOST;
            }

            if (gw.s_addr != 0) {
                rt.rt_flags |= RTF_GATEWAY;
                InitialSockAddrIn(&rt.rt_gateway, gw.s_addr);
            }

            int err = ioctl(ifc_ctl_sock.sock_v4, action, &rt);
            if (err < 0) {
                err = errno;
                if (err == EEXIST) {
                    err = 0;
                }
            }
            return err;
        }

        bool TapLinux::AddRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            if (ifc_ctl_sock.compatible_route) {
                char cmd[1000];
                if (prefix > 31) {
                    snprintf(cmd, sizeof(cmd), "route add -host %s gw %s",
                        IPEndPoint::ToAddressString(address).data(),
                        IPEndPoint::ToAddressString(gw).data());
                }
                else {
                    snprintf(cmd, sizeof(cmd), "route add -net %s netmask %s gw %s",
                        IPEndPoint::ToAddressString(address).data(),
                        IPEndPoint::ToAddressString(IPEndPoint::PrefixToNetmask(prefix)).data(),
                        IPEndPoint::ToAddressString(gw).data());
                }
                return system(cmd) == 0;
            }
            else {
                struct in_addr in_dst;
                struct in_addr in_gw;

                in_dst.s_addr = address;
                in_gw.s_addr = gw;

                return TapLinux::SetRoute(SIOCADDRT, ifrName, in_dst, prefix, in_gw) == 0;
            }
        }

        bool TapLinux::DeleteRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            if (ifc_ctl_sock.compatible_route) {
                char cmd[1000];
                if (prefix > 31) {
                    snprintf(cmd, sizeof(cmd), "route add -host %s gw %s",
                        IPEndPoint::ToAddressString(address).data(),
                        IPEndPoint::ToAddressString(gw).data());
                }
                else {
                    snprintf(cmd, sizeof(cmd), "route add -host %s/%d gw %s",
                        IPEndPoint::ToAddressString(address).data(),
                        prefix,
                        IPEndPoint::ToAddressString(gw).data());
                }
                return system(cmd) == 0;
            }
            else {
                struct in_addr in_dst;
                struct in_addr in_gw;

                in_dst.s_addr = address;
                in_gw.s_addr = gw;

                bool any = false;
                for (;;) {
                    int err = TapLinux::SetRoute(SIOCDELRT, ifrName, in_dst, prefix, in_gw);
                    if (err != 0) {
                        break;
                    }
                    else {
                        any = true;
                        continue;
                    }
                }
                return any;
            }
        }

        ppp::string TapLinux::GetDeviceId(const ppp::string& ifrName) noexcept {
            ppp::string nil_guid = GuidToString(boost::uuids::nil_uuid());
            if (ifrName.empty()) {
                return nil_guid;
            }

            char path[1000];
            snprintf(path, sizeof(path), "/sys/class/net/%s/device/device_id", ifrName.data());

            ppp::string guid = ppp::io::File::ReadAllText(path);
            if (guid.empty()) {
                return nil_guid;
            }

            guid = LTrim(RTrim(guid));
            if (guid.empty()) {
                return nil_guid;
            }

            boost::uuids::string_generator sgen;
            try {
                return GuidToString(sgen(guid));
            }
            catch (const std::exception&) {
                return nil_guid;
            }
        }

        bool TapLinux::GetPreferredNetworkInterface(ppp::string& interface_, UInt32& address, UInt32& mask, UInt32& gw) noexcept {
            char sz[256];
            ppp::string dev = ITap::FindAnyDevice();
            if (TapLinux::GetDefaultGateway(sz, &gw)) {
                interface_ = sz;
                if (interface_ != dev) {
                    address = IPEndPoint(TapLinux::GetIPAddress(interface_).data(), 0).GetAddress();
                    mask = IPEndPoint(TapLinux::GetMaskAddress(interface_).data(), 0).GetAddress();
                    return true;
                }
            }

            address = TapLinux::GetDefaultNetworkInterface();
            gw = IPEndPoint::NoneAddress;

            boost::asio::ip::address address_ip = Ipep::ToAddress(address);
            if (IPEndPoint::IsInvalid(address_ip) || address_ip.is_loopback() || address_ip.is_multicast()) {
                ppp::unordered_map<ppp::string, int> best_interfaces;
                address = IPEndPoint::NoneAddress;

                GetDefaultGateway(&address,
                    [&best_interfaces](const char* interface_name, uint32_t ip, uint32_t gw, uint32_t mask, int metric) noexcept {
                        boost::asio::ip::address address_ip = Ipep::ToAddress(ip);
                        if (IPEndPoint::IsInvalid(address_ip) || address_ip.is_loopback() || address_ip.is_multicast()) {
                            return false;
                        }
                        else {
                            best_interfaces[interface_name]++;
                            return false;
                        }
                    });

                ppp::string best_interface;
                for (auto&& kv : best_interfaces) {
                    if (best_interface.empty() || kv.second > best_interfaces[best_interface]) {
                        best_interface = kv.first;
                    }
                }

                if (best_interface.size() > 0) {
                    boost::system::error_code best_interface_ip_ec;
                    boost::asio::ip::address best_interface_ip = boost::asio::ip::address::from_string(TapLinux::GetIPAddress(best_interface).data(), best_interface_ip_ec);
                    if (!(best_interface_ip_ec || best_interface_ip.is_loopback() || best_interface_ip.is_multicast() || IPEndPoint::IsInvalid(best_interface_ip))) {
                        if (best_interface_ip.is_v4()) {
                            address = htonl(best_interface_ip.to_v4().to_uint());
                        }
                    }
                }   
            }

            if (address != IPEndPoint::NoneAddress) {
                interface_ = TapLinux::GetInterfaceName(IPEndPoint(address, 0));
                if (!interface_.empty() && interface_ != dev) {
                    mask = IPEndPoint(TapLinux::GetMaskAddress(interface_).data(), 0).GetAddress();
                    if (mask == UINT_MAX) {
                        gw = address;
                    }
                    else {
                        gw = htonl(ntohl(mask & address) + 1);
                    }
                    return true;
                }
            }
            return TapLinux::GetLocalNetworkInterface(interface_, address, gw, mask);
        }

        /* raw https://github.com/getlantern/libnatpmp/blob/master/getgateway.c
         * parse /proc/net/route which is as follow :
         * Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
         * wlan0   0001A8C0        00000000        0001    0       0       0       00FFFFFF        0       0       0
         * eth0    0000FEA9        00000000        0001    0       0       0       0000FFFF        0       0       0
         * wlan0   00000000        0101A8C0        0003    0       0       0       00000000        0       0       0
         * eth0    00000000        00000000        0001    0       0       1000    00000000        0       0       0
         * One header line, and then one line by route by route table entry.
        */
        bool TapLinux::GetDefaultGateway(UInt32* address, const ppp::function<bool(const char*, uint32_t ip, uint32_t gw, uint32_t mask, int metric)>& predicate) noexcept {
            unsigned long d, g, fl, rc, us, metric, mask;
            char buf[256];
            char eth[256];
            int line = 0;
            int calli;
            int status;
            FILE* f;
            char* p;

            if (!address || !predicate) {
                return false;
            }

            f = fopen("/proc/net/route", "r");
            if (!f) {
                return false;
            }

            while (fgets(buf, sizeof(buf), f)) {
                /* skip the first line */
                if (line > 0) {
                    p = buf;

                    /* skip the interface name */
                    while (*p && !isspace(*p)) {
                        p++;
                    }

                    while (*p && isspace(*p)) {
                        p++;
                    }

                    status = sscanf_s(p, "%lx%lx%lx%lx%lx%lx%lx", &d, &g, &fl, &rc, &us, &metric, &mask);
                    if (status >= 7) {
                        calli = true;
                    }
                    else if (status >= 2) {
                        mask = 0;
                        metric = -1;
                        calli = true;
                    }

                    /* default */
                    if (calli) {
                        *eth = '\x0';
                        if (sscanf_s(buf, "%[^\t\x20]", eth) > 0) {
                            if (predicate(eth, d, g, mask, metric)) {
                                *address = g;
                                fclose(f);
                                return true;
                            }
                        }
                    }
                }
                line++;
            }

            /* default route not found ! */
            if (f) {
                fclose(f);
            }
            return false;
        }

        bool TapLinux::GetDefaultGateway(char* ifrName, UInt32* address) noexcept {
            if (NULL == ifrName) {
                return false;
            }

            uint32_t mid = inet_addr("128.0.0.0");
            return GetDefaultGateway(address,
                [ifrName, mid](const char* interface_name, uint32_t ip, uint32_t gw, uint32_t mask, int metric) noexcept -> bool {
                    if (metric != -1) {
                        bool b = (ip == ppp::net::IPEndPoint::AnyAddress && mask == mid) ||
                            (ip == ppp::net::IPEndPoint::AnyAddress && mask == ppp::net::IPEndPoint::AnyAddress) ||
                            (ip == mid && mask == mid);
                        if (!b) {
                            return false;
                        }
                    }

                    strcpy(ifrName, interface_name);
                    return true;
                });
        }

        bool TapLinux::SetNextHop(const ppp::string& ip) noexcept {
            struct rtentry rt;
            memset(&rt, 0, sizeof(rt));

            struct sockaddr_in* gateAddr = (struct sockaddr_in*)&rt.rt_gateway;
            gateAddr->sin_family = AF_INET;
            gateAddr->sin_port = 0;

            if (!inet_aton(ip.data(), &gateAddr->sin_addr)) {
                return false;
            }

            struct sockaddr_in* dstAddr = (struct sockaddr_in*)&rt.rt_dst;
            dstAddr->sin_family = AF_INET;

            struct sockaddr_in* maskAddr = (struct sockaddr_in*)&rt.rt_genmask;
            maskAddr->sin_family = AF_INET;

            rt.rt_flags = RTF_GATEWAY | RTF_UP;
            rt.rt_metric = 0;
            return ioctl(ifc_ctl_sock.sock_v4, SIOCADDRT, &rt) == 0;
        }

        bool TapLinux::GetLocalNetworkInterface(ppp::string& interface_, UInt32& address, UInt32& gw, UInt32& mask) noexcept {
            bool b = false;
#if (!defined(ANDROID) || __ANDROID_API__ >= 24)
            struct ifaddrs* ifList = NULL;
            if (getifaddrs(&ifList)) {
                return b;
            }

            ppp::string dev = ITap::FindAnyDevice();
            UInt32 invalidIPAddr = inet_addr("169.254.0.0");
            UInt32 invalidIPMask = inet_addr("255.255.0.0");
            for (struct ifaddrs* ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr; // ifa_dstaddr
                if (NULL == sin || sin->sin_family != AF_INET) {
                    continue;
                }

                UInt32 ipAddr = sin->sin_addr.s_addr;
                if ((ipAddr & invalidIPMask) == invalidIPAddr) {
                    continue;
                }

                ipAddr = ntohl(ipAddr);
                if (ipAddr != INADDR_ANY && ipAddr != INADDR_NONE && ipAddr != INADDR_LOOPBACK) {
                    sin = (struct sockaddr_in*)ifa->ifa_netmask;
                    if (NULL == sin || sin->sin_family != AF_INET) {
                        continue;
                    }
                    else {
                        interface_ = ifa->ifa_name;
                    }

                    if (interface_ == dev) {
                        continue;
                    }

                    b = true;
                    address = htonl(ipAddr);
                    mask = sin->sin_addr.s_addr;
                    if (mask == UINT_MAX) {
                        gw = address;
                    }
                    else {
                        gw = htonl(ntohl(mask & address) + 1);
                    }
                    break;
                }
            }

            freeifaddrs(ifList);
#endif
            return b;
        }

        bool TapLinux::GetInterfaceName(int dev_handle, ppp::string& ifrName) noexcept {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            int err = ioctl(dev_handle, TUNGETIFF, &ifr);
            if (err < 0) {
                return false;
            }

            size_t len = strnlen(ifr.ifr_name, sizeof(ifr.ifr_name));
            if (len >= IF_NAMESIZE) {
                return false;
            }
            else {
                ifrName.assign(ifr.ifr_name, len);
                return true;
            }
        }

        bool TapLinux::SetInterfaceName(int dev_handle, const ppp::string& ifrName) noexcept {
            if (ifrName.size() >= IF_NAMESIZE) {
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            ppp::string oldName;
            if (!TapLinux::GetInterfaceName(dev_handle, oldName)) {
                return false;
            }

            memcpy(ifr.ifr_name, oldName.data(), oldName.size());
            ifr.ifr_name[oldName.size() + 1] = '\x0';

            memcpy(ifr.ifr_newname, ifrName.data(), ifrName.size());
            ifr.ifr_name[ifrName.size() + 1] = '\x0';

            return ioctl(dev_handle, SIOCSIFNAME, &ifr) == 0;
        }

        ppp::string TapLinux::GetInterfaceName(const IPEndPoint& address) noexcept {
#if (!defined(ANDROID) || __ANDROID_API__ >= 24)
            struct ifaddrs* ifa = NULL;
            if (getifaddrs(&ifa)) {
                return "";
            }

            struct ifaddrs* oifa = ifa;
            while (NULL != ifa) {
                struct sockaddr* addr = ifa->ifa_addr;
                if (NULL != addr) {
                    switch (addr->sa_family) {
                        case AF_INET:
                        {
                            if (address.GetAddressFamily() != AddressFamily::InterNetwork) {
                                break;
                            }
    
                            struct sockaddr_in* in4_addr = (struct sockaddr_in*)addr;
                            if (in4_addr->sin_addr.s_addr != address.GetAddress()) {
                                break;
                            }
                            return ifa->ifa_name;
                        }
                        case AF_INET6:
                        {
                            if (address.GetAddressFamily() != AddressFamily::InterNetwork) {
                                break;
                            }
    
                            struct sockaddr_in6* in6_addr = (struct sockaddr_in6*)addr;
                            {
                                int length;
                                Byte* address_bytes = address.GetAddressBytes(length);
                                length = std::min<int>(sizeof(in6_addr->sin6_addr), length);
                                if (memcmp(&in6_addr->sin6_addr, address_bytes, length) != 0) {
                                    break;
                                }
                            }
                            return ifa->ifa_name;
                        }
                    };
                }
                ifa = ifa->ifa_next;
            }

            if (NULL != oifa) {
                freeifaddrs(oifa);
            }
#endif
            return "";
        }

        bool TapLinux::AddRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::AddRoute(this->GetId(), address, prefix, gw);
        }

        bool TapLinux::DeleteRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::DeleteRoute(this->GetId(), address, prefix, gw);
        }

        void TapLinux::Dispose() noexcept {
            std::shared_ptr<ITap> self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            boost::asio::post(*context,
                [self, this]() noexcept {
                    SetNetifUp(false);
                });
            ITap::Dispose();
        }

        bool TapLinux::SetNetifUp(bool up) noexcept {
            std::shared_ptr<boost::asio::posix::stream_descriptor> sd = GetStream();
            if (NULL == sd) {
                return false;
            }

            if (!sd->is_open()) {
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            if (ioctl(sd->native_handle(), TUNGETIFF, &ifr) < 0) {
                return false;
            }

            if (up) {
                ifr.ifr_flags |= IFF_UP;
            }
            else {
                ifr.ifr_flags &= ~IFF_UP;
            }

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCSIFFLAGS, &ifr) < 0) {
                return false;
            }

            ifr.ifr_mtu = ITap::Mtu;
            return ioctl(ifc_ctl_sock.sock_v4, SIOCSIFMTU, &ifr) == 0;
        }

        std::shared_ptr<TapLinux> TapLinux::CreateInternal(const std::shared_ptr<boost::asio::io_context>& context, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, int tun, ppp::string interface_name, const ppp::vector<boost::asio::ip::address>& dns_addresses) noexcept {
            int interface_index = TapLinux::GetInterfaceIndex(interface_name);
            if (interface_index == -1) {
                bool fails = true;
                if (TapLinux::GetInterfaceName(tun, interface_name)) {
                    interface_index = TapLinux::GetInterfaceIndex(interface_name);
                    if (interface_index != -1) {
                        fails = false;
                    }
                }

                if (fails) {
                    close(tun);
                    return NULL;
                }
            }

            bool ok = TapLinux::SetIPAddress(interface_name,
                IPEndPoint(ip, IPEndPoint::MinPort).ToAddressString(),
                IPEndPoint(mask, IPEndPoint::MinPort).ToAddressString());
            if (!ok) {
                close(tun);
                return NULL;
            }

            std::shared_ptr<TapLinux> tap = make_shared_object<TapLinux>(context, interface_name, reinterpret_cast<void*>(tun), ip, gw, mask, hosted_network);
            tap->promisc_ = promisc;
            tap->dns_addresses_ = dns_addresses;

            if (ITap* my = tap.get(); NULL != my) {
                my->GetInterfaceIndex() = interface_index;
            }

            ok = tap->SetNetifUp(true);
            if (!ok) {
                tap->Dispose();
                tap.reset();
            }

            return tap;
        }

        std::shared_ptr<TapLinux> TapLinux::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept {
            if (NULL == context) {
                return NULL;
            }

            if (dev.empty()) {
                return NULL;
            }

            if (!IsUserAnAdministrator()) { // $ROOT is 0.
                return NULL;
            }

            IPEndPoint ipEP(ip, 0);
            if (IPEndPoint::IsInvalid(ipEP)) {
                return NULL;
            }

            IPEndPoint gwEP(ip, 0);
            if (IPEndPoint::IsInvalid(gwEP)) {
                return NULL;
            }

            IPEndPoint maskEP(ip, 0);
            if (IPEndPoint::IsInvalid(maskEP)) {
                return NULL;
            }

            int tun = OpenDriver(dev.data());
            if (tun == -1) {
                return NULL;
            }

            // GCC 7.5 compiler BUG, generated code, not split this part of the code into other functions, 
            // There will be a crash problem (can not be fixed, unless the upgrade of the GCC compiler version is very high, 
            // But most systems come with 7.5 version of GCC, the higher version is not common).
            // Clang 6.x compiler support.
            ppp::vector<boost::asio::ip::address> dns_servers;
            Ipep::ToAddresses(dns_addresses, dns_servers);
            return CreateInternal(context, ip, gw, mask, promisc, hosted_network, tun, dev, dns_servers);
        }

        bool TapLinux::SetDnsAddresses(const ppp::vector<uint32_t>& addresses) noexcept {
            ppp::vector<ppp::string> dns_servers;
            Ipep::ToAddresses(addresses, dns_servers);

            return SetDnsAddresses(dns_servers);
        }

        bool TapLinux::SetDnsAddresses(const ppp::vector<boost::asio::ip::address>& addresses) noexcept {
            ppp::vector<ppp::string> dns_servers;
            Ipep::AddressesTransformToStrings(addresses, dns_servers);

            return SetDnsAddresses(dns_servers);
        }

        bool TapLinux::SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept {
            ppp::string content;
            for (size_t i = 0, l = addresses.size(); i < l; i++) {
                const ppp::string& address = addresses[i];
                if (address.empty()) {
                    continue;
                }
                else {
                    content += "nameserver " + address + " \r\n";
                }
            }
            return ppp::io::File::WriteAllBytes(DNS_RESOLV_CONFIGURATION_FILE_PATH, content.data(), content.size());
        }

        ppp::string TapLinux::GetDnsResolveConfiguration() noexcept {
            return ppp::io::File::ReadAllText(DNS_RESOLV_CONFIGURATION_FILE_PATH);
        }

        bool TapLinux::SetDnsResolveConfiguration(const ppp::string& configuration) noexcept {
            return ppp::io::File::WriteAllBytes(DNS_RESOLV_CONFIGURATION_FILE_PATH, configuration.data(), configuration.size());
        }

        int TapLinux::GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses) noexcept {
            ppp::string in = GetDnsResolveConfiguration();
            return GetDnsAddresses(in, addresses);
        }

        int TapLinux::GetDnsAddresses(const ppp::string& in, ppp::vector<boost::asio::ip::address>& addresses) noexcept {
            if (in.empty()) {
                return 0;
            }

            ppp::vector<ppp::string> lines;
            if (Tokenize<ppp::string>(in, lines, "\r\n") < 1) {
                return 0;
            }

            int events = 0;
            const char nameserver_string[] = "nameserver";
            for (ppp::string& line : lines) {
                if (line.empty()) {
                    continue;
                }

                std::size_t index = line.find('#');
                if (index != ppp::string::npos) {
                    line = line.substr(0, index);
                }

                if (line.empty()) {
                    continue;
                }

                line = RTrim(LTrim(line));
                if (line.empty()) {
                    continue;
                }

                char* position = strcasestr((char*)line.data(), nameserver_string);
                if (NULL == position) {
                    continue;
                }

                position += sizeof(nameserver_string);
                line = RTrim(LTrim<ppp::string>(position));
                if (line.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address address = boost::asio::ip::address::from_string(line.data(), ec);
                if (ec) {
                    continue;
                }

                if (address.is_multicast()) {
                    continue;
                }

                if (IPEndPoint::IsInvalid(address)) {
                    continue;
                }

                events++;
                addresses.emplace_back(address);
            }
            return events;
        }

        bool TapLinux::AddShutdownApplicationEventHandler(ShutdownApplicationEventHandler e) noexcept {
            static ShutdownApplicationEventHandler eeh = NULL;

            auto SIG_EEH = [](int signo) noexcept -> void {
                ShutdownApplicationEventHandler e = std::move(eeh);
                if (NULL != e) {
                    eeh.reset();
                    e();
                }
                else {
                    signal(signo, SIG_DFL);
                    raise(signo);
                }
                };

            __sighandler_t SIG_IGN_V = SIG_IGN;
            __sighandler_t SIG_EEH_V = SIG_EEH;

            if (NULL != e) {
                eeh = e;
            }
            else {
                eeh.reset();
                SIG_EEH_V = SIG_DFL;
                SIG_IGN_V = SIG_DFL;
            }

            /*retrieve old and set new handlers*/
            /*restore prevouis signal actions*/
#ifdef ANDROID
            Watch(35, SIG_IGN_V); // FDSCAN(SI_QUEUE)
#endif

            signal(SIGPIPE, SIG_IGN_V);
            signal(SIGHUP, SIG_IGN_V);

            signal(SIGINT, SIG_EEH_V);
            signal(SIGTERM, SIG_EEH_V);
            signal(SIGSYS, SIG_EEH_V);
            signal(SIGIOT, SIG_EEH_V);
            signal(SIGUSR1, SIG_EEH_V);
            signal(SIGUSR2, SIG_EEH_V);
            signal(SIGXCPU, SIG_EEH_V);
            signal(SIGXFSZ, SIG_EEH_V);

            signal(SIGTRAP, SIG_EEH_V); // 调试陷阱
            signal(SIGBUS, SIG_EEH_V); // 总线错误(常见于结构对齐问题)
            signal(SIGQUIT, SIG_EEH_V); // CTRL+\退出终端
            signal(SIGSTKFLT, SIG_EEH_V); // 进程堆栈崩坏

            signal(SIGSEGV, SIG_EEH_V); // 段错误(试图访问无效地址)
            signal(SIGFPE, SIG_EEH_V); // 致命的算术运算问题(常见于试图除以零或者FPU/IEEE-754浮点数问题)
            signal(SIGABRT, SIG_EEH_V); // 程式被中止执行(常见于三方库或固有程式遭遇一般性错误执行abort()强行关闭主板程式）
            signal(SIGILL, SIG_EEH_V); // 非法硬件指令(CPU/RING 0 ABORT)
            return true;
        }

        bool TapLinux::AddAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            if (NULL == rib || NULL == interface_name) {
                return false;
            }

            bool any = false;
            for (auto&& [_, entries] : rib->GetAllRoutes()) {
                for (auto&& entry : entries) {
                    any |= AddRoute(interface_name(entry), entry.Destination, entry.Prefix, entry.NextHop);
                }
            }
            return any;
        }

        bool TapLinux::DeleteAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            if (NULL == rib || NULL == interface_name) {
                return false;
            }

            bool any = false;
            for (auto&& [_, entries] : rib->GetAllRoutes()) {
                for (auto&& entry : entries) {
                    any |= DeleteRoute(interface_name(entry), entry.Destination, entry.Prefix, entry.NextHop);
                }
            }
            return any;
        }

        std::shared_ptr<ppp::net::native::RouteInformationTable> TapLinux::FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>& bypass_gws) noexcept {
            std::shared_ptr<ppp::net::native::RouteInformationTable> rib = make_shared_object<ppp::net::native::RouteInformationTable>();
            if (NULL == rib) {
                return NULL;
            }

            uint32_t mid = inet_addr("128.0.0.0");
            bool any = false;
            uint32_t address = 0;
            GetDefaultGateway(&address,
                [&rib, mid, &any, &bypass_gws](const char* interface_name, uint32_t ip, uint32_t gw, uint32_t mask, int metric) noexcept {
                    if (metric != -1) {
                        bool b = (ip == ppp::net::IPEndPoint::AnyAddress && mask == mid) ||
                            (ip == ppp::net::IPEndPoint::AnyAddress && mask == ppp::net::IPEndPoint::AnyAddress) ||
                            (ip == mid && mask == mid);
                        if (!b) {
                            return false;
                        }
                    }

                    if (bypass_gws.find(gw) != bypass_gws.end()) {
                        return false;
                    }

                    boost::asio::ip::address gw_address = Ipep::ToAddress(gw);
                    if (gw_address.is_multicast()) {
                        return false;
                    }

                    if (gw_address.is_loopback()) {
                        return false;
                    }

                    if (IPEndPoint::IsInvalid(gw_address)) {
                        return false;
                    }

                    int prefix_mask = IPEndPoint::NetmaskToPrefix(mask); // cidr
                    any |= rib->AddRoute(ip, prefix_mask, gw);
                    return false;
                });
            return any ? rib : NULL;
        }
    }
}