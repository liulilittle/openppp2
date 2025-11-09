// https://android.googlesource.com/platform/frameworks/base.git/+/android-4.3_r2.1/services/jni/com_android_server_connectivity_Vpn.cpp
// https://android.googlesource.com/platform/system/core/+/master/libnetutils/ifc_utils.c
// https://www.androidos.net.cn/android/6.0.1_r16/xref/bionic/libc/bionic/if_nametoindex.c
// https://android.googlesource.com/platform/frameworks/native/+/master/include/android/multinetwork.h
// https://android.googlesource.com/platform/cts/+/fed9991/tests/tests/net/jni/NativeMultinetworkJni.c

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

#if defined(_ANDROID) 
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

#include <common/unix/UnixAfx.h>
#include <common/libtcpip/netstack.h>

#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/SpinLock.h>

// ip tuntap add mode tun dev tun0
// ip addr add 10.0.0.1/24 dev tun0
// ip link set dev tun0 up

#if defined(_ANDROID) || defined(__ANDROID__)
/* SIOCKILLADDR is an Android extension. */
#define SIOCKILLADDR 0x8939
#endif

using ppp::unix__::UnixAfx;
using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;

namespace ppp {
    namespace tap {
        class IfcctlSocket final { // ifc_ctl_sock6
        public:
            int                                 sock_v4;

        public:
            IfcctlSocket() noexcept
                : sock_v4(-1) {
                sock_v4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            }
            ~IfcctlSocket() noexcept {
                int fd = sock_v4;
                sock_v4 = -1;
                
                if (fd != -1) {
                    ::close(fd);
                }
            }
        };

        struct SsmtThreadLocalTls final {
            int                                 tun_fd_ = -1;
        };

        static thread_local SsmtThreadLocalTls  ssmt_tls_;
        static bool                             ifc_ctl_sock_compatible_route = false;

        TapLinux::TapLinux(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network)
            : ITap(context, dev, tun, address, gw, mask, hosted_network)
            , promisc_(false)
            , disposed_(FALSE) {

        }

        TapLinux::~TapLinux() noexcept {
            Finalize();
        }

        int TapLinux::OpenDriver(const char* ifrName) noexcept {
            if (NULL == ifrName || *ifrName == '\x0') {
                ifrName = "tun%d";
            }

            // __oflag
            int __open_flags = O_RDWR | O_NONBLOCK;
#if defined(O_CLOEXEC)
            __open_flags |= O_CLOEXEC;
#endif

            int tun = open("/dev/tun", __open_flags);
            if (tun == -1) {
                tun = open("/dev/net/tun", __open_flags);
                if (tun == -1) {
                    return -1;
                }
            }

            Socket::SetNonblocking(tun, true);
            ppp::unix__::UnixAfx::set_fd_cloexec(tun);

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            // By default, try to enable tun/tap-driver multi-queue mode, if not single-queue mode.
            // https://www.kernel.org/doc/Documentation/networking/tuntap.txt
            strncpy(ifr.ifr_name, ifrName, IFNAMSIZ);

            bool fails = false;
#if defined(IFF_MULTI_QUEUE)
#if defined(IFF_ATTACH_QUEUE)
            ifr.ifr_flags = IFF_ATTACH_QUEUE; /* IFF_DETACH_QUEUE */
            ioctl(tun, TUNSETQUEUE, &ifr);
#endif

            ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
            fails = ioctl(tun, TUNSETIFF, &ifr) < 0;

            if (fails) {
                ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
                fails = ioctl(tun, TUNSETIFF, &ifr) < 0;
            }
#else
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
            fails = ioctl(tun, TUNSETIFF, &ifr) < 0;
#endif

            if (fails) {
                ::close(tun);
                return -1;
            }
            else {
#if defined(IFF_ATTACH_QUEUE)
                ifr.ifr_flags = IFF_ATTACH_QUEUE; /* IFF_DETACH_QUEUE */
                ioctl(tun, TUNSETQUEUE, &ifr);
#endif
                return tun;
            }
        }

        void TapLinux::CompatibleRoute(bool compatible) noexcept {
            ifc_ctl_sock_compatible_route = compatible;
        }

        bool TapLinux::SetIPAddress(const ppp::string& ifrName, const ppp::string& addressIP, const ppp::string& mask) noexcept {
            if (ifrName.empty()) {
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
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
            else {
                memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
            }

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

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
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

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
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

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
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
                return -1;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return -1;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifrName.data(), ifrName.size());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOGIFINDEX, &ifr)) {
                return -1;
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

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return -1;
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

        static bool SetRouteToLinux(UInt32 address, int prefix, UInt32 gw, bool action_add_or_delete) noexcept {
            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            int len = 0;
            ppp::string address_string = IPEndPoint::ToAddressString(address);
            ppp::string gw_string = IPEndPoint::ToAddressString(gw);

            char cmd[1000];
            if (prefix > 31) {
                len = snprintf(cmd,
                    sizeof(cmd),
                    "route %s -host %s gw %s > /dev/null 2>&1",
                    action_add_or_delete ? "add" : "delete",
                    address_string.data(),
                    gw_string.data());
            }
            else {
                ppp::string netmask_string = IPEndPoint::ToAddressString(IPEndPoint::PrefixToNetmask(prefix));
                len = snprintf(cmd,
                    sizeof(cmd),
                    "route %s -net %s netmask %s gw %s > /dev/null 2>&1",
                    action_add_or_delete ? "add" : "delete",
                    address_string.data(),
                    netmask_string.data(),
                    gw_string.data());
            }

            if (len < 1) {
                return false;
            }

            if (action_add_or_delete) {
                int status = system(cmd);
                return status == 0;
            }

            bool any = false;
            for (;;) {
                int status = system(cmd);
                if (status != 0) {
                    break;
                }
                else {
                    any = true;
                }
            }

            return any;
        }

        bool TapLinux::AddRoute2(UInt32 address, int prefix, UInt32 gw) noexcept {
            return SetRouteToLinux(address, prefix, gw, true);
        }

        bool TapLinux::DeleteRoute2(UInt32 address, int prefix, UInt32 gw) noexcept {
            return SetRouteToLinux(address, prefix, gw, false);
        }

        bool TapLinux::AddRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            if (ifc_ctl_sock_compatible_route) {
                return SetRouteToLinux(address, prefix, gw, true);
            }

            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            struct in_addr in_dst;
            struct in_addr in_gw;

            in_dst.s_addr = address;
            in_gw.s_addr = gw;

            return TapLinux::SetRoute(SIOCADDRT, ifrName, in_dst, prefix, in_gw) == 0;
        }

        bool TapLinux::DeleteRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            if (ifc_ctl_sock_compatible_route) {
                return SetRouteToLinux(address, prefix, gw, false);
            }

            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

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

        ppp::string TapLinux::GetDeviceId(const ppp::string& ifrName) noexcept {
            ppp::string nil_guid = GuidToStringB(boost::uuids::nil_uuid());
            if (ifrName.empty()) {
                return nil_guid;
            }

            char path[PATH_MAX + 1];
            path[PATH_MAX] = '\x0';

            if (snprintf(path, PATH_MAX, "/sys/class/net/%s/device/device_id", ifrName.data()) < 1) {
                return nil_guid;
            }

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
                return GuidToStringB(sgen(guid));
            }
            catch (const std::exception&) {
                return nil_guid;
            }
        }

        bool TapLinux::GetPreferredNetworkInterface(ppp::string& interface_, UInt32& address, UInt32& mask, UInt32& gw, const ppp::string& nic) noexcept {
            ppp::string dev = ITap::FindAnyDevice();
            if (nic.size() > 0) {
                if (UnixAfx::GetLocalNetworkInterface2(interface_, address, gw, mask, nic,
                    [&dev](const ppp::string& name) noexcept {
                        return name == dev;
                    })) {
                    return true;
                }
            }
            
            char sz[256];
            if (TapLinux::GetDefaultGateway(sz, &gw)) {
                interface_ = sz;
                if (interface_ != dev) {
                    address = IPEndPoint(TapLinux::GetIPAddress(interface_).data(), 0).GetAddress();
                    mask = IPEndPoint(TapLinux::GetMaskAddress(interface_).data(), 0).GetAddress();
                    return true;
                }
            }

            address = UnixAfx::GetDefaultNetworkInterface();
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
                    boost::asio::ip::address best_interface_ip = StringToAddress(TapLinux::GetIPAddress(best_interface).data(), best_interface_ip_ec);
                    if (!(best_interface_ip_ec || best_interface_ip.is_loopback() || best_interface_ip.is_multicast() || IPEndPoint::IsInvalid(best_interface_ip))) {
                        if (best_interface_ip.is_v4()) {
                            address = htonl(best_interface_ip.to_v4().to_uint());
                        }
                    }
                }
            }

            if (address != IPEndPoint::NoneAddress) {
                interface_ = UnixAfx::GetInterfaceName(IPEndPoint(address, 0));
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
                        bool ok = (ip == ppp::net::IPEndPoint::AnyAddress && mask == mid) ||
                            (ip == ppp::net::IPEndPoint::AnyAddress && mask == ppp::net::IPEndPoint::AnyAddress) ||
                            (ip == mid && mask == mid);
                        if (!ok) {
                            return false;
                        }
                    }

                    strcpy(ifrName, interface_name);
                    return true;
                });
        }

        bool TapLinux::SetNextHop(const ppp::string& ip) noexcept {
            if (ip.empty()) {
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return false;
            }

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
            ppp::string dev = ITap::FindAnyDevice();
            return UnixAfx::GetLocalNetworkInterface(interface_, address, gw, mask,
                [&dev](const ppp::string& name) noexcept {
                    return name == dev;
                });
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

        bool TapLinux::AddRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::AddRoute(this->GetId(), address, prefix, gw);
        }

        bool TapLinux::DeleteRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::DeleteRoute(this->GetId(), address, prefix, gw);
        }

        void TapLinux::Dispose() noexcept {
            std::shared_ptr<ITap> self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            boost::asio::dispatch(*context, 
                [self, this, context]() noexcept {
                    Finalize();
                });
            ITap::Dispose();
        }

        void TapLinux::Finalize() noexcept {
            int disposed = disposed_.exchange(TRUE);
            if (disposed != TRUE) {
                SetNetifUp(false);
            }

            stl::remove_reference<decltype(tun_ssmt_sds_)>::type tun_ssmt_sds;
            if (Ssmt()) {
                SynchronizedObjectScope scope(syncobj_);
                tun_ssmt_sds = std::move(tun_ssmt_sds_);
                tun_ssmt_sds_.clear();
                tun_ssmt_fds_size_ = 0;
            }

            for (std::shared_ptr<boost::asio::posix::stream_descriptor>& sd : tun_ssmt_sds) {
                Socket::Closestream(sd);
            }
        }

        bool TapLinux::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept {
            return Output(packet.get(), packet_size);
        }

        bool TapLinux::Output(const void* packet, int packet_size) noexcept {
            // Windows virtual nics need to use Event to write to the kernel asynchronously, 
            // Linux virtual nics can directly write to the kernel ::write function,
            // Can reduce a memory allocation and replication, improve throughput efficiency.
            if (NULL == packet || packet_size < 1) {
                return false;
            }

            int disposed = disposed_.load();
            if (disposed != FALSE) {
                return false;
            }
            
            // https://man7.org/linux/man-pages/man2/write.2.html
            int tun = static_cast<int>(reinterpret_cast<std::intptr_t>(GetHandle()));
            if (Ssmt()) {
                int fd = ssmt_tls_.tun_fd_;
                if (fd != -1) {
                    tun = fd;
                }
            }

            ssize_t bytes_transferred = ::write(tun, (void*)packet, (size_t)packet_size);
            return bytes_transferred > -1;
        }

        bool TapLinux::Ssmt(const std::shared_ptr<boost::asio::io_context>& context) noexcept {
            if (NULL == context) {
                return false;
            }

            int disposed = disposed_.load();
            if (disposed != FALSE) {
                return false;
            }

            ppp::string dev = GetId();
            if (dev.empty()) {
                return false;
            }

            std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(ITap::Mtu);
            if (NULL == buffer) {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            int tun = OpenDriver(dev.data());
            if (tun == -1) {
                return false;
            }

            std::shared_ptr<boost::asio::posix::stream_descriptor> sd = make_shared_object<boost::asio::posix::stream_descriptor>(*context, tun);
            if (NULL == sd) {
                ::close(tun);
                return false;
            }

            tun_ssmt_fds_size_++;
            tun_ssmt_sds_.emplace_back(sd);

            if (Ssmt(context, tun, buffer, sd)) {
                return true;
            }

            ppp::net::Socket::Closestream(sd);
            return false;
        }

        bool TapLinux::Ssmt(const std::shared_ptr<boost::asio::io_context>& context, int fd, const std::shared_ptr<Byte>& buffer, const std::shared_ptr<boost::asio::posix::stream_descriptor>& sd) noexcept {
            int disposed = disposed_.load();
            if (disposed != FALSE) {
                return false;
            }   

            bool opened = sd->is_open();
            if (!opened) {
                return false;
            }

            std::shared_ptr<ITap> self = shared_from_this();
            sd->async_read_some(boost::asio::buffer(buffer.get(), ITap::Mtu), 
                [self, this, context, buffer, sd, fd](const boost::system::error_code& ec, std::size_t sz) noexcept {
                    if (ec != boost::system::errc::operation_canceled) {
                        int len = std::max<int>(ec ? -1 : sz, -1);
                        if (len > 0) {
                            PacketInputEventArgs e{ buffer.get(), len };
                            int* tun = &ssmt_tls_.tun_fd_;
                            *tun = fd;
                            OnInput(e);
                            *tun = -1;
                        }

                        Ssmt(context, fd, buffer, sd);
                    }
                });
            return true;
        }

        int TapLinux::GetLastHandle() noexcept {
            return ssmt_tls_.tun_fd_;
        }

        int TapLinux::SetLastHandle(int fd) noexcept {
            int* tun = &ssmt_tls_.tun_fd_;
            int old = *tun;
            *tun = fd;
            return old;
        }

        static bool TUNGETIFFF(const std::shared_ptr<boost::asio::posix::stream_descriptor>& sd, const ppp::function<bool(ifreq&, int)>& predicate) noexcept {
            if (NULL == sd) {
                return false;
            }

            if (!sd->is_open()) {
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            int tun = sd->native_handle();
            if (ioctl(tun, TUNGETIFF, &ifr) < 0) {
                return false;
            }

            return predicate(ifr, ifc_ctl_sock.sock_v4);
        }

        bool TapLinux::SetNetifUp(bool up) noexcept {
            bool ok = TUNGETIFFF(GetStream(),
                [up](ifreq& ifr, int control_fd) noexcept {
                    if (up) {
                        ifr.ifr_flags |= IFF_UP;
                    }
                    else {
                        ifr.ifr_flags &= ~IFF_UP;
                    }

                    if (ioctl(control_fd, SIOCSIFFLAGS, &ifr) < 0) {
                        return false;
                    }

                    return true;
                });

            if (!ok) {
                return false;
            }
            
            return !up || SetInterfaceMtu(ITap::Mtu);
        }

        bool TapLinux::SetInterfaceMtu(int mtu) noexcept {
            mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);

            return TUNGETIFFF(GetStream(),
                [mtu](ifreq& ifr, int control_fd) noexcept {
                    ifr.ifr_mtu = mtu;
                    if (ioctl(control_fd, SIOCSIFMTU, &ifr) < 0) {
                        return false;
                    }

                    return true;
                });
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
                    ::close(tun);
                    return NULL;
                }
            }

            bool ok = TapLinux::SetIPAddress(interface_name,
                IPEndPoint(ip, IPEndPoint::MinPort).ToAddressString(),
                IPEndPoint(mask, IPEndPoint::MinPort).ToAddressString());
            if (!ok) {
                ::close(tun);
                return NULL;
            }

            std::shared_ptr<TapLinux> tap = make_shared_object<TapLinux>(context, interface_name, reinterpret_cast<void*>(tun), ip, gw, mask, hosted_network);
            if (NULL == tap) {
                ::close(tun);
                return NULL;
            }

            tap->promisc_            = promisc;
            tap->dns_addresses_      = dns_addresses;

            ITap* my = tap.get(); 
            if (NULL != my) {
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

        static bool DeleteAddAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib, bool delete_or_add_operate) noexcept {
            if (NULL == rib || NULL == interface_name) {
                return false;
            }

            bool any = false;
            for (auto&& [_, entries] : rib->GetAllRoutes()) {
                for (auto&& entry : entries) {
                    if (delete_or_add_operate) {
                        any |= TapLinux::DeleteRoute(interface_name(entry), entry.Destination, entry.Prefix, entry.NextHop);
                    }
                    else {
                        any |= TapLinux::AddRoute(interface_name(entry), entry.Destination, entry.Prefix, entry.NextHop);
                    }
                }
            }
            return any;
        }

        static bool DeleteAddAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib, bool delete_or_add_operate) noexcept {
            if (NULL == rib) {
                return false;
            }

            bool any = false;
            for (auto&& [_, entries] : rib->GetAllRoutes()) {
                for (auto&& entry : entries) {
                    if (delete_or_add_operate) {
                        any |= TapLinux::DeleteRoute2(entry.Destination, entry.Prefix, entry.NextHop);
                    }
                    else {
                        any |= TapLinux::AddRoute2(entry.Destination, entry.Prefix, entry.NextHop);
                    }
                }
            }
            return any;
        }

        bool TapLinux::AddAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes(interface_name, rib, false);
        }

        bool TapLinux::DeleteAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes(interface_name, rib, true);
        }

        bool TapLinux::AddAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes2(rib, false);
        }

        bool TapLinux::DeleteAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes2(rib, true);
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
                        bool ok = (ip == ppp::net::IPEndPoint::AnyAddress && mask == mid) ||
                            (ip == ppp::net::IPEndPoint::AnyAddress && mask == ppp::net::IPEndPoint::AnyAddress) ||
                            (ip == mid && mask == mid);
                        if (!ok) {
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
    
#if defined(_ANDROID)
        static bool ITAP_FROM_REQUIRED(
            const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::string&                              id, 
            void*                                           tun, 
            uint32_t                                        address, 
            uint32_t                                        gw, 
            uint32_t                                        mask) noexcept 
        {
            if (tun == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            if (id.empty())
            {
                return false;
            }

            IPEndPoint ipEP(address, 0);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                return false;
            }

            IPEndPoint maskEP(address, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                return false;
            }

            IPEndPoint gwEP(address, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                return false;
            }

            return true;
        }

        std::shared_ptr<ITap> TapLinux::From(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network) noexcept
        {
            if (!ITAP_FROM_REQUIRED(context, id, tun, address, gw, mask))
            {
                return NULL;
            }

            std::shared_ptr<ppp::tap::TapLinux> linux_tap = make_shared_object<ppp::tap::TapLinux>(context, id, tun, address, gw, mask, hosted_network);
            if (NULL == linux_tap)
            {
                return NULL;
            }

            ppp::string interface_name;
            ppp::tap::ITap* tap = linux_tap.get();

            // Because it is not certain that the caller has correctly set tun to non-blocking and allows the child process to turn it off, 
            // It is being reset regardless of whether the caller has already set it or not.
            int tun_fd = static_cast<int>(reinterpret_cast<std::intptr_t>(tun));
            Socket::SetNonblocking(tun_fd, true);
            ppp::unix__::UnixAfx::set_fd_cloexec(tun_fd);

            // Get interface index of the vnic device, including the set interface name.
            int interface_index = -1;
            if (TapLinux::GetInterfaceName(tun_fd, interface_name)) 
            {
                std::size_t len = interface_name.size();
                if (len > 0)
                {
                    interface_index = TapLinux::GetInterfaceIndex(interface_name.data());
                }
            }
            
            linux_tap->IsPromisc() = promisc;
            tap->GetInterfaceIndex() = interface_index;
            
            return linux_tap;
        }
#endif
    }
}