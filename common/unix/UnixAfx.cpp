// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
// https://github.com/songgao/water/issues/3#issuecomment-158704536

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/unix/UnixAfx.h>

#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/SpinLock.h>

using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;

namespace ppp {
    namespace unix__ {
        static constexpr const char* DNS_RESOLV_CONFIGURATION_FILE_PATH = "/etc/resolv.conf";

        bool UnixAfx::CloseHandle(const void* handle) noexcept {
            int fd = (int)(std::intptr_t)handle;
            if (fd == -1) {
                return false;
            }

            ::close(fd);
            return true;
        }

        bool UnixAfx::SetDnsAddresses(const ppp::vector<uint32_t>& addresses) noexcept {
            ppp::vector<ppp::string> dns_servers;
            Ipep::ToAddresses(addresses, dns_servers);

            return SetDnsAddresses(dns_servers);
        }

        bool UnixAfx::SetDnsAddresses(const ppp::vector<boost::asio::ip::address>& addresses) noexcept {
            ppp::vector<ppp::string> dns_servers;
            Ipep::AddressesTransformToStrings(addresses, dns_servers);

            return SetDnsAddresses(dns_servers);
        }

        bool UnixAfx::SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept {
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

        ppp::string UnixAfx::GetDnsResolveConfiguration() noexcept {
            return ppp::io::File::ReadAllText(DNS_RESOLV_CONFIGURATION_FILE_PATH);
        }

        bool UnixAfx::SetDnsResolveConfiguration(const ppp::string& configuration) noexcept {
            return ppp::io::File::WriteAllBytes(DNS_RESOLV_CONFIGURATION_FILE_PATH, configuration.data(), configuration.size());
        }

        int UnixAfx::GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses) noexcept {
            ppp::string in = GetDnsResolveConfiguration();
            return GetDnsAddresses(in, addresses);
        }

        int UnixAfx::GetDnsAddresses(const ppp::string& in, ppp::vector<boost::asio::ip::address>& addresses) noexcept {
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
                boost::asio::ip::address address = StringToAddress(line.data(), ec);
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

        static bool Unix_GetLocalNetworkInterface2(
            ppp::string&                                interface_,
            UInt32&                                     address,
            UInt32&                                     gw,
            UInt32&                                     mask,
            const ppp::string&                          nic,
            const ppp::function<bool(ppp::string&)>&    predicate) noexcept {

            bool ok = false;
#if (!defined(_ANDROID) || __ANDROID_API__ >= 24)
            struct ifaddrs* ifList = NULL;
            if (getifaddrs(&ifList)) {
                return ok;
            }

            ppp::string nic_lower = ToLower(ATrim(nic));
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

                    if (strncmp(ifa->ifa_name, "lo", 2) == 0) {
                        continue;
                    }

                    interface_ = ifa->ifa_name;
                    if (predicate) {
                        if (predicate(interface_)) {
                            continue;
                        }
                    }

                    if (nic.size() > 0) {
                        ppp::string interface_lower = ToLower(ATrim(interface_));
                        if (interface_lower != nic_lower && interface_lower.find(nic_lower) == std::string::npos) {
                            continue;
                        }
                    }

                    ok = true;
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
            return ok;
        }

        bool UnixAfx::GetLocalNetworkInterface2(ppp::string& ifrName, UInt32& address, UInt32& gw, UInt32& mask, const ppp::string& nic, const ppp::function<bool(ppp::string&)>& predicate) noexcept {
            if (nic.empty()) {
                return false;
            }

            return Unix_GetLocalNetworkInterface2(ifrName, address, gw, mask, nic, predicate);
        }

        bool UnixAfx::GetLocalNetworkInterface(ppp::string& ifrName, UInt32& address, UInt32& gw, UInt32& mask, const ppp::function<bool(ppp::string&)>& predicate) noexcept {
            ppp::string nic;
            return Unix_GetLocalNetworkInterface2(ifrName, address, gw, mask, nic, predicate);
        }

        ppp::string UnixAfx::GetInterfaceName(const IPEndPoint& address) noexcept {
#if (!defined(_ANDROID) || __ANDROID_API__ >= 24)
            struct ifaddrs* ifa = NULL;
            if (getifaddrs(&ifa)) {
                return "";
            }

            struct ifaddrs* oifa = ifa;
            while (NULL != ifa) {
                struct sockaddr* addr = ifa->ifa_addr;
                if (NULL != addr) {
                    switch (addr->sa_family) {
                        case AF_INET: {
                            if (address.GetAddressFamily() != AddressFamily::InterNetwork) {
                                break;
                            }

                            struct sockaddr_in* in4_addr = (struct sockaddr_in*)addr;
                            if (in4_addr->sin_addr.s_addr != address.GetAddress()) {
                                break;
                            }
                            return ifa->ifa_name;
                        }
                        case AF_INET6: {
                            if (address.GetAddressFamily() != AddressFamily::InterNetwork) {
                                break;
                            }

                            struct sockaddr_in6* in6_addr = (struct sockaddr_in6*)addr; {
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

        UInt32 UnixAfx::GetDefaultNetworkInterface(const char* address_string) noexcept {
            if (NULL == address_string || *address_string == '\x0') {
                return IPEndPoint::NoneAddress;
            }

            uint32_t ip = inet_addr(address_string);
            return ppp::net::Socket::GetBestInterfaceIP(ip);
        }

        UInt32 UnixAfx::GetDefaultNetworkInterface() noexcept {
            std::unordered_map<UInt32, int> bests;
            for (const char* address_string : PPP_PUBLIC_DNS_SERVER_LIST) {
                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(address_string, ec);
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

        bool UnixAfx::set_fd_cloexec(int fd) noexcept {
            if (fd == -1) {
                return false;
            }
            
            int flags = fcntl(fd, F_GETFD, 0);
            if (flags == -1) {
                return false;
            }

            flags |= FD_CLOEXEC;
            if (fcntl(fd, F_SETFD, flags) < 0) {
                return false;
            }

            return true;
        }

        bool UnixAfx::AddShutdownApplicationEventHandler(ShutdownApplicationEventHandler e) noexcept {
            static ShutdownApplicationEventHandler eeh = NULL;

            auto SIG_EEH = 
                [](int signo) noexcept -> void {
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

            typedef void (*__sa_handler_unix__) (int); /* __sighandler_t */

            __sa_handler_unix__ SIG_IGN_V = SIG_IGN;
            __sa_handler_unix__ SIG_EEH_V = SIG_EEH;

            if (NULL != e) {
                eeh = e;
            }
            else {
                eeh.reset();
                SIG_EEH_V = SIG_DFL;
                SIG_IGN_V = SIG_DFL;
            }

            /* retrieve old and set new handlers */
            /* restore prevouis signal actions   */
#ifdef _ANDROID
            signal(35, SIG_IGN_V); // FDSCAN(SI_QUEUE)
#endif

#ifdef SIGPIPE
            signal(SIGPIPE, SIG_IGN_V);
#endif

#ifdef SIGHUP
            signal(SIGHUP, SIG_IGN_V);
#endif

#ifdef SIGINT
            signal(SIGINT, SIG_EEH_V);
#endif

#ifdef SIGTERM
            signal(SIGTERM, SIG_EEH_V);
#endif

#ifdef SIGSYS
            signal(SIGSYS, SIG_EEH_V);
#endif

#ifdef SIGIOT
            signal(SIGIOT, SIG_EEH_V);
#endif

#ifdef SIGUSR1
            signal(SIGUSR1, SIG_EEH_V);
#endif

#ifdef SIGUSR2
            signal(SIGUSR2, SIG_EEH_V);
#endif

#ifdef SIGXCPU
            signal(SIGXCPU, SIG_EEH_V);
#endif

#ifdef SIGXFSZ
            signal(SIGXFSZ, SIG_EEH_V);
#endif

#ifdef SIGTRAP
            signal(SIGTRAP, SIG_EEH_V);   // 调试陷阱
#endif

#ifdef SIGBUS
            signal(SIGBUS, SIG_EEH_V);    // 总线错误(常见于结构对齐问题)
#endif

#ifdef SIGQUIT
            signal(SIGQUIT, SIG_EEH_V);   // CTRL+\退出终端
#endif

            /* Some specific cpu architecture platforms do not support this signal macro, */
            /* Such as mips and mips64 instruction set cpu architecture platforms.        */
#ifdef SIGSTKFLT
            signal(SIGSTKFLT, SIG_EEH_V); // 进程堆栈崩坏
#endif

#ifdef SIGSEGV
            signal(SIGSEGV, SIG_EEH_V);   // 段错误(试图访问无效地址)
#endif

#ifdef SIGFPE
            signal(SIGFPE, SIG_EEH_V);    // 致命的算术运算问题(常见于试图除以零或者FPU/IEEE-754浮点数问题)
#endif

#ifdef SIGABRT
            signal(SIGABRT, SIG_EEH_V);   // 程式被中止执行(常见于三方库或固有程式遭遇一般性错误执行abort()强行关闭主板程式)
#endif

#ifdef SIGILL
            signal(SIGILL, SIG_EEH_V);    // 非法硬件指令(CPU/RING 0 ABORT)
#endif
            return true;
        }
    }
}