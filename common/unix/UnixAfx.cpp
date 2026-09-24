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

        bool UnixAfx::MergeDnsAddresses(const ppp::vector<boost::asio::ip::address>& preferred, const ppp::vector<boost::asio::ip::address>& append) noexcept {
            ppp::vector<boost::asio::ip::address> merged;
            auto append_unique = [&merged](const boost::asio::ip::address& address) noexcept {
                if (IPEndPoint::IsInvalid(address) || address.is_multicast()) {
                    return;
                }
                for (const auto& current : merged) {
                    if (current == address) {
                        return;
                    }
                }
                merged.emplace_back(address);
            };

            for (const auto& address : preferred) {
                append_unique(address);
            }
            for (const auto& address : append) {
                append_unique(address);
            }

            return SetDnsAddresses(merged);
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
                if (NULLPTR == position) {
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
            struct ifaddrs* ifList = NULLPTR;
            if (getifaddrs(&ifList)) {
                return ok;
            }

            ppp::string nic_lower = ToLower(ATrim(nic));
            UInt32 invalidIPAddr = inet_addr("169.254.0.0");
            UInt32 invalidIPMask = inet_addr("255.255.0.0");
            for (struct ifaddrs* ifa = ifList; ifa != NULLPTR; ifa = ifa->ifa_next) {
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr; // ifa_dstaddr
                if (NULLPTR == sin || sin->sin_family != AF_INET) {
                    continue;
                }

                UInt32 ipAddr = sin->sin_addr.s_addr;
                if ((ipAddr & invalidIPMask) == invalidIPAddr) {
                    continue;
                }

                ipAddr = ntohl(ipAddr);
                if (ipAddr != INADDR_ANY && ipAddr != INADDR_NONE && ipAddr != INADDR_LOOPBACK) {
                    sin = (struct sockaddr_in*)ifa->ifa_netmask;
                    if (NULLPTR == sin || sin->sin_family != AF_INET) {
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
            struct ifaddrs* ifa = NULLPTR;
            if (getifaddrs(&ifa)) {
                return "";
            }

            struct ifaddrs* oifa = ifa;
            while (NULLPTR != ifa) {
                struct sockaddr* addr = ifa->ifa_addr;
                if (NULLPTR != addr) {
                    switch (addr->sa_family) {
                        case AF_INET: {
                            if (address.GetAddressFamily() != AddressFamily::InterNetwork) {
                                break;
                            }

                            struct sockaddr_in* in4_addr = (struct sockaddr_in*)addr;
                            if (in4_addr->sin_addr.s_addr != address.GetAddress()) {
                                break;
                            }

                            freeifaddrs(oifa);
                            return ifa->ifa_name;
                        }
                        case AF_INET6: {
                            if (address.GetAddressFamily() != AddressFamily::InterNetworkV6) {
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

                            freeifaddrs(oifa);
                            return ifa->ifa_name;
                        }
                    };
                }
                ifa = ifa->ifa_next;
            }

            if (NULLPTR != oifa) {
                freeifaddrs(oifa);
            }
#endif
            return "";
        }

        UInt32 UnixAfx::GetDefaultNetworkInterface(const char* address_string) noexcept {
            if (NULLPTR == address_string || *address_string == '\x0') {
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
            static ShutdownApplicationEventHandler eeh = NULLPTR;
            /** @brief Guards eeh; only ever taken in normal thread context (registration/dispatcher). */
            static std::mutex eeh_mutex;
            static std::atomic<bool> shutdown_requested = false;
            /** @brief Self-pipe write end used by the signal handler (-1 when unavailable). */
            static std::atomic<int> shutdown_pipe_write = -1;

            /*
             * Self-pipe + dispatcher thread.  The signal handler may only perform
             * async-signal-safe operations (atomic stores, write(2)); copying or
             * invoking the std::function handler from signal context is undefined
             * behaviour (the handler chain takes mutexes and posts to asio, which
             * may allocate).  A dedicated dispatcher thread performs the actual
             * invocation in normal thread context.
             */
            static std::once_flag shutdown_pipe_once;
            std::call_once(shutdown_pipe_once, []() noexcept {
                int fds[2] = { -1, -1 };
                if (::pipe(fds) != 0) {
                    return;
                }

                set_fd_cloexec(fds[0]);
                set_fd_cloexec(fds[1]);

                int oflags = ::fcntl(fds[1], F_GETFL, 0);
                if (oflags != -1) {
                    ::fcntl(fds[1], F_SETFL, oflags | O_NONBLOCK);
                }

                shutdown_pipe_write.store(fds[1], std::memory_order_release);

                std::thread([fd = fds[0]]() noexcept {
                    int signo = 0;
                    for (;;) {
                        ssize_t n = ::read(fd, &signo, sizeof(signo));
                        if (n == (ssize_t)sizeof(signo)) {
                            break;
                        }
                        if (n < 0 && errno == EINTR) {
                            continue;
                        }
                        return; /* pipe broken: give up quietly */
                    }

                    ShutdownApplicationEventHandler handler;
                    {
                        std::lock_guard<std::mutex> scope(eeh_mutex);
                        handler = std::move(eeh);
                        eeh = NULLPTR;
                    }

                    if (NULLPTR != handler) {
                        handler();
                    }
                    else {
                        ::signal(signo, SIG_DFL);
                        ::raise(signo);
                    }
                }).detach();
            });

            auto SIG_EEH =
                [](int signo) noexcept {
                    static std::atomic<bool> processed = false;

                    /*
                     * Determine whether this signal indicates an unrecoverable
                     * synchronous fault (SIGSEGV / SIGBUS / SIGFPE / SIGILL /
                     * SIGABRT / SIGTRAP / SIGSTKFLT / SIGSYS).  For such signals
                     * the kernel re-executes the faulting instruction after the
                     * handler returns; if we do not restore the default
                     * disposition and re-raise (or _exit) the process spins
                     * forever at 100 % CPU on the same fault, ignoring even
                     * SIGTERM/SIGKILL from the user (since those are also
                     * intercepted by this same handler before the fatal signal
                     * is processed).  This was the root cause of the observed
                     * "ppp 卡死 100 % CPU" behaviour where strace showed an
                     * unbroken stream of SIGSEGV / rt_sigreturn pairs.
                     */
                    bool is_fatal_fault = false;
                    switch (signo) {
#ifdef SIGSEGV
                        case SIGSEGV:   is_fatal_fault = true; break;
#endif
#ifdef SIGBUS
                        case SIGBUS:    is_fatal_fault = true; break;
#endif
#ifdef SIGFPE
                        case SIGFPE:    is_fatal_fault = true; break;
#endif
#ifdef SIGILL
                        case SIGILL:    is_fatal_fault = true; break;
#endif
#ifdef SIGABRT
                        case SIGABRT:   is_fatal_fault = true; break;
#endif
#ifdef SIGTRAP
                        case SIGTRAP:   is_fatal_fault = true; break;
#endif
#ifdef SIGSTKFLT
                        case SIGSTKFLT: is_fatal_fault = true; break;
#endif
#ifdef SIGSYS
                        case SIGSYS:    is_fatal_fault = true; break;
#endif
                        default:        break;
                    }

                    if (processed.exchange(true)) {
                        /*
                         * Re-entrant or recurring delivery.  For fatal faults
                         * we must terminate the process here; simply returning
                         * would let the kernel re-execute the broken
                         * instruction and we would loop forever.
                         */
                        if (is_fatal_fault) {
                            signal(signo, SIG_DFL);
                            raise(signo);
                            _exit(128 + signo);
                        }
                        return;
                    }

                    shutdown_requested.store(true, std::memory_order_release);

                    /*
                     * Async-signal-safe wakeup only: hand the signal number to the
                     * dispatcher thread, which invokes the shutdown handler in
                     * normal thread context.  If the self-pipe is unavailable,
                     * fall back to the legacy direct invocation.
                     */
                    int pw = shutdown_pipe_write.load(std::memory_order_acquire);
                    if (pw != -1) {
                        ssize_t ignored = ::write(pw, &signo, sizeof(signo));
                        (void)ignored;
                    }
                    else {
                        ShutdownApplicationEventHandler handler = eeh;
                        if (NULLPTR != handler) {
                            eeh = NULLPTR;
                            handler();
                        }
                        else {
                            signal(signo, SIG_DFL);
                            raise(signo);
                        }
                    }

                    /*
                     * For fatal synchronous faults the handler() above only
                     * schedules an asynchronous graceful shutdown — control
                     * still returns to the broken instruction.  Restore the
                     * default disposition and re-raise so the kernel delivers
                     * the killing blow; _exit() is the belt-and-suspenders
                     * fallback in case raise() is somehow swallowed.
                     */
                    if (is_fatal_fault) {
                        signal(signo, SIG_DFL);
                        raise(signo);
                        _exit(128 + signo);
                    }
                };

            typedef void (*__sa_handler_unix__) (int); /* __sighandler_t */

            __sa_handler_unix__ SIG_IGN_V = SIG_IGN;
            __sa_handler_unix__ SIG_EEH_V = SIG_EEH;

            {
                std::lock_guard<std::mutex> scope(eeh_mutex);
                eeh = e;
            }

            if (NULLPTR == e) {
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

        int64_t UnixAfx::Lseek(int fd, int64_t offset, int whence) noexcept {
            if (fd == -1) {
                return -1;
            }

            whence = std::max<int>(whence, SEEK_SET);

#if defined(__USE_GNU)
#if defined(SEEK_HOLE)
            whence = std::min<int>(whence, SEEK_HOLE);
#elif defined(SEEK_DATA)
            whence = std::min<int>(whence, SEEK_DATA);
#else
            whence = std::min<int>(whence, SEEK_END);
#endif
#else
            whence = std::min<int>(whence, SEEK_END);
#endif

#if defined(_MACOS)
            // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/lseek.2.html
            return lseek(fd, offset, whence);
#else
#if defined(_LARGEFILE64_SOURCE)
            // https://android.googlesource.com/platform/bionic/+/b23f193/libc/unistd/lseek64.c
            int64_t r = lseek64(fd, offset, whence);
            if (r != -1) {
                return r;
            }
#endif
            return lseek(fd, offset, whence);
#endif
        }

        namespace {
            struct LineHandler {
                ppp::function<bool(const ppp::string&)> predicate;
                ppp::string* str_output = NULLPTR;
                ppp::vector<ppp::string>* lines_output = NULLPTR;
                bool* bool_output = NULLPTR;

                bool process_line(ppp::string&& line) noexcept {
                    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
                        line.pop_back();
                    }

                    if (line.empty()) {
                        return true;
                    }

                    bool accept = !predicate || predicate(line);
                    if (!accept) {
                        return true;
                    }

                    if (str_output) {
                        *str_output += line;
                        *str_output += '\n';
                        return true;
                    }

                    if (lines_output) {
                        lines_output->emplace_back(std::move(line));
                        return true;
                    }

                    if (bool_output) {
                        *bool_output = true;
                        return true;
                    }
                    return true;
                }
            };

            void ExecuteShellCommandCore(FILE* pipe, LineHandler& handler) noexcept {
                char buffer[1024];
                ppp::string accumulated;

                while (fgets(buffer, sizeof(buffer), pipe) != NULLPTR) {
                    int len = static_cast<int>(strlen(buffer));
                    bool line_complete = false;
                    if (len > 0) {
                        char& ch = buffer[len - 1];
                        if (ch == '\n' || ch == '\r') {
                            line_complete = true;
                            ch = '\x0';
                        }
                    }

                    if (!accumulated.empty()) {
                        accumulated += buffer;
                        if (line_complete) {
                            ppp::string line;
                            line.swap(accumulated);

                            accumulated.clear();
                            handler.process_line(std::move(line));
                        }
                        continue;
                    }

                    if (!line_complete) {
                        accumulated += buffer;
                        continue;
                    }

                    handler.process_line(ppp::string(buffer));
                }

                pclose(pipe);
            }
        }

        bool UnixAfx::ExecuteShellCommand(const ppp::string& command, const ppp::function<bool(ppp::string&)>& predicate) noexcept {
            if (command.empty()) {
                return false;
            }

            FILE* pipe = popen(command.data(), "r");
            if (NULLPTR == pipe) {
                return false;
            }

            bool result = false;
            LineHandler handler;
            handler.predicate = [&predicate](const ppp::string& line) noexcept -> bool {
                ppp::string modifiable = line;
                return predicate ? predicate(modifiable) : true;
            };
            handler.bool_output = &result;

            ExecuteShellCommandCore(pipe, handler);
            return result;
        }

        ppp::string UnixAfx::ExecuteShellCommand(const ppp::string& command) noexcept {
            if (command.empty()) {
                return ppp::string();
            }

            FILE* pipe = popen(command.data(), "r");
            if (NULLPTR == pipe) {
                return ppp::string();
            }

            ppp::string output;
            LineHandler handler;
            handler.str_output = &output;

            ExecuteShellCommandCore(pipe, handler);

            if (!output.empty() && output.back() == '\n') {
                output.pop_back();
            }

            return output;
        }

        ppp::vector<ppp::string> UnixAfx::ExecuteShellCommandLines(const ppp::string& command, const ppp::function<bool(const ppp::string&)>& predicate) noexcept {
            if (command.empty()) {
                return ppp::vector<ppp::string>();
            }

            FILE* pipe = popen(command.data(), "r");
            if (NULLPTR == pipe) {
                return ppp::vector<ppp::string>();
            }

            ppp::vector<ppp::string> lines;

            LineHandler handler;
            handler.predicate = predicate;
            handler.lines_output = &lines;

            ExecuteShellCommandCore(pipe, handler);
            return lines;
        }
    }
}
