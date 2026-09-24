// https://android.googlesource.com/platform/frameworks/base.git/+/android-4.3_r2.1/services/jni/com_android_server_connectivity_Vpn.cpp
// https://android.googlesource.com/platform/system/core/+/master/libnetutils/ifc_utils.c
// https://www.androidos.net.cn/android/6.0.1_r16/xref/bionic/libc/bionic/if_nametoindex.c
// https://android.googlesource.com/platform/frameworks/native/+/master/include/android/multinetwork.h
// https://android.googlesource.com/platform/cts/+/fed9991/tests/tests/net/jni/NativeMultinetworkJni.c

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <ppp/diagnostics/DatapathPerfJson.h>
#include "TapGsoLedger.h"
#include "TapGsoMergeabilityAnalyzer.h"
#include "TapVnetCodec.h"
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#if defined(_ANDROID)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#else
#include <net/if.h>
#include <net/route.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <string>
#include <chrono>
#include <limits>
#include <exception>

#include <linux/ppp/tap/TapLinux.h>
#include <ppp/ipv6/IPv6Packet.h>

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
using ppp::telemetry::Level;

namespace ppp {
    namespace tap {
        namespace {
            template <size_t N>
            struct NetlinkRequest final {
                struct nlmsghdr header;
                Byte payload[N];
            };

            static bool IsSafeShellToken(const ppp::string& value) noexcept {
                if (value.empty()) {
                    return false;
                }

                for (char ch : value) {
                    bool ok =
                        (ch >= 'a' && ch <= 'z') ||
                        (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') ||
                        ch == ':' || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '/';
                    if (!ok) {
                        return false;
                    }
                }

                return true;
            }

            static bool IsSafeInterfaceName(const ppp::string& value) noexcept {
                if (value.empty() || value.size() >= IFNAMSIZ) {
                    return false;
                }

                for (char ch : value) {
                    bool ok =
                        (ch >= 'a' && ch <= 'z') ||
                        (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') ||
                        ch == ':' || ch == '.' || ch == '_' || ch == '-';
                    if (!ok) {
                        return false;
                    }
                }

                return true;
            }

            static bool CopyInterfaceName(ifreq& ifr, const ppp::string& ifrName) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    return false;
                }

                memset(&ifr, 0, sizeof(ifr));
                memcpy(ifr.ifr_name, ifrName.data(), ifrName.size());
                ifr.ifr_name[ifrName.size()] = '\x0';
                return true;
            }

            static bool TryRouteExists(
                const ppp::string& interface_id,
                UInt32 address,
                int prefix,
                UInt32 gateway,
                bool& exists) noexcept {
                if (prefix < 0 || prefix > 32) {
                    prefix = 32;
                }
                const uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                uint32_t ignored_gateway = 0;
                bool query_succeeded = false;
                exists = TapLinux::GetDefaultGateway(
                    &ignored_gateway,
                    [&interface_id, address, gateway, mask](const char* interface_name,
                        uint32_t ip, uint32_t gw, uint32_t route_mask, int) noexcept {
                        return (interface_id.empty() || interface_id == interface_name) &&
                            ip == address && gw == gateway && route_mask == mask;
                    },
                    &query_succeeded);
                return query_succeeded;
            }

            static int GetInterfaceIndexByName(const ppp::string& ifrName) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return -1;
                }

                int sock_v4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (sock_v4 == -1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return -1;
                }

                struct ifreq ifr;
                if (!CopyInterfaceName(ifr, ifrName)) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxInterfaceNameTooLong);
                    return -1;
                }

                if (ioctl(sock_v4, SIOGIFINDEX, &ifr) < 0) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    return -1;
                }

                ::close(sock_v4);
                return ifr.ifr_ifindex;
            }

            static bool ParseIPv6Address(const ppp::string& address, struct in6_addr& out) noexcept {
                if (!IsSafeShellToken(address)) {
                    return false;
                }

                memset(&out, 0, sizeof(out));
                return inet_pton(AF_INET6, address.data(), &out) == 1;
            }

            static bool AppendNetlinkAttribute(struct nlmsghdr& header, size_t capacity, int type, const void* data, size_t length) noexcept {
                size_t attr_len = RTA_LENGTH(length);
                size_t aligned_msg_len = NLMSG_ALIGN(header.nlmsg_len);
                size_t next_len = aligned_msg_len + RTA_ALIGN(attr_len);
                if (NULLPTR == data || length < 1 || next_len > capacity) {
                    return false;
                }

                struct rtattr* attr = reinterpret_cast<struct rtattr*>(reinterpret_cast<Byte*>(&header) + aligned_msg_len);
                attr->rta_type = static_cast<unsigned short>(type);
                attr->rta_len = static_cast<unsigned short>(attr_len);
                memcpy(RTA_DATA(attr), data, length);
                header.nlmsg_len = static_cast<unsigned int>(next_len);
                return true;
            }

            static int SendNetlinkRequestStatus(struct nlmsghdr& header, ppp::diagnostics::ErrorCode failure_code) noexcept {
                int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
                if (fd < 0) {
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return errno > 0 ? errno : EIO;
                }

                struct sockaddr_nl local_addr;
                memset(&local_addr, 0, sizeof(local_addr));
                local_addr.nl_family = AF_NETLINK;
                if (bind(fd, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
                    int error = errno;
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return error > 0 ? error : EIO;
                }

                struct timeval timeout;
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) < 0) {
                    int error = errno;
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return error > 0 ? error : EIO;
                }

                header.nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
                header.nlmsg_pid = 0;
                header.nlmsg_seq = static_cast<unsigned int>(std::chrono::steady_clock::now().time_since_epoch().count());

                struct sockaddr_nl kernel_addr;
                memset(&kernel_addr, 0, sizeof(kernel_addr));
                kernel_addr.nl_family = AF_NETLINK;

                struct iovec iov;
                memset(&iov, 0, sizeof(iov));
                iov.iov_base = &header;
                iov.iov_len = header.nlmsg_len;

                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));
                msg.msg_name = &kernel_addr;
                msg.msg_namelen = sizeof(kernel_addr);
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                if (sendmsg(fd, &msg, 0) < 0) {
                    int error = errno;
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return error > 0 ? error : EIO;
                }

                Byte buffer[4096];
                for (;;) {
                    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
                    if (received < 0) {
                        if (errno == EINTR) {
                            continue;
                        }

                        int error = errno;
                        ::close(fd);
                        ppp::diagnostics::SetLastErrorCode(failure_code);
                        return error > 0 ? error : EIO;
                    }
                    if (received == 0) {
                        ::close(fd);
                        ppp::diagnostics::SetLastErrorCode(failure_code);
                        return EIO;
                    }

                    int remaining = static_cast<int>(received);
                    for (struct nlmsghdr* response = reinterpret_cast<struct nlmsghdr*>(buffer);
                        NLMSG_OK(response, remaining);
                        response = NLMSG_NEXT(response, remaining)) {
                        if (response->nlmsg_seq != header.nlmsg_seq) {
                            continue;
                        }

                        if (response->nlmsg_type == NLMSG_ERROR) {
                            if (response->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                                ::close(fd);
                                ppp::diagnostics::SetLastErrorCode(failure_code);
                                return EIO;
                            }

                            struct nlmsgerr* error = reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(response));
                            int error_code = error->error;
                            ::close(fd);
                            return error_code < 0 ? -error_code : error_code;
                        }

                        if (response->nlmsg_type == NLMSG_DONE) {
                            ::close(fd);
                            return 0;
                        }
                    }
                }
            }

            static bool SendNetlinkRequest(struct nlmsghdr& header, ppp::diagnostics::ErrorCode failure_code, bool missing_ok) noexcept {
                int error = SendNetlinkRequestStatus(header, failure_code);
                if (error == 0 || (missing_ok && (error == ENOENT || error == ESRCH))) {
                    return true;
                }

                ppp::diagnostics::SetLastErrorCode(failure_code);
                return false;
            }

            static bool DeleteIPv6AddressByNetlink(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return false;
                }

                struct in6_addr address;
                if (!ParseIPv6Address(addressIP, address)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
                request.header.nlmsg_type = RTM_DELADDR;

                struct ifaddrmsg* message = reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(&request.header));
                message->ifa_family = AF_INET6;
                message->ifa_prefixlen = static_cast<unsigned char>(prefix_length);
                message->ifa_scope = RT_SCOPE_UNIVERSE;
                message->ifa_index = static_cast<unsigned int>(interface_index);

                if (!AppendNetlinkAttribute(request.header, sizeof(request), IFA_LOCAL, &address, sizeof(address))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                    return false;
                }
                if (!AppendNetlinkAttribute(request.header, sizeof(request), IFA_ADDRESS, &address, sizeof(address))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                    return false;
                }

                return SendNetlinkRequest(request.header, ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed, false);
            }

            static bool DeleteIPv6RouteByNetlink(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return false;
                }

                bool is_default_route = addressIP == "::" && prefix_length == 0;
                struct in6_addr destination;
                if (!ParseIPv6Address(addressIP, destination)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                struct in6_addr gateway;
                bool has_gateway = !gw.empty();
                if (has_gateway && !ParseIPv6Address(gw, gateway)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
                request.header.nlmsg_type = RTM_DELROUTE;

                struct rtmsg* message = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(&request.header));
                message->rtm_family = AF_INET6;
                message->rtm_dst_len = static_cast<unsigned char>(is_default_route ? 0 : prefix_length);
                message->rtm_table = RT_TABLE_MAIN;
                message->rtm_protocol = RTPROT_UNSPEC;
                message->rtm_scope = RT_SCOPE_UNIVERSE;
                message->rtm_type = RTN_UNICAST;

                if (!is_default_route && !AppendNetlinkAttribute(request.header, sizeof(request), RTA_DST, &destination, sizeof(destination))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }
                if (has_gateway && !AppendNetlinkAttribute(request.header, sizeof(request), RTA_GATEWAY, &gateway, sizeof(gateway))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }
                if (!AppendNetlinkAttribute(request.header, sizeof(request), RTA_OIF, &interface_index, sizeof(interface_index))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }

                return SendNetlinkRequest(request.header, ppp::diagnostics::ErrorCode::RouteDeleteFailed, false);
            }

            static bool SetIPv6NeighborProxyByNetlink(const ppp::string& ifrName, const ppp::string& addressIP, bool add) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return false;
                }

                struct in6_addr address;
                if (!ParseIPv6Address(addressIP, address)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
                request.header.nlmsg_type = add ? RTM_NEWNEIGH : RTM_DELNEIGH;
                if (add) {
                    request.header.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE;
                }

                struct ndmsg* message = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(&request.header));
                message->ndm_family = AF_INET6;
                message->ndm_ifindex = interface_index;
                message->ndm_state = add ? NUD_PERMANENT : 0;
                message->ndm_flags = NTF_PROXY;

                if (!AppendNetlinkAttribute(request.header, sizeof(request), NDA_DST, &address, sizeof(address))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                return SendNetlinkRequest(request.header, ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed, false);
            }

            static bool QueryIPv6PermanentNeighborByNetlink(int interface_index, const struct in6_addr& address, bool& exact_exists) noexcept {
                exact_exists = false;

                int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
                if (fd < 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                struct sockaddr_nl local_addr;
                memset(&local_addr, 0, sizeof(local_addr));
                local_addr.nl_family = AF_NETLINK;
                if (bind(fd, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                struct timeval timeout;
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) < 0) {
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                NetlinkRequest<64> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
                request.header.nlmsg_type = RTM_GETNEIGH;
                request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
                request.header.nlmsg_seq = static_cast<unsigned int>(std::chrono::steady_clock::now().time_since_epoch().count());

                struct ndmsg* query = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(&request.header));
                query->ndm_family = AF_INET6;
                query->ndm_ifindex = interface_index;

                struct sockaddr_nl kernel_addr;
                memset(&kernel_addr, 0, sizeof(kernel_addr));
                kernel_addr.nl_family = AF_NETLINK;

                struct iovec iov;
                memset(&iov, 0, sizeof(iov));
                iov.iov_base = &request.header;
                iov.iov_len = request.header.nlmsg_len;

                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));
                msg.msg_name = &kernel_addr;
                msg.msg_namelen = sizeof(kernel_addr);
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                if (sendmsg(fd, &msg, 0) < 0) {
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                Byte buffer[8192];
                for (;;) {
                    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
                    if (received < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        ::close(fd);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                        return false;
                    }
                    if (received == 0) {
                        ::close(fd);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                        return false;
                    }

                    int remaining = static_cast<int>(received);
                    for (struct nlmsghdr* response = reinterpret_cast<struct nlmsghdr*>(buffer);
                        NLMSG_OK(response, remaining);
                        response = NLMSG_NEXT(response, remaining)) {
                        if (response->nlmsg_seq != request.header.nlmsg_seq) {
                            continue;
                        }
                        if (response->nlmsg_type == NLMSG_DONE) {
                            ::close(fd);
                            return true;
                        }
                        if (response->nlmsg_type == NLMSG_ERROR) {
                            ::close(fd);
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                            return false;
                        }
                        if (response->nlmsg_type != RTM_NEWNEIGH || response->nlmsg_len < NLMSG_LENGTH(sizeof(struct ndmsg))) {
                            continue;
                        }

                        struct ndmsg* neighbor = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(response));
                        if (neighbor->ndm_family != AF_INET6 || neighbor->ndm_ifindex != interface_index ||
                            (neighbor->ndm_flags & NTF_PROXY) != 0 || (neighbor->ndm_state & NUD_PERMANENT) == 0) {
                            continue;
                        }

                        bool destination_matches = false;
                        int attributes_length = NLMSG_PAYLOAD(response, sizeof(struct ndmsg));
                        struct rtattr* attribute = reinterpret_cast<struct rtattr*>(
                            reinterpret_cast<Byte*>(neighbor) + NLMSG_ALIGN(sizeof(struct ndmsg)));
                        for (; RTA_OK(attribute, attributes_length); attribute = RTA_NEXT(attribute, attributes_length)) {
                            if (attribute->rta_type == NDA_DST && RTA_PAYLOAD(attribute) == sizeof(address)) {
                                destination_matches = memcmp(RTA_DATA(attribute), &address, sizeof(address)) == 0;
                            }
                        }

                        if (destination_matches) {
                            exact_exists = true;
                            ::close(fd);
                            return true;
                        }
                    }
                }
            }

            static TapLinux::NeighborMutationResult AddIPv6PermanentNeighborByNetlink(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return TapLinux::NeighborMutationResult::Failed;
                }

                struct in6_addr address;
                if (!ParseIPv6Address(addressIP, address)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return TapLinux::NeighborMutationResult::Failed;
                }

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
                request.header.nlmsg_type = RTM_NEWNEIGH;
                request.header.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;

                struct ndmsg* message = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(&request.header));
                message->ndm_family = AF_INET6;
                message->ndm_ifindex = interface_index;
                message->ndm_state = NUD_PERMANENT;
                message->ndm_flags = 0;

                const Byte dummy_lladdr[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
                if (!AppendNetlinkAttribute(request.header, sizeof(request), NDA_DST, &address, sizeof(address)) ||
                    !AppendNetlinkAttribute(request.header, sizeof(request), NDA_LLADDR, dummy_lladdr, sizeof(dummy_lladdr))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return TapLinux::NeighborMutationResult::Failed;
                }

                int error = SendNetlinkRequestStatus(request.header, ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                bool query_succeeded = false;
                bool exact_exists = false;
                if (error == EEXIST) {
                    query_succeeded = QueryIPv6PermanentNeighborByNetlink(interface_index, address, exact_exists);
                }

                TapLinux::NeighborMutationResult result = TapLinux::ClassifyPermanentNeighborAddResult(error, query_succeeded, exact_exists);
                if (result == TapLinux::NeighborMutationResult::Failed) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                }
                return result;
            }

            static bool DeleteIPv6PermanentNeighborByNetlink(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return false;
                }

                struct in6_addr address;
                if (!ParseIPv6Address(addressIP, address)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
                request.header.nlmsg_type = RTM_DELNEIGH;

                struct ndmsg* message = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(&request.header));
                message->ndm_family = AF_INET6;
                message->ndm_ifindex = interface_index;

                if (!AppendNetlinkAttribute(request.header, sizeof(request), NDA_DST, &address, sizeof(address))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                return SendNetlinkRequest(request.header, ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed, true);
            }

            static ppp::string GetProxyNdpPath(const ppp::string& ifrName) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    return ppp::string();
                }

                return "/proc/sys/net/ipv6/conf/" + ifrName + "/proxy_ndp";
            }

            static bool ReadProxyNdpState(const ppp::string& ifrName, bool& enabled) noexcept {
                enabled = false;

                ppp::string path = GetProxyNdpPath(ifrName);
                if (path.empty()) {
                    return false;
                }

                ppp::string value = ppp::io::File::ReadAllText(path.data());
                value = LTrim(RTrim(value));
                if (value.empty()) {
                    return false;
                }

                enabled = atoi(value.c_str()) > 0;
                return true;
            }

            static bool WriteProxyNdpState(const ppp::string& ifrName, bool enabled) noexcept {
                ppp::string path = GetProxyNdpPath(ifrName);
                if (path.empty()) {
                    return false;
                }

                const char* value = enabled ? "1\n" : "0\n";
                int fd = ::open(path.data(), O_WRONLY | O_CLOEXEC);
                if (fd < 0) {
                    return false;
                }

                ssize_t written = ::write(fd, value, 2);
                int close_status = ::close(fd);
                return written == 2 && close_status == 0;
            }

            static bool SetInterfaceMtuByName(const ppp::string& ifrName, int mtu) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                int sock_v4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (sock_v4 == -1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return false;
                }

                struct ifreq ifr;
                if (!CopyInterfaceName(ifr, ifrName)) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxInterfaceNameTooLong);
                    return false;
                }

                ifr.ifr_mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);
                if (ioctl(sock_v4, SIOCSIFMTU, &ifr) < 0) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelMtuConfigureFailed);
                    return false;
                }

                ::close(sock_v4);
                return true;
            }
        }

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
        static thread_local bool                tun_gso_force_bare_ = false;
        static bool                             ifc_ctl_sock_compatible_route = false;

        static bool TapGsoMergeRequested() noexcept {
            const char* disable = std::getenv("OPENPPP2_TAP_GSO_MERGE_DISABLE");
            if (disable != NULLPTR && *disable == '1') return false;
            const char* enable = std::getenv("OPENPPP2_TAP_GSO_MERGE");
            return enable != NULLPTR && *enable == '1';
        }

        static bool TapNdiTsoRequested() noexcept {
            const char* enable = std::getenv("OPENPPP2_XTCP_NDI_TSO_TX");
            return enable != NULLPTR && enable[0] == '1' && enable[1] == '\0';
        }

        TapLinux::TapLinux(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network)
            : ITap(context, dev, tun, address, gw, mask, hosted_network)
            , promisc_(false)
            , disposed_(FALSE)
            , gso_hold_timer_(*context)
            , gso_coalescer_([this](const uint8_t* frame, size_t frame_size) noexcept { return WriteGsoFrameLocked(frame, frame_size); }) {

        }

        TapLinux::~TapLinux() noexcept {
            Finalize();
        }

        bool TapLinux::GetRuntimeStats(ppp::tap::TapRuntimeStats& stats) const noexcept {
            std::lock_guard<std::mutex> lock(gso_mutex_);
            stats.vnet_header = vnet_header_;
            stats.gso_merge_active = gso_merge_active_;
            stats.tx_gso_supported = disposed_.load(std::memory_order_acquire) == FALSE &&
                tun_write_failed_.load(std::memory_order_acquire) == FALSE &&
                vnet_header_ && tx_gso_supported_ && !gso_ssmt_disabled_;
            stats.direct_gso_packets = direct_gso_packets_.load(std::memory_order_relaxed);
            stats.direct_gso_bytes = direct_gso_bytes_.load(std::memory_order_relaxed);
            stats.direct_gso_rejected = direct_gso_rejected_.load(std::memory_order_relaxed);
            return true;
        }

        int TapLinux::OpenDriver(const char* ifrName) noexcept {
            if (NULLPTR == ifrName || *ifrName == '\x0') {
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
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
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

            bool request_gso = !tun_gso_force_bare_ &&
                (TapGsoMergeRequested() || TapNdiTsoRequested());
            if (request_gso) {
                unsigned int features = 0;
                request_gso = ioctl(tun, TUNGETFEATURES, &features) == 0 && (features & IFF_VNET_HDR) != 0;
            }

            bool fails = false;
#if defined(IFF_MULTI_QUEUE)
#if defined(IFF_ATTACH_QUEUE)
            ifr.ifr_flags = IFF_ATTACH_QUEUE; /* IFF_DETACH_QUEUE */
            ioctl(tun, TUNSETQUEUE, &ifr);
#endif

            ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | (request_gso ? IFF_VNET_HDR : 0);
            fails = ioctl(tun, TUNSETIFF, &ifr) < 0;

            if (fails) {
                ifr.ifr_flags = IFF_TUN | IFF_NO_PI | (request_gso ? IFF_VNET_HDR : 0);
                fails = ioctl(tun, TUNSETIFF, &ifr) < 0;
            }
#else
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI | (request_gso ? IFF_VNET_HDR : 0);
            fails = ioctl(tun, TUNSETIFF, &ifr) < 0;
#endif

            if (fails) {
                ::close(tun);
                if (request_gso) {
                    tun_gso_force_bare_ = true;
                    const int bare_tun = OpenDriver(ifrName);
                    tun_gso_force_bare_ = false;
                    return bare_tun;
                }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return -1;
            }
            else {
                if (request_gso) {
                    int header_size = static_cast<int>(sizeof(virtio_net_hdr));
                    int header_readback = 0;
                    const bool configured =
                        ioctl(tun, TUNSETVNETHDRSZ, &header_size) == 0 &&
                        ioctl(tun, TUNGETVNETHDRSZ, &header_readback) == 0 &&
                        header_readback == static_cast<int>(sizeof(virtio_net_hdr)) &&
                        ioctl(tun, TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO4) == 0;
                    if (!configured) {
                        ::close(tun);
                        tun_gso_force_bare_ = true;
                        const int bare_tun = OpenDriver(ifrName);
                        tun_gso_force_bare_ = false;
                        return bare_tun;
                    }
                }
#if defined(IFF_ATTACH_QUEUE)
                ifr.ifr_flags = IFF_ATTACH_QUEUE; /* IFF_DETACH_QUEUE */
                ioctl(tun, TUNSETQUEUE, &ifr);
#endif
                ppp::telemetry::Log(Level::kInfo, "tap", "TUN device opened: %s", ifrName);
                ppp::telemetry::Count("tap.open", 1);
                ppp::telemetry::Gauge("tap.active_fds", (int64_t)1);
                return tun;
            }
        }

        void TapLinux::CompatibleRoute(bool compatible) noexcept {
            ifc_ctl_sock_compatible_route = compatible;
        }

        bool TapLinux::SetIPAddress(const ppp::string& ifrName, const ppp::string& addressIP, const ppp::string& mask) noexcept {
            if (ifrName.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, ifrName.data());

            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_addr);
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = inet_addr(addressIP.data());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCSIFADDR, &ifr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
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
            if (ioctl(ifc_ctl_sock.sock_v4, SIOCSIFNETMASK, &ifr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                return false;
            }

            return true;
        }

        // NOTE: ExecuteIpCommand() calls system() which performs a blocking fork()+exec().
        // The remaining IPv6 callers are add/replace flows whose iproute2 semantics are
        // more subtle than cleanup operations.  Cleanup, NDP proxy and MTU paths below use
        // netlink/procfs/ioctl instead of shelling out.
        static bool ExecuteIpCommand(const ppp::string& command, ppp::diagnostics::ErrorCode failure_code) noexcept {
            if (command.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxCommandEmpty);
                return false;
            }

            int status = system(command.data());
            if (status != 0) {
                ppp::diagnostics::SetLastErrorCode(failure_code);
                return false;
            }

            return true;
        }

        bool TapLinux::SetIPv6Address(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.address.set");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            char command[1200];
            snprintf(command, sizeof(command), "ip -6 addr replace %s/%d dev %s > /dev/null 2>&1", addressIP.data(), std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length)), ifrName.data());
            auto started_at = std::chrono::steady_clock::now();
            bool ok = ExecuteIpCommand(command, ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("tap.ipv6.address.set.us", elapsed);
            }
            return ok;
        }

        bool TapLinux::SetMtu(const ppp::string& ifrName, int mtu) noexcept {
            ppp::telemetry::SpanScope span("tap.mtu.set");

            auto started_at = std::chrono::steady_clock::now();
            bool ok = SetInterfaceMtuByName(ifrName, mtu);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.mtu.set.us", elapsed);
            if (ok) {
                ppp::telemetry::Count("tap.mtu.set", 1);
            }
            return ok;
        }

        bool TapLinux::DeleteIPv6Address(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.address.delete");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = DeleteIPv6AddressByNetlink(ifrName, addressIP, prefix_length);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.address.delete.us", elapsed);
            if (ok) {
                ppp::telemetry::Count("tap.ipv6.address.delete", 1);
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 address delete: %s/%d", addressIP.data(), prefix_length);
            }
            return ok;
        }

        bool TapLinux::AddRoute6(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.route.add");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP) || (!gw.empty() && !IsSafeShellToken(gw))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            char command[1200];
            if (gw.empty()) {
                if (addressIP == "::" && prefix_length == 0) {
                    snprintf(command, sizeof(command), "ip -6 route replace default dev %s metric 1 > /dev/null 2>&1", ifrName.data());
                }
                else {
                    snprintf(command, sizeof(command), "ip -6 route replace %s/%d dev %s > /dev/null 2>&1", addressIP.data(), std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length)), ifrName.data());
                }
            }
            else {
                if (addressIP == "::" && prefix_length == 0) {
                    snprintf(command, sizeof(command), "ip -6 route replace default via %s dev %s onlink > /dev/null 2>&1", gw.data(), ifrName.data());
                }
                else {
                    snprintf(command, sizeof(command), "ip -6 route replace %s/%d via %s dev %s onlink > /dev/null 2>&1", addressIP.data(), std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length)), gw.data(), ifrName.data());
                }
            }
            auto started_at = std::chrono::steady_clock::now();
            bool ok = ExecuteIpCommand(command, ppp::diagnostics::ErrorCode::RouteReplaceFailed);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 route add: %s/%d", addressIP.data(), prefix_length);
                ppp::telemetry::Count("tap.ipv6.route.add", 1);
                ppp::telemetry::Histogram("tap.ipv6.route.add.us", elapsed);
                ppp::telemetry::Gauge("tap.ipv6_routes", (int64_t)1);
            }
            return ok;
        }

        bool TapLinux::DeleteRoute6(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.route.delete");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP) || (!gw.empty() && !IsSafeShellToken(gw))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = DeleteIPv6RouteByNetlink(ifrName, addressIP, prefix_length, gw);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.route.delete.us", elapsed);
            if (ok) {
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 route delete: %s/%d", addressIP.data(), prefix_length);
                ppp::telemetry::Count("tap.ipv6.route.delete", 1);
            }
            return ok;
        }

        bool TapLinux::EnableIPv6NeighborProxy(const ppp::string& ifrName) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.proxy.enable");
            if (!IsSafeShellToken(ifrName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = WriteProxyNdpState(ifrName, true);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.neighbor.proxy.enable.us", elapsed);
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        bool TapLinux::QueryIPv6NeighborProxy(const ppp::string& ifrName, bool& enabled) noexcept {
            enabled = false;
            if (!IsSafeShellToken(ifrName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }

            if (!ReadProxyNdpState(ifrName, enabled)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }
            return true;
        }

        bool TapLinux::DisableIPv6NeighborProxy(const ppp::string& ifrName) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.proxy.disable");
            if (!IsSafeShellToken(ifrName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = WriteProxyNdpState(ifrName, false);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.neighbor.proxy.disable.us", elapsed);
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        bool TapLinux::AddIPv6NeighborProxy(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.add");
            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = SetIPv6NeighborProxyByNetlink(ifrName, addressIP, true);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 neighbor add: %s", addressIP.data());
                ppp::telemetry::Count("tap.ipv6.neighbor.add", 1);
                ppp::telemetry::Histogram("tap.ipv6.neighbor.add.us", elapsed);
                ppp::telemetry::Gauge("tap.neighbor_proxies", (int64_t)1);
            }
            else {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        bool TapLinux::DeleteIPv6NeighborProxy(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.delete");
            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = SetIPv6NeighborProxyByNetlink(ifrName, addressIP, false);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 neighbor delete: %s", addressIP.data());
                ppp::telemetry::Histogram("tap.ipv6.neighbor.delete.us", elapsed);
            }
            else {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        TapLinux::NeighborMutationResult TapLinux::AddIPv6PermanentNeighbor(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.permanent.add");
            if (!IsSafeInterfaceName(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return NeighborMutationResult::Failed;
            }

            NeighborMutationResult result = AddIPv6PermanentNeighborByNetlink(ifrName, addressIP);
            if (result == NeighborMutationResult::Changed) {
                ppp::telemetry::Log(Level::kDebug, "tap", "permanent ipv6 neighbor added: %s", addressIP.data());
            }
            return result;
        }

        bool TapLinux::DeleteIPv6PermanentNeighbor(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.permanent.delete");
            if (!IsSafeInterfaceName(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }

            bool ok = DeleteIPv6PermanentNeighborByNetlink(ifrName, addressIP);
            if (ok) {
                ppp::telemetry::Log(Level::kDebug, "tap", "permanent ipv6 neighbor deleted: %s", addressIP.data());
            }
            return ok;
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
                rt.rt_dev = NULLPTR;
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
                ppp::diagnostics::SetLastErrorCode(action_add_or_delete
                    ? ppp::diagnostics::ErrorCode::RouteAddFailed
                    : ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                return false;
            }

            if (action_add_or_delete) {
                int status = system(cmd);
                if (0 == status) {
                    return true;
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
                return false;
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
            bool ok = SetRouteToLinux(address, prefix, gw, true);
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
            }
            return ok;
        }

        bool TapLinux::DeleteRoute2(UInt32 address, int prefix, UInt32 gw) noexcept {
            return SetRouteToLinux(address, prefix, gw, false);
        }

        TapLinux::RouteMutationResult TapLinux::AddRouteStatus(
            const ppp::string& ifrName,
            UInt32 address,
            int prefix,
            UInt32 gw) noexcept {
            if (ifc_ctl_sock_compatible_route) {
                bool exists = false;
                if (TryRouteExists(ifrName, address, prefix, gw, exists) && exists) {
                    return RouteMutationResult::Unchanged;
                }
                bool ok = SetRouteToLinux(address, prefix, gw, true);
                if (ok) {
                    return RouteMutationResult::Changed;
                }
                if (TryRouteExists(ifrName, address, prefix, gw, exists) && exists) {
                    return RouteMutationResult::Unchanged;
                }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
                return RouteMutationResult::Failed;
            }

            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            struct in_addr in_dst;
            struct in_addr in_gw;

            in_dst.s_addr = address;
            in_gw.s_addr = gw;

            int err = TapLinux::SetRoute(SIOCADDRT, ifrName, in_dst, prefix, in_gw);
            if (0 == err) {
                return RouteMutationResult::Changed;
            }
            if (EEXIST == err) {
                bool exists = false;
                const bool query_succeeded =
                    TryRouteExists(ifrName, address, prefix, gw, exists);
                return ClassifyRouteAddResult(err, query_succeeded, exists);
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
            return RouteMutationResult::Failed;
        }

        bool TapLinux::AddRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            return AddRouteStatus(ifrName, address, prefix, gw) !=
                RouteMutationResult::Failed;
        }

        bool TapLinux::DeleteRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            if (ifc_ctl_sock_compatible_route) {
                if (SetRouteToLinux(address, prefix, gw, false)) {
                    return true;
                }
                bool exists = false;
                return TryRouteExists(ifrName, address, prefix, gw, exists) && !exists;
            }

            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            struct in_addr in_dst;
            struct in_addr in_gw;

            in_dst.s_addr = address;
            in_gw.s_addr = gw;

            bool any = false;
            int last_err = 0;
            for (;;) {
                int err = TapLinux::SetRoute(SIOCDELRT, ifrName, in_dst, prefix, in_gw);
                if (err != 0) {
                    last_err = err;
                    break;
                }
                else {
                    any = true;
                    continue;
                }
            }

            if (!any && ENOENT != last_err && ESRCH != last_err) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
            }

            return any || ENOENT == last_err || ESRCH == last_err;
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
        bool TapLinux::GetDefaultGateway(UInt32* address, const ppp::function<bool(const char*, uint32_t ip, uint32_t gw, uint32_t mask, int metric)>& predicate, bool* query_succeeded) noexcept {
            unsigned long d, g, fl, rc, us, metric, mask;
            char buf[256];
            char eth[256];
            int line = 0;
            int calli;
            int status;
            FILE* f;
            char* p;

            if (query_succeeded) {
                *query_succeeded = false;
            }
            if (!address || !predicate) {
                return false;
            }

            f = fopen("/proc/net/route", "r");
            if (!f) {
                return false;
            }
            if (query_succeeded) {
                *query_succeeded = true;
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
                    calli = false;
                    if (status >= 7) {
                        calli = true;
                    }
                    elif (status >= 2) {
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
            if (NULLPTR == ifrName) {
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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return false;
            }

            struct rtentry rt;
            memset(&rt, 0, sizeof(rt));

            struct sockaddr_in* gateAddr = (struct sockaddr_in*)&rt.rt_gateway;
            gateAddr->sin_family = AF_INET;
            gateAddr->sin_port = 0;

            if (!inet_aton(ip.data(), &gateAddr->sin_addr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                return false;
            }

            struct sockaddr_in* dstAddr = (struct sockaddr_in*)&rt.rt_dst;
            dstAddr->sin_family = AF_INET;

            struct sockaddr_in* maskAddr = (struct sockaddr_in*)&rt.rt_genmask;
            maskAddr->sin_family = AF_INET;

            rt.rt_flags = RTF_GATEWAY | RTF_UP;
            rt.rt_metric = 0;
            bool ok = ioctl(ifc_ctl_sock.sock_v4, SIOCADDRT, &rt) == 0;
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
            }
            return ok;
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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxInterfaceNameTooLong);
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            ppp::string oldName;
            if (!TapLinux::GetInterfaceName(dev_handle, oldName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }

            memcpy(ifr.ifr_name, oldName.data(), oldName.size());
            ifr.ifr_name[oldName.size() + 1] = '\x0';

            memcpy(ifr.ifr_newname, ifrName.data(), ifrName.size());
            ifr.ifr_name[ifrName.size() + 1] = '\x0';

            bool ok = ioctl(dev_handle, SIOCSIFNAME, &ifr) == 0;
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            }
            return ok;
        }

        bool TapLinux::AddRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::AddRoute(this->GetId(), address, prefix, gw);
        }

        bool TapLinux::DeleteRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::DeleteRoute(this->GetId(), address, prefix, gw);
        }

        namespace { void RecordTunFinalizeDiagnostic() noexcept; }

        void TapLinux::Dispose() noexcept {
            std::shared_ptr<ITap> self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            // Schedule Finalize  asynchronously to avoid inline execution on the io_context thread.
            boost::asio::post(*context,
                [self, this, context]() noexcept {
                    Finalize();
                });
            ITap::Dispose();
        }

        void TapLinux::Finalize() noexcept {
            RecordTunFinalizeDiagnostic();
            int disposed = disposed_.exchange(TRUE);
            if (disposed != TRUE) {
                {
                    std::lock_guard<std::mutex> lock(gso_mutex_);
                    gso_ssmt_disabled_ = true;
                    if (gso_merge_active_) {
                        DisableGsoMergeLocked(static_cast<int>(reinterpret_cast<std::intptr_t>(GetHandle())));
                    } else {
                        CancelGsoHoldTimerLocked();
                    }
                }
                ppp::telemetry::Log(Level::kInfo, "tap", "TUN device closing");
                ppp::telemetry::Count("tap.close", 1);
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
                ppp::telemetry::Log(Level::kDebug, "tap", "ssmt fd remove");
                ppp::telemetry::Count("tap.ssmt.fd.remove", 1);
                Socket::Closestream(sd);
                ppp::telemetry::Gauge("tap.active_fds", (int64_t)tun_ssmt_fds_size_);
            }
        }

        namespace {
            struct GsoMergeabilityTelemetry {
                bool enabled = false;
                bool ledger_enabled = false;
                bool tun_output_diagnostics_enabled = false;
                bool measurement_window_closed = false;
                std::atomic<uint64_t> tun_output_invalid{0};
                std::atomic<uint64_t> tun_output_disposed{0};
                std::atomic<uint64_t> tun_output_write_failed{0};
                std::atomic<uint64_t> tun_write_latch_bare{0};
                std::atomic<uint64_t> tun_write_latch_gso_disable_flush{0};
                std::atomic<uint64_t> tun_write_latch_gso_hold_timer_flush{0};
                std::atomic<uint64_t> tun_write_latch_gso_ordinary_write{0};
                std::atomic<uint64_t> tun_write_latch_gso_coalescer_push{0};
                std::atomic<uint64_t> tun_vnet_input_close{0};
                std::atomic<uint64_t> tun_finalize{0};
                std::atomic<uint64_t> first_push_returned_false_ns{0};
                std::atomic<uint64_t> first_fail_tun_write_latch_ns{0};
                std::atomic<uint64_t> first_dispose_from_tun_write_latch_ns{0};
                std::atomic<uint64_t> push_false_without_terminal{0};
                std::sig_atomic_t applied_boundary = 0;
                ppp::tap::TunGsoMergeabilityAnalyzer analyzer;
                ppp::tap::TunGsoLedger ledger;
                ppp::tap::TunGsoFirstPushFailure first_push_failure;

                void SynchronizeMeasurementBoundary() noexcept {
                    const std::sig_atomic_t boundary = ppp::diagnostics::datapath_perf::MeasurementBoundaryRequest();
                    if (boundary == 0 || boundary == applied_boundary) return;
                    applied_boundary = boundary;
                    if (boundary == 1) {
                        measurement_window_closed = false;
                        if (enabled) analyzer.ResetWindow();
                        if (ledger_enabled) ledger.ResetWindow();
                    } else if (boundary == 2) {
                        measurement_window_closed = true;
                        if (enabled) analyzer.FinalizeOpenRun();
                        if (ledger_enabled) ledger.FinalizeWindow();
                    }
                }

                void CountTunOutputInvalid() noexcept {
                    if (tun_output_diagnostics_enabled) tun_output_invalid.fetch_add(1, std::memory_order_relaxed);
                }

                void CountTunOutputDisposed() noexcept {
                    if (tun_output_diagnostics_enabled) tun_output_disposed.fetch_add(1, std::memory_order_relaxed);
                }

                void CountTunOutputWriteFailed() noexcept {
                    if (tun_output_diagnostics_enabled) tun_output_write_failed.fetch_add(1, std::memory_order_relaxed);
                }

                void CountTunWriteLatch(unsigned source) noexcept {
                    if (!tun_output_diagnostics_enabled) return;
                    switch (source) {
                        case 0: tun_write_latch_bare.fetch_add(1, std::memory_order_relaxed); break;
                        case 1: tun_write_latch_gso_disable_flush.fetch_add(1, std::memory_order_relaxed); break;
                        case 2: tun_write_latch_gso_hold_timer_flush.fetch_add(1, std::memory_order_relaxed); break;
                        case 3: tun_write_latch_gso_ordinary_write.fetch_add(1, std::memory_order_relaxed); break;
                        case 4: tun_write_latch_gso_coalescer_push.fetch_add(1, std::memory_order_relaxed); break;
                        default: break;
                    }
                }

                void CountTunVnetInputClose() noexcept {
                    if (tun_output_diagnostics_enabled) tun_vnet_input_close.fetch_add(1, std::memory_order_relaxed);
                }

                void CountTunFinalize() noexcept {
                    if (tun_output_diagnostics_enabled) tun_finalize.fetch_add(1, std::memory_order_relaxed);
                }

                static void RecordFirstTimestamp(std::atomic<uint64_t>& destination,
                    uint64_t timestamp_ns) noexcept {
                    uint64_t expected = 0;
                    (void)destination.compare_exchange_strong(expected, timestamp_ns,
                        std::memory_order_relaxed);
                }

                void RecordPushReturnedFalse(uint64_t timestamp_ns) noexcept {
                    if (tun_output_diagnostics_enabled) {
                        RecordFirstTimestamp(first_push_returned_false_ns, timestamp_ns);
                    }
                }

                void RecordFailTunWriteLatch() noexcept {
                    if (tun_output_diagnostics_enabled) {
                        RecordFirstTimestamp(first_fail_tun_write_latch_ns, TunGsoCoalescer::NowNs());
                    }
                }

                void RecordDisposeFromTunWriteLatch() noexcept {
                    if (tun_output_diagnostics_enabled) {
                        RecordFirstTimestamp(first_dispose_from_tun_write_latch_ns, TunGsoCoalescer::NowNs());
                    }
                }

                void CountPushFalseWithoutTerminal() noexcept {
                    if (tun_output_diagnostics_enabled) {
                        push_false_without_terminal.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                static const char* FirstPushFailureKindName(ppp::tap::TunGsoFirstPushFailure::Kind kind) noexcept {
                    switch (kind) {
                    case ppp::tap::TunGsoFirstPushFailure::Kind::Ordinary: return "ordinary";
                    case ppp::tap::TunGsoFirstPushFailure::Kind::Gso: return "gso";
                    case ppp::tap::TunGsoFirstPushFailure::Kind::None: return "none";
                    }
                    return "none";
                }

                static const char* WriteOutcomeName(TunGsoCoalescer::WriteOutcome outcome) noexcept {
                    switch (outcome) {
                    case TunGsoCoalescer::WriteOutcome::NegativeFailure: return "negative";
                    case TunGsoCoalescer::WriteOutcome::PartialDelivery: return "partial";
                    case TunGsoCoalescer::WriteOutcome::Complete: return "complete";
                    case TunGsoCoalescer::WriteOutcome::None: return "none";
                    }
                    return "none";
                }

                static const char* RejectionReasonName(TunGsoCoalescer::RejectionReason reason) noexcept {
                    switch (reason) {
                    case TunGsoCoalescer::RejectionReason::Incompatible: return "incompatible";
                    case TunGsoCoalescer::RejectionReason::Psh: return "psh";
                    case TunGsoCoalescer::RejectionReason::Control: return "control";
                    case TunGsoCoalescer::RejectionReason::Mtu: return "mtu";
                    case TunGsoCoalescer::RejectionReason::None: return "none";
                    }
                    return "none";
                }

                static const char* FlushReasonName(TunGsoCoalescer::FlushReason reason, bool captured) noexcept {
                    if (!captured) return "none";
                    switch (reason) {
                    case TunGsoCoalescer::FlushReason::Explicit: return "explicit";
                    case TunGsoCoalescer::FlushReason::Cap: return "cap";
                    case TunGsoCoalescer::FlushReason::Timeout: return "timeout";
                    case TunGsoCoalescer::FlushReason::Incompatible: return "incompatible";
                    case TunGsoCoalescer::FlushReason::ShortTail: return "short_tail";
                    case TunGsoCoalescer::FlushReason::Psh: return "psh";
                    case TunGsoCoalescer::FlushReason::Control: return "control";
                    case TunGsoCoalescer::FlushReason::Ssmt: return "ssmt";
                    case TunGsoCoalescer::FlushReason::Terminate: return "terminate";
                    }
                    return "none";
                }

                void RenderTunOutputJson(std::ostream& output) const {
                    const ppp::tap::TunGsoFirstPushFailure::Snapshot first = first_push_failure.GetSnapshot();
                    const bool captured = first.kind != ppp::tap::TunGsoFirstPushFailure::Kind::None;
                    const bool mtu_terminal = captured && first.rejection == TunGsoCoalescer::RejectionReason::Mtu;
                    const ppp::tap::TunGsoCoalescer::PacketShape empty_packet_shape;
                    const ppp::tap::TunGsoCoalescer::PacketShape& packet_shape =
                        mtu_terminal ? first.packet_shape : empty_packet_shape;
                    const ppp::tap::TunGsoFirstPushFailure::Precursor& precursor = first.precursor;
                    output << ",\"tun_output\":{\"invalid\":"
                        << tun_output_invalid.load(std::memory_order_relaxed)
                        << ",\"disposed\":" << tun_output_disposed.load(std::memory_order_relaxed)
                        << ",\"already_tun_write_failed\":" << tun_output_write_failed.load(std::memory_order_relaxed)
                        << ",\"first_latch\":{\"bare_write\":" << tun_write_latch_bare.load(std::memory_order_relaxed)
                        << ",\"gso_disable_flush\":" << tun_write_latch_gso_disable_flush.load(std::memory_order_relaxed)
                        << ",\"gso_hold_timer_flush\":" << tun_write_latch_gso_hold_timer_flush.load(std::memory_order_relaxed)
                        << ",\"gso_ordinary_write\":" << tun_write_latch_gso_ordinary_write.load(std::memory_order_relaxed)
                        << ",\"gso_coalescer_push\":" << tun_write_latch_gso_coalescer_push.load(std::memory_order_relaxed)
                        << "},\"first_push_failure\":{\"semantic\":\"terminal\",\"terminal\":{\"stage\":\"terminal\",\"kind\":\""
                        << FirstPushFailureKindName(first.kind)
                        << "\",\"outcome\":\"" << (captured ? WriteOutcomeName(first.outcome) : "none")
                        << "\",\"flush_reason\":\"" << FlushReasonName(first.flush_reason, captured)
                        << "\",\"rejection_reason\":\"" << (captured ? RejectionReasonName(first.rejection) : "none")
                        << "\",\"original_packet_bytes\":" << first.packet_bytes
                        << ",\"requested_vnet_frame_bytes\":" << first.frame_bytes
                        << ",\"written_bytes\":" << first.written_bytes
                        << ",\"error_number\":" << first.error_number
                        << ",\"segments\":" << first.segments
                        << ",\"hold_ns\":" << first.hold_ns
                        << ",\"monotonic_ns\":" << first.monotonic_ns
                        << ",\"negative_fallback\":" << (first.negative_fallback ? "true" : "false")
                        << ",\"packet_shape\":{\"parsed\":" << (packet_shape.parsed ? "true" : "false")
                        << ",\"supplied_bytes\":" << packet_shape.supplied_bytes
                        << ",\"ipv4_total_length\":" << packet_shape.ipv4_total_length
                        << ",\"ipv4_ihl_bytes\":" << packet_shape.ipv4_ihl_bytes
                        << ",\"tcp_data_offset_bytes\":" << packet_shape.tcp_data_offset_bytes
                        << ",\"tcp_payload_bytes\":" << packet_shape.tcp_payload_bytes
                        << ",\"ipv4_version\":" << static_cast<unsigned>(packet_shape.ipv4_version)
                        << ",\"ipv4_protocol\":" << static_cast<unsigned>(packet_shape.ipv4_protocol)
                        << ",\"ipv4_fragment_flags\":" << packet_shape.ipv4_fragment_flags
                        << ",\"ipv4_df\":" << (packet_shape.ipv4_df ? "true" : "false")
                        << ",\"tcp_flags\":" << static_cast<unsigned>(packet_shape.tcp_flags)
                        << ",\"fixed_max_guard_bytes\":" << packet_shape.max_guard_bytes
                        << ",\"excess_bytes\":" << packet_shape.excess_bytes
                        << "}},\"precursor\":{\"stage\":\"" << (precursor.present ? "gso_negative" : "none")
                        << "\",\"kind\":\"" << (precursor.present ? "gso" : "none")
                        << "\",\"requested_vnet_frame_bytes\":" << precursor.requested_bytes
                        << ",\"written_bytes\":" << precursor.written_bytes
                        << ",\"error_number\":" << precursor.error_number
                        << ",\"monotonic_ns\":" << precursor.monotonic_ns
                        << "}},\"failure_timeline\":{\"push_returned_false_ns\":"
                        << first_push_returned_false_ns.load(std::memory_order_relaxed)
                        << ",\"fail_tun_write_latch_ns\":"
                        << first_fail_tun_write_latch_ns.load(std::memory_order_relaxed)
                        << ",\"dispose_from_tun_write_latch_ns\":"
                        << first_dispose_from_tun_write_latch_ns.load(std::memory_order_relaxed)
                        << ",\"push_false_without_terminal\":"
                        << push_false_without_terminal.load(std::memory_order_relaxed)
                        << "},\"vnet_input_close\":" << tun_vnet_input_close.load(std::memory_order_relaxed)
                        << ",\"finalize\":" << tun_finalize.load(std::memory_order_relaxed) << '}';
                }

                static bool Initialize(GsoMergeabilityTelemetry& result) noexcept {
                    const char* mergeability_flag = std::getenv("OPENPPP2_DATAPATH_GSO_MERGEABILITY");
                    result.enabled = mergeability_flag != nullptr && *mergeability_flag == '1';
                    const char* ledger_flag = std::getenv("OPENPPP2_DATAPATH_GSO_LEDGER");
                    result.ledger_enabled = ledger_flag != nullptr && *ledger_flag == '1';
                    const char* tun_output_flag = std::getenv("OPENPPP2_DATAPATH_TUN_OUTPUT_DIAGNOSTICS");
                    result.tun_output_diagnostics_enabled = tun_output_flag != nullptr && *tun_output_flag == '1';
                    if (result.tun_output_diagnostics_enabled) {
                        ppp::diagnostics::datapath_perf::SetTunOutputRender(
                            [](std::ostream& output) { Instance().RenderTunOutputJson(output); });
                    }
                    if (result.enabled) {
                        ppp::diagnostics::datapath_perf::SetMergeabilityRender(
                            [](std::ostream& output, const char*) {
                                output << ",\"tun_gso_mergeability\":" << Instance().analyzer.RenderWindowJson();
                            });
                    }
                    if (result.ledger_enabled) {
                        ppp::diagnostics::datapath_perf::SetGsoLedgerRender(
                            [](std::ostream& output, const char*) {
                                output << ",\"tun_gso_ledger\":" << Instance().ledger.RenderWindowJson();
                            });
                    }
                    return true;
                }

                static GsoMergeabilityTelemetry& Instance() {
                    static GsoMergeabilityTelemetry instance;
                    static const bool initialized = Initialize(instance);
                    (void)initialized;
                    return instance;
                }
            };

            void RecordTunFinalizeDiagnostic() noexcept {
                GsoMergeabilityTelemetry::Instance().CountTunFinalize();
            }
        }
        ssize_t TapLinux::WriteTunFrame(int fd, const uint8_t* frame, size_t frame_size) noexcept {
            ppp::diagnostics::datapath_perf::Scope write_scope;
            const bool direct_write_accounting = ppp::diagnostics::datapath_perf::BeginTunDirectWrite();
            const ssize_t bytes_transferred = ::write(fd, frame, frame_size);
            ppp::diagnostics::datapath_perf::EndTunDirectWrite(direct_write_accounting);
            ppp::diagnostics::datapath_perf::RecordTunDirectWrite(static_cast<int>(frame_size),
                static_cast<int>(bytes_transferred), write_scope.Elapsed());
            return bytes_transferred;
        }

        ssize_t TapLinux::WriteGsoFrameLocked(const uint8_t* frame, size_t frame_size) noexcept {
            return WriteTunFrame(gso_write_fd_, frame, frame_size);
        }

        void TapLinux::FailTunWrite(TunWriteFailureSource source) noexcept {
            if (tun_write_failed_.exchange(TRUE) == FALSE) {
                GsoMergeabilityTelemetry& telemetry = GsoMergeabilityTelemetry::Instance();
                telemetry.RecordFailTunWriteLatch();
                telemetry.CountTunWriteLatch(static_cast<unsigned>(source));
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                telemetry.RecordDisposeFromTunWriteLatch();
                Dispose();
            }
        }

        void TapLinux::DisableGsoMergeLocked(int write_fd, TunGsoCoalescer::FlushReason reason) noexcept {
            CancelGsoHoldTimerLocked();
            gso_write_fd_ = write_fd;
            const bool flushed = gso_coalescer_.DisableAndFlush(reason);
            gso_merge_active_ = false;
            if (!flushed) {
                FailTunWrite(TunWriteFailureSource::GsoDisableFlush);
            }
        }

        void TapLinux::ArmGsoHoldTimerLocked() noexcept {
            if (gso_timer_armed_ || !gso_merge_active_ || gso_ssmt_disabled_) return;
            gso_timer_armed_ = true;
            const uint64_t generation = ++gso_timer_generation_;
            gso_hold_timer_.expires_after(std::chrono::microseconds(100));
            std::shared_ptr<ITap> self = shared_from_this();
            gso_hold_timer_.async_wait([self, this, generation](const boost::system::error_code& ec) noexcept {
                std::lock_guard<std::mutex> lock(gso_mutex_);
                if (generation != gso_timer_generation_) return;
                gso_timer_armed_ = false;
                if (ec || !gso_merge_active_ || gso_ssmt_disabled_ || disposed_.load() != FALSE) return;
                gso_write_fd_ = static_cast<int>(reinterpret_cast<std::intptr_t>(GetHandle()));
                if (!gso_coalescer_.FlushExpired()) {
                    gso_merge_active_ = false;
                    FailTunWrite(TunWriteFailureSource::GsoHoldTimerFlush);
                }
            });
        }

        void TapLinux::CancelGsoHoldTimerLocked() noexcept {
            if (!gso_timer_armed_) return;
            gso_timer_armed_ = false;
            ++gso_timer_generation_;
            boost::system::error_code ec;
            gso_hold_timer_.cancel(ec);
        }

        void TapLinux::OnInput(PacketInputEventArgs& e) noexcept {
            if (!vnet_header_) {
                ITap::OnInput(e);
                return;
            }
            auto fail_vnet_input = [this](const char* message) noexcept {
                GsoMergeabilityTelemetry::Instance().CountTunVnetInputClose();
                ppp::telemetry::Log(Level::kInfo, "tap", "%s", message);
                {
                    std::lock_guard<std::mutex> lock(gso_mutex_);
                    DisableGsoMergeLocked(static_cast<int>(reinterpret_cast<std::intptr_t>(GetHandle())));
                }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelReadFailed);
                Dispose();
            };
            if (e.Packet == NULLPTR || e.PacketLength <= 0 || !vnet::IsStandardHeaderSize(vnet_header_size_)) {
                fail_vnet_input("malformed VNET frame received; closing TUN");
                return;
            }

            uint8_t* frame = static_cast<uint8_t*>(e.Packet);
            const size_t frame_size = static_cast<size_t>(e.PacketLength);
            virtio_net_hdr virtio{};
            if (!vnet::ReadHeader(frame, frame_size, vnet_header_size_, virtio)) {
                fail_vnet_input("malformed VNET frame received; closing TUN");
                return;
            }

            if (virtio.gso_type == VIRTIO_NET_HDR_GSO_NONE) {
                if (virtio.flags == 0 && le16toh(virtio.hdr_len) == 0 && le16toh(virtio.gso_size) == 0 &&
                    le16toh(virtio.csum_start) == 0 && le16toh(virtio.csum_offset) == 0) {
                    const size_t packet_size = frame_size - vnet_header_size_;
                    // Input is borrowed until this callback returns; the read
                    // loop keeps the original allocation for its next read.
                    e.Packet = frame + vnet_header_size_;
                    e.PacketLength = static_cast<int>(packet_size);
                    ITap::OnInput(e);
                    return;
                }
                if (!vnet::CompleteChecksumOnlyTcpV4(frame, frame_size, vnet_header_size_)) {
                    fail_vnet_input("unsupported or malformed inbound VNET checksum-only frame; closing TUN");
                    return;
                }
                const size_t packet_size = frame_size - vnet_header_size_;
                e.Packet = frame + vnet_header_size_;
                e.PacketLength = static_cast<int>(packet_size);
                ITap::OnInput(e);
                return;
            }

            vnet::TcpV4GsoFrame gso;
            if (!vnet::ParseTcpV4Gso(frame, frame_size, vnet_header_size_, ITap::Mtu, gso)) {
                fail_vnet_input("unsupported or malformed inbound VNET GSO frame; closing TUN");
                return;
            }

            if (!vnet::CompleteTcpV4GsoChecksums(gso)) {
                fail_vnet_input("failed to complete inbound TCPv4 GSO checksums; closing TUN");
                return;
            }
            PacketInputEventArgs gso_event{
                gso.ip, static_cast<int>(gso.packet_size), true
            };
            PacketInputEventHandler handler = GetPacketInput();
            if (handler && handler(this, gso_event)) {
                return;
            }

            for (size_t offset = 0; offset < gso.payload_size; offset += gso.gso_size) {
                std::array<Byte, ITap::Mtu> segment{};
                size_t segment_size = 0;
                if (!vnet::BuildTcpV4GsoSegment(gso, offset, segment.data(), segment.size(), segment_size)) {
                    fail_vnet_input("failed to build inbound TCPv4 GSO segment; closing TUN");
                    return;
                }
                PacketInputEventArgs segment_event{ segment.data(), static_cast<int>(segment_size) };
                ITap::OnInput(segment_event);
            }
        }

        bool TapLinux::AsynchronousReadPacketLoops() noexcept {
            if (!vnet_header_) {
                return ITap::AsynchronousReadPacketLoops();
            }
            std::shared_ptr<boost::asio::posix::stream_descriptor> stream = GetStream();
            if (NULLPTR == stream || !stream->is_open() || NULLPTR == vnet_read_buffer_ || read_capacity_ == 0) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelReadFailed);
            }

            std::shared_ptr<ITap> self = shared_from_this();
            stream->async_read_some(boost::asio::buffer(vnet_read_buffer_.get(), read_capacity_),
                [self, this, stream](const boost::system::error_code& ec, std::size_t sz) noexcept {
                    if (ec == boost::system::errc::operation_canceled) {
                        return;
                    }
                    const int length = std::max<int>(ec ? -1 : sz, -1);
                    if (length > 0) {
                        ppp::diagnostics::datapath_perf::RecordTunRead(length);
                        PacketInputEventArgs event{ vnet_read_buffer_.get(), length };
                        OnInput(event);
                    }
                    if (disposed_.load() == FALSE) {
                        AsynchronousReadPacketLoops();
                    }
                });
            return true;
        }

        bool TapLinux::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept {
            return Output(packet.get(), packet_size);
        }

        bool TapLinux::SupportsTxGso() const noexcept {
            std::lock_guard<std::mutex> lock(gso_mutex_);
            return disposed_.load(std::memory_order_acquire) == FALSE &&
                tun_write_failed_.load(std::memory_order_acquire) == FALSE &&
                vnet_header_ && tx_gso_supported_ && !gso_ssmt_disabled_;
        }

        bool TapLinux::OutputGso(const std::shared_ptr<Byte>& packet, int packet_size,
            TxGsoMetadata metadata) noexcept {
            virtio_net_hdr header{};
            if (!packet || packet_size < 1 ||
                !vnet::BuildTcpV4GsoHeader(packet.get(), static_cast<size_t>(packet_size), metadata, header)) {
                direct_gso_rejected_.fetch_add(1, std::memory_order_relaxed);
                ppp::telemetry::Count("tap.ndi_gso.rejected", 1);
                return false;
            }
            if (disposed_.load(std::memory_order_acquire) != FALSE ||
                tun_write_failed_.load(std::memory_order_acquire) != FALSE) {
                direct_gso_rejected_.fetch_add(1, std::memory_order_relaxed);
                ppp::telemetry::Count("tap.ndi_gso.rejected", 1);
                return false;
            }

            const int tun = static_cast<int>(reinterpret_cast<std::intptr_t>(GetHandle()));
            std::lock_guard<std::mutex> lock(gso_mutex_);
            if (!vnet_header_ || !tx_gso_supported_ || gso_ssmt_disabled_ || tun < 0) {
                direct_gso_rejected_.fetch_add(1, std::memory_order_relaxed);
                ppp::telemetry::Count("tap.ndi_gso.rejected", 1);
                return false;
            }

            // Preserve ordering with ordinary packets retained by the edge
            // coalescer. A flush failure is terminal and the super-packet is
            // never replayed through the ordinary oversized path.
            gso_write_fd_ = tun;
            if (!gso_coalescer_.Flush(TunGsoCoalescer::FlushReason::Explicit)) {
                direct_gso_rejected_.fetch_add(1, std::memory_order_relaxed);
                ppp::telemetry::Count("tap.ndi_gso.rejected", 1);
                FailTunWrite(TunWriteFailureSource::DirectGsoWrite);
                return false;
            }
            CancelGsoHoldTimerLocked();

            struct iovec iov[2];
            iov[0].iov_base = &header;
            iov[0].iov_len = sizeof(header);
            iov[1].iov_base = packet.get();
            iov[1].iov_len = static_cast<size_t>(packet_size);
            const size_t expected = sizeof(header) + static_cast<size_t>(packet_size);
            ppp::diagnostics::datapath_perf::Scope write_scope;
            const bool direct_write_accounting = ppp::diagnostics::datapath_perf::BeginTunDirectWrite();
            const ssize_t written = ::writev(tun, iov, 2);
            ppp::diagnostics::datapath_perf::EndTunDirectWrite(direct_write_accounting);
            ppp::diagnostics::datapath_perf::RecordTunDirectWrite(
                static_cast<int>(expected), static_cast<int>(written), write_scope.Elapsed());
            if (written != static_cast<ssize_t>(expected)) {
                direct_gso_rejected_.fetch_add(1, std::memory_order_relaxed);
                ppp::telemetry::Count("tap.ndi_gso.rejected", 1);
                FailTunWrite(TunWriteFailureSource::DirectGsoWrite);
                return false;
            }
            direct_gso_packets_.fetch_add(1, std::memory_order_relaxed);
            direct_gso_bytes_.fetch_add(static_cast<uint64_t>(packet_size), std::memory_order_relaxed);
            ppp::telemetry::Count("tap.ndi_gso.packets", 1);
            ppp::telemetry::Count("tap.ndi_gso.bytes", packet_size);
            return true;
        }

        bool TapLinux::Output(const void* packet, int packet_size) noexcept {
            // Windows virtual nics need to use Event to write to the kernel asynchronously,
            // Linux virtual nics can directly write to the kernel ::write function,
            // Can reduce a memory allocation and replication, improve throughput efficiency.
            GsoMergeabilityTelemetry& mergeability = GsoMergeabilityTelemetry::Instance();
            if (NULLPTR == packet || packet_size < 1) {
                mergeability.CountTunOutputInvalid();
                return false;
            }

            int disposed = disposed_.load();
            if (disposed != FALSE) {
                mergeability.CountTunOutputDisposed();
                return false;
            }
            if (tun_write_failed_.load() != FALSE) {
                mergeability.CountTunOutputWriteFailed();
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

            // Mergeability is a packet-input model; the ledger below is driven
            // by actual coalescer events. Boundaries are applied before either
            // can observe the triggering output packet.
            mergeability.SynchronizeMeasurementBoundary();
            if (mergeability.enabled && !mergeability.measurement_window_closed && !Ssmt()) {
                mergeability.analyzer.Observe(static_cast<const uint8_t*>(packet), static_cast<size_t>(packet_size));
            }
            if (!vnet_header_) {
                // Preserve the bare/default path: no GSO state and no feature lock.
                const ssize_t written = WriteTunFrame(tun, static_cast<const uint8_t*>(packet), static_cast<size_t>(packet_size));
                if (written != packet_size) {
                    FailTunWrite(TunWriteFailureSource::BareWrite);
                    return false;
                }
                return true;
            }

            std::lock_guard<std::mutex> lock(gso_mutex_);
            if ((mergeability.ledger_enabled || mergeability.tun_output_diagnostics_enabled) &&
                !gso_observer_hooked_ && !Ssmt()) {
                GsoMergeabilityTelemetry* telemetry = &mergeability;
                gso_coalescer_.SetObserver([this, telemetry](const TunGsoCoalescer::Event& event) {
                    if (telemetry->ledger_enabled) telemetry->ledger.OnEvent(event);
                    if (gso_push_observation_active_) telemetry->first_push_failure.OnEvent(event);
                });
                gso_observer_hooked_ = true;
            }
            if (gso_merge_active_ && !TapGsoMergeRequested()) {
                DisableGsoMergeLocked(tun);
            }
            if (tun_write_failed_.load() != FALSE) {
                mergeability.CountTunOutputWriteFailed();
                return false;
            }
            gso_write_fd_ = tun;
            if (!gso_merge_active_) {
                // VNET framing remains mandatory after merging has been disabled.
                // Do not call Push(): this write is physically synchronous.
                const bool ok = gso_coalescer_.WriteOrdinaryFrame(static_cast<const uint8_t*>(packet), static_cast<size_t>(packet_size));
                if (!ok) FailTunWrite(TunWriteFailureSource::GsoOrdinaryWrite);
                return ok;
            }

            const bool was_pending = gso_coalescer_.has_pending();
            gso_push_observation_active_ = mergeability.tun_output_diagnostics_enabled;
            if (gso_push_observation_active_) mergeability.first_push_failure.BeginPush();
            const bool ok = gso_coalescer_.Push(static_cast<const uint8_t*>(packet), static_cast<size_t>(packet_size));
            const uint64_t push_returned_false_ns = !ok && gso_push_observation_active_
                ? TunGsoCoalescer::NowNs() : 0;
            if (gso_push_observation_active_) {
                const bool terminal_observed = mergeability.first_push_failure.EndPush(ok);
                if (!ok) {
                    mergeability.RecordPushReturnedFalse(push_returned_false_ns);
                    if (!terminal_observed) mergeability.CountPushFalseWithoutTerminal();
                }
                gso_push_observation_active_ = false;
            }
            if (ok && !was_pending && gso_coalescer_.has_pending()) ArmGsoHoldTimerLocked();
            if (!gso_coalescer_.has_pending()) CancelGsoHoldTimerLocked();
            if (!gso_coalescer_.enabled()) gso_merge_active_ = false;
            if (!ok) FailTunWrite(TunWriteFailureSource::GsoCoalescerPush);
            return ok;
        }

        bool TapLinux::Ssmt(const std::shared_ptr<boost::asio::io_context>& context) noexcept {
            if (NULLPTR == context) {
                return false;
            }

            int disposed = disposed_.load();
            if (disposed != FALSE) {
                return false;
            }

            {
                std::lock_guard<std::mutex> lock(gso_mutex_);
                gso_ssmt_disabled_ = true;
                if (gso_merge_active_) {
                    DisableGsoMergeLocked(static_cast<int>(reinterpret_cast<std::intptr_t>(GetHandle())), TunGsoCoalescer::FlushReason::Ssmt);
                } else {
                    CancelGsoHoldTimerLocked();
                }
            }

            ppp::string dev = GetId();
            if (dev.empty()) {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            // Re-check under the lock: Finalize() holds syncobj_ while tearing
            // down tun_ssmt_sds_, so a concurrent Ssmt() must not create a new
            // descriptor (and re-arm a read loop) after disposal.
            if (disposed_.load() != FALSE) {
                return false;
            }

            int tun = OpenDriver(dev.data());
            if (tun == -1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                return false;
            }
            struct ifreq driver_ifr;
            memset(&driver_ifr, 0, sizeof(driver_ifr));
            const bool got_secondary_ifr = ioctl(tun, TUNGETIFF, &driver_ifr) == 0;
            const bool secondary_vnet = got_secondary_ifr && (driver_ifr.ifr_flags & IFF_VNET_HDR) != 0;
            int header_readback = 0;
            if (!got_secondary_ifr || secondary_vnet != vnet_header_ ||
                (secondary_vnet && (ioctl(tun, TUNGETVNETHDRSZ, &header_readback) != 0 ||
                    static_cast<size_t>(header_readback) != vnet_header_size_ ||
                    !vnet::IsStandardHeaderSize(vnet_header_size_)))) {
                ::close(tun);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }
            std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(read_capacity_);
            if (NULLPTR == buffer) {
                ::close(tun);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            std::shared_ptr<boost::asio::posix::stream_descriptor> sd = make_shared_object<boost::asio::posix::stream_descriptor>(*context, tun);
            if (NULLPTR == sd) {
                ::close(tun);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            tun_ssmt_fds_size_++;
            tun_ssmt_sds_.emplace_back(sd);
            ppp::telemetry::Log(Level::kDebug, "tap", "ssmt fd add: %d", tun);
            ppp::telemetry::Count("tap.ssmt.fd.add", 1);
            ppp::telemetry::Gauge("tap.active_fds", (int64_t)tun_ssmt_fds_size_);

            if (Ssmt(context, tun, buffer, sd)) {
                return true;
            }

            tun_ssmt_fds_size_--;
            tun_ssmt_sds_.pop_back();
            ppp::telemetry::Log(Level::kDebug, "tap", "ssmt fd remove: %d", tun);
            ppp::telemetry::Count("tap.ssmt.fd.remove", 1);
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
            sd->async_read_some(boost::asio::buffer(buffer.get(), read_capacity_),
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
            if (NULLPTR == sd) {
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
            ppp::telemetry::Log(Level::kInfo, "tap", "interface %s", up ? "up" : "down");
            auto started_at = std::chrono::steady_clock::now();
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
                if (up) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                }
                return false;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.interface.state.us", elapsed);

            return !up || SetInterfaceMtu(ITap::Mtu);
        }

        bool TapLinux::SetInterfaceMtu(int mtu) noexcept {
            mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);

            bool ok = TUNGETIFFF(GetStream(),
                [mtu](ifreq& ifr, int control_fd) noexcept {
                    ifr.ifr_mtu = mtu;
                    if (ioctl(control_fd, SIOCSIFMTU, &ifr) < 0) {
                        return false;
                    }

                    return true;
                });
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelMtuConfigureFailed);
            }

            return ok;
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
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    return NULLPTR;
                }
            }

            bool ok = TapLinux::SetIPAddress(interface_name,
                IPEndPoint(ip, IPEndPoint::MinPort).ToAddressString(),
                IPEndPoint(mask, IPEndPoint::MinPort).ToAddressString());
            if (!ok) {
                ::close(tun);
                return NULLPTR;
            }

            std::shared_ptr<TapLinux> tap = make_shared_object<TapLinux>(context, interface_name, reinterpret_cast<void*>(tun), ip, gw, mask, hosted_network);
            if (NULLPTR == tap) {
                ::close(tun);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            struct ifreq driver_ifr;
            memset(&driver_ifr, 0, sizeof(driver_ifr));
            if (ioctl(tun, TUNGETIFF, &driver_ifr) != 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return NULLPTR;
            }
            tap->vnet_header_ = (driver_ifr.ifr_flags & IFF_VNET_HDR) != 0;
            if (tap->vnet_header_) {
                int header_readback = 0;
                if (ioctl(tun, TUNGETVNETHDRSZ, &header_readback) != 0 ||
                    !vnet::IsStandardHeaderSize(static_cast<size_t>(header_readback)) ||
                    !vnet::ReadCapacity(static_cast<size_t>(header_readback), tap->read_capacity_)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                    return NULLPTR;
                }
                tap->vnet_header_size_ = static_cast<size_t>(header_readback);
                tap->vnet_read_buffer_ = make_shared_alloc<Byte>(tap->read_capacity_);
                if (NULLPTR == tap->vnet_read_buffer_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }
            }
            tap->tx_gso_supported_ = tap->vnet_header_;
            tap->gso_merge_active_ = tap->vnet_header_ && TapGsoMergeRequested();
            tap->promisc_ = promisc;
            tap->dns_addresses_ = dns_addresses;

            ITap* my = tap.get();
            if (NULLPTR != my) {
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
            if (NULLPTR == context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                return NULLPTR;
            }

            if (dev.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                return NULLPTR;
            }

            IPEndPoint ipEP(ip, 0);
            if (IPEndPoint::IsInvalid(ipEP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return NULLPTR;
            }

            IPEndPoint gwEP(gw, 0);
            if (IPEndPoint::IsInvalid(gwEP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                return NULLPTR;
            }

            IPEndPoint maskEP(mask, 0);
            if (IPEndPoint::IsInvalid(maskEP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                return NULLPTR;
            }

            int tun = OpenDriver(dev.data());
            if (tun == -1) {
                return NULLPTR;
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
            if (NULLPTR == rib || NULLPTR == interface_name) {
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
            if (NULLPTR == rib) {
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

        bool TapLinux::TryFindAllDefaultGatewayRoutes(
            const ppp::unordered_set<uint32_t>& bypass_gws,
            std::shared_ptr<ppp::net::native::RouteInformationTable>& routes) noexcept {
            routes.reset();
            std::shared_ptr<ppp::net::native::RouteInformationTable> rib = make_shared_object<ppp::net::native::RouteInformationTable>();
            if (NULLPTR == rib) {
                return false;
            }

            uint32_t mid = inet_addr("128.0.0.0");
            uint32_t address = 0;
            bool query_succeeded = false;
            GetDefaultGateway(&address,
                [&rib, mid, &bypass_gws](const char* interface_name, uint32_t ip, uint32_t gw, uint32_t mask, int metric) noexcept {
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
                    rib->AddRoute(ip, prefix_mask, gw);
                    return false;
                },
                &query_succeeded);
            if (!query_succeeded) {
                return false;
            }
            routes = std::move(rib);
            return true;
        }

        std::shared_ptr<ppp::net::native::RouteInformationTable> TapLinux::FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>& bypass_gws) noexcept {
            std::shared_ptr<ppp::net::native::RouteInformationTable> routes;
            if (!TryFindAllDefaultGatewayRoutes(bypass_gws, routes) ||
                !routes || routes->GetAllRoutes().empty()) {
                return NULLPTR;
            }
            return routes;
        }

#if defined(_ANDROID)
        static bool ITAP_FROM_REQUIRED(
            const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::string& id,
            void* tun,
            uint32_t                                        address,
            uint32_t                                        gw,
            uint32_t                                        mask) noexcept
        {
            if (tun == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            if (NULL == context)
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

            IPEndPoint maskEP(mask, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                return false;
            }

            IPEndPoint gwEP(gw, 0);
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
                return NULLPTR;
            }

            std::shared_ptr<ppp::tap::TapLinux> linux_tap = make_shared_object<ppp::tap::TapLinux>(context, id, tun, address, gw, mask, hosted_network);
            if (NULLPTR == linux_tap)
            {
                return NULLPTR;
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
