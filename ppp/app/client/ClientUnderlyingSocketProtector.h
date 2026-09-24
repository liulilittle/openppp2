#pragma once

#include <ppp/app/client/ClientNetworkInterface.h>
#include <ppp/net/rinetd/RinetdConnection.h>

namespace ppp {
    namespace net {
        class ProtectorNetwork;
    }

    namespace app {
        namespace client {
            using ClientUnderlyingSocketProtector =
                ppp::net::rinetd::RinetdConnection::RemoteSocketProtector;
            using ClientUnderlyingSocketHandle =
                ppp::net::rinetd::RinetdConnection::RemoteSocketHandle;

            inline bool IsClientUnderlyingSocketHandleValid(
                ClientUnderlyingSocketHandle socket) noexcept {
#if defined(_WIN32)
                return socket != INVALID_SOCKET;
#else
                return socket >= 0;
#endif
            }

            inline bool IsClientUnderlyingSocketProtectionSnapshotValid(
                bool ipv4,
                const ppp::string& interface_name,
                int interface_index,
                bool has_protector_network) noexcept {
#if defined(_IPHONE) || defined(IPHONE)
                return false;
#elif defined(_ANDROID)
                return has_protector_network;
#elif defined(_LINUX)
                return ipv4 && !interface_name.empty();
#elif defined(_WIN32) || defined(_MACOS)
                return ipv4 && interface_index > 0;
#else
                return false;
#endif
            }

            inline bool ProtectClientUnderlyingSocket(
                ClientUnderlyingSocketHandle socket,
                const ppp::string& interface_name,
                int interface_index) noexcept {
                if (!IsClientUnderlyingSocketHandleValid(socket)) {
                    return false;
                }

#if defined(_LINUX) && !defined(_ANDROID)
                if (interface_name.empty()) {
                    return false;
                }
                return ::setsockopt(
                    socket,
                    SOL_SOCKET,
                    SO_BINDTODEVICE,
                    interface_name.c_str(),
                    static_cast<socklen_t>(interface_name.size() + 1)) == 0;
#elif defined(_WIN32)
                if (interface_index <= 0) {
                    return false;
                }
                const DWORD network_index = htonl(static_cast<DWORD>(interface_index));
                return ::setsockopt(
                    socket,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    reinterpret_cast<const char*>(&network_index),
                    sizeof(network_index)) == 0;
#elif defined(_MACOS) && !defined(_IPHONE) && !defined(IPHONE)
                if (interface_index <= 0) {
                    return false;
                }
                const unsigned int native_index = static_cast<unsigned int>(interface_index);
                return ::setsockopt(
                    socket,
                    IPPROTO_IP,
                    IP_BOUND_IF,
                    &native_index,
                    sizeof(native_index)) == 0;
#else
                (void)interface_name;
                (void)interface_index;
                return false;
#endif
            }

            inline ClientUnderlyingSocketProtector BuildClientUnderlyingSocketProtector(
                bool ipv4,
                const std::shared_ptr<ClientNetworkInterface>& network_interface,
                const std::shared_ptr<ppp::net::ProtectorNetwork>& protector_network) noexcept {
                const ppp::string interface_name = network_interface
                    ? network_interface->Name
                    : ppp::string();
                const int interface_index = network_interface
                    ? network_interface->Index
                    : -1;
                if (!IsClientUnderlyingSocketProtectionSnapshotValid(
                    ipv4,
                    interface_name,
                    interface_index,
                    protector_network != NULLPTR)) {
                    return ClientUnderlyingSocketProtector();
                }

#if defined(_ANDROID)
                return [protector_network](
                    ClientUnderlyingSocketHandle socket,
                    ppp::coroutines::YieldContext& y) noexcept {
                        return IsClientUnderlyingSocketHandleValid(socket) &&
                            protector_network->Protect(socket, y);
                    };
#elif defined(_IPHONE) || defined(IPHONE)
                return ClientUnderlyingSocketProtector();
#else
                return [interface_name, interface_index](
                    ClientUnderlyingSocketHandle socket,
                    ppp::coroutines::YieldContext&) noexcept {
                        return ProtectClientUnderlyingSocket(
                            socket,
                            interface_name,
                            interface_index);
                    };
#endif
            }
        }
    }
}
