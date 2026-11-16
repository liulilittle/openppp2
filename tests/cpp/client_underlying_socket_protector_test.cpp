#include <ppp/app/client/ClientUnderlyingSocketProtector.h>

#include <cassert>

#if defined(_WIN32)
#include <iphlpapi.h>
#else
#include <unistd.h>
#endif

int main() {
    using namespace ppp::app::client;

#if defined(_WIN32)
    assert(!IsClientUnderlyingSocketHandleValid(INVALID_SOCKET));
    assert(IsClientUnderlyingSocketProtectionSnapshotValid(true, "", 1, false));
    assert(!IsClientUnderlyingSocketProtectionSnapshotValid(true, "", 0, false));
    assert(!IsClientUnderlyingSocketProtectionSnapshotValid(false, "", 1, false));

    // Exercise the real socket option without connecting or changing any
    // adapter, route, DNS, or system proxy state.
    WSADATA winsock{};
    assert(::WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
    DWORD loopback_index = 0;
    assert(::GetBestInterface(htonl(INADDR_LOOPBACK), &loopback_index) == NO_ERROR);
    assert(loopback_index > 0);
    const SOCKET socket_handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(socket_handle != INVALID_SOCKET);
    assert(!ProtectClientUnderlyingSocket(socket_handle, "", 0));
    assert(ProtectClientUnderlyingSocket(socket_handle, "", static_cast<int>(loopback_index)));
    DWORD bound_index = 0;
    int option_size = sizeof(bound_index);
    assert(::getsockopt(socket_handle, IPPROTO_IP, IP_UNICAST_IF,
        reinterpret_cast<char*>(&bound_index), &option_size) == 0);
    assert(option_size == sizeof(bound_index));
    assert(bound_index == htonl(loopback_index));
    ::closesocket(socket_handle);
    ::WSACleanup();
#elif defined(_LINUX)
    assert(!IsClientUnderlyingSocketHandleValid(-1));
    assert(IsClientUnderlyingSocketProtectionSnapshotValid(true, "eth0", -1, false));
    assert(!IsClientUnderlyingSocketProtectionSnapshotValid(false, "eth0", -1, false));
    assert(!IsClientUnderlyingSocketProtectionSnapshotValid(true, "", -1, false));

    auto network_interface = std::make_shared<ClientNetworkInterface>();
    network_interface->Name = "lo";
    assert(BuildClientUnderlyingSocketProtector(
        true,
        network_interface,
        std::shared_ptr<ppp::net::ProtectorNetwork>()));
    assert(!BuildClientUnderlyingSocketProtector(
        false,
        network_interface,
        std::shared_ptr<ppp::net::ProtectorNetwork>()));

    const int socket_handle = ::socket(AF_INET, SOCK_STREAM, 0);
    assert(socket_handle >= 0);
    assert(!ProtectClientUnderlyingSocket(socket_handle, "", -1));
    assert(!ProtectClientUnderlyingSocket(-1, "lo", -1));
    ::close(socket_handle);
#elif defined(_MACOS) && !defined(_IPHONE) && !defined(IPHONE)
    assert(!IsClientUnderlyingSocketHandleValid(-1));
    assert(IsClientUnderlyingSocketProtectionSnapshotValid(true, "", 1, false));
    assert(!IsClientUnderlyingSocketProtectionSnapshotValid(true, "", 0, false));
    assert(!IsClientUnderlyingSocketProtectionSnapshotValid(false, "", 1, false));
#endif

    return 0;
}
