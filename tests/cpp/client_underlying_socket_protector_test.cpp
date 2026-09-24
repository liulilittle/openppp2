#include <ppp/app/client/ClientUnderlyingSocketProtector.h>

#include <cassert>

#if !defined(_WIN32)
#include <unistd.h>
#endif

int main() {
    using namespace ppp::app::client;

#if defined(_WIN32)
    assert(!IsClientUnderlyingSocketHandleValid(INVALID_SOCKET));
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
