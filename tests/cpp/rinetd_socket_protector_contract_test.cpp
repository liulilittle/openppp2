#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {
    std::string ReadAll(const std::string& path) {
        std::ifstream stream(path);
        std::ostringstream contents;
        contents << stream.rdbuf();
        return contents.str();
    }

    void Require(bool condition, const char* message) {
        if (!condition) {
            std::cerr << message << std::endl;
            std::exit(1);
        }
    }
}

int main(int argc, char* argv[]) {
    const std::string root = argc > 1 ? argv[1] : ".";
    const std::string open_source = ReadAll(
        root + "/ppp/net/rinetd/RinetdConnection.cpp");
    const std::string forwarding_source = ReadAll(
        root + "/ppp/app/client/VEthernetNetworkTcpipForwarding.inl");
    const std::string helper_source = ReadAll(
        root + "/ppp/app/client/ClientUnderlyingSocketProtector.h");

    const std::size_t open = open_source.find("async_open(y, *socket");
    const std::size_t required = open_source.find(
        "RemoteSocketProtectorRequired && !remote_socket_protector");
    const std::size_t protect = open_source.find(
        "remote_socket_protector(socket->native_handle(), y)");
    const std::size_t connect = open_source.find("async_connect(*socket");

    Require(open != std::string::npos, "remote socket open step is missing");
    Require(required != std::string::npos, "required protector missing check is absent");
    Require(protect != std::string::npos, "remote socket protector invocation is absent");
    Require(connect != std::string::npos, "remote socket connect step is missing");
    Require(open < required && required < protect && protect < connect,
        "protector must run after socket open and before connect");

    const std::size_t force = forwarding_source.find("if (force)");
    const std::size_t mark_required = forwarding_source.find(
        "RemoteSocketProtectorRequired = true", force);
    const std::size_t build = forwarding_source.find(
        "BuildClientUnderlyingSocketProtector", force);
    const std::size_t invoke_open = forwarding_source.find(
        "connection_rinetd->Open(remoteEP, y)", force);

    Require(force != std::string::npos, "ForceDirect setup branch is missing");
    Require(mark_required != std::string::npos,
        "ForceDirect does not mark socket protection required");
    Require(build != std::string::npos,
        "ForceDirect does not build the underlying socket protector");
    Require(invoke_open != std::string::npos,
        "Rinetd Open invocation is missing");
    Require(force < mark_required && mark_required < build && build < invoke_open,
        "ForceDirect protector must be configured before Rinetd Open");

    Require(forwarding_source.find(
        "if (!force && !switcher->IsBypassIpAddress") != std::string::npos,
        "LegacyAuto bypass gate changed unexpectedly");

    Require(helper_source.find("SO_BINDTODEVICE") != std::string::npos,
        "Linux per-socket interface binding is missing");
    Require(helper_source.find("IP_UNICAST_IF") != std::string::npos,
        "Windows per-socket interface binding is missing");
    Require(helper_source.find(
        "htonl(static_cast<DWORD>(interface_index))") != std::string::npos,
        "Windows interface index must use network byte order");
    Require(helper_source.find("IP_BOUND_IF") != std::string::npos,
        "macOS per-socket interface binding is missing");
    Require(helper_source.find("protector_network->Protect(socket, y)") !=
            std::string::npos,
        "Android must use the existing ProtectorNetwork path");

    return 0;
}
