/**
 * @file PppApplicationInternal.h
 * @brief Internal declarations for PPP application startup and platform setup.
 */

#pragma once

#include <ppp/app/PppApplication.h>
#include <ppp/app/ConsoleUI.h>
#include <ppp/app/TcpStackMode.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/tap/ITap.h>
#include <ppp/tap/TapStub.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

#if defined(_WIN32)
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_IPHONE)
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ios/ppp/tap/TapIos.h>
#elif defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/diagnostics/UnixStackTrace.h>
#endif
#endif

#if defined(CURLINC_CURL)
#include <curl/curl.h>
#endif

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <common/aesni/aes.h>
#include <common/chnroutes2/chnroutes2.h>

namespace ppp {
namespace configurations {
class AppConfiguration;
}
namespace app {
namespace client {
class VEthernetExchanger;
class VEthernetNetworkSwitcher;
namespace proxys {
class VEthernetHttpProxySwitcher;
class VEthernetLocalProxySwitcher;
class VEthernetSocksProxySwitcher;
}
}
namespace server {
class VirtualEthernetSwitcher;
}
}
}

namespace ppp::app {

using ppp::configurations::AppConfiguration;
using ppp::threading::Executors;
using ppp::threading::Thread;
using ppp::threading::Timer;
using ppp::threading::BufferswapAllocator;
using ppp::tap::ITap;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::net::Socket;
using ppp::io::File;
using ppp::io::FileAccess;
using ppp::auxiliary::StringAuxiliary;
using ppp::Int128;

#if !defined(_WIN32) && !defined(_ANDROID) && !defined(_IPHONE)
#define SIGRESTART 64
#endif

struct NetworkInterface final {
    typedef ppp::unordered_set<ppp::string> BypassSet;

#if defined(_WIN32)
    uint32_t LeaseTimeInSeconds = 0;
    bool SetHttpProxy = false;
#else
    bool Promisc = false;
    int Ssmt = 0;
#if defined(_LINUX)
    bool SsmtMQ = false;
    bool ProtectNetwork = false;
#endif
#endif

    bool StaticMode = false;
    TcpStackMode TcpStack = TcpStackMode::Native;
    // Legacy compatibility mirror; TcpStack remains the authoritative value.
    bool Lwip = false;
    bool VNet = false;
    bool HostedNetwork = false;
    bool BlockQUIC = false;

    uint16_t Mux = 0;
    uint8_t MuxAcceleration = 0;

    const std::shared_ptr<BypassSet> Bypass;
#if defined(_LINUX)
    ppp::string BypassNic;
#endif
    boost::asio::ip::address BypassNgw;

    ppp::string ComponentId;
#if defined(_WIN32)
    ppp::string Wintun;
#endif

    ppp::string FirewallRules;
    ppp::string DNSRules;
    ppp::string Nic;

    ppp::vector<boost::asio::ip::address> DnsAddresses;
    /**
     * @brief Optional human-readable label aligned by index with DnsAddresses.
     *
     * When non-empty, the TUN status banner prefers this label over the raw
     * IP literal (for example "cloudflare-dns.com (DoH)" instead of
     * "1.1.1.1"). Empty entries fall back to the IP rendering. Populated by
     * GetDnsAddresses() when the value was derived from a structured
     * DnsServerEntry whose protocol is DoH or DoT and hostname is non-empty.
     */
    ppp::vector<ppp::string> DnsLabels;

    boost::asio::ip::address Ngw;
    boost::asio::ip::address IPAddress;
    boost::asio::ip::address IPv6Address;
    boost::asio::ip::address GatewayServer;
    boost::asio::ip::address SubmaskAddress;

    /**
     * @brief Gets the default TUN/TAP interface name for the current platform.
     * @return Default interface identifier string.
     */
    static ppp::string GetDefaultTun() noexcept;

    /**
     * @brief Loads bypass entries from a source string.
     * @param s Input string that describes bypass targets.
     * @return Number of loaded entries or an error code.
     */
    int BypassLoadList(const ppp::string& s) noexcept;

    NetworkInterface() noexcept
        : Bypass(ppp::make_shared_object<BypassSet>()) {}
};

struct ApplicationGlobals {
    using BypassSet = NetworkInterface::BypassSet;
    int link_restart = 0;
    int auto_restart = 0;
    ppp::string virr_argument;
    std::shared_ptr<BypassSet> bypass;
};

extern std::shared_ptr<PppApplication> DEFAULT_;
extern std::atomic<bool> GLOBAL_RESTART;
extern std::atomic<bool> GLOBAL_VBGP;
extern std::atomic<uint64_t> GLOBAL_VBGP_LAST;
extern std::atomic<bool> GLOBAL_VIRR;
extern std::atomic<uint64_t> GLOBAL_VIRR_NEXT;
extern ApplicationGlobals GLOBAL_;

/**
 * @brief Runs the application after pre-start preparation is complete.
 * @param app Application instance to execute.
 * @param prepared_status Result of environment preparation.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument values.
 * @return Process exit code.
 */
int RunPreparedApplication(const std::shared_ptr<PppApplication>& app, int prepared_status, int argc, const char* argv[]) noexcept;

#if defined(_WIN32)
/**
 * @brief Prepares Ethernet-related runtime environment on Windows.
 * @param network_interface Network interface configuration.
 * @return True on success, otherwise false.
 */
bool Windows_PreparedEthernetEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept;

/**
 * @brief Applies startup behavior for the Windows no-LSP option.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument values.
 * @return True if processing succeeds, otherwise false.
 */
bool Windows_NoLsp(int argc, const char* argv[]) noexcept;

/**
 * @brief Applies startup behavior for preferred Windows network settings.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument values.
 * @return True if processing succeeds, otherwise false.
 */
bool Windows_PreferredNetwork(int argc, const char* argv[]) noexcept;
#endif

} // namespace ppp::app
