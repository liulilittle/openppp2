// Windows-side stubs for the aggregator_loader_test target.
//
// NetworkRecoveryJournal.cpp references the Windows platform recovery
// implementations (DNS, firewall, proxy, Wintun, IPv6) which are not linked
// into this offline test binary. The stubs return false so pending journal
// entries stay retryable, matching the journal contract: a callback failure
// is not an I/O error and must never remove a record.

#include <string>
#include <string_view>

#if defined(_WIN32)

#include <ppp/app/client/NetworkRecoveryJournal.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/win32/network/Router.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/tap/WintunAdapter.h>
#include <ppp/app/client/WindowsIPv6Snapshot.h>
#include <windows/ppp/ipv6/WindowsIPv6RouteOwner.h>

namespace ppp {


} // namespace ppp


namespace ppp::win32::network {

bool RestoreDnsSnapshot(const NetworkDnsSnapshot&) noexcept {
    return false;
}

std::shared_ptr<NetworkInterface> GetNetworkInterfaceByInterfaceIndex(int) noexcept {
    return nullptr;
}

bool Fw::RestoreApplicationOwned(const Fw::ApplicationOwnership&) noexcept {
    return false;
}

bool Fw::DeserializeApplicationOwnership(const std::string&, Fw::ApplicationOwnership*) noexcept {
    return false;
}

std::string Fw::ApplicationOwnershipTarget(const Fw::ApplicationOwnership&) {
    return std::string();
}

ppp::string GetInterfaceName(int) noexcept {
    return ppp::string();
}

bool SetDefaultIPGateway(int, const ppp::vector<ppp::string>&) noexcept {
    return false;
}

bool SetDefaultIPGateway(int, const ppp::vector<boost::asio::ip::address>&) noexcept {
    return false;
}

int Router::GetBestInterface(uint32_t) noexcept {
    return -1;
}

bool Router::GetBestRoute(uint32_t, MIB_IPFORWARDROW&) noexcept {
    return false;
}

bool Router::GetBestRoute(uint32_t, uint32_t, MIB_IPFORWARDROW&) noexcept {
    return false;
}

std::shared_ptr<MIB_IPFORWARDTABLE> Router::GetIpForwardTable() noexcept {
    return nullptr;
}

bool Router::Delete(MIB_IPFORWARDROW&) noexcept {
    return false;
}

bool Router::Add(uint32_t, uint32_t, int) noexcept {
    return false;
}

bool Router::Add(uint32_t, uint32_t, uint32_t, int) noexcept {
    return false;
}

bool Router::Add(uint32_t, uint32_t, uint32_t, int, int) noexcept {
    return false;
}

bool Router::Add(MIB_IPFORWARDROW&) noexcept {
    return false;
}

} // namespace ppp::win32::network

namespace ppp::net::proxies {

bool HttpProxy::RecoverSystemProxy() noexcept {
    return false;
}

} // namespace ppp::net::proxies

namespace ppp::tap {

bool TapWindows::SetAddresses(int, unsigned int, unsigned int, unsigned int) noexcept {
    return false;
}

} // namespace ppp::tap

bool WintunAdapter::RecoverPending() noexcept {
    return false;
}

namespace ppp::win32::ipv6 {

WindowsIPv6RouteOwner::~WindowsIPv6RouteOwner() noexcept {}

ppp::ipv6::client_policy::OwnershipMutation WindowsIPv6RouteOwner::Create(
    const ppp::ipv6::route_transaction::RouteIdentity&) noexcept {
    return ppp::ipv6::client_policy::OwnershipMutation{};
}

bool WindowsIPv6RouteOwner::Delete(
    const ppp::ipv6::route_transaction::RouteIdentity&) noexcept {
    return false;
}

namespace auxiliary {

bool RecoverClientSnapshot(const ppp::app::client::WindowsIPv6Snapshot&) noexcept {
    return false;
}

} // namespace auxiliary

} // namespace ppp::win32::ipv6

namespace ppp::app::client {

bool DeserializeWindowsIPv6Snapshot(std::string_view, WindowsIPv6Snapshot&) noexcept {
    return false;
}

bool VEthernetNetworkSwitcher::SetHttpProxyToSystemEnv() noexcept {
    return false;
}

bool VEthernetNetworkSwitcher::ClearHttpProxyToSystemEnv() noexcept {
    return false;
}

VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::NewPaperAirplaneController() noexcept {
    return nullptr;
}

} // namespace ppp::app::client

#endif // _WIN32
