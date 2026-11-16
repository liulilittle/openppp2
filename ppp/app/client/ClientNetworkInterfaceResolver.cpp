#include <ppp/app/client/ClientNetworkInterfaceResolver.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>

#if defined(_WIN32)
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#include <ifaddrs.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#endif
#endif

using ppp::net::IPEndPoint;
using ppp::net::Ipep;

namespace ppp {
    namespace app {
        namespace client {

#if !defined(_ANDROID) && !defined(_IPHONE)

            namespace {

#if !defined(_WIN32)
                void CollectGlobalIPv6(const ppp::string& interface_name,
                    ppp::vector<boost::asio::ip::address>& output) noexcept {
                    if (interface_name.empty()) return;
                    struct ifaddrs* list = nullptr;
                    if (getifaddrs(&list) != 0) return;
                    for (auto* item = list; item; item = item->ifa_next) {
                        if (!item->ifa_name || interface_name != item->ifa_name || !item->ifa_addr ||
                            item->ifa_addr->sa_family != AF_INET6) continue;
                        const auto* address = reinterpret_cast<const sockaddr_in6*>(item->ifa_addr);
                        boost::asio::ip::address_v6::bytes_type bytes{};
                        std::copy(std::begin(address->sin6_addr.s6_addr),
                            std::end(address->sin6_addr.s6_addr), bytes.begin());
                        const auto value = boost::asio::ip::address_v6(bytes);
                        if (value.is_unspecified() || value.is_loopback() || value.is_multicast() ||
                            value.is_link_local() || (bytes[0] & 0xfe) == 0xfc) continue;
                        if (std::find(output.begin(), output.end(), value) == output.end())
                            output.emplace_back(value);
                    }
                    freeifaddrs(list);
                }
#endif

#if defined(_WIN32)
                /** @brief Builds network-interface snapshot from Windows adapter details. */
                std::shared_ptr<ClientNetworkInterface> GetNetworkInterface(
                    const ppp::win32::network::AdapterInterfacePtr& ai,
                    const ppp::win32::network::NetworkInterfacePtr& ni) noexcept {
                    if (NULLPTR == ai || NULLPTR == ni) {
                        return NULLPTR;
                    }

                    std::shared_ptr<ClientNetworkInterface> result = make_shared_object<ClientNetworkInterface>();
                    if (NULLPTR == result) {
                        return NULLPTR;
                    }

                    boost::system::error_code ec;
                    result->Id = ni->Guid;
                    result->Index = ai->IfIndex;
                    result->Name = ni->ConnectionId;
                    result->Description = ni->Description;
                    Ipep::StringsTransformToAddresses(ni->DnsAddresses, result->DnsAddresses);

                    result->IPAddress = StringToAddress(ai->Address.data(), ec);
                    result->SubmaskAddress = StringToAddress(ai->Mask.data(), ec);
                    result->GatewayServer = StringToAddress(ai->GatewayServer.data(), ec);
                    return result;
                }

                /** @brief Resolves network-interface snapshot by adapter interface. */
                std::shared_ptr<ClientNetworkInterface> GetNetworkInterface(
                    const ppp::win32::network::AdapterInterfacePtr& ai) noexcept {
                    if (NULLPTR == ai) {
                        return NULLPTR;
                    }

                    auto ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(ai->IfIndex);
                    return GetNetworkInterface(ai, ni);
                }
#else
                class UnixNetworkInterface final : public ClientNetworkInterface {
                public:
                    ppp::string DnsResolveConfiguration;
                };
#endif

            }

#if defined(_WIN32)
            std::shared_ptr<ClientNetworkInterface> ClientNetworkInterfaceResolver::GetTapNetworkInterface(
                const std::shared_ptr<ppp::tap::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULLPTR;
                }

                ppp::vector<ppp::win32::network::AdapterInterfacePtr> interfaces;
                if (ppp::win32::network::GetAllAdapterInterfaces(interfaces)) {
                    for (auto&& ai : interfaces) {
                        if (ai->IfIndex == interface_index) {
                            return GetNetworkInterface(ai);
                        }
                    }
                }

                return NULLPTR;
            }

            std::shared_ptr<ClientNetworkInterface> ClientNetworkInterfaceResolver::GetUnderlyingNetworkInterface(
                const std::shared_ptr<ppp::tap::ITap>& tap,
                const ppp::string& nic) noexcept {
                auto [ai, ni] = ppp::win32::network::GetUnderlyingNetowrkInterface2(tap->GetId(), nic);
                return GetNetworkInterface(ai, ni);
            }
#else
            std::shared_ptr<ClientNetworkInterface> ClientNetworkInterfaceResolver::GetTapNetworkInterface(
                const std::shared_ptr<ppp::tap::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULLPTR;
                }

                int dev_handle = (int)reinterpret_cast<std::intptr_t>(tap->GetHandle());
                if (dev_handle == -1) {
                    return NULLPTR;
                }

                ppp::string interface_name;
#if defined(_MACOS)
                if (!ppp::darwin::tun::utun_get_if_name(dev_handle, interface_name)) {
                    return NULLPTR;
                }
#else
                if (!ppp::tap::TapLinux::GetInterfaceName(dev_handle, interface_name)) {
                    return NULLPTR;
                }
#endif

                std::shared_ptr<ClientNetworkInterface> ni = make_shared_object<ClientNetworkInterface>();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

                ni->Index = interface_index;
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->GatewayServer, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->IPAddress, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->SubmaskAddress, IPEndPoint::MinPort)).address();

#if defined(_MACOS)
                ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                if (NULLPTR != darwin_tap) {
                    ni->DnsAddresses = darwin_tap->GetDnsAddresses();
                }
#else
                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);

                if (NULLPTR != linux_tap) {
                    ni->DnsAddresses = linux_tap->GetDnsAddresses();
                }
#endif
                return ni;
            }

            std::shared_ptr<ClientNetworkInterface> ClientNetworkInterfaceResolver::GetUnderlyingNetworkInterface(
                const std::shared_ptr<ppp::tap::ITap>& tap,
                const ppp::string& nic) noexcept {
                std::shared_ptr<UnixNetworkInterface> ni = make_shared_object<UnixNetworkInterface>();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

#if defined(_MACOS)
                using NetworkInterface = ppp::tap::TapDarwin::NetworkInterface;

                ppp::vector<NetworkInterface::Ptr> network_interfaces;
                if (!ppp::tap::TapDarwin::GetAllNetworkInterfaces(network_interfaces)) {
                    return NULLPTR;
                }

                NetworkInterface::Ptr network_interface = ppp::tap::TapDarwin::GetPreferredNetworkInterface2(network_interfaces, nic);
                if (NULLPTR == network_interface) {
                    return NULLPTR;
                }

                ni->Index = network_interface->Index;
                ni->Name = network_interface->Name;

                struct {
                    boost::asio::ip::address* address;
                    ppp::string* address_string;
                } addresses[] = {{&ni->GatewayServer, &network_interface->GatewayServer},
                    {&ni->IPAddress, &network_interface->IPAddress}, {&ni->SubmaskAddress, &network_interface->SubnetmaskAddress}};

                for (int i = 0; i < arraysizeof(addresses); i++) {
                    auto& r = addresses[i];
                    ppp::string* address_string = r.address_string;
                    if (address_string->empty()) {
                        continue;
                    }

                    boost::system::error_code ec;
                    *r.address = StringToAddress(address_string->data(), ec);
                    if (ec) {
                        return NULLPTR;
                    }
                }

                ni->DefaultRoutes = std::move(network_interface->GatewayAddresses);
                CollectGlobalIPv6(ni->Name, ni->IPv6Addresses);
#else
                ppp::string interface_name;
                ppp::UInt32 ip, gw, mask;
                if (!ppp::tap::TapLinux::GetPreferredNetworkInterface(interface_name, ip, mask, gw, nic)) {
                    return NULLPTR;
                }

                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);
                ni->Index = ppp::tap::TapLinux::GetInterfaceIndex(interface_name);
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(gw, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(ip, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(mask, IPEndPoint::MinPort)).address();
                CollectGlobalIPv6(interface_name, ni->IPv6Addresses);
#endif

                ni->DnsResolveConfiguration = ppp::unix__::UnixAfx::GetDnsResolveConfiguration();
                ppp::unix__::UnixAfx::GetDnsAddresses(ni->DnsResolveConfiguration, ni->DnsAddresses);
                return ni;
            }

            bool ClientNetworkInterfaceResolver::SetDnsResolveConfiguration(
                const std::shared_ptr<ClientNetworkInterface>& underlying_ni) noexcept {
                if (NULLPTR == underlying_ni) {
                    return false;
                }

                UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get());
                if (NULLPTR == ni) {
                    return false;
                }

                return ppp::unix__::UnixAfx::SetDnsResolveConfiguration(ni->DnsResolveConfiguration);
            }
#endif

#endif

        }
    }
}
