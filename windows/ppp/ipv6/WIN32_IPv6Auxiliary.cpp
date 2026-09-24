#include <windows/ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/ipv6/IPv6ClientPolicy.h>
#include <ppp/diagnostics/Error.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>
#include <iphlpapi.h>

#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/NetworkInterface.h>

namespace ppp {
    namespace win32 {
        namespace ipv6 {
            namespace auxiliary {
                namespace {
                    using GatewayNeighborIdentity = ppp::ipv6::client_policy::GatewayNeighborIdentity;
                    using OwnershipMutation = ppp::ipv6::client_policy::OwnershipMutation;

                    static bool IsWintunContext(const ::ppp::ipv6::auxiliary::ClientContext& context) noexcept {
                        auto tap = dynamic_cast<ppp::tap::TapWindows*>(context.Tap);
                        return NULLPTR != tap && tap->IsWintunBackend();
                    }

                    static bool BuildGatewayNeighborRow(
                        int interface_index,
                        const boost::asio::ip::address_v6& gateway,
                        MIB_IPNET_ROW2& row) noexcept {
                        if (interface_index < 0 || gateway.is_unspecified() || gateway.is_multicast() || gateway.is_loopback()) {
                            return false;
                        }

                        MIB_IF_ROW2 interface_row{};
                        interface_row.InterfaceIndex = static_cast<NET_IFINDEX>(interface_index);
                        if (::GetIfEntry2(&interface_row) != NO_ERROR) {
                            return false;
                        }

                        row = {};
                        row.InterfaceLuid = interface_row.InterfaceLuid;
                        row.InterfaceIndex = interface_row.InterfaceIndex;
                        row.Address.Ipv6.sin6_family = AF_INET6;
                        const auto bytes = gateway.to_bytes();
                        memcpy(&row.Address.Ipv6.sin6_addr, bytes.data(), bytes.size());
                        row.Address.Ipv6.sin6_scope_id = static_cast<ULONG>(gateway.scope_id());
                        if (gateway.is_link_local() && row.Address.Ipv6.sin6_scope_id == 0) {
                            row.Address.Ipv6.sin6_scope_id = interface_row.InterfaceIndex;
                        }

                        static const UCHAR kWintunGatewayMac[] = { 0, 0, 0, 0, 0, 1 };
                        memcpy(row.PhysicalAddress, kWintunGatewayMac, sizeof(kWintunGatewayMac));
                        row.PhysicalAddressLength = sizeof(kWintunGatewayMac);
                        row.State = NlnsPermanent;
                        row.IsRouter = TRUE;
                        return true;
                    }

                    static GatewayNeighborIdentity ToGatewayNeighborIdentity(const MIB_IPNET_ROW2& row) noexcept {
                        GatewayNeighborIdentity identity;
                        memcpy(identity.Address.data(), &row.Address.Ipv6.sin6_addr, identity.Address.size());
                        identity.ScopeId = row.Address.Ipv6.sin6_scope_id;
                        identity.InterfaceLuid = row.InterfaceLuid.Value;
                        identity.InterfaceIndex = row.InterfaceIndex;
                        identity.PhysicalAddressLength = row.PhysicalAddressLength;
                        if (identity.PhysicalAddressLength <= identity.PhysicalAddress.size()) {
                            memcpy(identity.PhysicalAddress.data(), row.PhysicalAddress, identity.PhysicalAddressLength);
                        }
                        identity.IsRouter = row.IsRouter == TRUE;
                        identity.IsPermanent = row.State == NlnsPermanent;
                        return identity;
                    }

                    static bool IsEquivalentGatewayNeighbor(
                        const MIB_IPNET_ROW2& existing,
                        const MIB_IPNET_ROW2& expected) noexcept {
                        return existing.Address.si_family == AF_INET6 &&
                            expected.Address.si_family == AF_INET6 &&
                            ppp::ipv6::client_policy::IsExactGatewayNeighborMatch(
                                ToGatewayNeighborIdentity(existing),
                                ToGatewayNeighborIdentity(expected));
                    }

                    static OwnershipMutation AddWintunGatewayNeighbor(
                        int interface_index,
                        const boost::asio::ip::address_v6& gateway,
                        std::uint64_t& owned_interface_luid,
                        int& owned_interface_index) noexcept {
                        owned_interface_luid = 0;
                        owned_interface_index = -1;

                        MIB_IPNET_ROW2 expected;
                        if (!BuildGatewayNeighborRow(interface_index, gateway, expected)) {
                            return OwnershipMutation::Failed;
                        }

                        const NETIO_STATUS status = ::CreateIpNetEntry2(&expected);
                        bool query_succeeded = false;
                        bool equivalent = false;
                        if (status == ERROR_OBJECT_ALREADY_EXISTS) {
                            MIB_IPNET_ROW2 existing = expected;
                            query_succeeded = ::GetIpNetEntry2(&existing) == NO_ERROR;
                            equivalent = query_succeeded && IsEquivalentGatewayNeighbor(existing, expected);
                        }

                        const OwnershipMutation result = ppp::ipv6::client_policy::ClassifyCreateResult(
                            status, NO_ERROR, ERROR_OBJECT_ALREADY_EXISTS,
                            query_succeeded, equivalent);
                        if (result == OwnershipMutation::Changed) {
                            owned_interface_luid = expected.InterfaceLuid.Value;
                            owned_interface_index = static_cast<int>(expected.InterfaceIndex);
                        }
                        return result;
                    }

                    static bool DeleteOwnedWintunGatewayNeighbor(
                        int current_interface_index,
                        std::uint64_t owned_interface_luid,
                        int owned_interface_index,
                        const boost::asio::ip::address_v6& gateway) noexcept {
                        if (current_interface_index != owned_interface_index ||
                            owned_interface_luid == 0 || owned_interface_index < 0) {
                            return false;
                        }

                        MIB_IF_ROW2 current_interface{};
                        current_interface.InterfaceIndex = static_cast<NET_IFINDEX>(owned_interface_index);
                        if (::GetIfEntry2(&current_interface) != NO_ERROR ||
                            current_interface.InterfaceLuid.Value != owned_interface_luid ||
                            current_interface.InterfaceIndex != static_cast<NET_IFINDEX>(owned_interface_index)) {
                            return false;
                        }

                        MIB_IPNET_ROW2 expected;
                        if (!BuildGatewayNeighborRow(owned_interface_index, gateway, expected) ||
                            expected.InterfaceLuid.Value != owned_interface_luid ||
                            expected.InterfaceIndex != static_cast<NET_IFINDEX>(owned_interface_index)) {
                            return false;
                        }

                        MIB_IPNET_ROW2 existing = expected;
                        const NETIO_STATUS query_status = ::GetIpNetEntry2(&existing);
                        if (query_status == ERROR_NOT_FOUND) {
                            return true;
                        }
                        if (query_status != NO_ERROR || !IsEquivalentGatewayNeighbor(existing, expected)) {
                            return false;
                        }

                        const NETIO_STATUS delete_status = ::DeleteIpNetEntry2(&existing);
                        return delete_status == NO_ERROR || delete_status == ERROR_NOT_FOUND;
                    }

                    using UnicastAddressIdentity = ppp::ipv6::client_policy::UnicastAddressIdentity;

                    static bool BuildUnicastAddressRow(
                        int interface_index,
                        const boost::asio::ip::address_v6& address,
                        MIB_UNICASTIPADDRESS_ROW& row) noexcept {
                        if (interface_index < 0 || address.is_unspecified() || address.is_multicast() ||
                            address.is_loopback() || address.is_link_local()) {
                            return false;
                        }

                        MIB_IF_ROW2 interface_row{};
                        interface_row.InterfaceIndex = static_cast<NET_IFINDEX>(interface_index);
                        if (::GetIfEntry2(&interface_row) != NO_ERROR) {
                            return false;
                        }

                        ::InitializeUnicastIpAddressEntry(&row);
                        row.InterfaceLuid = interface_row.InterfaceLuid;
                        row.InterfaceIndex = interface_row.InterfaceIndex;
                        row.Address.Ipv6.sin6_family = AF_INET6;
                        const auto bytes = address.to_bytes();
                        memcpy(&row.Address.Ipv6.sin6_addr, bytes.data(), bytes.size());
                        row.Address.Ipv6.sin6_scope_id = static_cast<ULONG>(address.scope_id());
                        row.PrefixOrigin = IpPrefixOriginManual;
                        row.SuffixOrigin = IpSuffixOriginManual;
                        row.ValidLifetime = 0xffffffff;
                        row.PreferredLifetime = 0xffffffff;
                        row.OnLinkPrefixLength = ppp::ipv6::IPv6_MAX_PREFIX_LENGTH;
                        row.SkipAsSource = FALSE;
                        return true;
                    }

                    static UnicastAddressIdentity ToUnicastAddressIdentity(
                        const MIB_UNICASTIPADDRESS_ROW& row) noexcept {
                        UnicastAddressIdentity identity;
                        memcpy(identity.Address.data(), &row.Address.Ipv6.sin6_addr, identity.Address.size());
                        identity.ScopeId = row.Address.Ipv6.sin6_scope_id;
                        identity.InterfaceLuid = row.InterfaceLuid.Value;
                        identity.InterfaceIndex = row.InterfaceIndex;
                        identity.PrefixLength = row.OnLinkPrefixLength;
                        identity.PrefixOrigin = static_cast<std::uint32_t>(row.PrefixOrigin);
                        identity.SuffixOrigin = static_cast<std::uint32_t>(row.SuffixOrigin);
                        identity.SkipAsSource = row.SkipAsSource == TRUE;
                        return identity;
                    }

                    static bool IsEquivalentUnicastAddress(
                        const MIB_UNICASTIPADDRESS_ROW& existing,
                        const MIB_UNICASTIPADDRESS_ROW& expected) noexcept {
                        return existing.Address.si_family == AF_INET6 &&
                            expected.Address.si_family == AF_INET6 &&
                            ppp::ipv6::client_policy::IsExactUnicastAddressMatch(
                                ToUnicastAddressIdentity(existing),
                                ToUnicastAddressIdentity(expected));
                    }

                    static OwnershipMutation AddManagedUnicastAddress(
                        int interface_index,
                        const boost::asio::ip::address_v6& address,
                        UnicastAddressIdentity& owned_address) noexcept {
                        owned_address = {};

                        MIB_UNICASTIPADDRESS_ROW expected;
                        if (!BuildUnicastAddressRow(interface_index, address, expected)) {
                            return OwnershipMutation::Failed;
                        }

                        const NETIO_STATUS status = ::CreateUnicastIpAddressEntry(&expected);
                        bool query_succeeded = false;
                        bool equivalent = false;
                        if (status == ERROR_OBJECT_ALREADY_EXISTS) {
                            MIB_UNICASTIPADDRESS_ROW existing = expected;
                            query_succeeded = ::GetUnicastIpAddressEntry(&existing) == NO_ERROR;
                            equivalent = query_succeeded && IsEquivalentUnicastAddress(existing, expected);
                        }

                        const OwnershipMutation result = ppp::ipv6::client_policy::ClassifyCreateResult(
                            status, NO_ERROR, ERROR_OBJECT_ALREADY_EXISTS,
                            query_succeeded, equivalent);
                        if (result == OwnershipMutation::Changed) {
                            owned_address = ToUnicastAddressIdentity(expected);
                        }
                        return result;
                    }

                    static bool DeleteOwnedUnicastAddress(
                        int current_interface_index,
                        const boost::asio::ip::address_v6& address,
                        const UnicastAddressIdentity& owned_address) noexcept {
                        if (current_interface_index < 0 ||
                            owned_address.InterfaceLuid == 0 ||
                            owned_address.InterfaceIndex != static_cast<std::uint32_t>(current_interface_index)) {
                            return false;
                        }

                        MIB_IF_ROW2 current_interface{};
                        current_interface.InterfaceIndex = static_cast<NET_IFINDEX>(current_interface_index);
                        if (::GetIfEntry2(&current_interface) != NO_ERROR ||
                            current_interface.InterfaceLuid.Value != owned_address.InterfaceLuid ||
                            current_interface.InterfaceIndex != owned_address.InterfaceIndex) {
                            return false;
                        }

                        MIB_UNICASTIPADDRESS_ROW expected;
                        if (!BuildUnicastAddressRow(current_interface_index, address, expected) ||
                            !ppp::ipv6::client_policy::IsExactUnicastAddressMatch(
                                ToUnicastAddressIdentity(expected), owned_address)) {
                            return false;
                        }

                        MIB_UNICASTIPADDRESS_ROW existing = expected;
                        const NETIO_STATUS query_status = ::GetUnicastIpAddressEntry(&existing);
                        if (query_status == ERROR_NOT_FOUND) {
                            return true;
                        }
                        if (query_status != NO_ERROR ||
                            !ppp::ipv6::client_policy::IsExactUnicastAddressMatch(
                                ToUnicastAddressIdentity(existing), owned_address)) {
                            return false;
                        }

                        const NETIO_STATUS delete_status = ::DeleteUnicastIpAddressEntry(&existing);
                        return delete_status == NO_ERROR || delete_status == ERROR_NOT_FOUND;
                    }
                }

                void CaptureClientOriginalState(const ::ppp::ipv6::auxiliary::ClientContext& context, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    (void)nat_mode;
                    if (auto current_ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(context.InterfaceIndex); NULLPTR != current_ni) {
                        state.OriginalDnsServers = current_ni->DnsAddresses;
                    }
                }

                bool ApplyClientAddress(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    (void)gua_mode;
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty() ||
                        !address.is_v6() || prefix_length != ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    }

                    const boost::asio::ip::address_v6 address_v6 = address.to_v6();
                    if (address_v6.is_unspecified() || address_v6.is_multicast() ||
                        address_v6.is_loopback() || address_v6.is_link_local()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6AddressUnsafe);
                    }

                    UnicastAddressIdentity owned_address;
                    const OwnershipMutation result = AddManagedUnicastAddress(
                        context.InterfaceIndex, address_v6, owned_address);
                    if (result == OwnershipMutation::Failed) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                    }

                    std::string address_text = address.to_string();
                    state.Address.assign(address_text.data(), address_text.size());
                    state.AddressApplied = true;
                    state.AddressOwned = result == OwnershipMutation::Changed;
                    state.OwnedAddress = owned_address;
                    return true;
                }

                bool ApplyClientDefaultRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        return false;
                    }

                    if (nat_mode) {
                        state.DefaultRouteApplied = true;
                        state.DefaultRouteGateway.clear();
                        return true;
                    }
                    if (!gateway.is_v6()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayMissing);
                    }

                    const boost::asio::ip::address_v6 gateway_v6 = gateway.to_v6();
                    if (gateway_v6.is_unspecified() || gateway_v6.is_multicast() || gateway_v6.is_loopback()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayMissing);
                    }

                    std::string gateway_text = gateway.to_string();
                    ppp::string gateway_string(gateway_text.data(), gateway_text.size());
                    if (IsWintunContext(context)) {
                        std::uint64_t owned_interface_luid = 0;
                        int owned_interface_index = -1;
                        const OwnershipMutation neighbor_result = AddWintunGatewayNeighbor(
                            context.InterfaceIndex, gateway_v6,
                            owned_interface_luid, owned_interface_index);
                        if (neighbor_result == OwnershipMutation::Failed) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                        }
                        state.GatewayNeighborOwned = neighbor_result == OwnershipMutation::Changed;
                        state.GatewayNeighborInterfaceLuid = owned_interface_luid;
                        state.GatewayNeighborInterfaceIndex = owned_interface_index;
                    }

                    state.DefaultRouteApplied = true;
                    state.DefaultRouteGateway = std::move(gateway_string);
                    return true;
                }

                bool ApplyClientSubnetRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& prefix, int prefix_length, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (!nat_mode) {
                        return true;
                    }

                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty() || !prefix.is_v6()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        return false;
                    }

                    std::string prefix_std = prefix.to_string();
                    ppp::string prefix_str(prefix_std.data(), prefix_std.size());
                    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

                    ppp::string gateway_str;
                    if (gateway.is_v6()) {
                        std::string gw_std = gateway.to_string();
                        gateway_str.assign(gw_std.data(), gw_std.size());
                    }
                    elif (!nat_mode) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayMissing);
                    }

                    if (!ppp::win32::network::AddIPv6Route(context.InterfaceIndex, prefix_str, prefix_length, gateway_str, 0)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed);
                        return false;
                    }

                    state.SubnetRouteApplied = true;
                    state.SubnetRoutePrefix = prefix_str;
                    state.SubnetRoutePrefixLength = prefix_length;
                    state.SubnetRouteGateway = gateway_str;
                    return true;
                }

                bool ApplyClientDns(const ::ppp::ipv6::auxiliary::ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty() || dns_servers.empty()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed);
                    }

                    if (!ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, dns_servers)) {
                        ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, state.OriginalDnsServers);
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed);
                    }

                    state.DnsApplied = true;
                    state.DnsServers = dns_servers;
                    ppp::tap::TapWindows::DnsFlushResolverCache();
                    return true;
                }

                void RestoreClientConfiguration(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    (void)address;
                    (void)prefix_length;
                    (void)nat_mode;
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty()) {
                        return;
                    }

                    if (state.SubnetRouteApplied && !state.SubnetRoutePrefix.empty()) {
                        ppp::win32::network::DeleteIPv6Route(
                            context.InterfaceIndex,
                            state.SubnetRoutePrefix,
                            state.SubnetRoutePrefixLength,
                            state.SubnetRouteGateway);
                    }

                    if (state.GatewayNeighborOwned && !state.DefaultRouteGateway.empty()) {
                        boost::system::error_code ec;
                        const boost::asio::ip::address_v6 gateway =
                            boost::asio::ip::make_address_v6(state.DefaultRouteGateway.c_str(), ec);
                        if (!ec && DeleteOwnedWintunGatewayNeighbor(
                            context.InterfaceIndex,
                            state.GatewayNeighborInterfaceLuid,
                            state.GatewayNeighborInterfaceIndex,
                            gateway)) {
                            state.GatewayNeighborOwned = false;
                            state.GatewayNeighborInterfaceLuid = 0;
                            state.GatewayNeighborInterfaceIndex = -1;
                        }
                        else {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                        }
                    }

                    if (state.AddressOwned && !state.Address.empty()) {
                        boost::system::error_code ec;
                        const boost::asio::ip::address_v6 assigned_address =
                            boost::asio::ip::make_address_v6(state.Address.c_str(), ec);
                        if (!ec && DeleteOwnedUnicastAddress(
                            context.InterfaceIndex,
                            assigned_address,
                            state.OwnedAddress)) {
                            state.AddressOwned = false;
                            state.OwnedAddress = {};
                        }
                        else {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                        }
                    }

                    if (state.DnsApplied) {
                        ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, state.OriginalDnsServers);
                        ppp::tap::TapWindows::DnsFlushResolverCache();
                    }
                }
            }
        }
    }
}
