#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/WindowsIPv6Snapshot.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/dns/DnsController.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/net/IPEndPoint.h>

#include <chrono>

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#endif
#endif

using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            namespace {
                using VirtualEthernetInformationExtensions = ppp::app::protocol::VirtualEthernetInformationExtensions;

                /** @brief Returns whether current platform supports managed IPv6 operations. */
                bool ClientSupportsManagedIPv6() noexcept {
#if defined(_WIN32) || defined(_LINUX) || defined(_MACOS)
                    return true;
#else
                    return false;
#endif
                }

                /** @brief Clears restored state while preserving exact-owned cleanup retry records. */
                void ClearRestoredIPv6State(ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    const bool address_owned = state.AddressOwned;
                    const auto owned_address = state.OwnedAddress;
                    ppp::string address = address_owned ? std::move(state.Address) : ppp::string();
                    const bool neighbor_owned = state.GatewayNeighborOwned;
                    ppp::string gateway = neighbor_owned ? std::move(state.DefaultRouteGateway) : ppp::string();
                    const std::uint64_t interface_luid = state.GatewayNeighborInterfaceLuid;
                    const int interface_index = state.GatewayNeighborInterfaceIndex;
                    const bool subnet_route_pending = state.SubnetRouteApplied;
                    const ppp::string subnet_prefix = subnet_route_pending ? state.SubnetRoutePrefix : ppp::string();
                    const int subnet_prefix_length = state.SubnetRoutePrefixLength;
                    const ppp::string subnet_gateway = subnet_route_pending ? state.SubnetRouteGateway : ppp::string();
                    const bool dns_pending = state.DnsApplied;
                    const auto dns_servers = dns_pending ? state.DnsServers : ppp::vector<ppp::string>();
                    const auto original_dns_servers = dns_pending ? state.OriginalDnsServers : ppp::vector<ppp::string>();
                    const bool original_dns_automatic = dns_pending ? state.OriginalDnsAutomatic : false;
                    const ppp::string original_dns_configuration =
                        dns_pending ? state.OriginalDnsConfiguration : ppp::string();

                    state.Clear();
                    if (address_owned) {
                        state.AddressOwned = true;
                        state.OwnedAddress = owned_address;
                        state.Address = std::move(address);
                    }
                    if (neighbor_owned) {
                        state.GatewayNeighborOwned = true;
                        state.GatewayNeighborInterfaceLuid = interface_luid;
                        state.GatewayNeighborInterfaceIndex = interface_index;
                        state.DefaultRouteGateway = std::move(gateway);
                    }
                    if (subnet_route_pending) {
                        state.SubnetRouteApplied = true;
                        state.SubnetRoutePrefix = subnet_prefix;
                        state.SubnetRoutePrefixLength = subnet_prefix_length;
                        state.SubnetRouteGateway = subnet_gateway;
                    }
                    if (dns_pending) {
                        state.DnsApplied = true;
                        state.DnsServers = dns_servers;
                        state.OriginalDnsServers = original_dns_servers;
                        state.OriginalDnsAutomatic = original_dns_automatic;
                        state.OriginalDnsConfiguration = original_dns_configuration;
                    }
                }

#if defined(_WIN32)
                std::string SerializeAssignedIPv4Snapshot(
                    const ppp::string& guid, const ppp::string& luid, int interface_index,
                    const boost::asio::ip::address& address,
                    const boost::asio::ip::address& mask,
                    const boost::asio::ip::address& gateway) {
                    return "ipv4-v2|" + std::string(guid.data(), guid.size()) + "|" +
                        std::string(luid.data(), luid.size()) + "|" +
                        std::to_string(interface_index) + "|" +
                        (address.is_v4() ? address.to_string() : std::string()) + "|" +
                        (mask.is_v4() ? mask.to_string() : std::string()) + "|" +
                        (gateway.is_v4() ? gateway.to_string() : std::string());
                }

                std::string SerializeAssignedIPv6Snapshot(
                    const ppp::string& guid, int interface_index,
                    const VirtualEthernetInformationExtensions& extensions,
                    const ppp::ipv6::auxiliary::ClientState& state,
                    const ppp::vector<ppp::string>& dns_servers,
                    const ppp::string& interface_luid = ppp::string()) {
                    WindowsIPv6Snapshot snapshot;
                    snapshot.interface_index = interface_index < 0 ? 0 : static_cast<std::uint32_t>(interface_index);
                    snapshot.interface_guid.assign(guid.data(), guid.size());
                    snapshot.interface_luid.assign(interface_luid.data(), interface_luid.size());
                    snapshot.address = extensions.AssignedIPv6Address.is_v6() ? extensions.AssignedIPv6Address.to_string() : std::string();
                    snapshot.address_prefix_length = extensions.AssignedIPv6AddressPrefixLength;
                    snapshot.gateway = extensions.AssignedIPv6Gateway.is_v6() ? extensions.AssignedIPv6Gateway.to_string() : std::string();
                    snapshot.subnet_prefix = extensions.AssignedIPv6RoutePrefix.is_v6() ? extensions.AssignedIPv6RoutePrefix.to_string() : std::string();
                    snapshot.subnet_prefix_length = extensions.AssignedIPv6RoutePrefixLength;
                    snapshot.subnet_gateway = !state.SubnetRouteGateway.empty()
                        ? std::string(state.SubnetRouteGateway.data(), state.SubnetRouteGateway.size())
                        : std::string();
                    // The intent is persisted before ApplyClientSubnetRoute
                    // populates runtime ownership state. Preserve the
                    // negotiated next hop in that pre-write window.
                    if (snapshot.subnet_gateway.empty() && extensions.AssignedIPv6Gateway.is_v6()) {
                        snapshot.subnet_gateway = extensions.AssignedIPv6Gateway.to_string();
                    }
                    snapshot.mode = extensions.AssignedIPv6Mode;
                    snapshot.neighbor_interface_luid = state.GatewayNeighborInterfaceLuid;
                    snapshot.neighbor_interface_index = state.GatewayNeighborInterfaceIndex < 0 ? 0 : static_cast<std::uint32_t>(state.GatewayNeighborInterfaceIndex);
                    // This record is written before the first OS call.  The
                    // desired target, rather than the still-empty runtime
                    // ownership flags, must therefore describe resources that
                    // may have been partially applied when the process dies.
                    snapshot.address_owned = extensions.AssignedIPv6Address.is_v6();
                    snapshot.neighbor_owned = !extensions.AssignedIPv6Gateway.is_unspecified() &&
                        extensions.AssignedIPv6Gateway.is_v6() &&
                        extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                    snapshot.subnet_owned = extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66 &&
                        extensions.AssignedIPv6RoutePrefix.is_v6() && extensions.AssignedIPv6RoutePrefixLength > 0;
                    snapshot.dns_applied = !dns_servers.empty();
                    snapshot.original_dns_automatic = state.OriginalDnsAutomatic;
                    for (const auto& value : dns_servers) snapshot.dns_servers.emplace_back(value.data(), value.size());
                    for (const auto& value : state.OriginalDnsServers) snapshot.original_dns_servers.emplace_back(value.data(), value.size());
                    std::string serialized;
                    if (!SerializeWindowsIPv6Snapshot(snapshot, serialized)) return {};
                    return serialized;
                }

#endif
            }

            void AssignedAddressManager::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            /** @brief Applies managed IPv6 address, route, and DNS configuration. */
            bool AssignedAddressManager::ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept {
                if (!ClientSupportsManagedIPv6()) {
                    return false;
                }

                if (ipv6_applied_) {
                    return false;
                }

                auto tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                auto tun_ni = owner_->tun_ni_;
                if (NULLPTR == tun_ni) {
                    return false;
                }

                ppp::telemetry::SpanScope span("client.ipv6.apply");
                struct ScopedIPv6ApplyHistogram final {
                    std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                    ~ScopedIPv6ApplyHistogram() noexcept {
                        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                        ppp::telemetry::Histogram("client.ipv6.apply.us", elapsed);
                    }
                } ipv6_apply_histogram;


                bool nat_mode = extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66;
                bool gua_mode = extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                if (!nat_mode && !gua_mode) {
                    return false;
                }

                if (extensions.AssignedIPv6AddressPrefixLength != ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                    return false;
                }

                if (!extensions.AssignedIPv6Address.is_v6()) {
                    return false;
                }

                bool applied = true;
                bool attempted = false;
                if (ipv6_state_.HasPendingOwnedMutations()) {
                    // Do not overwrite exact ownership needed to retry cleanup while the TAP exists.
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                    return false;
                }
                ipv6_state_.Clear();

                ppp::ipv6::auxiliary::ClientContext ipv6_context;
                ipv6_context.Tap = tap.get();
                ipv6_context.InterfaceIndex = tun_ni->Index;
                ipv6_context.InterfaceName = tun_ni->Name;

                ppp::vector<ppp::string> dns_servers;
                if (extensions.AssignedIPv6Dns1.is_v6()) {
                    std::string dns1_std = extensions.AssignedIPv6Dns1.to_string();
                    dns_servers.emplace_back(dns1_std.data(), dns1_std.size());
                }
                if (extensions.AssignedIPv6Dns2.is_v6()) {
                    std::string dns2_std = extensions.AssignedIPv6Dns2.to_string();
                    dns_servers.emplace_back(dns2_std.data(), dns2_std.size());
                }

                // Capture the complete pre-mutation state before writing the
                // intent, so a crash between any later OS calls still has a
                // durable rollback baseline.
                ppp::ipv6::auxiliary::CaptureClientOriginalState(ipv6_context, nat_mode, ipv6_state_);

#if defined(_WIN32)
                // Persist an intent before the first IPv6 OS mutation.  The
                // standalone worker deliberately retains this resource until
                // a MIB snapshot codec can prove TAP identity across process
                // lifetimes; the durable record still prevents a new session
                // from overwriting unresolved IPv6 state.
                if (!owner_->EnsureNetworkRecoveryJournal() ||
                    !owner_->network_recovery_journal_ || tun_ni->Id.empty() ||
                    tun_ni->Index < 0) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                    return false;
                }
                const auto durable_ipv6_interface =
                    ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(tun_ni->Index);
                if (!durable_ipv6_interface || durable_ipv6_interface->Guid.empty() ||
                    _stricmp(durable_ipv6_interface->Guid.data(), tun_ni->Id.data()) != 0 ||
                    durable_ipv6_interface->InterfaceLuid.empty()) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                    return false;
                }
                ipv6_journal_target_ = tun_ni->Id;
                const std::string ipv6_snapshot = SerializeAssignedIPv6Snapshot(
                    tun_ni->Id, tun_ni->Index, extensions, ipv6_state_, dns_servers,
                    durable_ipv6_interface->InterfaceLuid);
                if (!owner_->network_recovery_journal_->RecordIntent(
                        "assigned-ipv6", stl::transform<std::string>(ipv6_journal_target_), ipv6_snapshot,
                        ipv6_snapshot, nullptr)) {
                    ipv6_journal_target_.clear();
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                    return false;
                }
                ipv6_journal_pending_ = true;
#endif

                int prefix = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH + 1, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, (int)extensions.AssignedIPv6AddressPrefixLength));
                if (prefix < 1) {
                    prefix = 64;
                }

                if (extensions.AssignedIPv6Address.is_v6()) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientAddress(ipv6_context, extensions.AssignedIPv6Address, prefix, gua_mode, ipv6_state_);
                }

                if (extensions.AssignedIPv6Gateway.is_v6() || nat_mode) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientDefaultRoute(ipv6_context, extensions.AssignedIPv6Gateway, nat_mode, ipv6_state_);
                }

                if (nat_mode && extensions.AssignedIPv6RoutePrefix.is_v6() &&
                    extensions.AssignedIPv6RoutePrefixLength > 0 &&
                    extensions.AssignedIPv6RoutePrefixLength < ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientSubnetRoute(
                        ipv6_context,
                        extensions.AssignedIPv6RoutePrefix,
                        extensions.AssignedIPv6RoutePrefixLength,
                        extensions.AssignedIPv6Gateway,
                        nat_mode,
                        ipv6_state_);
                }

                if (!dns_servers.empty()) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientDns(ipv6_context, dns_servers, ipv6_state_);
                }

                applied &= attempted;

                if (applied) {
#if defined(_WIN32)
                    if (!owner_->network_recovery_journal_->Confirm(
                            "assigned-ipv6", stl::transform<std::string>(ipv6_journal_target_), nullptr)) {
                        // The OS may already have changed state; leave the
                        // intent pending and force the rollback path.
                        applied = false;
                    }
#endif
                }

                if (applied) {
                    ipv6_applied_      = true;
                    // Memoize the successfully-applied address so that SendRequestedIPv6Configuration()
                    // can use it as a sticky hint on reconnect to re-request the same address when the
                    // user has not configured an explicit RequestedIPv6() preference.
                    last_assigned_ipv6_ = extensions.AssignedIPv6Address;
                    ppp::telemetry::Log(Level::kDebug, "client", "IPv6 applied");
                    ppp::telemetry::Count("client.ipv6.apply", 1);
                }
                else {
                    ppp::ipv6::auxiliary::RestoreClientConfiguration(ipv6_context, extensions.AssignedIPv6Address, prefix, nat_mode, ipv6_state_);
 #if defined(_WIN32)
                    if (ipv6_journal_pending_ &&
                        !ipv6_state_.HasPendingOwnedMutations() &&
                        owner_->network_recovery_journal_ &&
                        owner_->network_recovery_journal_->Remove(
                            "assigned-ipv6", stl::transform<std::string>(ipv6_journal_target_), nullptr)) {
                        ipv6_journal_pending_ = false;
                        ipv6_journal_target_.clear();
                    }
 #endif
                    ClearRestoredIPv6State(ipv6_state_);
                }

                return applied;
            }

            /** @brief Restores previous IPv6 configuration captured before apply. */
            void AssignedAddressManager::RestoreAssignedIPv6() noexcept {
                ppp::telemetry::SpanScope span("client.ipv6.restore");
                if (!ipv6_applied_ && !ipv6_state_.HasPendingOwnedMutations()
#if defined(_WIN32)
                    && !ipv6_journal_pending_
#endif
                ) {
                    return;
                }

                ppp::telemetry::Log(Level::kDebug, "client", "IPv6 removed");

                auto tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    ipv6_applied_ = false;
                    return;
                }

                auto tun_ni = owner_->tun_ni_;
                if (NULLPTR == tun_ni) {
                    ipv6_applied_ = false;
                    return;
                }

                int prefix = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH + 1, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, (int)owner_->information_extensions_->AssignedIPv6AddressPrefixLength));
                if (prefix < 1) {
                    prefix = 64;
                }

                ppp::ipv6::auxiliary::ClientContext ipv6_context;
                ipv6_context.Tap = tap.get();
                ipv6_context.InterfaceIndex = tun_ni->Index;
                ipv6_context.InterfaceName = tun_ni->Name;

                bool nat_mode = owner_->information_extensions_->AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66;
                auto started_at = std::chrono::steady_clock::now();
                ppp::ipv6::auxiliary::RestoreClientConfiguration(ipv6_context, owner_->information_extensions_->AssignedIPv6Address, prefix, nat_mode, ipv6_state_);

#if defined(_WIN32)
                if (ipv6_journal_pending_ &&
                    !ipv6_state_.HasPendingOwnedMutations() &&
                    owner_->network_recovery_journal_ &&
                    owner_->network_recovery_journal_->Remove(
                        "assigned-ipv6", stl::transform<std::string>(ipv6_journal_target_), nullptr)) {
                    ipv6_journal_pending_ = false;
                    ipv6_journal_target_.clear();
                }
#endif
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("client.ipv6.restore.us", elapsed);

                ipv6_applied_ = false;
                ClearRestoredIPv6State(ipv6_state_);
                // Failed exact-owned address or neighbor deletion remains available for retry.
                // The void platform API cannot guarantee cleanup after the TAP lifetime ends.
            }

            /** @brief Applies the server-assigned IPv4 address to the TAP interface. */
            bool AssignedAddressManager::ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept {
                if (ipv4_applied_) {
                    return false;
                }

                const auto& ipv4 = extensions.ClientIPv4Assign;
                if (!ipv4.enabled || !ipv4.accepted) {
                    return false;
                }

                if (ipv4.address.empty() || ipv4.mask.empty()) {
                    return false;
                }

                auto tun_ni = owner_->tun_ni_;
                if (NULLPTR == tun_ni || tun_ni->Name.empty()) {
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::ip::address addr = StringToAddress(ipv4.address.data(), ec);
                if (ec || !addr.is_v4()) {
                    return false;
                }

                uint32_t fake_network = 0;
                int fake_prefix = 0;
                if (owner_->dns_controller_ && owner_->dns_controller_->GetFakeIpRoute(fake_network, fake_prefix) &&
                    fake_prefix >= 0 && fake_prefix <= 32) {
                    const uint32_t mask_value = fake_prefix == 0 ? 0u : 0xffffffffu << (32 - fake_prefix);
                    if ((addr.to_v4().to_uint() & mask_value) == fake_network) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigFieldInvalid);
                    }
                }

                ec.clear();
                boost::asio::ip::address mask = StringToAddress(ipv4.mask.data(), ec);
                if (ec || !mask.is_v4()) {
                    return false;
                }

                ppp::telemetry::SpanScope span("client.ipv4.apply");
                struct ScopedIPv4ApplyHistogram final {
                    std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                    ~ScopedIPv4ApplyHistogram() noexcept {
                        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                        ppp::telemetry::Histogram("client.ipv4.apply.us", elapsed);
                    }
                } ipv4_apply_histogram;

#if defined(_WIN32)
                // Address changes need a durable intent before touching the
                // adapter. The GUID is the ownership identity; the index is
                // retained as an operational hint and is never used alone.
                if (!owner_->EnsureNetworkRecoveryJournal() ||
                    !owner_->network_recovery_journal_ ||
                    tun_ni->Id.empty() || tun_ni->Index < 0) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    return false;
                }
                const auto durable_ipv4_interface =
                    ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(tun_ni->Index);
                if (!durable_ipv4_interface || durable_ipv4_interface->Guid.empty() ||
                    _stricmp(durable_ipv4_interface->Guid.data(), tun_ni->Id.data()) != 0 ||
                    durable_ipv4_interface->InterfaceLuid.empty()) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    return false;
                }
                if (!static_ipv4_captured_) {
                    static_ipv4_address_ = tun_ni->IPAddress;
                    static_ipv4_gateway_ = tun_ni->GatewayServer;
                    static_ipv4_mask_ = tun_ni->SubmaskAddress;
                    static_ipv4_captured_ = true;
                }
                const std::string journal_before = SerializeAssignedIPv4Snapshot(
                    durable_ipv4_interface->Guid, durable_ipv4_interface->InterfaceLuid,
                    tun_ni->Index, static_ipv4_address_,
                    static_ipv4_mask_, static_ipv4_gateway_);
                ec.clear();
                boost::asio::ip::address journal_gateway = StringToAddress(ipv4.gateway.data(), ec);
                if (ec || !journal_gateway.is_v4()) {
                    journal_gateway = static_ipv4_gateway_;
                }
                const std::string journal_after = SerializeAssignedIPv4Snapshot(
                    durable_ipv4_interface->Guid, durable_ipv4_interface->InterfaceLuid,
                    tun_ni->Index, addr, mask,
                    journal_gateway);
                if (!owner_->network_recovery_journal_->RecordIntent(
                        "assigned-ipv4", stl::transform<std::string>(tun_ni->Id), journal_before,
                        journal_after, nullptr)) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    return false;
                }
                ipv4_journal_pending_ = true;
                ipv4_restore_verified_ = false;
                ipv4_journal_target_ = tun_ni->Id;
                // Treat an intent as owned even when the subsequent platform
                // call fails: WMI/adapter APIs can report failure after a
                // partial mutation and the record must remain retryable.
                ipv4_applied_ = true;
#endif

                bool applied = false;
#if defined(_LINUX)
                applied = ppp::tap::TapLinux::SetIPAddress(tun_ni->Name, ipv4.address, ipv4.mask);
#elif defined(_MACOS)
                {
                    ec.clear();
                    boost::asio::ip::address gw = StringToAddress(ipv4.gateway.data(), ec);
                    if (ec || !gw.is_v4()) {
                        return false;
                    }

                    std::string address_text = addr.to_v4().to_string();
                    std::string gateway_text = gw.to_v4().to_string();
                    std::string mask_text = mask.to_v4().to_string();

                    char cmd[1024];
                    snprintf(cmd, sizeof(cmd),
                        "ifconfig %s inet %s %s netmask %s up > /dev/null 2>&1",
                        tun_ni->Name.data(), address_text.data(), gateway_text.data(), mask_text.data());
                    applied = system(cmd) == 0;
                }
#elif defined(_WIN32)
                {
                    uint32_t nip = htonl(addr.to_v4().to_uint());
                    uint32_t nmask = htonl(mask.to_v4().to_uint());
                    ec.clear();
                    boost::asio::ip::address gw = StringToAddress(ipv4.gateway.data(), ec);
                    uint32_t ngw = (!ec && gw.is_v4()) ? htonl(gw.to_v4().to_uint()) : IPEndPoint::NoneAddress;
                    applied = ppp::tap::TapWindows::SetAddresses(tun_ni->Index, nip, nmask, ngw);
                }
#endif

                if (applied) {
                    ipv4_applied_ = true;
                    assigned_ipv4_address_ = addr;
                    assigned_ipv4_mask_ = mask;

                    ec.clear();
                    boost::asio::ip::address gw = StringToAddress(ipv4.gateway.data(), ec);
                    if (!ec && gw.is_v4()) {
                        assigned_ipv4_gateway_ = gw;
                    }

                    // Capture the static (config-time) IPv4 values once, before we
                    // overwrite the snapshots below.  RestoreAssignedIPv4 needs
                    // these to roll the interface back to its original address.
                    if (!static_ipv4_captured_) {
                        static_ipv4_address_  = tun_ni->IPAddress;
                        static_ipv4_gateway_  = tun_ni->GatewayServer;
                        static_ipv4_mask_     = tun_ni->SubmaskAddress;
                        static_ipv4_captured_ = true;
                    }

                    // Refresh the in-memory ITap and NetworkInterface snapshots so
                    // external consumers (status panels / IPC clients reading
                    // tun_ni_->IPAddress or tap->IPAddress) see the address that
                    // was actually programmed onto the kernel interface, not the
                    // static config IP captured at TAP creation.  Without these
                    // updates the UI keeps showing the pre-assignment value
                    // (e.g. 10.0.0.2/255.255.255.252) even when the live address
                    // is the dynamically-allocated one (e.g. 10.0.0.3/24).
                    tun_ni->IPAddress      = addr;
                    tun_ni->SubmaskAddress = mask;
                    if (!ec && gw.is_v4()) {
                        tun_ni->GatewayServer = gw;
                    }

                    if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                        tap->IPAddress      = htonl(addr.to_v4().to_uint());
                        tap->SubmaskAddress = htonl(mask.to_v4().to_uint());
                        if (!ec && gw.is_v4()) {
                            tap->GatewayServer = htonl(gw.to_v4().to_uint());
                        }
                    }

                    ppp::telemetry::Log(Level::kDebug, "client", "IPv4 applied: %s/%s gw=%s",
                        ipv4.address.c_str(), ipv4.mask.c_str(), ipv4.gateway.c_str());
                    ppp::telemetry::Count("client.ipv4.apply", 1);
                }

#if defined(_WIN32)
                if (applied) {
                    if (!owner_->network_recovery_journal_->Confirm(
                            "assigned-ipv4", stl::transform<std::string>(ipv4_journal_target_), nullptr)) {
                        // The OS mutation may have succeeded even when the
                        // durable confirmation failed. Keep ownership pending
                        // and force the caller down the rollback path.
                        applied = false;
                    }
                }
#endif

                return applied;
            }

            /** @brief Restores the original IPv4 configuration on the TAP interface. */
            void AssignedAddressManager::RestoreAssignedIPv4() noexcept {
                ppp::telemetry::SpanScope span("client.ipv4.restore");
                if (!ipv4_applied_ && !ipv4_journal_pending_) {
                    return;
                }

#if defined(_WIN32)
                // If the platform restore was already verified, a journal I/O
                // failure is the only remaining work. Do not write the old
                // address again after a user could have changed it.
                if (ipv4_restore_verified_) {
                    if (!owner_->network_recovery_journal_ ||
                        !owner_->network_recovery_journal_->Remove(
                            "assigned-ipv4", stl::transform<std::string>(ipv4_journal_target_), nullptr)) {
                        ppp::diagnostics::SetLastErrorCode(
                            ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                        return;
                    }
                    ipv4_journal_pending_ = false;
                    ipv4_journal_target_.clear();
                    ipv4_restore_verified_ = false;
                    if (auto restored_ni = owner_->tun_ni_; restored_ni) {
                        restored_ni->IPAddress = static_ipv4_address_;
                        restored_ni->SubmaskAddress = static_ipv4_mask_;
                        restored_ni->GatewayServer = static_ipv4_gateway_;
                    }
                    if (auto tap = owner_->GetTap(); tap) {
                        if (static_ipv4_address_.is_v4())
                            tap->IPAddress = htonl(static_ipv4_address_.to_v4().to_uint());
                        if (static_ipv4_mask_.is_v4())
                            tap->SubmaskAddress = htonl(static_ipv4_mask_.to_v4().to_uint());
                        if (static_ipv4_gateway_.is_v4())
                            tap->GatewayServer = htonl(static_ipv4_gateway_.to_v4().to_uint());
                    }
                    ipv4_applied_ = false;
                    assigned_ipv4_address_ = boost::asio::ip::address();
                    assigned_ipv4_gateway_ = boost::asio::ip::address();
                    assigned_ipv4_mask_ = boost::asio::ip::address();
                    static_ipv4_captured_ = false;
                    static_ipv4_address_ = boost::asio::ip::address();
                    static_ipv4_gateway_ = boost::asio::ip::address();
                    static_ipv4_mask_ = boost::asio::ip::address();
                    return;
                }
#endif

                ppp::telemetry::Log(Level::kDebug, "client", "IPv4 removed");

                auto tun_ni = owner_->tun_ni_;
                if (NULLPTR == tun_ni || tun_ni->Name.empty()) {
                    // Keep the ownership snapshot intact.  The TAP may be
                    // temporarily unavailable during teardown; clearing this
                    // state would make a later DisposeAttempt unable to retry.
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                    return;
                }

                // ApplyAssignedIPv4 overwrote tun_ni_->IPAddress with the dynamic
                // value, so the original (config-time) values needed for restore
                // come from the stash captured on the first Apply call.  Fall
                // back to the current tun_ni_ values when nothing was stashed
                // (e.g. Restore invoked without prior Apply).
                boost::asio::ip::address restore_addr = static_ipv4_captured_ ? static_ipv4_address_ : tun_ni->IPAddress;
                boost::asio::ip::address restore_mask = static_ipv4_captured_ ? static_ipv4_mask_    : tun_ni->SubmaskAddress;
                boost::asio::ip::address restore_gw   = static_ipv4_captured_ ? static_ipv4_gateway_ : tun_ni->GatewayServer;

                ppp::string orig_addr(restore_addr.is_v4() ? restore_addr.to_string().c_str() : "");
                ppp::string orig_mask(restore_mask.is_v4() ? restore_mask.to_string().c_str() : "");
                bool restored = false;
#if defined(_LINUX)
                if (!orig_addr.empty() && !orig_mask.empty()) {
                    restored = ppp::tap::TapLinux::SetIPAddress(tun_ni->Name, orig_addr, orig_mask);
                }
#elif defined(_MACOS)
                if (!orig_addr.empty() && !orig_mask.empty()) {
                    char cmd[1024];
                    snprintf(cmd, sizeof(cmd),
                        "ifconfig %s inet %s netmask %s up > /dev/null 2>&1",
                        tun_ni->Name.data(), orig_addr.data(), orig_mask.data());
                    restored = system(cmd) == 0;
                }
#elif defined(_WIN32)
                if (!orig_addr.empty() && !orig_mask.empty()) {
                    uint32_t nip = htonl(restore_addr.to_v4().to_uint());
                    uint32_t nmask = htonl(restore_mask.to_v4().to_uint());
                    uint32_t ngw = restore_gw.is_v4() ? htonl(restore_gw.to_v4().to_uint()) : IPEndPoint::NoneAddress;
                    restored = ppp::tap::TapWindows::SetAddresses(tun_ni->Index, nip, nmask, ngw);
                }
#endif

                if (!restored) {
                    // Do not publish the original snapshot to consumers until
                    // the platform confirms that the kernel operation worked.
                    // Keeping ipv4_applied_ true makes cleanup retryable and
                    // prevents teardown from releasing the TAP prematurely.
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                    return;
                }

#if defined(_WIN32)
                if (ipv4_journal_pending_) {
                    ipv4_restore_verified_ = true;
                    if (!owner_->network_recovery_journal_ ||
                        !owner_->network_recovery_journal_->Remove(
                            "assigned-ipv4", stl::transform<std::string>(ipv4_journal_target_), nullptr)) {
                        // The adapter is restored, but ownership cannot be
                        // durably committed. Retain the marker for retry.
                        ppp::diagnostics::SetLastErrorCode(
                            ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                        return;
                    }
                    ipv4_journal_pending_ = false;
                    ipv4_journal_target_.clear();
                    ipv4_restore_verified_ = false;
                }
#endif

                // Mirror the kernel-level restore by rolling back the in-memory
                // NetworkInterface and ITap snapshots to the original config-time
                // values, so status panels reflect the post-restore reality.
                tun_ni->IPAddress      = restore_addr;
                tun_ni->SubmaskAddress = restore_mask;
                tun_ni->GatewayServer  = restore_gw;

                if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                    if (restore_addr.is_v4()) {
                        tap->IPAddress = htonl(restore_addr.to_v4().to_uint());
                    }
                    if (restore_mask.is_v4()) {
                        tap->SubmaskAddress = htonl(restore_mask.to_v4().to_uint());
                    }
                    if (restore_gw.is_v4()) {
                        tap->GatewayServer = htonl(restore_gw.to_v4().to_uint());
                    }
                }

                ipv4_applied_ = false;
                assigned_ipv4_address_ = boost::asio::ip::address();
                assigned_ipv4_gateway_ = boost::asio::ip::address();
                assigned_ipv4_mask_ = boost::asio::ip::address();
                static_ipv4_captured_ = false;
                static_ipv4_address_ = boost::asio::ip::address();
                static_ipv4_gateway_ = boost::asio::ip::address();
                static_ipv4_mask_ = boost::asio::ip::address();

                auto elapsed = 0;
                ppp::telemetry::Histogram("client.ipv4.restore.us", elapsed);
                ppp::telemetry::Count("client.ipv4.restore", 1);
            }

#endif
        }
    }
}
