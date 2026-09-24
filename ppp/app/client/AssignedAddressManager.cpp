#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
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
                }
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

                int prefix = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH + 1, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, (int)extensions.AssignedIPv6AddressPrefixLength));
                if (prefix < 1) {
                    prefix = 64;
                }

                ppp::ipv6::auxiliary::CaptureClientOriginalState(ipv6_context, nat_mode, ipv6_state_);

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

                ppp::vector<ppp::string> dns_servers;
                if (extensions.AssignedIPv6Dns1.is_v6()) {
                    std::string dns1_std = extensions.AssignedIPv6Dns1.to_string();
                    dns_servers.emplace_back(dns1_std.data(), dns1_std.size());
                }
                if (extensions.AssignedIPv6Dns2.is_v6()) {
                    std::string dns2_std = extensions.AssignedIPv6Dns2.to_string();
                    dns_servers.emplace_back(dns2_std.data(), dns2_std.size());
                }

                if (!dns_servers.empty()) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientDns(ipv6_context, dns_servers, ipv6_state_);
                }

                applied &= attempted;

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
                    ClearRestoredIPv6State(ipv6_state_);
                }

                return applied;
            }

            /** @brief Restores previous IPv6 configuration captured before apply. */
            void AssignedAddressManager::RestoreAssignedIPv6() noexcept {
                ppp::telemetry::SpanScope span("client.ipv6.restore");
                if (!ipv6_applied_ && !ipv6_state_.HasPendingOwnedMutations()) {
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
                        tap->IPAddress      = addr.to_v4().to_uint();
                        tap->SubmaskAddress = mask.to_v4().to_uint();
                        if (!ec && gw.is_v4()) {
                            tap->GatewayServer = gw.to_v4().to_uint();
                        }
                    }

                    ppp::telemetry::Log(Level::kDebug, "client", "IPv4 applied: %s/%s gw=%s",
                        ipv4.address.c_str(), ipv4.mask.c_str(), ipv4.gateway.c_str());
                    ppp::telemetry::Count("client.ipv4.apply", 1);
                }

                return applied;
            }

            /** @brief Restores the original IPv4 configuration on the TAP interface. */
            void AssignedAddressManager::RestoreAssignedIPv4() noexcept {
                ppp::telemetry::SpanScope span("client.ipv4.restore");
                if (!ipv4_applied_) {
                    return;
                }

                ppp::telemetry::Log(Level::kDebug, "client", "IPv4 removed");

                auto tun_ni = owner_->tun_ni_;
                if (NULLPTR == tun_ni || tun_ni->Name.empty()) {
                    ipv4_applied_ = false;
                    assigned_ipv4_address_ = boost::asio::ip::address();
                    assigned_ipv4_gateway_ = boost::asio::ip::address();
                    assigned_ipv4_mask_ = boost::asio::ip::address();
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
#if defined(_LINUX)
                if (!orig_addr.empty() && !orig_mask.empty()) {
                    ppp::tap::TapLinux::SetIPAddress(tun_ni->Name, orig_addr, orig_mask);
                }
#elif defined(_MACOS)
                if (!orig_addr.empty() && !orig_mask.empty()) {
                    char cmd[1024];
                    snprintf(cmd, sizeof(cmd),
                        "ifconfig %s inet %s netmask %s up > /dev/null 2>&1",
                        tun_ni->Name.data(), orig_addr.data(), orig_mask.data());
                    system(cmd);
                }
#elif defined(_WIN32)
                if (!orig_addr.empty() && !orig_mask.empty()) {
                    uint32_t nip = htonl(restore_addr.to_v4().to_uint());
                    uint32_t nmask = htonl(restore_mask.to_v4().to_uint());
                    uint32_t ngw = restore_gw.is_v4() ? htonl(restore_gw.to_v4().to_uint()) : IPEndPoint::NoneAddress;
                    ppp::tap::TapWindows::SetAddresses(tun_ni->Index, nip, nmask, ngw);
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
                        tap->IPAddress = restore_addr.to_v4().to_uint();
                    }
                    if (restore_mask.is_v4()) {
                        tap->SubmaskAddress = restore_mask.to_v4().to_uint();
                    }
                    if (restore_gw.is_v4()) {
                        tap->GatewayServer = restore_gw.to_v4().to_uint();
                    }
                }

                ipv4_applied_ = false;
                assigned_ipv4_address_ = boost::asio::ip::address();
                assigned_ipv4_gateway_ = boost::asio::ip::address();
                assigned_ipv4_mask_ = boost::asio::ip::address();

                auto elapsed = 0;
                ppp::telemetry::Histogram("client.ipv4.restore.us", elapsed);
                ppp::telemetry::Count("client.ipv4.restore", 1);
            }

#endif
        }
    }
}
