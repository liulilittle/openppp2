#include <ppp/app/client/ClientNetworkInterfaceResolver.h>
#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/ClientConnectionTeardown.h>
#include <ppp/app/client/ClientConnectionOpener.h>
#include <ppp/app/client/ClientPacketDispatchHandler.h>
#include <ppp/app/client/xtcp/XtcpRuntime.h>
#include <ppp/app/client/ClientBypassRouteLoader.h>
#include <ppp/app/client/QuicRejectRateLimiter.h>
#include <ppp/app/client/PeerPrefixRouteManager.h>
#include <ppp/app/client/AggregatorLoader.h>
#include <ppp/app/client/RemoteEndpointLoader.h>
#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/app/client/dns/DnsController.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <common/aggligator/aggligator.h>
#include <ppp/IDisposable.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/ipv6/IPv6Packet.h>

#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/rib.h>

#include <ppp/net/asio/vdns.h>
#include <ppp/net/Ipep.h>

#include <chrono>

#if defined(_ANDROID)
#include <android/log.h>
#include <android/OpenPPP2VpnProtectBridge.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#endif

/**
 * @file VEthernetNetworkSwitcher.cpp
 * @brief Client-side virtual Ethernet network switcher implementation.
 * @details Licensed under GPL-3.0.
 */

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#include <windows/ppp/ipv6/WindowsIPv6RouteOwner.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/net/ProtectorNetwork.h>
#endif
#endif

/** @brief Validates whether extensions describe an applicable managed IPv6 assignment. */
static bool HasManagedIPv6Assignment(const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions) noexcept {
    bool status_ok = extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_Applied ||
        extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned ||
        extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_ClientRequested;

    return status_ok &&
        (extensions.AssignedIPv6Mode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
        extensions.AssignedIPv6Mode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Mode_Gua) &&
        extensions.AssignedIPv6AddressPrefixLength == ppp::ipv6::IPv6_MAX_PREFIX_LENGTH &&
        extensions.AssignedIPv6Address.is_v6() &&
        !extensions.AssignedIPv6Address.is_unspecified() &&
        !extensions.AssignedIPv6Address.is_multicast() &&
        !extensions.AssignedIPv6Address.is_loopback();
}

/** @brief Compares two managed IPv6 assignment snapshots for equality. */
static bool SameManagedIPv6Configuration(
    const ppp::app::protocol::VirtualEthernetInformationExtensions& left,
    const ppp::app::protocol::VirtualEthernetInformationExtensions& right) noexcept {

    return left.AssignedIPv6Mode == right.AssignedIPv6Mode &&
        left.AssignedIPv6AddressPrefixLength == right.AssignedIPv6AddressPrefixLength &&
        left.AssignedIPv6Flags == right.AssignedIPv6Flags &&
        left.AssignedIPv6Address == right.AssignedIPv6Address &&
        left.AssignedIPv6Gateway == right.AssignedIPv6Gateway &&
        left.AssignedIPv6RoutePrefix == right.AssignedIPv6RoutePrefix &&
        left.AssignedIPv6RoutePrefixLength == right.AssignedIPv6RoutePrefixLength &&
        left.AssignedIPv6Dns1 == right.AssignedIPv6Dns1 &&
        left.AssignedIPv6Dns2 == right.AssignedIPv6Dns2;
}

using ppp::auxiliary::StringAuxiliary;
using ppp::collections::Dictionary;
using ppp::threading::Timer;
using ppp::threading::Executors;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::net::Ipep;
using ppp::net::native::ip_hdr;
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;
using ppp::net::packet::BufferSegment;
using ppp::transmissions::ITransmission;
using ppp::transmissions::proxys::IForwarding;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {
            VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
                : VEthernetNetworkSwitcher(context, lwip ? ppp::app::TcpStackMode::Lwip : ppp::app::TcpStackMode::Native, vnet, mta, configuration) {
            }

            /** @brief Constructs network switcher and freezes the selected TCP stack mode. */
            VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, ppp::app::TcpStackMode tcp_stack_mode, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
                : VEthernet(context, tcp_stack_mode == ppp::app::TcpStackMode::Lwip, vnet, mta)
                , configuration_(configuration)
                , tcp_stack_mode_(tcp_stack_mode)
                , dns_controller_(std::make_shared<dns::DnsController>(
                    std::make_unique<dns::DnsInterceptor>(), nullptr))
                , route_coordinator_(std::make_unique<route::RouteCoordinator>(nullptr))
                , address_manager_(std::make_unique<AssignedAddressManager>())
                , teardown_(std::make_unique<ClientConnectionTeardown>())
                , connection_opener_(std::make_unique<ClientConnectionOpener>())
                , packet_dispatch_(std::make_unique<ClientPacketDispatchHandler>())
                , bypass_loader_(std::make_unique<ClientBypassRouteLoader>())
                , quic_reject_limiter_(std::make_unique<QuicRejectRateLimiter>())
                , peer_prefix_routes_(std::make_unique<PeerPrefixRouteManager>())
                , aggregator_loader_(std::make_unique<AggregatorLoader>())
                , remote_endpoint_loader_(std::make_unique<RemoteEndpointLoader>())
                , timeout_registry_(std::make_unique<SwitcherTimeoutRegistry>())
                , information_extensions_(std::make_unique<VirtualEthernetInformationExtensions>())
                , icmppackets_aid_(0) {

                address_manager_->Bind(this);
                teardown_->Bind(this);
                connection_opener_->Bind(this);
                packet_dispatch_->Bind(this);
                bypass_loader_->Bind(this);
                peer_prefix_routes_->Bind(this);
                aggregator_loader_->Bind(this);
                remote_endpoint_loader_->Bind(this);
                timeout_registry_->Bind(&GetSynchronizedObject());

#if defined(_WIN32)
                windows_ipv6_route_owner_ = std::make_unique<ppp::win32::ipv6::WindowsIPv6RouteOwner>();
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_LINUX)
                protect_mode_    = false;
#endif
#endif
                static_mode_     = false;
                block_quic_      = false;
                icmppackets_aid_ = RandomNext();
            }

            /** @brief Finalizes network switcher on destruction. */
            VEthernetNetworkSwitcher::~VEthernetNetworkSwitcher() noexcept {
                Finalize();
            }

#if defined(_WIN32)
            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::GetPaperAirplaneController() noexcept {
                return paper_airplane_ctrl_;
            }
#elif defined(_LINUX)
            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::GetProtectorNetwork() noexcept {
                return protect_network_;
            }
#endif

            std::shared_ptr<ppp::configurations::AppConfiguration> VEthernetNetworkSwitcher::GetConfiguration() noexcept {
                return configuration_;
            }

            ppp::app::TcpStackMode VEthernetNetworkSwitcher::GetTcpStackMode() const noexcept {
                return tcp_stack_mode_;
            }

            std::shared_ptr<const routing::HumanRoutingRules> VEthernetNetworkSwitcher::GetHumanRoutingRulesSnapshot() const noexcept {
                std::shared_ptr<dns::DnsController> controller = dns_controller_;
                return controller ? controller->GetHumanRoutingRules() : nullptr;
            }

            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::GetExchanger() noexcept {
                return exchanger_;
            }

            bool VEthernetNetworkSwitcher::GetTapRuntimeStats(ppp::tap::TapRuntimeStats& stats) noexcept {
#if defined(_LINUX)
                const std::shared_ptr<ppp::tap::ITap> tap = GetTap();
                const auto* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                return linux_tap != NULLPTR && linux_tap->GetRuntimeStats(stats);
#else
                (void)stats;
                return false;
#endif
            }

            bool VEthernetNetworkSwitcher::GetXtcpRuntimeStats(ppp::app::runtime::RuntimeXtcpStats& stats) noexcept {
                if (tcp_stack_mode_ != ppp::app::TcpStackMode::Xtcp) {
                    return false;
                }
                const std::shared_ptr<xtcp::XtcpRuntime> runtime = xtcp_runtime_;
                if (NULLPTR == runtime) {
                    return false;
                }
                stats = runtime->SnapshotStats();
                return true;
            }

            ppp::app::runtime::RuntimeReadiness VEthernetNetworkSwitcher::GetRuntimeReadiness() noexcept {
                ppp::app::runtime::ClientRuntimeReadinessFacts facts;
                const std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                const std::shared_ptr<ppp::tap::ITap> tap = GetTap();
                const route::RouteStateSnapshot route_snapshot = route_coordinator_->Snapshot();
                facts.session_established = exchanger &&
                    exchanger->GetNetworkState() == VEthernetExchanger::NetworkState_Established;
                facts.adapter_open = tap && tap->IsOpen();
#if defined(_ANDROID) || defined(_IPHONE)
                facts.route_required = !proxy_only_;
#else
                facts.route_required = !proxy_only_ && tap && tap->IsHostedNetwork();
#endif
                facts.route_applied = route_snapshot.applied;
                facts.dns_required = !proxy_only_;
                facts.dns_configured = dns_controller_ && dns_controller_->IsConfigured();
                facts.dns_session_active = dns_controller_ && dns_controller_->HasActiveSession();
                // INFO is optional for unmanaged compatibility sessions. The
                // switcher is published only after Open() has applied policy.
                facts.policy_negotiated = facts.session_established;
                ppp::app::runtime::RuntimeReadiness readiness =
                    ppp::app::runtime::BuildClientRuntimeReadiness(facts);
                if (tcp_stack_mode_ == ppp::app::TcpStackMode::Xtcp) {
                    const std::shared_ptr<xtcp::XtcpRuntime> runtime = xtcp_runtime_;
                    readiness.policy = readiness.policy && runtime && runtime->IsReady();
                }
                return readiness;
            }

            void VEthernetNetworkSwitcher::RequestedIPv6(const ppp::string& value) noexcept {
                requested_ipv6_ = value;
            }

            ppp::string VEthernetNetworkSwitcher::RequestedIPv6() noexcept {
                return requested_ipv6_;
            }

            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::GetQoS() noexcept {
                return qos_;
            }

            std::shared_ptr<ppp::transmissions::ITransmissionStatistics> VEthernetNetworkSwitcher::GetStatistics() noexcept {
                return statistics_;
            }

            VEthernetNetworkSwitcher::VirtualEthernetInformationExtensions VEthernetNetworkSwitcher::GetInformationExtensions() noexcept {
                return *information_extensions_;
            }

            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::GetHttpProxy() noexcept {
                return http_proxy_;
            }

            VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::GetSocksProxy() noexcept {
                return socks_proxy_;
            }

            VEthernetNetworkSwitcher::RouteInformationTablePtr VEthernetNetworkSwitcher::GetRib() noexcept {
                return route_coordinator_->Snapshot().rib;
            }

            VEthernetNetworkSwitcher::ForwardInformationTablePtr VEthernetNetworkSwitcher::GetFib() noexcept {
                return route_coordinator_->Snapshot().fib;
            }

            VEthernetNetworkSwitcher::IForwardingPtr VEthernetNetworkSwitcher::GetForwarding() noexcept {
                return forwarding_;
            }

#if defined(_WIN32)
            bool VEthernetNetworkSwitcher::BindWindowsIPv6RouteOwner() noexcept {
                return windows_ipv6_route_owner_ && tun_ni_ && underlying_ni_ &&
                    windows_ipv6_route_owner_->BindInterfaces(tun_ni_->Index, underlying_ni_->Index);
            }

            bool VEthernetNetworkSwitcher::StageWindowsIPv6Egress(
                const boost::asio::ip::tcp::endpoint& endpoint,
                bool proven_external) noexcept {
                return windows_ipv6_route_owner_ &&
                    windows_ipv6_route_owner_->StageEgressEndpoint(endpoint, proven_external);
            }

            bool VEthernetNetworkSwitcher::EnsureWindowsIPv6Sink() noexcept {
                return windows_ipv6_route_owner_ && windows_ipv6_route_owner_->EnsureSinkMode();
            }

            bool VEthernetNetworkSwitcher::ActivateWindowsManagedIPv6(
                const boost::asio::ip::address& gateway,
                bool nat_mode) noexcept {
                return windows_ipv6_route_owner_ &&
                    windows_ipv6_route_owner_->ActivateManagedMode(gateway, nat_mode);
            }

            bool VEthernetNetworkSwitcher::CommitWindowsIPv6Egress() noexcept {
                return windows_ipv6_route_owner_ && windows_ipv6_route_owner_->CommitStagedPin();
            }

            bool VEthernetNetworkSwitcher::RollbackWindowsIPv6Egress() noexcept {
                return !windows_ipv6_route_owner_ || windows_ipv6_route_owner_->RollbackStagedPin();
            }

            bool VEthernetNetworkSwitcher::StopWindowsIPv6Routes() noexcept {
                return !windows_ipv6_route_owner_ || windows_ipv6_route_owner_->Stop();
            }

            bool VEthernetNetworkSwitcher::HasActiveWindowsIPv6Takeover() const noexcept {
                return windows_ipv6_route_owner_ && windows_ipv6_route_owner_->HasActiveTakeover();
            }

            bool VEthernetNetworkSwitcher::HasPendingWindowsIPv6Cleanup() const noexcept {
                return windows_ipv6_route_owner_ && windows_ipv6_route_owner_->HasPendingCleanup();
            }
#endif

            std::shared_ptr<aggligator::aggligator> VEthernetNetworkSwitcher::GetAggligator() noexcept {
                return aggligator_;
            }

            VEthernetNetworkSwitcher::RouteIPListTablePtr VEthernetNetworkSwitcher::GetVbgp() noexcept {
                return vbgp_;
            }

            bool VEthernetNetworkSwitcher::IsBlockQUIC() noexcept {
                return block_quic_;
            }

            bool VEthernetNetworkSwitcher::IsMuxEnabled() noexcept {
                return mux_ > 0;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            std::shared_ptr<ClientNetworkInterface> VEthernetNetworkSwitcher::GetTapNetworkInterface() noexcept {
                return tun_ni_;
            }

            std::shared_ptr<ClientNetworkInterface> VEthernetNetworkSwitcher::GetUnderlyingNetworkInterface() noexcept {
                return underlying_ni_;
            }
#endif

            bool VEthernetNetworkSwitcher::IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept {
                return ip == gw ? true : htonl((ntohl(gw) & ntohl(mask)) + 1) == ip;
            }

            route::RoutePlanInput VEthernetNetworkSwitcher::BuildRoutePlanInput() noexcept {
                route::RoutePlanInput input;
                if (const std::shared_ptr<ppp::tap::ITap> tap = GetTap(); tap) {
                    input.tap_ip = tap->IPAddress;
                    input.tap_gateway = tap->GatewayServer;
                    input.tap_submask = tap->SubmaskAddress;
                    input.tap_hosted = tap->IsHostedNetwork();
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    if (auto* platform_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get())) {
                        input.tap_promiscuous = platform_tap->IsPromisc();
                    }
#elif defined(_MACOS)
                    if (auto* platform_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get())) {
                        input.tap_promiscuous = platform_tap->IsPromisc();
                    }
#endif
                }

                auto copy_interface = [](const std::shared_ptr<ClientNetworkInterface>& source) {
                    route::RouteInterfaceSnapshot target;
                    if (!source) return target;
                    target.name.assign(source->Name.begin(), source->Name.end());
                    target.index = source->Index;
                    target.ip = source->IPAddress;
                    target.gateway = source->GatewayServer;
                    target.submask = source->SubmaskAddress;
                    target.dns.assign(source->DnsAddresses.begin(), source->DnsAddresses.end());
                    return target;
                };
#if !defined(_ANDROID) && !defined(_IPHONE)
                input.tap_interface = copy_interface(tun_ni_);
                input.underlying_interface = copy_interface(underlying_ni_);
#endif
                for (const auto& pair : route_coordinator_->Snapshot().nics) {
                    input.nics.emplace(pair.first, std::string(pair.second.begin(), pair.second.end()));
                }
#if defined(_ANDROID) || defined(_IPHONE)
                if (configuration_) {
                    // Mobile RouteCoordinator loads these files into the native
                    // RIB/FIB; it does not use the desktop AddLoadIPList API.
                    const auto& routes = configuration_->client.routing.configured
                        ? configuration_->client.routing.routes
                        : configuration_->client.routes;
                    input.route_sources.reserve(routes.size());
                    for (const auto& route : routes) {
                        route::RouteSource source;
                        source.path.assign(route.path.begin(), route.path.end());
                        source.gateway = route.ngw;
                        if (!source.path.empty()) {
                            input.route_sources.emplace_back(std::move(source));
                        }
                    }
                }
#endif
                // DNS reachability routes belong to the TUN/native interception
                // path. Proxy-only keeps the rule table available to the client
                // policy, but must not turn those rules into tunnel DNS routes.
                if (!proxy_only_ && dns_controller_ && configuration_) {
                    dns_controller_->CollectReachabilityIps(
                        configuration_,
                        configuration_->dns.intercept_unmatched,
                        [&input](uint32_t ip) noexcept { input.tunnel_dns.emplace(ip); },
                        [&input](uint32_t ip) noexcept { input.underlying_dns.emplace(ip); });
                    if (const auto human_rules = dns_controller_->GetHumanRoutingRules(); human_rules) {
                        input.human_ipv4_rules = human_rules->Ipv4Cidrs();
                    }
                    input.has_fake_ip_route = dns_controller_->GetFakeIpRoute(
                        input.fake_ip_route.network, input.fake_ip_route.prefix);
                    input.fake_ip_route.gateway = input.tap_gateway;
                }
                return input;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            boost::asio::ip::address VEthernetNetworkSwitcher::LastAssignedIPv6() noexcept {
                return address_manager_->LastAssignedIPv6();
            }

            bool VEthernetNetworkSwitcher::TryApplyHostedNetworkRoutes() noexcept {
                route::RoutePlanInput input = BuildRoutePlanInput();
                if (!input.tap_hosted) return true;
                const route::RouteStateSnapshot snapshot = route_coordinator_->Snapshot();
                if (snapshot.applied) return true;
                const bool established = exchanger_ &&
                    exchanger_->GetNetworkState() == VEthernetExchanger::NetworkState_Established;
                if (route::RouteCoordinator::ShouldDeferHostedRouteApply(snapshot.apply_ready, established)) {
                    ppp::telemetry::Count("client.route.defer", 1);
                    return true;
                }
                if (!route_coordinator_->AddRoute(input)) return false;
#if defined(_WIN32)
                if (!UsePaperAirplaneController()) {
                    route_coordinator_->DeleteRoute();
                    return false;
                }
#endif
                {
                    ppp::telemetry::SpanScope span("client.dns.apply");
#if defined(_WIN32)
                    if (tun_ni_) {
                        ppp::win32::network::SetAllNicsDnsAddresses(tun_ni_->DnsAddresses, ni_dns_servers_);
                    }
                    ppp::tap::TapWindows::DnsFlushResolverCache();
                    if (underlying_ni_) {
                        ppp::win32::network::DeleteAllDefaultGatewayRoutes(underlying_ni_->GatewayServer);
                    }
#else
                    if (tun_ni_) ppp::unix__::UnixAfx::SetDnsAddresses(tun_ni_->DnsAddresses);
#endif
                }
                ppp::telemetry::Count("client.dns.setup", 1);
                route_coordinator_->ProtectDefaultRoute(input);
                return true;
            }
#endif

            /** @brief Creates concrete TCP/IP stack implementation for VEthernet. */
            std::shared_ptr<ppp::ethernet::VNetstack> VEthernetNetworkSwitcher::NewNetstack() noexcept {
                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetNetworkTcpipStack>(self);
            }

            /** @brief Performs periodic tick maintenance for QoS, exchanger, and timers. */
            bool VEthernetNetworkSwitcher::OnTick(uint64_t now) noexcept {
                if (!VEthernet::OnTick(now)) {
                    return false;
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULLPTR != qos) {
                    qos->Update(now);
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR != exchanger) {
                    exchanger->Update();
                }

                std::shared_ptr<IForwarding> forwarding = forwarding_;
                if (NULLPTR != forwarding) {
                    forwarding->Update(now);
                }

                ppp::vector<int> releases_icmppackets;
                for (;;) {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    for (auto&& kv : icmppackets_) {
                        const VEthernetIcmpPacket& icmppacket = kv.second;
                        if (icmppacket.datetime > now) {
                            continue;
                        }

                        releases_icmppackets.emplace_back(kv.first);
                    }

                    for (int ack_id : releases_icmppackets) {
                        ppp::collections::Dictionary::RemoveValueByKey(icmppackets_, ack_id);
                    }

                    break;
                }

                VEthernetTickEventHandler tick_event = TickEvent;
                if (tick_event) {
                    tick_event(this, now);
                }

                return true;
            }

            /** @brief Allows complete TCPv4 GSO delivery only while the XTCP runtime is ready. */
            bool VEthernetNetworkSwitcher::CanConsumeTcpV4Gso() noexcept {
                if (tcp_stack_mode_ != ppp::app::TcpStackMode::Xtcp) {
                    return false;
                }
                const std::shared_ptr<xtcp::XtcpRuntime> runtime = xtcp_runtime_;
                return runtime && runtime->IsReady();
            }

            /** @brief Handles native IPv4 packet input and forwards eligible NAT traffic. */
            bool VEthernetNetworkSwitcher::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept {
                if (packet_dispatch_->OnPacketInput(
                        packet, packet_length, header_length, proto, vnet)) {
                    return true;
                }
                if (tcp_stack_mode_ == ppp::app::TcpStackMode::Xtcp &&
                    proto == ppp::net::native::ip_hdr::IP_PROTO_TCP) {
                    const std::shared_ptr<xtcp::XtcpRuntime> runtime = xtcp_runtime_;
                    if (NULLPTR != runtime) {
                        runtime->SubmitIPv4Tcp(packet, packet_length);
                    }
                    return true;
                }
                return false;
            }

            /** @brief Handles raw IPv6 packet input and forwards approved traffic. */
            bool VEthernetNetworkSwitcher::OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept {
                return packet_dispatch_->OnPacketInput(packet, packet_length, vnet);
            }

            /** @brief Routes parsed IP frame to protocol-specific handlers. */
            bool VEthernetNetworkSwitcher::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                return packet_dispatch_->OnPacketInput(packet);
            }

            /** @brief Resolves ACK identifier and emits appropriate ICMP response packet. */
            bool VEthernetNetworkSwitcher::ERORTE(int ack_id) noexcept {
                return packet_dispatch_->ERORTE(ack_id);
            }

            /** @brief Dispatches switcher finalization and then disposes base VEthernet. */
            void VEthernetNetworkSwitcher::Dispose() noexcept {
                Dispose(ppp::function<void(bool)>());
            }

            /** @brief Disposes the switcher and reports after host rollback has completed. */
            void VEthernetNetworkSwitcher::Dispose(
                ppp::function<void(bool)> completion) noexcept {
                auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::dispatch(*context,
                    [self, this, completion = std::move(completion)]() mutable noexcept {
                        DisposeAttempt(std::move(completion), 3);
                    });
            }

            /** @brief Retries host cleanup before releasing the TAP and its interface identity. */
            void VEthernetNetworkSwitcher::DisposeAttempt(
                ppp::function<void(bool)> completion,
                int attempts_remaining) noexcept {
                Finalize();
                const bool cleanup_success = WasTeardownSuccessful();
                if (!cleanup_success && attempts_remaining > 1) {
                    DisposeAttempt(std::move(completion), attempts_remaining - 1);
                    return;
                }

                VEthernet::Dispose();
                ppp::telemetry::Log(Level::kInfo, "client", "TUN detached");
                if (completion) {
                    completion(cleanup_success);
                }
            }

            /** @brief Releases objects, packets, and timeout handlers. */
            void VEthernetNetworkSwitcher::Finalize() noexcept {
#if !defined(_ANDROID) && !defined(_IPHONE)
                RestoreAssignedIPv4();
#endif
                ReleaseAllObjects();
                ReleaseAllPackets();
                ReleaseAllTimeouts();
            }

            /** @brief Clears all tracked ICMP packet records. */
            void VEthernetNetworkSwitcher::ReleaseAllPackets() noexcept {
                // Clear all ICMP packet container.
                SynchronizedObjectScope scope(GetSynchronizedObject());
                icmppackets_.clear();
                quic_reject_limiter_->Clear();
            }

            /** @brief Releases all registered timeout callbacks. */
            void VEthernetNetworkSwitcher::ReleaseAllTimeouts() noexcept {
                timeout_registry_->ReleaseAll();
            }

#if defined(_ANDROID) || defined(_IPHONE)
            void VEthernetNetworkSwitcher::SetBypassIpList(ppp::string&& bypass_ip_list) noexcept {
                bypass_loader_->SetBypassIpList(std::move(bypass_ip_list));
            }
#endif

            /** @brief Creates QoS controller with configured bandwidth policy. */
            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::NewQoS() noexcept {
                int64_t bandwidth = std::max<int64_t>(0, configuration_->client.bandwidth);
                if (bandwidth < 0) {
                    bandwidth *= (1024 >> 3); /* Kbps. */
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                return make_shared_object<ppp::transmissions::ITransmissionQoS>(context, bandwidth);
            }

            /** @brief Creates exchanger instance using configured client GUID. */
            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::NewExchanger() noexcept {
                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                auto guid = StringAuxiliary::GuidStringToInt128(configuration->client.guid);
                if (guid == 0) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionIdInvalid, std::shared_ptr<VEthernetExchanger>(NULLPTR));
                }

                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetExchanger>(self, configuration, GetContext(), guid);
            }

            /** @brief Creates HTTP proxy switcher bound to exchanger. */
            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr(NULLPTR));
                }
                else {
                    return make_shared_object<VEthernetHttpProxySwitcher>(exchanger);
                }
            }

            /** @brief Creates SOCKS proxy switcher bound to exchanger. */
            VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr(NULLPTR));
                }
                else {
                    return make_shared_object<VEthernetSocksProxySwitcher>(exchanger);
                }
            }

            /** @brief Returns buffer allocator from runtime configuration. */
            std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetNetworkSwitcher::GetBufferAllocator() noexcept {
                return configuration_->GetBufferAllocator();
            }

            /** @brief Converts UDP payload to IP frame and emits it to local output. */
            boost::asio::ip::address VEthernetNetworkSwitcher::RewriteFakeIpAddress(const boost::asio::ip::address& addr) const noexcept {
                if (!addr.is_v4() || NULLPTR == dns_controller_) {
                    return addr;
                }
                return dns_controller_->RewriteFakeIpAddress(addr);
            }

            bool VEthernetNetworkSwitcher::ResolveDestination(
                const ppp::net::IPEndPoint& endpoint,
                routing::ResolvedDestination& destination) const noexcept {
                if (NULLPTR != dns_controller_) {
                    return dns_controller_->ResolveDestination(endpoint, destination);
                }
                destination = routing::ResolvedDestination{};
                destination.original_endpoint = endpoint;
                destination.connect_endpoint = endpoint;
                return true;
            }

            bool VEthernetNetworkSwitcher::DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching) noexcept {
                return DatagramOutput(sourceEP, destinationEP, nullptr, packet, packet_size, caching);
            }

            bool VEthernetNetworkSwitcher::DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, void* packet, int packet_size, bool caching) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                boost::asio::ip::address address = remoteEP.address();
                if (address.is_v4()) {
                    std::shared_ptr<BufferSegment> messages = make_shared_object<BufferSegment>();
                    if (NULLPTR == messages) {
                        return false;
                    }

                    // Zero-copy when owner is available; otherwise allocate + copy for safety.
                    if (NULLPTR != owner) {
                        messages->Buffer = ppp::wrap_shared_pointer(reinterpret_cast<Byte*>(packet), owner);
                    }

                    if (NULLPTR == messages->Buffer) {
                        std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                        messages->Buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_size);
                        if (NULLPTR == messages->Buffer) {
                            return false;
                        }
                        memcpy(messages->Buffer.get(), packet, packet_size);
                    }
                    messages->Length = packet_size;

                    std::shared_ptr<UdpFrame> frame = make_shared_object<UdpFrame>();
                    if (NULLPTR == frame) {
                        return false;
                    }

                    frame->AddressesFamily = AddressFamily::InterNetwork;
                    frame->Source = IPEndPoint::ToEndPoint(remoteEP);
                    frame->Destination = IPEndPoint::ToEndPoint(sourceEP);
                    frame->Payload = messages;

                    if (caching && configuration_->udp.dns.cache) {
                        int destinationPort = destinationEP.port();
                        if (destinationPort == PPP_DNS_SYS_PORT) {
                            ppp::net::asio::vdns::AddCache((Byte*)packet, packet_size);
                        }
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<IPFrame> ip = UdpFrame::ToIp(allocator, frame.get());
                    return Output(ip.get());
                }

                return false;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool VEthernetNetworkSwitcher::ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept {
                const bool applied = address_manager_->ApplyAssignedIPv6(extensions);
#if defined(_WIN32)
                if (!applied) {
                    return false;
                }

                const bool nat_mode = extensions.AssignedIPv6Mode ==
                    VirtualEthernetInformationExtensions::IPv6Mode_Nat66;
                if (!ActivateWindowsManagedIPv6(extensions.AssignedIPv6Gateway, nat_mode)) {
                    // Route protection is best-effort: keep the VPN session, but do not leave
                    // a managed IPv6 address active without the split takeover pair.
                    EnsureWindowsIPv6Sink();
                    address_manager_->RestoreAssignedIPv6();
                    return true;
                }
#endif
                return applied;
            }

            void VEthernetNetworkSwitcher::RestoreAssignedIPv6() noexcept {
#if defined(_WIN32)
                EnsureWindowsIPv6Sink();
#endif
                address_manager_->RestoreAssignedIPv6();
            }

            bool VEthernetNetworkSwitcher::ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept {
                return address_manager_->ApplyAssignedIPv4(extensions);
            }

            void VEthernetNetworkSwitcher::RestoreAssignedIPv4() noexcept {
                address_manager_->RestoreAssignedIPv4();
            }

#endif

            void VEthernetNetworkSwitcher::ClearPeerPrefixRoutes() noexcept {
                peer_prefix_routes_->Clear();
            }

            bool VEthernetNetworkSwitcher::ApplyPeerPrefixRoutes(const VirtualEthernetInformationExtensions& extensions) noexcept {
                return peer_prefix_routes_->Apply(extensions);
            }

            /** @brief Adapts base information callback to extension-aware overload. */
            bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>& info) noexcept {
                VirtualEthernetInformationExtensions extensions;
                extensions.Clear();
                return OnInformation(info, extensions);
            }

            /** @brief Updates runtime state from server information and extensions. */
            bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>& info, const VirtualEthernetInformationExtensions& extensions) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }


#if !defined(_ANDROID) && !defined(_IPHONE)
                bool previous_assignment = HasManagedIPv6Assignment(*information_extensions_);
                bool current_assignment = HasManagedIPv6Assignment(extensions);
                if (address_manager_->Ipv6Applied() && (!previous_assignment || !current_assignment || !SameManagedIPv6Configuration(*information_extensions_, extensions))) {
                    RestoreAssignedIPv6();
                }

                *information_extensions_ = extensions;

                if (NULLPTR != dns_controller_) {
                    dns_controller_->OnSessionInfo(extensions, HasManagedIPv6Assignment(extensions));
                }

                bool valid_ipv6_assignment = HasManagedIPv6Assignment(extensions);
                if (!valid_ipv6_assignment) {
                    if (address_manager_->Ipv6Applied()) {
                        RestoreAssignedIPv6();
                    }
#if defined(_WIN32)
                    else {
                        EnsureWindowsIPv6Sink();
                    }
#endif
                }

                if (valid_ipv6_assignment &&
                    (extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
                        extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Gua) &&
                    !address_manager_->Ipv6Applied()) {
                    ApplyAssignedIPv6(extensions);
                }

                // Apply server-assigned IPv4 address to TAP interface.
                {
                    const auto& ipv4 = extensions.ClientIPv4Assign;
                    if (ipv4.enabled && ipv4.accepted) {
                        if (!address_manager_->Ipv4Applied()) {
                            ApplyAssignedIPv4(extensions);
                        }
                    }
                    elif (address_manager_->Ipv4Applied()) {
                        RestoreAssignedIPv4();
                    }
                }
#else
                *information_extensions_ = extensions;

                if (NULLPTR != dns_controller_) {
                    dns_controller_->OnSessionInfo(extensions, HasManagedIPv6Assignment(extensions));
                }
#endif

                // Parse and log IPv4 assignment response from server.
                // The assignment is stored in information_extensions_ (already saved above)
                // and logged here for telemetry.  TAP application of the assigned IPv4
                // address is intentionally deferred to a future phase.
                if (extensions.ClientIPv4Assign.enabled) {
                    const auto& ipv4 = extensions.ClientIPv4Assign;
                    if (ipv4.accepted) {
                        ppp::telemetry::Count("client.ipv4.assigned", 1);
                        ppp::telemetry::Log(Level::kInfo, "client", "ipv4 assigned: %s/%s gw=%s (mode=%s conflict=%d)",
                            ipv4.address.c_str(), ipv4.mask.c_str(), ipv4.gateway.c_str(),
                            ipv4.mode.c_str(), static_cast<int>(ipv4.conflict));
                    }
                    else {
                        ppp::telemetry::Count("client.ipv4.rejected", 1);
                        ppp::telemetry::Log(Level::kInfo, "client", "ipv4 request rejected: reason=%s mode=%s",
                            ipv4.reason.c_str(), ipv4.mode.c_str());
                    }
                }

                if (extensions.P2P.HasAny()) {
                    const auto& p2p = extensions.P2P;
                    ppp::telemetry::Log(Level::kInfo, "p2p", "control action=%s mode=%s peer=%s candidates=%zu reason=%s",
                        p2p.action.c_str(),
                        p2p.mode.c_str(),
                        ppp::net::IPEndPoint::ToAddressString(p2p.peer_virtual_ip).c_str(),
                        p2p.candidates.size(),
                        p2p.reason.c_str());
                    ppp::telemetry::Count("p2p.control", 1);
                }

                if (extensions.PeerRouteTable.HasAny()) {
                    dynamic_peer_routes_ = extensions.PeerRouteTable.routes;
                    ApplyPeerPrefixRoutes(extensions);
                }
                elif (configuration_ && !(configuration_->client.routing.configured
                        ? configuration_->client.routing.peer_routes
                        : configuration_->client.peer_routes).empty()) {
                    ApplyPeerPrefixRoutes(extensions);
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULLPTR != qos) {
                    int64_t bandwidth = static_cast<int64_t>(info->BandwidthQoS) * (1024 >> 3); /* Kbps. */
                    qos->SetBandwidth(bandwidth);
                }

                // If the user still has the remaining incoming/outgoing traffic and the expiration time is not reached,
                // The VPN link is regarded as successful. Otherwise, the VPN link needs to be disconnected.
                if (info->Valid()) {
                    return true;
                }

                // If the VPN link needs to be disconnected, the client requires the active end, and the server forcibly disconnects.
                // This prevents you from bypassing the disconnection problem by modifying the code of the client switch.
                std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->GetTransmission();
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                return false;
            }

#if defined(_WIN32)
            /** @brief Creates Windows PaperAirplane controller bound to exchanger. */
            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::NewPaperAirplaneController() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();
                if (NULLPTR == exchanger) {
                    return NULLPTR;
                }
                else {
                    return make_shared_object<PaperAirplaneController>(exchanger);
                }
            }
#elif defined(_LINUX)
            /** @brief Creates Linux protector network instance for socket protection. */
            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::NewProtectorNetwork() noexcept {
#if defined(_ANDROID)
                // Embedding the so framework into the Android platform does not use sendfd/recvfd unix to share fd across processes,
                // So you cannot pass in network cards or unix path names.
                ppp::string dev;
                return make_shared_object<ProtectorNetwork>(dev);
#else
                std::shared_ptr<NetworkInterface> ni = GetUnderlyingNetworkInterface();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

                return make_shared_object<ProtectorNetwork>(ni->Name);
#endif
            }
#endif

            /** @brief Retrieves latest information snapshot from exchanger. */
            std::shared_ptr<VEthernetNetworkSwitcher::VirtualEthernetInformation> VEthernetNetworkSwitcher::GetInformation() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return NULLPTR;
                }

                return exchanger->GetInformation();
            }

            /** @brief Creates transmission statistics collector instance. */
            VEthernetNetworkSwitcher::ITransmissionStatisticsPtr VEthernetNetworkSwitcher::NewStatistics() noexcept {
                return make_shared_object<ITransmissionStatistics>();
            }

            /** @brief Enables or disables outbound QUIC blocking policy. */
            bool VEthernetNetworkSwitcher::BlockQUIC(bool value) noexcept {
                // Set the status of the current VPN client switcher that needs to block QUIC traffic flags.
                block_quic_ = value;
                return true;
            }

#if defined(_WIN32)
            /** @brief Applies local HTTP proxy endpoint to Windows system settings. */
            bool VEthernetNetworkSwitcher::SetHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to set the system HTTP proxy environment.
                auto http_proxy = GetHttpProxy();
                if (NULLPTR == http_proxy) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::tcp::endpoint localEP = http_proxy->GetLocalEndPoint();
                int localPort = localEP.port();
                if (localPort <= IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::address localIP = localEP.address();
                if (IPEndPoint::IsInvalid(localIP)) {
                    localIP = boost::asio::ip::address_v4::loopback();
                }

                ppp::string server = ppp::net::Ipep::ToAddressString<ppp::string>(localIP) + ":" + stl::to_string<ppp::string>(localPort);
                ppp::string pac;
                bool bok = ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, true) &&
                    ppp::net::proxies::HttpProxy::SetSystemProxy(server) &&
                    ppp::net::proxies::HttpProxy::RefreshSystemProxy();
                if (!bok) {
                    return ClearHttpProxyToSystemEnv();
                }

                return bok;
            }

            /** @brief Clears Windows system HTTP proxy settings managed by switcher. */
            bool VEthernetNetworkSwitcher::ClearHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to clear the system HTTP proxy environment.
                ppp::string server;
                ppp::string pac;
                return ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, false);
            }
#endif

#if defined(_ANDROID) || defined(_IPHONE)
            /** @brief Builds mobile-side route table including bypass and DNS exceptions. */
            bool VEthernetNetworkSwitcher::AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept {
                route::RoutePlanInput input = BuildRoutePlanInput();
                input.tap_ip = tap->IPAddress;
                input.tap_gateway = tap->GatewayServer;
                input.tap_submask = tap->SubmaskAddress;
                input.bypass_ip_list.assign(bypass_ip_list_.begin(), bypass_ip_list_.end());
                bypass_ip_list_.clear();
                if (!route_coordinator_->AddAllRoute(input)) {
                    return false;
                }

                return AddRemoteEndPointToIPList(Ipep::ToAddress(IPEndPoint::LoopbackAddress));
            }
#endif

            /** @brief Creates and configures static-mode aggligator instance. */
            bool VEthernetNetworkSwitcher::PreparedAggregator() noexcept {
                return aggregator_loader_->Prepare();
            }

            /** @brief Initializes switcher runtime components and opens all services. */
            bool VEthernetNetworkSwitcher::Open(const std::shared_ptr<ITap>& tap) noexcept {
                return connection_opener_->Open(tap);
            }

#if defined(_WIN32)
            /** @brief Starts optional PaperAirplane helper service on Windows. */
            bool VEthernetNetworkSwitcher::UsePaperAirplaneController() noexcept {
                // Open the [PaperAirplane NSP/LSP] paper airplane server controller,
                // Depending on the configuration and whether it is a CLI command line hosted network flag.
                if (configuration_->client.paper_airplane.tcp) {
                    PaperAirplaneControllerPtr controller = NewPaperAirplaneController();
                    if (NULLPTR == controller) {
                        return false;
                    }

                    // Clean up resources constructed by the current function when opening the server side of the paper plane fails.
                    auto tun_ni = tun_ni_;
                    if (NULLPTR != tun_ni) {
                        auto tap = GetTap();
                        if (NULLPTR != tap) {
                            if (!controller->Open(tun_ni->Index, tap->IPAddress, tap->SubmaskAddress)) {
                                IDisposable::DisposeReferences(controller);
                                return false;
                            }
                        }
                    }

                    // Open the paper plane successfully when you move the created instance on the local variable to
                    // The virtual ethernet switch hosted fields.
                    paper_airplane_ctrl_ = std::move(controller);
                }
                return true;
            }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            /** @brief Attempts to restore default route on underlying physical NIC. */
            bool VEthernetNetworkSwitcher::FixUnderlyingNgw() noexcept {
                return route_coordinator_->EnsureUnderlyingDefault(BuildRoutePlanInput());
            }

            /** @brief Removes VPN route entries and restores system defaults. */
            bool VEthernetNetworkSwitcher::DeleteRoute() noexcept {
                if (!route_coordinator_->DeleteRoute()) {
                    return false;
                }
                applied_peer_prefix_routes_.clear();
                route_coordinator_->ReplacePeerPrefix(NULLPTR, NULLPTR);
                return true;
            }

            /** @brief Returns formatted cached remote URI string. */
            ppp::string VEthernetNetworkSwitcher::GetRemoteUri() noexcept {
                return server_ru_;
            }

            /** @brief Sets preferred physical NIC hint for route operations. */
            void VEthernetNetworkSwitcher::PreferredNic(const ppp::string& nic) noexcept {
                preferred_nic_ = nic;
            }

            /** @brief Sets preferred physical gateway hint for route operations. */
            void VEthernetNetworkSwitcher::PreferredNgw(const boost::asio::ip::address& gw) noexcept {
                preferred_ngw_ = gw;
            }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool VEthernetNetworkSwitcher::AddLoadIPList(
                const ppp::string& path,
#if defined(_LINUX)
                const ppp::string& nic,
#endif
                const boost::asio::ip::address& gw,
                const ppp::string& url) noexcept {
                return bypass_loader_->AddLoadIPList(path,
#if defined(_LINUX)
                    nic,
#endif
                    gw, url);
            }

            bool VEthernetNetworkSwitcher::AddLoadIPListText(
                const ppp::string& text,
#if defined(_LINUX)
                const ppp::string& nic,
#endif
                const boost::asio::ip::address& gw) noexcept {
                return bypass_loader_->AddLoadIPListText(text,
#if defined(_LINUX)
                    nic,
#endif
                    gw);
            }

            bool VEthernetNetworkSwitcher::LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept {
                return bypass_loader_->LoadAllIPListWithFilePaths(gw);
            }
#endif

            bool VEthernetNetworkSwitcher::IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept {
                return bypass_loader_->IsBypassIpAddress(ip);
            }

            /** @brief Releases all runtime services, routes, and related resources. */
            void VEthernetNetworkSwitcher::ReleaseAllObjects() noexcept {
                const ppp::app::runtime::RuntimeStopResult result =
                    teardown_->ReleaseAllObjects();
                last_teardown_success_.store(result.success, std::memory_order_release);
            }

            /** @brief Removes timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::DeleteTimeout(void* k) noexcept {
                return timeout_registry_->Delete(k);
            }

            /** @brief Registers timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept {
                return timeout_registry_->Emplace(k, timeout);
            }

            /** @brief Loads DNS redirect rules from file or inline content. */
            bool VEthernetNetworkSwitcher::LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept {
                if (rules.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetNetworkSwitcherDnsRulesEmpty);
                }

                int events = 0;
                if (NULLPTR != dns_controller_) {
                    events = dns_controller_->LoadRules(rules, load_file_or_string);
                }

                if (1 > events) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigDnsRuleLoadFailed);
                }

                return true;
            }

            /** @brief Adds remote endpoints and static servers to route/bypass tables. */
            bool VEthernetNetworkSwitcher::AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept {
                return remote_endpoint_loader_->Apply(gw);
            }

            bool VEthernetNetworkSwitcher::StaticEchoAddRemoteEndPoint(
                boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                if (NULLPTR == exchanger_) {
                    return false;
                }
                return exchanger_->StaticEchoAddRemoteEndPoint(remoteEP);
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool VEthernetNetworkSwitcher::AddRoute() noexcept {
                return route_coordinator_->AddRoute(BuildRoutePlanInput());
            }
#endif

            /** @brief Gets current static mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::StaticMode(bool* static_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = static_mode_;
                if (NULLPTR != static_mode) {
                    static_mode_ = *static_mode;
                }

                return snow;
            }

            /** @brief Gets current proxy-only mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::ProxyOnly(bool* proxy_only) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool previous = proxy_only_;
                if (NULLPTR != proxy_only) {
                    proxy_only_ = *proxy_only;
                }

                return previous;
            }

            /** @brief Gets current mux size and optionally updates it. */
            uint16_t VEthernetNetworkSwitcher::Mux(uint16_t* mux) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint16_t snow = mux_;
                if (NULLPTR != mux) {
                    mux_ = *mux;
                }

                return snow;
            }

            /** @brief Gets current mux acceleration flags and optionally updates them. */
            uint8_t VEthernetNetworkSwitcher::MuxAcceleration(uint8_t* mux_acceleration) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint8_t snow = mux_acceleration_;
                if (NULLPTR != mux_acceleration) {
                    mux_acceleration_ = *mux_acceleration;
                }

                return snow;
            }

            /** @brief Performs periodic update work for static-echo socket rotation. */
            bool VEthernetNetworkSwitcher::OnUpdate(uint64_t now) noexcept {
                if (VEthernet::OnUpdate(now)) {
                    std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                    if (NULLPTR != exchanger) {
                        exchanger->StaticEchoSwapAsynchronousSocket();
                    }
                }

                return false;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_LINUX)
            /** @brief Gets current Linux protect mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::ProtectMode(bool* protect_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = protect_mode_;
                if (NULLPTR != protect_mode) {
                    protect_mode_ = *protect_mode;
                }

                return snow;
            }
#endif
#endif
        }
    }
}
