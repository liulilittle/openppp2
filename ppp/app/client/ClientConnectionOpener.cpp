#include <ppp/app/client/ClientConnectionOpener.h>
#include <ppp/app/client/ClientNetworkInterfaceResolver.h>
#include <ppp/app/client/RemoteEndpointLoader.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/xtcp/XtcpRuntime.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/app/client/dns/DnsController.h>
#include <ppp/app/client/dns/DnsQueryContext.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/IDisposable.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/net/native/rib.h>
#include <common/aggligator/aggligator.h>

#include <chrono>
#include <cstdlib>

#if defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void ClientConnectionOpener::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

            /** @brief Initializes switcher runtime components and opens all services. */
            bool ClientConnectionOpener::Open(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept {
                ppp::telemetry::SpanScope span("client.connect");
                struct ScopedConnectHistogram final {
                    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

                    ~ScopedConnectHistogram() noexcept {
                        int64_t elapsed = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                        ppp::telemetry::Histogram("client.connect.us", elapsed);
                    }
                } connect_histogram;

#if !defined(_ANDROID) && !defined(_IPHONE)
                if (!owner_->proxy_only_) {
                owner_->underlying_ni_ = ClientNetworkInterfaceResolver::GetUnderlyingNetworkInterface(tap, owner_->preferred_nic_);

                if (auto underlying_ni = owner_->underlying_ni_; NULLPTR != underlying_ni) {
                    boost::asio::ip::address& ngw = owner_->preferred_ngw_;
                    if (!IPEndPoint::IsInvalid(ngw)) {
                        underlying_ni->GatewayServer = ngw;
                    }
                }
                else {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                owner_->FixUnderlyingNgw();
                }
#endif
                // Construction of VEtherent virtual Ethernet switcher processing framework.
                /** @brief Creates base VEthernet framework before higher-level services. */
                if (!owner_->VEthernet::Open(tap)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                }

                if (owner_->tcp_stack_mode_ == ppp::app::TcpStackMode::Xtcp) {
#if defined(PPP_ENABLE_XTCP)
                    const auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(
                        owner_->shared_from_this());
                    const std::weak_ptr<VEthernetNetworkSwitcher> weak = self;
                    const char* xtcp_perf_json = std::getenv("OPENPPP2_XTCP_PERF_JSON");
                    const char* output_rejection_flag = std::getenv("OPENPPP2_XTCP_OUTPUT_REJECTION_JSON");
                    const bool output_rejection_enabled = xtcp_perf_json != nullptr && *xtcp_perf_json != '\0' &&
                        output_rejection_flag != nullptr && *output_rejection_flag == '1';
                    const std::shared_ptr<xtcp::XtcpOutputRejectionDiagnostics> output_rejection_diagnostics =
                        output_rejection_enabled
                            ? make_shared_object<xtcp::XtcpOutputRejectionDiagnostics>(true) : nullptr;
                    std::shared_ptr<xtcp::XtcpRuntime> runtime =
                        make_shared_object<xtcp::XtcpRuntime>(
                            owner_->GetContext(),
                            [weak, output_rejection_diagnostics](std::shared_ptr<Byte>&& packet, int size,
                                std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
                                const std::shared_ptr<VEthernetNetworkSwitcher> owner = weak.lock();
                                const auto emit = [&]() noexcept {
                                    if (!owner) {
                                        return false;
                                    }
                                    return gso ? owner->OutputGso(packet, size, *gso)
                                               : owner->Output(packet, size);
                                };
                                if (output_rejection_diagnostics == nullptr) {
                                    return emit();
                                }
                                const bool vethernet_disposed = owner && owner->IsDisposed();
                                const bool tap_present = owner && owner->GetTap() != nullptr;
                                const bool accepted = emit();
                                output_rejection_diagnostics->Record(static_cast<bool>(owner),
                                    vethernet_disposed, tap_present, accepted);
                                return accepted;
                            },
                            [weak]() noexcept {
                                const std::shared_ptr<VEthernetNetworkSwitcher> owner = weak.lock();
                                const std::shared_ptr<ppp::ethernet::VNetstack> netstack =
                                    owner ? owner->GetNetstack() : nullptr;
                                return netstack ? netstack->GetLocalListenerEndpoint()
                                    : boost::asio::ip::tcp::endpoint();
                            },
                            [weak](const boost::asio::ip::tcp::endpoint& localEP,
                                const boost::asio::ip::tcp::endpoint& remoteEP,
                                uint16_t source_port, uint64_t runtime_generation,
                                uint64_t flow_generation,
                                const std::weak_ptr<xtcp::XtcpFirstLegHooks>& hooks, int fd) noexcept {
                                const std::shared_ptr<VEthernetNetworkSwitcher> owner = weak.lock();
                                const std::shared_ptr<VEthernetNetworkTcpipStack> netstack =
                                    owner ? std::dynamic_pointer_cast<VEthernetNetworkTcpipStack>(
                                        owner->GetNetstack()) : nullptr;
                                if (netstack) {
                                    return netstack->BeginExternalAcceptWithFd(
                                        localEP, remoteEP, source_port, runtime_generation,
                                        flow_generation, hooks, fd);
                                }
                                if (fd >= 0) {
                                    ppp::net::Socket::Closesocket(fd);
                                }
                                return false;
                            },
                            [weak](uint16_t source_port, uint64_t runtime_generation) noexcept {
                                const std::shared_ptr<VEthernetNetworkSwitcher> owner = weak.lock();
                                const std::shared_ptr<ppp::ethernet::VNetstack> netstack =
                                    owner ? owner->GetNetstack() : nullptr;
                                if (netstack) {
                                    netstack->CancelExternalClient(
                                        source_port, runtime_generation);
                                }
                            },
                            output_rejection_diagnostics,
                            owner_->SupportsTxGso());
                    if (NULLPTR == runtime || !runtime->Start()) {
                        return ppp::diagnostics::SetLastError(
                            ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                    }
                    owner_->xtcp_runtime_ = std::move(runtime);
#else
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::NetworkProtocolUnsupported);
#endif
                }

                ppp::net::asio::vdns::ClearCache();

                ppp::telemetry::Log(Level::kInfo, "client", owner_->proxy_only_ ? "proxy-only session starting" : "TUN attached");
                ppp::telemetry::Count(owner_->proxy_only_ ? "client.proxy.attach" : "client.tun.attach", 1);

#if !defined(_ANDROID) && !defined(_IPHONE)
                if (!owner_->proxy_only_) {
                owner_->tun_ni_ = ClientNetworkInterfaceResolver::GetTapNetworkInterface(tap);

                if (NULLPTR == owner_->tun_ni_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                }
#if defined(_WIN32)
                // Route-only IPv6 protection is best-effort; binding failure must not block the VPN.
                owner_->BindWindowsIPv6RouteOwner();
#endif
                }
#endif

                // Initial a new network statistics.
                owner_->statistics_ = owner_->NewStatistics();

                // Instantiate the local QoS throughput speed control module!
                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = owner_->NewQoS();
                if (NULLPTR == qos) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                }

#if defined(_LINUX)
                VEthernetNetworkSwitcher::ProtectorNetworkPtr protector_network;
#if defined(_ANDROID)
                protector_network = owner_->NewProtectorNetwork();
                if (NULLPTR == protector_network) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                }
#else
                if (!owner_->proxy_only_ && owner_->protect_mode_) {
                    protector_network = owner_->NewProtectorNetwork();
                }
#endif
#endif
                // Instantiate the exchanger. Windows prepares forwarding first so the
                // main coroutine can never cache or pin the logical server instead of the proxy.
                std::shared_ptr<VEthernetExchanger> exchanger = owner_->NewExchanger();
                if (NULLPTR == exchanger) {
                    return false;
                }
                owner_->exchanger_ = exchanger;

#if defined(_WIN32)
                if (!owner_->remote_endpoint_loader_->PrepareForwarding()) {
                    owner_->exchanger_.reset();
                    IDisposable::DisposeReferences(qos, exchanger);
                    return false;
                }
#endif

                if (!exchanger->Open()) {
                    owner_->exchanger_.reset();
                    IDisposable::DisposeReferences(qos, exchanger);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                }
                if (owner_->tcp_stack_mode_ == ppp::app::TcpStackMode::Xtcp) {
                    const std::shared_ptr<xtcp::XtcpRuntime> runtime = owner_->xtcp_runtime_;
                    if (NULLPTR == runtime) {
                        return ppp::diagnostics::SetLastError(
                            ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                    }
                    runtime->MarkReady();
                    if (!runtime->IsReady()) {
                        return ppp::diagnostics::SetLastError(
                            ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                    }
                }

                // Enable the local HTTP PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr http_proxy = owner_->NewHttpProxy(exchanger);
                if (NULLPTR == http_proxy) {
                    return false;
                }
                elif(http_proxy->Open()) {
                    owner_->http_proxy_ = std::move(http_proxy);
                }
                else {
                    http_proxy->Dispose();
                    http_proxy.reset();
                }

                // Enable the local SOCKS PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr socks_proxy = owner_->NewSocksProxy(exchanger);
                if (NULLPTR == socks_proxy) {
                    return false;
                }
                elif(socks_proxy->Open()) {
                    owner_->socks_proxy_ = std::move(socks_proxy);
                }
                else {
                    socks_proxy->Dispose();
                    socks_proxy.reset();
                }

                // Mounts the various service objects created and opened by the current constructor.
                owner_->qos_             = std::move(qos);
                owner_->exchanger_       = std::move(exchanger);
                if (NULLPTR != owner_->dns_controller_) {
                    const auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(owner_->shared_from_this());
                    dns::DnsQueryContext dns_context;
                    dns_context.datagram_output = [self](const auto& source, const auto& destination, const std::shared_ptr<Byte>& owner, void* packet, int size, bool caching) noexcept {
                        return self->DatagramOutput(source, destination, owner, packet, size, caching);
                    };
                    dns_context.tap = owner_->GetTap();
                    dns_context.configuration = owner_->configuration_;
                    dns_context.allocator = owner_->GetBufferAllocator();
                    dns_context.io_context = owner_->GetContext();
                    dns_context.emplace_timeout = [self](void* key, const auto& timeout) noexcept {
                        return self->EmplaceTimeout(key, timeout);
                    };
                    dns_context.delete_timeout = [self](void* key) noexcept {
                        return self->DeleteTimeout(key);
                    };
                    dns_context.write_cache = [](const Byte* packet, int size) noexcept {
                        ppp::net::asio::vdns::AddCache(packet, size);
                    };
#if defined(_LINUX)
                    dns_context.protector_network = protector_network;
#endif
                    dns_context.handle_resolver_response = [](const auto&, const auto&, const auto&, auto) noexcept {};
                    if (!owner_->dns_controller_->Configure(std::move(dns_context))) {
                        return false;
                    }
                    owner_->dns_session_ = owner_->dns_controller_->OpenSession(owner_->exchanger_);
                    if (NULLPTR == owner_->dns_session_) {
                        return false;
                    }
                }

#if defined(_LINUX)
                owner_->protect_network_ = std::move(protector_network);
#endif

                if (NULLPTR != owner_->dns_controller_) {
                    if (!owner_->dns_controller_->Open(
                            owner_->configuration_,
                            owner_->GetContext(),
                            owner_->proxy_only_
#if defined(_LINUX)
                            , owner_->protect_network_
#endif
                        )) {
                        return false;
                    }
                }

                // New the beast network bandwidth aggregator only for full TUN mode.
                if (!owner_->proxy_only_ && owner_->static_mode_ && owner_->configuration_->udp.static_.aggligator > 0) {
                    if (!owner_->PreparedAggregator()) {
                        return false;
                    }
                }

#if defined(_ANDROID) || defined(_IPHONE)
                if (!owner_->AddAllRoute(tap)) {
                    IDisposable::DisposeReferences(qos, exchanger, http_proxy);
                    return false;
                }
#else
                // Proxy-only has no underlying NIC. Use loopback as the native-only
                // next hop so route sources populate the in-process RIB/FIB without
                // installing any host route.
                if (auto underlying_ni = owner_->underlying_ni_; NULLPTR != underlying_ni || owner_->proxy_only_) {
                    const boost::asio::ip::address native_gateway = owner_->proxy_only_
                        ? boost::asio::ip::address(boost::asio::ip::address_v4::loopback())
                        : underlying_ni->GatewayServer;
                    owner_->LoadAllIPListWithFilePaths(native_gateway);

                    // Add VPN remote server to the native route table.
                    if (!owner_->AddRemoteEndPointToIPList(native_gateway)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteAddFailed);
                    }
                }
#endif

                // Attempt to load the routing table configuration if the routing table is configured correctly.
                if (VEthernetNetworkSwitcher::RouteInformationTablePtr rib = owner_->GetRib(); NULLPTR != rib) {
                    VEthernetNetworkSwitcher::ForwardInformationTablePtr fib = make_shared_object<VEthernetNetworkSwitcher::ForwardInformationTable>();
                    if (NULLPTR != fib) {
                        fib->Fill(*rib);

                        if (fib->IsAvailable()) {
                            owner_->route_coordinator_->ReplaceFib(fib);
                        }
                    }
                }

                if (owner_->proxy_only_) {
                    if (NULLPTR == owner_->http_proxy_ && NULLPTR == owner_->socks_proxy_) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketBindFailed);
                    }

                    ppp::telemetry::Log(Level::kInfo, "client", "proxy-only connected");
                    ppp::telemetry::Count("client.proxy.connect", 1);
                    return true;
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
                owner_->route_coordinator_->MarkApplyReady(true);
                if (!owner_->TryApplyHostedNetworkRoutes()) {
                    return false;
                }
#endif
                ppp::telemetry::Log(Level::kInfo, "client", "client connected");
                ppp::telemetry::Count("client.connect", 1);
                return true;
            }

        }
    }
}
