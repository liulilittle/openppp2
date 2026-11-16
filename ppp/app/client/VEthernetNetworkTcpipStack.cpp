#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/routing/ResolvedDestination.h>
#include <ppp/app/client/routing/TcpRoutingSelector.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

/**
 * @file VEthernetNetworkTcpipStack.cpp
 * @brief Implements client-side TCP/IP stack entry points.
 * @license GPL-3.0
 */

namespace ppp {
    namespace app {
        namespace client {
            /** @brief Initializes stack state from the owning network switcher. */
            VEthernetNetworkTcpipStack::VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept
                : VNetstack()
                , Ethernet(ethernet)
                , configuration_(ethernet->GetConfiguration()) {

            }

            bool VEthernetNetworkTcpipStack::BeginExternalAccept(
                const boost::asio::ip::tcp::endpoint& localEP,
                const boost::asio::ip::tcp::endpoint& remoteEP,
                uint16_t source_port,
                uint64_t runtime_generation,
                uint64_t flow_generation,
                const std::weak_ptr<xtcp::XtcpFirstLegHooks>& hooks) noexcept {
                std::shared_ptr<TapTcpClient> base = BeginAcceptClient(localEP, remoteEP);
                std::shared_ptr<VEthernetNetworkTcpipConnection> connection =
                    std::dynamic_pointer_cast<VEthernetNetworkTcpipConnection>(base);
                if (NULLPTR == connection) {
                    return false;
                }
                connection->SetExternalFirstLeg(
                    runtime_generation, flow_generation, hooks);
                if (!RegisterExternalClient(source_port, runtime_generation,
                        flow_generation, connection)) {
                    connection->Dispose();
                    return false;
                }
                return true;
            }

            bool VEthernetNetworkTcpipStack::BeginExternalAcceptWithFd(
                const boost::asio::ip::tcp::endpoint& localEP,
                const boost::asio::ip::tcp::endpoint& remoteEP,
                uint16_t source_port,
                uint64_t runtime_generation,
                uint64_t flow_generation,
                const std::weak_ptr<xtcp::XtcpFirstLegHooks>& hooks, int fd) noexcept {
                if (fd < 0) {
                    return BeginExternalAccept(localEP, remoteEP, source_port,
                        runtime_generation, flow_generation, hooks);
                }
                // XTCP-VNET-BRIDGE-BYPASS-001: 注册后直接采纳 XTCP 侧 socketpair
                // fd, 跳过 listener accept + 内核 loopback TCP 配对。
                std::shared_ptr<TapTcpClient> base = BeginAcceptClient(localEP, remoteEP);
                std::shared_ptr<VEthernetNetworkTcpipConnection> connection =
                    std::dynamic_pointer_cast<VEthernetNetworkTcpipConnection>(base);
                if (NULLPTR == connection) {
#if defined(_WIN32)
                    ppp::net::Socket::Closesocket(fd);
#else
                    ::close(fd);
#endif
                    return false;
                }
                connection->SetExternalFirstLeg(
                    runtime_generation, flow_generation, hooks);
                if (!RegisterExternalClient(source_port, runtime_generation,
                        flow_generation, connection)) {
                    connection->Dispose();
#if defined(_WIN32)
                    ppp::net::Socket::Closesocket(fd);
#else
                    ::close(fd);
#endif
                    return false;
                }
                const boost::asio::ip::tcp::endpoint natEP(
                    boost::asio::ip::address_v4::loopback(), source_port);
                // CompleteExternalAcceptWithFd consumes fd and closes it before
                // adoption or disposes its Asio owner after adoption.
                return CompleteExternalAcceptWithFd(
                    source_port, runtime_generation, fd, natEP);
            }

            /**
             * @brief Creates a connection handler when exchanger state is established.
             */
            std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient> VEthernetNetworkTcpipStack::BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                using NetworkState = VEthernetExchanger::NetworkState;

                std::shared_ptr<VEthernetNetworkSwitcher> ethernet = this->Ethernet;
                if (NULLPTR == ethernet) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                std::shared_ptr<VEthernetExchanger> exchanger = ethernet->GetExchanger();
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                NetworkState network_state = exchanger->GetNetworkState();
                if (network_state != NetworkState::NetworkState_Established) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept rejected: network state=%d local=%s:%u remote=%s:%u",
                        (int)network_state,
                        localEP.address().to_string().c_str(),
                        localEP.port(),
                        remoteEP.address().to_string().c_str(),
                        remoteEP.port());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                routing::ResolvedDestination destination;
                if (!ethernet->ResolveDestination(
                        ppp::net::IPEndPoint::ToEndPoint(remoteEP), destination)) {
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::TcpConnectFailed,
                        std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                const bool policy_v2 = ethernet->HasPolicyV2();
                const auto policy_snapshot = policy_v2 ? ethernet->GetPolicySnapshot() : nullptr;
                bool domain_sniff_candidate = false;
#if !defined(_IPHONE) && !defined(IPHONE)
                const bool sniff_enabled = (policy_v2
                    ? policy_snapshot && policy_snapshot->TcpDomainSniff()
                    : configuration_ && configuration_->routing.tcp_domain_sniff) &&
                    remoteEP.address().is_v4() && !destination.is_fake_ip;
                domain_sniff_candidate = policy_v2 && policy_snapshot && sniff_enabled;
#endif

                routing::TcpRoutingSelectorInput selector_input;
                selector_input.action = destination.action;
                selector_input.is_fake_ip = destination.is_fake_ip;
                selector_input.is_resolved = destination.is_resolved;
#if defined(_IPHONE) || defined(IPHONE)
                selector_input.direct_supported = false;
#endif
                routing::TcpRoutingMode routing_mode =
                    routing::TcpRoutingSelector::Select(selector_input);
                std::string policy_reason;
                bool policy_resolution_pending = false;
                if (policy_v2) {
                    policy::PolicyTcpFlowInput input;
                    input.hostname = destination.hostname;
                    input.ipv6 = !remoteEP.address().is_v4() ||
                        destination.connect_endpoint.GetAddressFamily() != ppp::net::AddressFamily::InterNetwork;
                    if (!input.ipv6) input.ipv4 = ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(
                        destination.connect_endpoint).address().to_string();
                    input.is_fake_ip = destination.is_fake_ip;
                    // Resolve fake identities under the pinned policy, rather than reuse legacy cached IPs.
                    input.is_resolved = !destination.is_fake_ip;
                    input.direct_supported = selector_input.direct_supported;
                    const auto decision = policy::EvaluatePolicyTcpFlow(policy_snapshot, input);
                    policy_reason = decision.reason;
                    policy_resolution_pending = decision.needs_dns_resolution;
                    if (!decision.needs_dns_resolution) {
                        if (Ethernet) Ethernet->RecordPolicyDecision(
                            decision.disposition == policy::PolicyTcpDisposition::Direct ? policy::PolicyAction::Direct :
                            decision.disposition == policy::PolicyTcpDisposition::Proxy ? policy::PolicyAction::Proxy :
                            policy::PolicyAction::Reject);
                    }
                    routing_mode = decision.disposition == policy::PolicyTcpDisposition::Direct
                        ? routing::TcpRoutingMode::ForceDirect
                        : decision.disposition == policy::PolicyTcpDisposition::Proxy
                            ? routing::TcpRoutingMode::ForceProxy : routing::TcpRoutingMode::Reject;
                    // A sniffed domain can override an IP/default action; infrastructure failures cannot.
                    if (decision.reason == "policy_unavailable" || decision.reason == "unsupported_ipv6" ||
                        decision.reason == "unresolved_fake_ip" || decision.reason == "unresolved_destination")
                        domain_sniff_candidate = false;
                }
                if (routing_mode == routing::TcpRoutingMode::Reject && !domain_sniff_candidate && !policy_resolution_pending) {
                    ppp::telemetry::Log(
                        ppp::telemetry::Level::kInfo,
                        "tcpip_stack",
                        "begin accept rejected by routing policy v2=%d reason=%s mode=%d fake=%d resolved=%d action=%d remote=%s:%u",
                        policy_v2 ? 1 : 0,
                        policy_reason.c_str(),
                        static_cast<int>(routing_mode),
                        destination.is_fake_ip ? 1 : 0,
                        destination.is_resolved ? 1 : 0,
                        static_cast<int>(destination.action),
                        remoteEP.address().to_string().c_str(),
                        remoteEP.port());
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::TcpConnectFailed,
                        std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

#if defined(_IPHONE)
                if (routing_mode != routing::TcpRoutingMode::ForceDirect &&
                    exchanger->IosPeerConnectBackpressured()) {
                    ppp::telemetry::Count("tcpip_stack.begin_accept.backpressure", 1);
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept rejected under iOS child slot backpressure local=%s:%u remote=%s:%u",
                        localEP.address().to_string().c_str(),
                        localEP.port(),
                        remoteEP.address().to_string().c_str(),
                        remoteEP.port());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionQuotaExceeded, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }
#endif

                ppp::threading::Executors::ContextPtr context;
                ppp::threading::Executors::StrandPtr strand;
                context = ppp::threading::Executors::SelectScheduler(strand);

                if (NULLPTR == context) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept failed: scheduler unavailable");
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeSchedulerUnavailable, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                const boost::asio::ip::tcp::endpoint connectEP =
                    ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(
                        destination.connect_endpoint);

                std::shared_ptr<const routing::HumanRoutingRules> routing_rules;
#if !defined(_IPHONE) && !defined(IPHONE)
                if (!policy_v2 && sniff_enabled) {
                    routing_rules = ethernet->GetHumanRoutingRulesSnapshot();
                    domain_sniff_candidate = routing_rules &&
                        routing_rules->HasDomainRules();
                }
#endif

                auto connection = make_shared_object<VEthernetNetworkTcpipConnection>(
                    exchanger, context, strand, routing_mode, routing_rules,
                    domain_sniff_candidate);
                if (NULLPTR == connection) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept failed: allocation failed");
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                if (policy_v2) connection->SetPolicyContext(policy_snapshot, destination.hostname, policy_resolution_pending);
                connection->Open(localEP, connectEP);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept client local=%s:%u remote=%s:%u",
                    localEP.address().to_string().c_str(),
                    localEP.port(),
                    remoteEP.address().to_string().c_str(),
                    remoteEP.port());
                return connection;
            }

            /** @brief Returns socket connect timeout in milliseconds. */
            uint64_t VEthernetNetworkTcpipStack::GetMaxConnectTimeout() noexcept {
                uint64_t tcp_connect_timeout = (uint64_t)configuration_->tcp.connect.timeout;
                return (tcp_connect_timeout + 1) * 1000;
            }

            /** @brief Returns established inactivity timeout in milliseconds. */
            uint64_t VEthernetNetworkTcpipStack::GetMaxEstablishedTimeout() noexcept {
                uint64_t tcp_inactive_timeout = (uint64_t)configuration_->tcp.inactive.timeout;
                if (tcp_inactive_timeout < PPP_TCP_INACTIVE_TIMEOUT) {
                    tcp_inactive_timeout = PPP_TCP_INACTIVE_TIMEOUT;
                }
                return (tcp_inactive_timeout + 1) * 1000;
            }
        }
    }
}
