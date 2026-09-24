#include <ppp/app/client/ClientConnectionTeardown.h>
#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/ClientNetworkInterfaceResolver.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/xtcp/XtcpRuntime.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/app/client/dns/DnsController.h>
#include <ppp/app/runtime/RuntimeStopPipeline.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Error.h>
#include <common/aggligator/aggligator.h>

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/net/ProtectorNetwork.h>
#endif
#endif

using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void ClientConnectionTeardown::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

            /** @brief Releases all runtime services, routes, and related resources. */
            ppp::app::runtime::RuntimeStopResult
            ClientConnectionTeardown::ReleaseAllObjects() noexcept {
                ppp::telemetry::Log(Level::kInfo, "client", "client disconnected");
                ppp::telemetry::Count("client.disconnect", 1);

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Desktop teardown owns prdr_ for the whole rollback sequence.
                ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->prdr_);
#endif

                ppp::app::runtime::RuntimeStopActions actions;
                actions.stop_input = [this]() noexcept {
                    owner_->TickEvent = NULLPTR;
                    if (const std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); tap) {
                        tap->SetPacketInput(NULLPTR);
                    }
                    if (auto runtime = std::move(owner_->xtcp_runtime_); runtime) {
                        runtime->Stop();
                    }
                    if (auto http_proxy = std::move(owner_->http_proxy_); http_proxy) {
                        http_proxy->Dispose();
                    }
                    if (auto socks_proxy = std::move(owner_->socks_proxy_); socks_proxy) {
                        socks_proxy->Dispose();
                    }
                    return true;
                };

                actions.close_dns = [this]() noexcept {
                    if (owner_->dns_controller_) {
                        owner_->dns_controller_->Close();
                    }
                    owner_->dns_session_.reset();
                    return true;
                };

                actions.dispose_exchanger = [this]() noexcept {
                    if (auto exchanger = std::move(owner_->exchanger_); exchanger) {
                        exchanger->Dispose();
                    }
                    if (auto qos = std::move(owner_->qos_); qos) {
                        qos->Dispose();
                    }
                    if (auto aggligator = std::move(owner_->aggligator_); aggligator) {
                        aggligator->close();
                    }
                    if (auto forwarding = std::move(owner_->forwarding_); forwarding) {
                        forwarding->Dispose();
                    }
#if defined(_WIN32)
                    if (auto controller = std::move(owner_->paper_airplane_ctrl_); controller) {
                        controller->Dispose();
                    }
#endif
                    return true;
                };

                actions.rollback_route = [this]() noexcept {
                    bool route_cleanup_complete = true;
#if !defined(_ANDROID) && !defined(_IPHONE)
                    owner_->RestoreAssignedIPv6();
                    route_cleanup_complete =
                        !owner_->address_manager_->HasPendingIPv6Cleanup();
#if defined(_WIN32)
                    const bool windows_ipv6_stopped = owner_->StopWindowsIPv6Routes();
                    route_cleanup_complete = windows_ipv6_stopped &&
                        !owner_->HasPendingWindowsIPv6Cleanup() &&
                        route_cleanup_complete;
#endif
                    const route::RouteStateSnapshot route_snapshot =
                        owner_->route_coordinator_->Snapshot();
                    const bool routes_applied = route_snapshot.applied;
                    const bool rollback_pending =
                        routes_applied || !route_snapshot.default_routes.empty();
                    owner_->route_coordinator_->MarkApplyReady(false);
                    if (rollback_pending) {
                        route_cleanup_complete = owner_->DeleteRoute() && route_cleanup_complete;
                    }

                    const ClientTeardownRouteActions route_actions =
                        route_state_.CompleteAttempt(routes_applied, route_cleanup_complete);
                    if (route_actions.restore_dns) {
#if defined(_WIN32)
                        ppp::win32::network::SetAllNicsDnsAddresses(owner_->ni_dns_servers_);
                        ppp::tap::TapWindows::DnsFlushResolverCache();
#else
                        ClientNetworkInterfaceResolver::SetDnsResolveConfiguration(
                            owner_->GetUnderlyingNetworkInterface());
#endif
                    }
                    if (route_actions.release_network_state) {
                        owner_->ribs_.reset();
                        owner_->tun_ni_.reset();
                        owner_->underlying_ni_.reset();
                        owner_->vbgp_ = NULLPTR;
                        owner_->route_coordinator_->Clear();
                        owner_->LoadAllIPListWithFilePaths(
                            boost::asio::ip::address_v4::any());
                    }
#else
                    route_cleanup_complete = owner_->route_coordinator_->Stop();
#endif

#if defined(_LINUX)
                    if (auto protector = std::move(owner_->protect_network_); protector) {
#if defined(_ANDROID)
                        protector->DetachJNI();
#endif
                    }
#endif
                    if (!route_cleanup_complete) {
                        ppp::diagnostics::SetLastErrorCode(
                            ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    }
                    return route_cleanup_complete;
                };

                const ppp::app::runtime::RuntimeStopResult result =
                    ppp::app::runtime::RuntimeStopPipeline::Execute(actions);
                if (!result.success) {
                    ppp::telemetry::Count("client.disconnect.failed", 1);
                }
                return result;
            }

        }
    }
}
