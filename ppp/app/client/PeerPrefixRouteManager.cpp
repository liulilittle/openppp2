#include <ppp/app/client/PeerPrefixRouteManager.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/protocol/PeerPrefixRoute.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>


using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void PeerPrefixRouteManager::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

            void PeerPrefixRouteManager::Clear() noexcept {
#if !defined(_ANDROID) && !defined(_IPHONE)
                const route::RoutePlanInput input = owner_->BuildRoutePlanInput();
                if (!owner_->proxy_only_) {
                    for (const auto& route : owner_->applied_peer_prefix_routes_) {
                        owner_->route_coordinator_->DeleteRoute(
                            input, route.Destination, route.NextHop, route.Prefix);
                    }
                }
#endif
                owner_->applied_peer_prefix_routes_.clear();
                const route::RouteStateSnapshot snapshot = owner_->route_coordinator_->Snapshot();
                if (NULLPTR != snapshot.peer_prefix_rib) {
                    snapshot.peer_prefix_rib->Clear();
                }
                if (NULLPTR != snapshot.peer_prefix_fib) {
                    snapshot.peer_prefix_fib->Clear();
                }
                owner_->route_coordinator_->ReplacePeerPrefix(NULLPTR, NULLPTR);
            }

            bool PeerPrefixRouteManager::Apply(const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions) noexcept {
                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                Clear();

                VEthernetNetworkSwitcher::RouteInformationTablePtr rib =
                    make_shared_object<VEthernetNetworkSwitcher::RouteInformationTable>();
                if (NULLPTR == rib) {
                    return false;
                }

                const auto& dynamic_routes = extensions.PeerRouteTable.HasAny()
                    ? extensions.PeerRouteTable.routes
                    : owner_->dynamic_peer_routes_;
#if !defined(_ANDROID) && !defined(_IPHONE)
                const route::RoutePlanInput route_input = owner_->BuildRoutePlanInput();
                const bool apply_host_routes = !owner_->proxy_only_;
#endif

                auto install_route = [&](const ppp::app::protocol::PeerPrefixRouteEntry& route) -> bool {
                    if (!route.HasVia()) {
                        return false;
                    }

                    if (route.prefix <= 0 || route.prefix > ppp::net::native::MAX_PREFIX_VALUE_V4) {
                        return false;
                    }

                    uint32_t network = route.NetworkHost();
                    uint32_t via = route.ViaHost();
                    if (network == 0 || via == 0) {
                        return false;
                    }

                    if (via == tap->IPAddress) {
                        return false;
                    }

#if !defined(_ANDROID) && !defined(_IPHONE)
                    if (apply_host_routes && !owner_->route_coordinator_->AddRoute(route_input, network, via, route.prefix)) {
                        return false;
                    }
#endif

                    if (!rib->AddRoute(network, route.prefix, via)) {
#if !defined(_ANDROID) && !defined(_IPHONE)
                        if (apply_host_routes) {
                            owner_->route_coordinator_->DeleteRoute(
                                route_input, network, via, route.prefix);
                        }
#endif
                        return false;
                    }

                    ppp::net::native::RouteEntry entry;
                    entry.Destination = network;
                    entry.Prefix = route.prefix;
                    entry.NextHop = via;
                    owner_->applied_peer_prefix_routes_.emplace_back(entry);
                    return true;
                };

                bool any = false;
                if (NULLPTR != owner_->configuration_) {
                    // Use canonical peer_routes when client.routing was supplied;
                    // fall back to the legacy field only when the canonical object
                    // is absent (mirrors the precedence in ApplicationClientBootstrap).
                    const auto& static_peer_routes =
                        owner_->configuration_->client.routing.configured
                            ? owner_->configuration_->client.routing.peer_routes
                            : owner_->configuration_->client.peer_routes;
                    for (const auto& route : static_peer_routes) {
                        ppp::app::protocol::PeerPrefixRouteEntry entry;
                        entry.network = route.network;
                        entry.prefix = route.prefix;
                        entry.via = route.via;
                        any |= install_route(entry);
                    }
                }

                for (const auto& route : dynamic_routes) {
                    any |= install_route(route);
                }

                if (any) {
                    VEthernetNetworkSwitcher::ForwardInformationTablePtr fib =
                        make_shared_object<VEthernetNetworkSwitcher::ForwardInformationTable>();
                    if (NULLPTR != fib) {
                        fib->Fill(*rib);
                        if (fib->IsAvailable()) {
                            owner_->route_coordinator_->ReplacePeerPrefix(rib, fib);
                        }
                    }

                    ppp::telemetry::Log(Level::kInfo, "client", "peer prefix routes applied: static+dynamic count=%zu",
                        owner_->applied_peer_prefix_routes_.size());
                    ppp::telemetry::Count("client.peer_routes.applied", 1);
                }

                return any;
            }

        }
    }
}
