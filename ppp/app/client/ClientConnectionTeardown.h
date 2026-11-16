#pragma once

#include <ppp/app/runtime/RuntimeStopPipeline.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            struct ClientTeardownRouteActions final {
                bool restore_dns = false;
                bool release_network_state = false;
            };

            class ClientTeardownRouteState final {
            public:
                ClientTeardownRouteActions CompleteAttempt(
                    bool routes_applied,
                    bool cleanup_complete) noexcept {
                    if (routes_applied && !dns_restore_attempted_) {
                        dns_restore_pending_ = true;
                        dns_restore_attempted_ = true;
                    }
                    ClientTeardownRouteActions actions;
                    actions.restore_dns = dns_restore_pending_;
                    // Network state may only be released after both the route
                    // and DNS rollback have been verified.
                    actions.release_network_state =
                        cleanup_complete && !dns_restore_pending_;
                    if (actions.release_network_state) {
                        dns_restore_attempted_ = false;
                    }
                    return actions;
                }

                void MarkDnsRestoreResult(bool success) noexcept {
                    if (success) {
                        dns_restore_pending_ = false;
                    }
                }

            private:
                bool dns_restore_pending_ = false;
                bool dns_restore_attempted_ = false;
            };

            class ClientConnectionTeardown {
            public:
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;
                ppp::app::runtime::RuntimeStopResult ReleaseAllObjects() noexcept;

            private:
                VEthernetNetworkSwitcher* owner_ = nullptr;
                ClientTeardownRouteState route_state_;
            };
        }
    }
}
