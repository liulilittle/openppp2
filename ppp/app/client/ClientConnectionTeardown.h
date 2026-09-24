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
                    dns_restore_pending_ = dns_restore_pending_ || routes_applied;
                    if (!cleanup_complete) {
                        return {};
                    }

                    ClientTeardownRouteActions actions;
                    actions.restore_dns = dns_restore_pending_;
                    actions.release_network_state = true;
                    dns_restore_pending_ = false;
                    return actions;
                }

            private:
                bool dns_restore_pending_ = false;
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
