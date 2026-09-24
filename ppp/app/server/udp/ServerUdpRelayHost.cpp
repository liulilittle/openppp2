#include <ppp/app/server/udp/ServerUdpRelayHost.h>

/**
 * @file ServerUdpRelayHost.cpp
 * @brief Factory bridging IServerUdpRelayHost into a ServerUdpRelayHostPorts value (P2-e).
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {

                ServerUdpRelayHostPorts MakeServerUdpRelayHostPorts(const std::shared_ptr<IServerUdpRelayHost>& host) noexcept {
                    if (NULLPTR == host) {
                        return ServerUdpRelayHostPorts();
                    }

                    return host->BuildServerUdpRelayHostPorts();
                }

            }
        }
    }
}
