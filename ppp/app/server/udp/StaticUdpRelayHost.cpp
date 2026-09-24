#include <ppp/app/server/udp/StaticUdpRelayHost.h>

/**
 * @file StaticUdpRelayHost.cpp
 * @brief Factory bridging IStaticUdpRelayHost into a StaticUdpRelayHostPorts value (P2-f).
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {

                StaticUdpRelayHostPorts MakeStaticUdpRelayHostPorts(const std::shared_ptr<IStaticUdpRelayHost>& host) noexcept {
                    if (NULLPTR == host) {
                        return StaticUdpRelayHostPorts();
                    }

                    return host->BuildStaticUdpRelayHostPorts();
                }

            }
        }
    }
}
