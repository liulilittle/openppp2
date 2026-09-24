#include <ppp/app/client/udp/UdpRelayHost.h>

/**
 * @file UdpRelayHost.cpp
 * @brief Factory bridging IUdpRelayHost into a UdpRelayHostPorts value (P2-c).
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {

                UdpRelayHostPorts MakeUdpRelayHostPorts(const std::shared_ptr<IUdpRelayHost>& host) noexcept {
                    if (NULLPTR == host) {
                        return UdpRelayHostPorts();
                    }

                    return host->BuildUdpRelayHostPorts();
                }

            }
        }
    }
}
