#pragma once

/**
 * @file StaticUdpRelayHost.h
 * @brief Narrow host surface for the static-echo UDP relay pipeline without VirtualEthernetExchanger.h.
 *
 * P2-f: mirrors the ServerUdpRelayHostPorts pattern for the second, static-echo class of UDP
 * relay port. Lets StaticDatagramPortManager own the static_echo_datagram_ports_ session table
 * (and its lock) outside the God-Object exchanger, reaching the exchanger's port factory and
 * session logger through injected callbacks. See docs/UDP_DECOUPLING_P2E_PLAN.md.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace app {
        namespace server {

            class VirtualEthernetDatagramPortStatic;

            namespace udp {

                /** @brief Static-echo datagram relay port handle. */
                using VirtualEthernetDatagramPortStaticPtr = std::shared_ptr<VirtualEthernetDatagramPortStatic>;

                /** @brief Injectable exchanger capabilities for the static-echo UDP relay table (no exchanger header). */
                struct StaticUdpRelayHostPorts final {
                    /** @brief Build (and bind context to) a static-echo port for source_ip:source_port. Matches NewDatagramPort. */
                    ppp::function<VirtualEthernetDatagramPortStaticPtr(uint32_t source_ip, int source_port)> create_port;

                    /** @brief Notify that a static-echo port was newly opened (session-log side-effect). */
                    ppp::function<void(const VirtualEthernetDatagramPortStaticPtr& port)> on_port_opened;

                    bool IsValid() const noexcept {
                        return create_port && on_port_opened;
                    }
                };

                /** @brief Implemented by the exchanger to hand out static-echo relay capabilities. */
                class IStaticUdpRelayHost {
                public:
                    virtual ~IStaticUdpRelayHost() noexcept = default;

                    virtual StaticUdpRelayHostPorts BuildStaticUdpRelayHostPorts() noexcept = 0;
                };

                /** @brief Factory bridging an IStaticUdpRelayHost into a StaticUdpRelayHostPorts value. */
                StaticUdpRelayHostPorts MakeStaticUdpRelayHostPorts(const std::shared_ptr<IStaticUdpRelayHost>& host) noexcept;

            }
        }
    }
}
