#pragma once

/**
 * @file ServerUdpRelayHost.h
 * @brief Narrow host surface for the server UDP relay pipeline without VirtualEthernetExchanger.h.
 *
 * P2-e: server-side mirror of the client udp::UdpRelayHostPorts / ClientDatagramPortManager
 * pattern. Lets ServerDatagramPortManager (P2-e-1) and VirtualEthernetDatagramPort (P2-e-2)
 * consume exchanger/switcher capabilities through injected callbacks instead of a back-pointer
 * + friend, so the UDP relay can be extracted from the God-Object exchanger. See
 * docs/UDP_DECOUPLING_P2E_PLAN.md.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace transmissions {
        class ITransmission;
    }
    namespace coroutines {
        class YieldContext;
    }
}

namespace ppp {
    namespace app {
        namespace server {

            class VirtualEthernetDatagramPort;

            namespace udp {

                /** @brief Active session transmission handle (matches exchanger's ITransmissionPtr). */
                using ITransmissionPtr = std::shared_ptr<ppp::transmissions::ITransmission>;

                /** @brief Datagram relay port handle (matches exchanger's VirtualEthernetDatagramPortPtr). */
                using VirtualEthernetDatagramPortPtr = std::shared_ptr<VirtualEthernetDatagramPort>;

                /** @brief Application configuration snapshot handle. */
                using AppConfigurationPtr = std::shared_ptr<ppp::configurations::AppConfiguration>;

                /** @brief Injectable exchanger/switcher capabilities for the server UDP relay pipeline (no exchanger header). */
                struct ServerUdpRelayHostPorts final {
                    // --- Session manager surface (P2-e-1) ---

                    /** @brief Build a datagram relay port bound to (transmission, source endpoint). Matches NewDatagramPort. */
                    ppp::function<VirtualEthernetDatagramPortPtr(const ITransmissionPtr& transmission,
                                                                 const boost::asio::ip::udp::endpoint& source)> create_port;

                    /**
                     * @brief Notify that a datagram port was newly opened (session-log side-effect).
                     * @note Keeps the switcher logger / telemetry on the exchanger side so the manager
                     *       stays pure mechanism, mirroring how the client manager leaves telemetry out.
                     */
                    ppp::function<void(const ITransmissionPtr& transmission,
                                       const VirtualEthernetDatagramPortPtr& port)> on_port_opened;

                    // --- Datagram port surface (P2-e-2) ---

                    /** @brief Active application configuration. Matches exchanger->GetConfiguration(). */
                    ppp::function<AppConfigurationPtr()> get_configuration;

                    /**
                     * @brief Send a datagram to the client over the link-layer SENDTO path. Mirrors
                     *        VirtualEthernetLinklayer::DoSendTo; the port supplies its own transmission
                     *        and coroutine yield context.
                     */
                    ppp::function<bool(const ITransmissionPtr& transmission,
                                       const boost::asio::ip::udp::endpoint& source,
                                       const boost::asio::ip::udp::endpoint& destination,
                                       ppp::Byte* packet, int packet_length,
                                       ppp::coroutines::YieldContext& y)> do_send_to;

                    /** @brief Deregister this port from the session table on finalize. Matches exchanger->ReleaseDatagramPort. */
                    ppp::function<void(const boost::asio::ip::udp::endpoint& source)> release_port;

                    /** @brief Local interface address used to bind the relay socket. Matches switcher->GetInterfaceIP(). */
                    ppp::function<boost::asio::ip::address()> get_interface_ip;

                    /** @brief Parse an inbound DNS response and store it in the server namespace cache. */
                    ppp::function<bool(const void* packet, int packet_length)> namespace_query;

                    bool IsValid() const noexcept {
                        return create_port && on_port_opened && get_configuration && do_send_to &&
                            release_port && get_interface_ip && namespace_query;
                    }
                };

                /** @brief Implemented by the exchanger to hand out server UDP relay capabilities. */
                class IServerUdpRelayHost {
                public:
                    virtual ~IServerUdpRelayHost() noexcept = default;

                    virtual ServerUdpRelayHostPorts BuildServerUdpRelayHostPorts() noexcept = 0;
                };

                /** @brief Factory bridging an IServerUdpRelayHost into a ServerUdpRelayHostPorts value. */
                ServerUdpRelayHostPorts MakeServerUdpRelayHostPorts(const std::shared_ptr<IServerUdpRelayHost>& host) noexcept;

            }
        }
    }
}
