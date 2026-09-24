#pragma once

/**
 * @file ClientDatagramPortManager.h
 * @brief Self-contained client UDP relay session manager with an independent lock (P2-c).
 *
 * Extracts the datagrams_/datagram_handlers_ session tables and their management out of the
 * God-Object VEthernetExchanger. Guarded by its OWN lock, extending H1's "drop the shared
 * lock" spirit to the UDP session table: UDP packets no longer contend the exchanger lock
 * shared with FRP mappings and deadline timers. Consumes exchanger/switcher capabilities via
 * an injected UdpRelayHostPorts instead of a back-pointer + friend.
 */

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h> // std::hash<udp::endpoint> specialization (must precede the endpoint-keyed tables)
#include <ppp/app/client/udp/UdpRelayHost.h>
#include <ppp/app/client/routing/HumanRoutingRules.h>

namespace ppp {
    namespace coroutines {
        class YieldContext;
    }
}

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {

                class ClientDatagramPortManager final {
                public:
                    explicit ClientDatagramPortManager(UdpRelayHostPorts ports) noexcept;
                    ~ClientDatagramPortManager() noexcept;

                    ClientDatagramPortManager(const ClientDatagramPortManager&) = delete;
                    ClientDatagramPortManager& operator=(const ClientDatagramPortManager&) = delete;

                    /** @brief Whether the injected ports surface is complete. */
                    bool IsValid() const noexcept;

                    /** @brief Find-or-create the datagram port bound to source (deduplicated). */
                    VEthernetDatagramPortPtr AddNewDatagramPort(const ITransmissionPtr& transmission,
                                                                const boost::asio::ip::udp::endpoint& source) noexcept;
                    /** @brief Look up the datagram port for source, or null. */
                    VEthernetDatagramPortPtr GetDatagramPort(const boost::asio::ip::udp::endpoint& source) noexcept;
                    /** @brief Remove and return the datagram port for source, or null. */
                    VEthernetDatagramPortPtr ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& source) noexcept;
                    /** @brief Remove source only when it still maps to the self-finalizing port. */
                    VEthernetDatagramPortPtr ReleaseDatagramPortIf(
                        const boost::asio::ip::udp::endpoint& source,
                        const VEthernetDatagramPort* expected) noexcept;

                    /** @brief Send a UDP datagram to the server via the source-bound relay port. */
                    bool SendTo(const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                                const void* packet, int packet_size) noexcept;
                    bool SendTo(const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                                const void* packet, int packet_size, routing::RoutingAction action) noexcept;
                    /** @brief Route an inbound datagram to its port, a local handler, or the TUN. */
                    bool ReceiveFromDestination(const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                                                ppp::Byte* packet, int packet_length) noexcept;
                    /** @brief Link-layer inbound entry point; forwards to ReceiveFromDestination. */
                    bool OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source,
                                  const boost::asio::ip::udp::endpoint& destination, ppp::Byte* packet, int packet_length,
                                  ppp::coroutines::YieldContext& y) noexcept;
                    /** @brief Dispatch an inbound datagram to a registered local handler, if any. */
                    bool TryHandleDatagram(const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                                           void* packet, int packet_size) noexcept;
                    /** @brief Register a local proxy reply handler for source. */
                    bool RegisterDatagramHandler(const boost::asio::ip::udp::endpoint& source, const DatagramPacketHandler& handler) noexcept;
                    /** @brief Remove a local proxy reply handler and finalize any bound port. */
                    bool ReleaseDatagramHandler(const boost::asio::ip::udp::endpoint& source) noexcept;

                    /** @brief Rebind every retained UDP flow to a replacement carrier, or null while suspended. */
                    bool RebindTransmission(const ITransmissionPtr& transmission) noexcept;
                    /** @brief Dispose retained UDP flows while preserving registered local handlers. */
                    void ResetPorts() noexcept;

                    /** @brief NAT-timeout sweep: dispose aging ports two-phase (collect/erase under
                     *         lock, dispose outside it) with an identity check to survive races. */
                    void Tick(UInt64 now) noexcept;

                    /** @brief Dispose every port and clear both tables (exchanger teardown). */
                    void Release() noexcept;

                private:
                    UdpRelayHostPorts                                                    ports_;
                    /** @brief Independent lock guarding closed_, datagrams_, and datagram_handlers_. */
                    std::mutex                                                          syncobj_;
                    /** @brief Permanent manager-local admission gate, closed by Release(). */
                    bool                                                                closed_ = false;
                    /** @brief Active UDP datagram relay port table. */
                    ppp::unordered_map<boost::asio::ip::udp::endpoint,
                        VEthernetDatagramPortPtr>                                       datagrams_;
                    /** @brief Optional local proxy UDP reply handlers. */
                    ppp::unordered_map<boost::asio::ip::udp::endpoint,
                        DatagramPacketHandler>                                          datagram_handlers_;
                };

            }
        }
    }
}
