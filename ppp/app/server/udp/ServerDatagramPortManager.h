#pragma once

/**
 * @file ServerDatagramPortManager.h
 * @brief Self-contained server UDP relay session manager (P2-e). LOCK-FREE by design.
 *
 * Extracts the datagrams_ session table and its management out of the God-Object
 * VirtualEthernetExchanger. Unlike the client manager (P2-c), the server runs the whole
 * datagram data-plane on the single owning io_context thread, so the table needs NO lock:
 * the exchanger's syncobj_ never actually guarded datagrams_ (it only protects
 * preferred_tun_fd_ and the FRP mappings). Consumes exchanger capabilities via an injected
 * ServerUdpRelayHostPorts instead of a back-pointer + friend.
 */

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h> // std::hash<udp::endpoint> specialization (must precede the endpoint-keyed table)
#include <ppp/app/server/udp/ServerUdpRelayHost.h>

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {

                class ServerDatagramPortManager final {
                public:
                    explicit ServerDatagramPortManager(ServerUdpRelayHostPorts ports) noexcept;
                    ~ServerDatagramPortManager() noexcept;

                    ServerDatagramPortManager(const ServerDatagramPortManager&) = delete;
                    ServerDatagramPortManager& operator=(const ServerDatagramPortManager&) = delete;

                    /** @brief Whether the injected ports surface is complete. */
                    bool IsValid() const noexcept;

                    /** @brief Find-or-create the datagram port for source (deduplicated), opening its socket. */
                    VirtualEthernetDatagramPortPtr AddNewDatagramPort(const ITransmissionPtr& transmission,
                                                                      const boost::asio::ip::udp::endpoint& source) noexcept;
                    /** @brief Look up the datagram port for source, or null. */
                    VirtualEthernetDatagramPortPtr GetDatagramPort(const boost::asio::ip::udp::endpoint& source) noexcept;
                    /** @brief Remove, dispose, and return the datagram port for source, or null. */
                    VirtualEthernetDatagramPortPtr ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& source) noexcept;

                    /**
                     * @brief Forward a client UDP payload to its destination via the per-source relay port.
                     * @param fin True when the client signalled a finalize (empty packet); tears the port down.
                     * @note Mirrors the exchanger data-plane tail (SendPacketToDestination lines 907-945): find
                     *       the port and send, finalize on fin, or open a fresh port and send on first contact.
                     */
                    bool SendToDestination(const ITransmissionPtr& transmission,
                                           const boost::asio::ip::udp::endpoint& source,
                                           const boost::asio::ip::udp::endpoint& destination,
                                           ppp::Byte* packet, int packet_length, bool fin) noexcept;

                    /** @brief Rebind every retained UDP socket to the current carrier (or null on suspend). */
                    void RebindTransmission(const ITransmissionPtr& transmission) noexcept;

                    /** @brief NAT-timeout sweep: dispose aging ports (single-thread, delegates to Dictionary). */
                    void Tick(UInt64 now) noexcept;

                    /** @brief Dispose every port and clear the table (exchanger teardown). */
                    void Release() noexcept;

                private:
                    ServerUdpRelayHostPorts                                              ports_;
                    /** @brief Active UDP datagram relay port table (no lock: single io_context thread). */
                    ppp::unordered_map<boost::asio::ip::udp::endpoint,
                        VirtualEthernetDatagramPortPtr>                                 datagrams_;
                };

            }
        }
    }
}
