#pragma once

/**
 * @file VEthernetSocksProxyConnection.h
 * @brief Declares the SOCKS5 local proxy connection implementation.
 */

#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>

namespace ppp {
    namespace tap {
        class TapUserspace;
    }

    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetNetworkSwitcher;

            namespace proxys {
                class VEthernetSocksProxySwitcher;

                /**
                 * @class VEthernetSocksProxyConnection
                 * @brief Handles SOCKS5 handshake, authentication, CONNECT, and UDP ASSOCIATE processing.
                 * @note This connection serves local SOCKS clients and forwards validated targets to the bridge layer.
                 */
                class VEthernetSocksProxyConnection : public VEthernetLocalProxyConnection {
                public:
                    typedef std::shared_ptr<VEthernetSocksProxySwitcher>                VEthernetSocksProxySwitcherPtr;
                    typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,
                        boost::asio::ip::udp::endpoint>                                 UdpAssociateEndpointTable;

                public:
                    /**
                     * @brief Constructs a SOCKS proxy connection object.
                     * @param proxy Parent SOCKS switcher that owns this connection lifecycle.
                     * @param exchanger Shared exchanger used to create upstream bridge links.
                     * @param context I/O context used for asynchronous operations.
                     * @param strand Serialized execution strand for connection callbacks.
                     * @param socket Accepted client TCP socket.
                     */
                    VEthernetSocksProxyConnection(const VEthernetSocksProxySwitcherPtr& proxy,
                        const VEthernetExchangerPtr&                                    exchanger, 
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;
                    /**
                     * @brief Releases UDP ASSOCIATE resources owned by this SOCKS connection.
                     */
                    virtual ~VEthernetSocksProxyConnection() noexcept;

                private:
                    /**
                     * @brief Selects a negotiated SOCKS5 method from the client offer list.
                     * @param y Coroutine yield context for asynchronous reads.
                     * @param method Output selected method code.
                     * @return SOCKS status code indicating success, protocol rejection, or transport error.
                     */
                    int                                                                 SelectMethod(YieldContext& y, int& method) noexcept;
                    /**
                     * @brief Sends a compact two-byte reply packet.
                     * @param y Coroutine yield context for asynchronous writes.
                     * @param k First reply byte.
                     * @param v Second reply byte.
                     * @return true if write succeeds; otherwise false.
                     */
                    bool                                                                Replay(YieldContext& y, int k, int v) noexcept;
                    /**
                     * @brief Authenticates client credentials using SOCKS username/password sub-protocol.
                     * @param y Coroutine yield context for asynchronous reads.
                     * @return SOCKS status code indicating authenticated, denied, or transport failure.
                     */
                    int                                                                 Authentication(YieldContext& y) noexcept;
                    /**
                     * @brief Reads and validates a SOCKS5 CONNECT or UDP ASSOCIATE request.
                     * @param y Coroutine yield context for asynchronous I/O.
                     * @param address Output destination host string.
                     * @param port Output destination port.
                     * @param address_type Output destination address type.
                     * @param command Output SOCKS command id.
                     * @return SOCKS request status code.
                     * @note This method writes the SOCKS request-reply packet to the client.
                     */
                    int                                                                 Requirement(YieldContext& y, ppp::string& address, int& port, ppp::app::protocol::AddressType& address_type, int& command) noexcept;
                    /**
                     * @brief Opens the UDP relay socket used by SOCKS5 UDP ASSOCIATE.
                     * @param y Coroutine yield context for asynchronous operations.
                     * @return true if the relay socket is bound and receive loop scheduled.
                     */
                    bool                                                                OpenUdpAssociate(YieldContext& y) noexcept;
                    /**
                     * @brief Starts one asynchronous receive operation for SOCKS5 UDP datagrams.
                     * @return true if the receive operation was scheduled.
                     */
                    bool                                                                UdpAssociateLoopback() noexcept;
                    /**
                     * @brief Parses one SOCKS5 UDP request and forwards its payload through the exchanger.
                     * @param packet SOCKS UDP request bytes.
                     * @param packet_length Request length in bytes.
                     * @param sourceEP UDP endpoint of the local SOCKS client.
                     * @return true if parsed and accepted for forwarding.
                     */
                    bool                                                                ForwardUdpAssociatePacket(YieldContext& y, Byte* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                    /**
                     * @brief Sends one SOCKS5 UDP response packet back to the local client endpoint.
                     * @param sourceEP Remote UDP source endpoint encoded in the SOCKS header.
                     * @param destinationEP Local SOCKS client UDP endpoint.
                     * @param packet UDP payload bytes.
                     * @param packet_length Payload length in bytes.
                     * @return true if the response datagram was sent.
                     */
                    bool                                                                SendUdpAssociatePacketToClient(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_length) noexcept;
                    /**
                     * @brief Sends a virtual-subnet datagram from the virtual IP through the in-process adapter.
                     * @note Proxy-only without a host adapter: a host socket would leave through the physical default route.
                     */
                    bool                                                                SendUserspaceDatagram(const std::shared_ptr<VEthernetNetworkSwitcher>& switcher,
                        const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP,
                        const void* payload, int payload_length) noexcept;

                protected:
                    /**
                     * @brief Runs the complete SOCKS5 handshake and establishes upstream bridge endpoint.
                     * @param y Coroutine yield context.
                     * @return true when handshake succeeds and bridge setup is completed.
                     */
                    virtual bool                                                        Handshake(YieldContext& y) noexcept override;
                    /**
                     * @brief Keeps the SOCKS5 UDP ASSOCIATE control connection alive after handshake.
                     * @param y Coroutine yield context.
                     * @return false when the control connection closes or errors.
                     */
                    virtual bool                                                        RunAfterHandshakeWithoutBridge(YieldContext& y) noexcept override;

                private:
                    std::shared_ptr<boost::asio::ip::udp::socket>                       udp_socket_;
                    std::shared_ptr<Byte>                                               udp_buffer_;
                    boost::asio::ip::udp::endpoint                                      udp_remote_ep_;
                    boost::asio::ip::udp::endpoint                                      udp_client_ep_;
                    UdpAssociateEndpointTable                                           udp_destination_clients_;
                    std::weak_ptr<ppp::tap::TapUserspace>                               userspace_tap_;
                    uint16_t                                                            userspace_udp_port_ = 0;
                };
            }
        }
    }
}
