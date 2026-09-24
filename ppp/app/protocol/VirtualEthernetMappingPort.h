#pragma once

/**
 * @file VirtualEthernetMappingPort.h
 * @brief Declares virtual Ethernet mapping port server/client forwarding components.
 * @author ("OPENPPP2 Team")
 * @license ("GPL-3.0")
 */

#include <ppp/stdafx.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>

namespace ppp::configurations { class AppConfiguration; }
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>

namespace ppp {
    namespace app {
        namespace protocol {
            /**
             * @brief Manages one virtual Ethernet mapping port for TCP/UDP forwarding.
             */
            class VirtualEthernetMappingPort : public std::enable_shared_from_this<VirtualEthernetMappingPort> {
            public:
                // Type aliases for convenience
                typedef ppp::coroutines::YieldContext                                       YieldContext;        ///< Coroutine suspend/resume context passed through async call chains.
                typedef ppp::transmissions::ITransmission                                   ITransmission;       ///< Abstract virtual Ethernet transmission channel.
                typedef std::shared_ptr<ITransmission>                                      ITransmissionPtr;    ///< Shared ownership handle for a transmission channel.
                typedef ppp::configurations::AppConfiguration                               AppConfiguration;    ///< Application-wide runtime configuration type.
                typedef std::shared_ptr<AppConfiguration>                                   AppConfigurationPtr; ///< Shared ownership handle for the configuration object.
                typedef std::shared_ptr<VirtualEthernetMappingPort>                         Ptr;                 ///< Canonical shared-pointer alias for this class.
                typedef std::shared_ptr<VirtualEthernetLogger>                              VirtualEthernetLoggerPtr; ///< Shared ownership handle for the structured event logger.

            public:
                /**
                 * @brief Constructs a mapping port instance.
                 * @param linklayer Linklayer used for FRP control/data messaging.
                 * @param transmission Active transmission channel.
                 * @param tcp True for TCP mapping, false for UDP mapping.
                 * @param in Direction/side flag used by mapping key.
                 * @param remote_port Remote service port.
                 * @return N/A.
                 * @note The object starts in non-opened state until server/client open methods are called.
                 */
                VirtualEthernetMappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept;
                /**
                 * @brief Destroys the mapping port and owned runtime resources.
                 * @return N/A.
                 * @note Equivalent cleanup path is also reachable through `Dispose()`.
                 */
                virtual ~VirtualEthernetMappingPort() noexcept;

            public:
                /** @brief Gets IO context. @return Shared io_context pointer. @note Lightweight getter. */
                std::shared_ptr<boost::asio::io_context>                                    GetContext() noexcept;
                /** @brief Gets linklayer instance. @return Shared VirtualEthernetLinklayer pointer. @note Lightweight getter. */
                std::shared_ptr<VirtualEthernetLinklayer>                                   GetLinklayer() noexcept;
                /** @brief Gets transmission instance. @return Shared ITransmission pointer. @note Lightweight getter. */
                ITransmissionPtr                                                            GetTransmission() noexcept;
                /** @brief Checks TCP mode. @return True when protocol is TCP. @note Lightweight state check. */
                bool                                                                        ProtocolIsTcpNetwork() noexcept;
                /** @brief Checks UDP mode. @return True when protocol is UDP. @note Lightweight state check. */
                bool                                                                        ProtocolIsUdpNetwork() noexcept;
                /** @brief Checks inbound flag. @return True when inbound/in flag is set. @note Naming follows existing protocol semantics. */
                bool                                                                        ProtocolIsNetworkV4() noexcept;
                /** @brief Checks non-inbound flag. @return True when inbound/in flag is not set. @note Naming follows existing protocol semantics. */
                bool                                                                        ProtocolIsNetworkV6() noexcept;
                /** @brief Gets mapped remote port. @return Remote port number. @note Lightweight getter. */
                int                                                                         GetRemotePort() noexcept;
                /** @brief Gets logger. @return Shared logger pointer. @note Lightweight getter. */
                VirtualEthernetLoggerPtr                                                    GetLogger() noexcept { return logger_; }
                /** @brief Gets buffer allocator. @return Shared allocator pointer. @note Lightweight getter. */
                std::shared_ptr<ppp::threading::BufferswapAllocator>                        GetBufferAllocator() noexcept { return buffer_allocator_; }
                
            public:
                /**
                 * @brief Builds mapping dictionary key.
                 * @param in Direction/side flag.
                 * @param tcp Protocol flag.
                 * @param remote_port Remote port value.
                 * @return 32-bit composite key.
                 * @note Key packs flags in high bits and port in low 16 bits.
                 */
                static constexpr uint32_t                                                   GetHashCode(bool in, bool tcp, int remote_port) noexcept {
                    uint32_t key = (in ? 1 : 0) << 24;   // bit 24: IPv4=1, IPv6=0
                    key |= (tcp ? 1 : 0) << 16;          // bit 16: TCP=1, UDP=0
                    key |= remote_port & 0xffff;         // lower 16 bits: port number
                    return key;
                }

            public:
                /** @brief Gets currently bound FRP server endpoint. @return TCP endpoint value. @note Returns default endpoint when server is not opened. */
                boost::asio::ip::tcp::endpoint                                              BoundEndPointOfFrpServer() noexcept;
                /** @brief Opens FRP server side. @param logger Logger for connect/session events. @return True on success. @note Creates TCP/UDP network sockets by mapping mode. */
                virtual bool                                                                OpenFrpServer(const VirtualEthernetLoggerPtr& logger) noexcept;
                /** @brief Opens FRP client side. @param local_ip Local destination bind/connect address. @param local_port Local destination port. @return True on success. @note Used by remote side to reach local service. */
                virtual bool                                                                OpenFrpClient(const boost::asio::ip::address& local_ip, int local_port) noexcept;
                /** @brief Disposes mapping port and owned sessions. @return void. @note Safe to call multiple times. */
                virtual void                                                                Dispose() noexcept;
                /** @brief Updates timeouts/aging state. @param now Current tick count in milliseconds. @return True when update completed. @note Expired sessions/ports may be closed during this pass. */
                virtual bool                                                                Update(UInt64 now) noexcept;
                /** @brief Generates a new connection id. @return Positive unique id. @note Used for FRP connection correlation. */
                static int                                                                  NewId() noexcept;

            public:
                /** @brief Finds mapping port by key fields. @param mappings Mapping dictionary. @param in Direction flag. @param tcp Protocol flag. @param remote_port Remote port. @return Matched mapping port or null. @note Lookup key is generated by `GetHashCode()`. */
                static std::shared_ptr<VirtualEthernetMappingPort>                          FindMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept;
                /** @brief Inserts mapping port by key fields. @param mappings Mapping dictionary. @param in Direction flag. @param tcp Protocol flag. @param remote_port Remote port. @param mapping_port Mapping object to insert. @return True on success. @note Existing key insertion behavior follows container semantics. */
                static bool                                                                 AddMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port, const Ptr& mapping_port) noexcept;
                /** @brief Removes and returns mapping port by key fields. @param mappings Mapping dictionary. @param in Direction flag. @param tcp Protocol flag. @param remote_port Remote port. @return Removed mapping object or null. @note Safe when key is absent. */
                static std::shared_ptr<VirtualEthernetMappingPort>                          DeleteMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept;

            public:
                /** @brief Handles server-side connect-ok control packet. @param connection_id Connection identifier. @param error_code Protocol error code. @return True when handled successfully. @note Primarily used for TCP server sessions. */
                bool                                                                        Server_OnFrpConnectOK(int connection_id, Byte error_code) noexcept;
                /** @brief Handles server-side disconnect control packet. @param connection_id Connection identifier. @return True when handled successfully. @note Missing connection ids are treated as no-op failures by implementation. */
                bool                                                                        Server_OnFrpDisconnect(int connection_id) noexcept;
                /** @brief Handles server-side payload push. @param connection_id Connection identifier. @param packet Payload pointer. @param packet_length Payload length. @return True on successful dispatch. @note Data is forwarded to local FRP user socket/port. */
                bool                                                                        Server_OnFrpPush(int connection_id, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept;
                /** @brief Handles server-side UDP send-to request. @param packet Datagram payload pointer. @param packet_length Datagram payload length. @param sourceEP Source endpoint metadata. @return True on successful send. @note Used by UDP mapping mode. */
                bool                                                                        Server_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            public:
                /** @brief Handles client-side disconnect control packet. @param connection_id Connection identifier. @return True when handled successfully. @note Closes corresponding local destination session. */
                bool                                                                        Client_OnFrpDisconnect(int connection_id) noexcept;
                /** @brief Handles client-side payload push. @param connection_id Connection identifier. @param packet Payload pointer. @param packet_length Payload length. @return True on successful dispatch. @note Data is forwarded to destination server/socket. */
                bool                                                                        Client_OnFrpPush(int connection_id, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept;
                /** @brief Handles client-side connect request. @param connection_id Connection identifier. @return True when local connect sequence starts. @note Mainly used by TCP mapping mode. */
                bool                                                                        Client_OnFrpConnect(int connection_id) noexcept;
                /** @brief Handles client-side UDP send-to request. @param packet Datagram payload pointer. @param packet_length Datagram payload length. @param sourceEP Source endpoint metadata. @return True on successful send. @note Used by UDP mapping mode. */
                bool                                                                        Client_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                /**
                 * @brief Server runtime container for incoming FRP-side traffic.
                 */
                class Server final {
                public:
                    /**
                     * @brief Represents one server-side TCP bridged connection.
                     */
                    class Connection final : public ppp::net::asio::IAsynchronousWriteIoQueue {
                    public:
                        /** @brief Constructs server-side connection object. @param mapping_port Owning mapping port. @param server Owning server container. @param connection_id Connection identifier. @param socket Accepted user TCP socket. @return N/A. @note Socket ownership is shared. */
                        Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Server>& server, int connection_id, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                        /** @brief Destroys server-side connection object. @return N/A. @note Finalization can also occur through `Dispose()`. */
                        ~Connection() noexcept;

                    public:
                        /** @brief Disposes this connection. @return void. @note Delegates to `Finalize(false)`. */
                        void                                                                Dispose() noexcept { Finalize(false); }
                        /** @brief Sends connect request to FRP client side. @return True on successful request dispatch. @note Used after local user socket accept. */
                        bool                                                                ConnectToFrpClient() noexcept;
                        /** @brief Writes data to local FRP user socket. @param packet Payload pointer. @param packet_size Payload length. @return True on async write queue acceptance. @note Data path: remote FRP client -> local user. */
                        bool                                                                SendToFrpUser(const std::shared_ptr<Byte>& owner, const void* packet, int packet_size) noexcept;
                        /** @brief Writes data to remote FRP client channel. @param packet Payload pointer. @param packet_size Payload length. @return True on successful transmission write. @note Data path: local user -> remote FRP client. */
                        bool                                                                SendToFrpClient(const void* packet, int packet_size) noexcept;
                        /** @brief Refreshes timeout deadline based on connection stage. @return void. @note Uses connect timeout before active state and inactive timeout afterwards. */
                        void                                                                Update() noexcept;
                        /** @brief Checks whether connection is expired. @param now Current tick count. @return True when disposed stage reached or timeout elapsed. @note Lightweight state check. */
                        bool                                                                IsPortAging(UInt64 now) noexcept { return connection_stated_.load() > 3 || now >= timeout_; }

                    public:
                        /** @brief Handles FRP connect result callback. @param error_code Protocol error code. @return True on successful state transition. @note Called when peer acknowledges connect request. */
                        bool                                                                OnConnectOK(Byte error_code) noexcept;
                        /** @brief Handles disconnect event. @return void. @note Delegates to `Finalize(true)`. */
                        void                                                                OnDisconnect() noexcept { Finalize(true); }

                    private:
                        /** @brief Finalizes connection resources. @param disconnect True to notify remote side about disconnect. @return void. @note Idempotent cleanup is expected by callers. */
                        void                                                                Finalize(bool disconnect) noexcept;
                        /** @brief Starts user-to-client forwarding loop. @return True when receive loop starts. @note Uses async reads from local socket. */
                        bool                                                                ForwardFrpUserToFrpClient() noexcept;
                        /** @brief Queue write implementation for local socket. @param packet Managed buffer. @param offset Start offset. @param packet_length Number of bytes. @param cb Completion callback. @return True when async write starts. @note Called by `IAsynchronousWriteIoQueue`. */
                        virtual bool                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                    private:
                        std::atomic<int>                                                    connection_stated_;          // 0=init,1=connecting,2=connected,3=active,4=dead
                        std::shared_ptr<Server>                                             server_;                     // Parent server object
                        int                                                                 connection_id_;              // Unique ID for this connection
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;               // Parent mapping port
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;                  // Link layer for FRP operations
                        std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;                     // TCP socket to local user
                        std::atomic<UInt64>                                                   timeout_;                    // Expiration timestamp
                        AppConfigurationPtr                                                 configuration_;              // App configuration
                        std::shared_ptr<Byte>                                               buffer_chunked_;             // Read buffer for socket
                    };
                    typedef std::shared_ptr<Connection>                                     ConnectionPtr;

                public:
                    std::shared_ptr<Byte>                                                   socket_source_buf_;          // Buffer for UDP receive
                    boost::asio::ip::udp::endpoint                                          socket_source_ep_;           // Endpoint of UDP sender
                    boost::asio::ip::udp::socket                                            socket_udp_;                 // UDP socket (for datagram mode)
                    boost::asio::ip::tcp::acceptor                                          socket_tcp_;                 // TCP acceptor (for stream mode)
                    boost::asio::ip::tcp::endpoint                                          socket_endpoint_;            // Bound endpoint of the server
                    ppp::unordered_map<int, ConnectionPtr>                                  socket_connections_;         // Map from connection ID to connection object

                public:
                    /** @brief Constructs server container. @param owner Raw owner pointer. @return N/A. @note Owner lifetime is controlled externally by shared mapping object. */
                    Server(VirtualEthernetMappingPort* owner) noexcept;
                };
                /** @brief Gets server connection by id. @param connection_id Connection identifier. @return Connection shared pointer or null. @note Lookup is performed in server connection map. */
                Server::ConnectionPtr                                                       Server_GetConnection(int connection_id) noexcept;

            private:
                /**
                 * @brief Client runtime container for local destination forwarding.
                 */
                class Client final {
                public:
                    /**
                     * @brief Represents one client-side TCP bridged connection.
                     */
                    class Connection final : public ppp::net::asio::IAsynchronousWriteIoQueue {
                    public:
                        /** @brief Constructs client-side connection object. @param mapping_port Owning mapping port. @param client Owning client container. @param connection_id Connection identifier. @return N/A. @note Socket is created during connect sequence. */
                        Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, int connection_id) noexcept;
                        /** @brief Destroys client-side connection object. @return N/A. @note Finalization can also occur through `Dispose()`. */
                        ~Connection() noexcept;

                    public:
                        /** @brief Connects to local destination service. @return True when connect flow starts/succeeds. @note Called after FRP connect request arrives. */
                        bool                                                                ConnectToDestinationServer() noexcept;
                        /** @brief Refreshes timeout deadline based on connection stage. @return void. @note Uses connect timeout before active state and inactive timeout afterwards. */
                        void                                                                Update() noexcept;
                        /** @brief Checks whether connection is expired. @param now Current tick count. @return True when disposed stage reached or timeout elapsed. @note Lightweight state check. */
                        bool                                                                IsPortAging(UInt64 now) noexcept { return connection_stated_.load() > 3 || now >= timeout_; }
                        /** @brief Disposes this connection. @return void. @note Delegates to `Finalize(false)`. */
                        void                                                                Dispose() noexcept { Finalize(false); }
                        /** @brief Sends payload to local destination server. @param packet Payload pointer. @param packet_size Payload length. @return True on queue acceptance. @note Data path: remote FRP server -> local destination. */
                        bool                                                                SendToDestinationServer(const std::shared_ptr<Byte>& owner, const void* packet, int packet_size) noexcept;

                    public:
                        /** @brief Handles local destination connect result. @param ok True when connect succeeded. @return True on successful protocol notification. @note Sends FRP connect-ok response. */
                        bool                                                                OnConnectedOK(bool ok) noexcept;
                        /** @brief Handles disconnect event. @return void. @note Delegates to `Finalize(true)`. */
                        void                                                                OnDisconnect() noexcept { Finalize(true); }

                    private:
                        /** @brief Finalizes connection resources. @param disconnect True to notify peer about disconnect. @return void. @note Cleanup closes socket and updates maps/state. */
                        void                                                                Finalize(bool disconnect) noexcept;
                        /** @brief Starts destination-to-peer forwarding loop. @return True when receive loop starts. @note Uses async reads from destination socket. */
                        bool                                                                Loopback() noexcept;
                        /** @brief Queue write implementation for destination socket. @param packet Managed buffer. @param offset Start offset. @param packet_length Number of bytes. @param cb Completion callback. @return True when async write starts. @note Called by `IAsynchronousWriteIoQueue`. */
                        virtual bool                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                    private:
                        std::atomic<int>                                                    connection_stated_ = FALSE;  // 0=init,1=connecting,2=connected,3=active,4=dead
                        std::shared_ptr<Client>                                             client_;                     // Parent client object
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;               // Parent mapping port
                        int                                                                 connection_id_     = 0;     // Unique ID
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;                  // Link layer
                        std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;                     // TCP socket to destination
                        std::atomic<UInt64>                                                   timeout_           = 0;     // Expiration timestamp
                        AppConfigurationPtr                                                 configuration_;              // App config
                        ITransmissionPtr                                                    transmission_;               // Transmission object
                        std::shared_ptr<Byte>                                               buffer_chunked_;             // Read buffer
                    };
                    typedef std::shared_ptr<Connection>                                     ConnectionPtr;

                public:
                    /**
                     * @brief Represents one UDP NAT datagram forwarding port.
                     */
                    class DatagramPort final : public std::enable_shared_from_this<DatagramPort> {
                    public:
                        /** @brief Constructs datagram port object. @param mapping_port Owning mapping port. @param client Owning client container. @param natEP NAT endpoint key. @return N/A. @note Each NAT endpoint maps to one datagram port instance. */
                        DatagramPort(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, const boost::asio::ip::udp::endpoint& natEP) noexcept;
                        /** @brief Destroys datagram port object. @return N/A. @note Ensures UDP socket is closed during cleanup. */
                        ~DatagramPort() noexcept;

                    public:
                        /** @brief Sends UDP payload to peer/local destination path. @param packet Payload pointer. @param packet_length Payload length. @param sourceEP Source endpoint metadata. @return True on successful send dispatch. @note Direction depends on caller side. */
                        bool                                                                SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                        /** @brief Refreshes inactive timeout deadline. @return void. @note Uses UDP inactive timeout from configuration. */
                        void                                                                Update() noexcept;
                        /** @brief Opens UDP socket and starts receive loop. @return True on success. @note Socket bind/open mode follows endpoint protocol family. */
                        bool                                                                Open() noexcept;
                        /** @brief Checks whether datagram port is expired. @param now Current tick count. @return True when disposed or timeout elapsed. @note Lightweight state check. */
                        bool                                                                IsPortAging(UInt64 now) noexcept { return disposed_.load() != FALSE || now >= timeout_; }
                        /** @brief Disposes datagram port resources. @return void. @note Safe to call repeatedly. */
                        void                                                                Dispose() noexcept;

                    private:
                        /** @brief Starts asynchronous UDP receive loop. @return True when loop is armed. @note Received datagrams are forwarded to peer path. */
                        bool                                                                Loopback() noexcept;
                        /** @brief Forwards UDP payload to destination side. @param packet Payload pointer. @param packet_length Payload length. @return True on successful forwarding dispatch. @note Called from receive loop callbacks. */
                        bool                                                                SendToDestinationServer(const void* packet, int packet_length) noexcept;

                    private:
                        std::atomic<int>                                                    disposed_ = FALSE;           // Disposal flag
                        boost::asio::ip::udp::socket                                        socket_;                     // UDP socket for local communication
                        std::atomic<uint64_t>                                                 timeout_  = 0;               // Expiration timestamp
                        AppConfigurationPtr                                                 configuration_;              // App config
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;               // Parent mapping port
                        std::shared_ptr<Byte>                                               buffer_chunked_;             // Receive buffer
                        boost::asio::ip::udp::endpoint                                      source_ep_;                  // Endpoint of last received packet
                        boost::asio::ip::udp::endpoint                                      nat_ep_;                     // NAT endpoint (remote peer)
                        std::shared_ptr<Client>                                             client_;                     // Parent client object
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;                  // Link layer
                        ITransmissionPtr                                                    transmission_;               // Transmission object
                    };
                    typedef std::shared_ptr<DatagramPort>                                   DatagramPortPtr;

                public:
                    boost::asio::ip::udp::endpoint                                          local_ep_;                   // Local endpoint to bind to
                    bool                                                                    local_in_;                   // True if local IP is IPv4
                    ppp::unordered_map<int, ConnectionPtr>                                  socket_connections_;         // Map from connection ID to connection object
                    ppp::unordered_map<boost::asio::ip::udp::endpoint, DatagramPortPtr>     socket_datagram_ports_;      // Map from NAT endpoint to datagram port
                    
                public:
                    /** @brief Constructs client container. @return N/A. @note Maps/sockets are initialized empty. */
                    Client() noexcept;
                };
                /** @brief Gets client connection by id. @param connection_id Connection identifier. @return Connection shared pointer or null. @note Lookup is performed in client connection map. */
                Client::ConnectionPtr                                                       Client_GetConnection(int connection_id) noexcept;
                /** @brief Gets datagram port by NAT endpoint key. @param nat_key NAT endpoint key. @return Datagram port shared pointer or null. @note Lookup is performed in client UDP port map. */
                Client::DatagramPortPtr                                                     Client_GetDatagramPort(const boost::asio::ip::udp::endpoint& nat_key) noexcept;

            private:
                /** @brief Sends UDP payload from server side to FRP client. @param packet Payload pointer. @param packet_length Payload length. @param sourceEP Source endpoint metadata. @return True on successful send. @note Internal helper for server UDP mapping mode. */
                bool                                                                        Server_SendToFrpClient(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /** @brief Accepts an incoming local FRP user TCP socket. @param server Server container. @param context Asio context object. @param socket Accepted socket object. @return True when connection object is created and started. @note Internal helper for TCP mapping mode. */
                bool                                                                        Server_AcceptFrpUserSocket(const std::shared_ptr<Server>& server, const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept;

            private:
                /** @brief Finalizes whole mapping port state. @return void. @note Closes sockets, sessions, and clears runtime maps. */
                void                                                                        Finalize() noexcept;
                /** @brief Starts UDP receive loop for server mode. @return True when loop is armed. @note Used only when mapping protocol is UDP. */
                bool                                                                        LoopbackFrpServer() noexcept;
                /** @brief Opens TCP acceptor for server mode. @return True on successful open/bind/listen. @note Used only when mapping protocol is TCP. */
                bool                                                                        OpenNetworkSocketStream() noexcept;
                /** @brief Opens UDP socket for server mode. @return True on successful open/bind. @note Used only when mapping protocol is UDP. */
                bool                                                                        OpenNetworkSocketDatagram() noexcept;

            private:
                std::atomic<int>                                                            disposed_     = FALSE;      // Disposal flag
                std::mutex                                                                  socket_connections_mutex_;   // Guards server/client connection & datagram-port tables
                std::shared_ptr<VirtualEthernetLinklayer>                                   linklayer_;                  // Link layer reference
                ITransmissionPtr                                                            transmission_;               // Transmission reference

                struct {
                    bool                                                                    tcp_          : 1;          // True for TCP, false for UDP
                    bool                                                                    in_           : 7;          // True for IPv4, false for IPv6
                };

                int                                                                         remote_port_  = 0;          // Remote port number
                std::shared_ptr<boost::asio::io_context>                                    context_;                    // Asio IO context
                std::shared_ptr<Server>                                                     server_;                     // Server instance (if acting as server)
                std::shared_ptr<Client>                                                     client_;                     // Client instance (if acting as client)
                AppConfigurationPtr                                                         configuration_;              // App configuration
                VirtualEthernetLoggerPtr                                                    logger_;                     // Logger instance
                std::shared_ptr<ppp::threading::BufferswapAllocator>                        buffer_allocator_;           // Buffer allocator for memory management
            };
        }
    }
}
