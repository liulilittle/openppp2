// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file VirtualEthernetMappingPort.cpp
 * @brief FRP mapping port runtime for TCP/UDP forwarding paths.
 */

#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/MappingPortConnectReentrancy.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

namespace ppp {
    namespace app {
        namespace protocol {
            /** @brief Maximum UDP payload buffer size used by forwarding loops. */
            static constexpr int PPP_UDP_BUFFER_SIZE = 65000;
            /** @brief Maximum TCP buffer size used by forwarding loops. */
            static constexpr int PPP_TCP_BUFFER_SIZE = PPP_UDP_BUFFER_SIZE;

            static void LogNetworkPortInvalidToSessionLog(const std::shared_ptr<VirtualEthernetLogger>& logger, const char* where, int remote_port, int local_port, bool tcp, bool in) noexcept {
                if (NULLPTR == logger || NULLPTR == where) {
                    return;
                }

                ppp::string line = "{\"event\":\"network_port_invalid\",\"code\":100,\"where\":\"";
                line += where;
                line += "\",\"remote_port\":";
                line += stl::to_string<ppp::string>(remote_port);
                line += ",\"local_port\":";
                line += stl::to_string<ppp::string>(local_port);
                line += ",\"tcp\":";
                line += tcp ? "true" : "false";
                line += ",\"in\":";
                line += in ? "true" : "false";
                line += "}\n";
                logger->Write(line.data(), static_cast<int>(line.size()), ppp::function<void(bool)>());
            }

            /** @brief Constructs a mapping port bound to one FRP endpoint definition. */
            VirtualEthernetMappingPort::VirtualEthernetMappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                : disposed_(FALSE)                      // Initially not disposed
                , linklayer_(linklayer)                 // Store linklayer reference
                , transmission_(transmission)           // Store transmission reference
                , tcp_(tcp)                             // Store protocol type (TCP/UDP)
                , in_(in)                               // Store IP version (IPv4/IPv6)
                , remote_port_(remote_port)             // Store remote port
                , context_(linklayer->GetContext()) {   // Get IO context from linklayer
                configuration_ = linklayer->GetConfiguration();   // Get app configuration
                buffer_allocator_ = configuration_->GetBufferAllocator(); // Get buffer allocator
            }

            /** @brief Destroys mapping port and releases sockets/state. */
            VirtualEthernetMappingPort::~VirtualEthernetMappingPort() noexcept {
                Finalize();     // Release all resources
            }

            /** @brief Returns IO context used by this mapping runtime. */
            std::shared_ptr<boost::asio::io_context> VirtualEthernetMappingPort::GetContext() noexcept {
                return context_;
            }

            /** @brief Returns owning link-layer instance. */
            std::shared_ptr<VirtualEthernetLinklayer> VirtualEthernetMappingPort::GetLinklayer() noexcept {
                return linklayer_;
            }

            /** @brief Returns transport used to exchange FRP control/data frames. */
            VirtualEthernetMappingPort::ITransmissionPtr VirtualEthernetMappingPort::GetTransmission() noexcept {
                return transmission_;
            }

            /** @brief Returns true when this mapping uses TCP transport. */
            bool VirtualEthernetMappingPort::ProtocolIsTcpNetwork() noexcept {
                return tcp_;
            }

            /** @brief Returns true when this mapping uses UDP transport. */
            bool VirtualEthernetMappingPort::ProtocolIsUdpNetwork() noexcept {
                return !tcp_;
            }

            /** @brief Returns true when mapping uses IPv4 direction. */
            bool VirtualEthernetMappingPort::ProtocolIsNetworkV4() noexcept {
                return in_;
            }

            /** @brief Returns true when mapping uses IPv6 direction. */
            bool VirtualEthernetMappingPort::ProtocolIsNetworkV6() noexcept {
                return !in_;
            }

            /** @brief Returns externally exposed mapping port number. */
            int VirtualEthernetMappingPort::GetRemotePort() noexcept {
                return remote_port_;
            }

            /** @brief Finalizes mapping role objects and closes all sockets. */
            void VirtualEthernetMappingPort::Finalize() noexcept {
                int disposed = disposed_.exchange(TRUE);   // Atomically set disposed flag to TRUE and get previous value
                transmission_.reset();                     // Release transmission reference

                if (disposed != TRUE) {                    // If not already disposed
                    std::shared_ptr<Server> server = std::move(server_);   // Take ownership of server
                    std::shared_ptr<Client> client = std::move(client_);   // Take ownership of client

                    if (NULLPTR != server) {               // If server exists
                        // Close UDP and TCP sockets
                        ppp::net::Socket::Closesocket(server->socket_udp_);
                        ppp::net::Socket::Closesocket(server->socket_tcp_);

                        // Detach all connection objects under the table lock
                        ppp::unordered_map<int, Server::ConnectionPtr> connections;
                        {
                            std::lock_guard<std::mutex> lock(socket_connections_mutex_);
                            connections.swap(server->socket_connections_);
                        }

                        // Release all connection objects (outside the lock: disposal may run peer I/O)
                        ppp::collections::Dictionary::ReleaseAllObjects(connections);
                    }

                    if (NULLPTR != client) {               // If client exists
                        // Detach all connection and datagram port objects under the table lock
                        ppp::unordered_map<int, Client::ConnectionPtr> connections;
                        ppp::unordered_map<boost::asio::ip::udp::endpoint, Client::DatagramPortPtr> datagram_ports;
                        {
                            std::lock_guard<std::mutex> lock(socket_connections_mutex_);
                            connections.swap(client->socket_connections_);
                            datagram_ports.swap(client->socket_datagram_ports_);
                        }

                        // Release all connection and datagram port objects (outside the lock)
                        ppp::collections::Dictionary::ReleaseAllObjects(connections);
                        ppp::collections::Dictionary::ReleaseAllObjects(datagram_ports);
                    }
                }
            }

            /** @brief Public disposable entry that delegates to `Finalize()`. */
            void VirtualEthernetMappingPort::Dispose() noexcept {
                Finalize();
            }

#if defined(VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET)
#error "Compiler macro "OPENNETWORKSOCKET" definition conflict found, please check the project C/C++ code implementation for problems."
#else
            /**
             * @brief Opens and configures server network socket for UDP/TCP role.
             * @details The macro centralizes endpoint family selection, socket options,
             * bind validation, and endpoint publication for both stream and datagram paths.
             */
#define VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(SERVER_OBJ, PROTOCOL, SOCKET_OBJECT)           \
                auto& socket = SOCKET_OBJECT;                                                              \
                if (socket.is_open()) {                                                                    \
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerSocketAlreadyOpen); \
                }                                                                                          \
                                                                                                           \
                boost::system::error_code ec;                                                              \
                boost::asio::ip::address address;                                                          \
                if (in_) {                                                                                 \
                    address = boost::asio::ip::address_v4::any();                                          \
                    socket.open(PROTOCOL::v4(), ec);                                                       \
                }                                                                                          \
                else {                                                                                     \
                    address = boost::asio::ip::address_v6::any();                                          \
                    socket.open(PROTOCOL::v6(), ec);                                                       \
                }                                                                                          \
                                                                                                           \
                if (ec) {                                                                                  \
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOpenFailed); \
                }                                                                                          \
                                                                                                           \
                int handle = socket.native_handle();                                                       \
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, address.is_v4());                    \
                ppp::net::Socket::SetTypeOfService(handle);                                                \
                ppp::net::Socket::SetSignalPipeline(handle, false);                                        \
                ppp::net::Socket::ReuseSocketAddress(handle, remote_port_);                                \
                ppp::net::Socket::SetWindowSizeIfNotZero(handle,                                           \
                    configuration_->tcp.cwnd, configuration_->tcp.rwnd);                                   \
                                                                                                           \
                socket.set_option(PROTOCOL::socket::reuse_address(true), ec);                              \
                if (ec) {                                                                                  \
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOptionSetFailed); \
                }                                                                                          \
                                                                                                           \
                socket.set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec);          \
                socket.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(  \
                    configuration_->tcp.fast_open), ec);                                                   \
                                                                                                           \
                socket.bind(PROTOCOL::endpoint(address, remote_port_), ec);                                \
                if (ec) {                                                                                  \
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketBindFailed); \
                }                                                                                          \
                                                                                                           \
                auto local_ep = socket.local_endpoint(ec);                                                 \
                if (local_ep.port() != remote_port_) {                                                     \
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mapping_port", "network port invalid after bind expected=%d actual=%d tcp=%d in=%d ec=%d", remote_port_, ec ? -1 : local_ep.port(), tcp_ ? 1 : 0, in_ ? 1 : 0, ec.value()); \
                    LogNetworkPortInvalidToSessionLog(logger_, "mapping_port.after_bind", remote_port_, ec ? -1 : local_ep.port(), tcp_, in_); \
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid); \
                }                                                                                          \
                                                                                                           \
                SERVER_OBJ->socket_endpoint_ =                                                             \
                    ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(                                \
                            ppp::net::IPEndPoint::ToEndPoint(local_ep));

             /** @brief Opens server UDP socket for datagram mapping mode. */
            bool VirtualEthernetMappingPort::OpenNetworkSocketDatagram() noexcept {
                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {                     // Server must exist
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                // Use the macro to open UDP socket
                VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(server, boost::asio::ip::udp, server->socket_udp_);
                return true;
            }

            /** @brief Opens server TCP acceptor for stream mapping mode. */
            bool VirtualEthernetMappingPort::OpenNetworkSocketStream() noexcept {
                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {                     // Server must exist
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                // Use the macro to open TCP socket
                VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(server, boost::asio::ip::tcp, server->socket_tcp_);
                return true;
            }
#undef VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET
#endif

            /** @brief Starts FRP server mode and begins accept/receive loops. */
            bool VirtualEthernetMappingPort::OpenFrpServer(const VirtualEthernetLoggerPtr& logger) noexcept {
                // Validate remote port range
                if (remote_port_ <= ppp::net::IPEndPoint::MinPort || remote_port_ > ppp::net::IPEndPoint::MaxPort) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mapping_port", "network port invalid in OpenFrpServer remote_port=%d tcp=%d in=%d", remote_port_, tcp_ ? 1 : 0, in_ ? 1 : 0);
                    LogNetworkPortInvalidToSessionLog(logger, "mapping_port.open_frp_server", remote_port_, ppp::net::IPEndPoint::MinPort, tcp_, in_);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                if (disposed_) {                             // Already disposed
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                if (client_) {                               // Cannot be both client and server
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                if (server_) {                               // Already a server
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                // Create a new server instance
                std::shared_ptr<Server> server = make_shared_object<Server>(this);
                if (NULLPTR == server) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerInstanceAllocFailed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {               // Need a valid transmission
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                server_ = server;                       // Publish only for the open/listen sequence
                logger_ = logger;                       // Store logger after successful startup

                for (;;) {
                    if (tcp_) {                                  // TCP (stream) mode
                        bool opened = OpenNetworkSocketStream(); // Open TCP acceptor
                        if (false == opened) {
                            break;
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::tcp::acceptor& acceptor = server->socket_tcp_;
                        acceptor.listen(configuration_->tcp.backlog, ec);   // Start listening

                        if (ec) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketListenFailed);
                            break;
                        }

                        // Start asynchronous accept loop
                        std::shared_ptr<VirtualEthernetMappingPort> self = shared_from_this();
                        bool accepted = ppp::net::Socket::AcceptLoopbackAsync(acceptor,
                            [self, this, server](const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept {
                                return Server_AcceptFrpUserSocket(server, context, socket);
                            });
                        if (accepted) {
                            return true;
                        }

                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAcceptFailed);
                    }
                    else {                                         // UDP (datagram) mode
                        bool opened = OpenNetworkSocketDatagram(); // Open UDP socket
                        if (opened) {
                            if (LoopbackFrpServer()) {             // Start receive loop
                                return true;
                            }
                        }
                    }

                    break;
                }

                if (tcp_) {
                    ppp::net::Socket::Closesocket(server->socket_tcp_);
                }
                else {
                    ppp::net::Socket::Closesocket(server->socket_udp_);
                }

                server_.reset(); // Clean
                logger_.reset();

                return false;
            }

            /** @brief Returns currently bound server endpoint, or wildcard fallback. */
            boost::asio::ip::tcp::endpoint VirtualEthernetMappingPort::BoundEndPointOfFrpServer() noexcept {
                std::shared_ptr<Server> server = server_;
                if (server) {
                    return server->socket_endpoint_;         // Return stored endpoint
                }

                // Return a dummy endpoint if no server
                return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
            }

            /** @brief Starts/continues UDP receive loop in server mode. */
            bool VirtualEthernetMappingPort::LoopbackFrpServer() noexcept {
                if (disposed_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                bool opened = server->socket_udp_.is_open();
                if (false == opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                }

                // Asynchronously receive UDP datagrams
                std::shared_ptr<VirtualEthernetMappingPort> self = shared_from_this();
                server->socket_udp_.async_receive_from(boost::asio::buffer(server->socket_source_buf_.get(), PPP_UDP_BUFFER_SIZE), server->socket_source_ep_,
                    [self, this, server](boost::system::error_code ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                // Convert IPv6-mapped IPv4 to pure IPv4 if needed
                                boost::asio::ip::udp::endpoint natEP = ppp::net::Ipep::V6ToV4(server->socket_source_ep_);
                                Server_SendToFrpClient(server->socket_source_buf_.get(), sz, natEP);
                            }
                        }

                        LoopbackFrpServer();   // Continue receiving
                    });
                return true;
            }

            /** @brief Removes aging entries from a connection table; the table lock is only held for map operations, never during disposal. */
            template <typename TTable>
            static inline void MAPPINGPORT_UpdateAllObjects(std::mutex& mutex_, TTable& table_, UInt64 now) noexcept {
                typedef typename TTable::key_type                                       TKey;
                typedef typename TTable::mapped_type                                    TValue;

                ppp::vector<std::pair<TKey, TValue>> snapshot;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    for (auto&& kv : table_) {
                        snapshot.emplace_back(kv.first, kv.second);
                    }
                }

                for (auto&& kv : snapshot) {
                    TValue& obj = kv.second;
                    if (NULLPTR != obj && !obj->IsPortAging(now)) {
                        continue;
                    }

                    TValue removed;
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        auto tail = table_.find(kv.first);
                        if (tail == table_.end() || tail->second != obj) {
                            continue;
                        }

                        removed = std::move(tail->second);
                        table_.erase(tail);
                    }

                    if (NULLPTR != removed) {
                        // Dispose outside the lock: finalization may perform peer I/O.
                        IDisposable::Dispose(*removed);
                    }
                }
            }

            /** @brief Updates child connection/datagram timeout states. */
            bool VirtualEthernetMappingPort::Update(UInt64 now) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;                            // Already disposed
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR != server) {
                    // Update all server-side connections
                    MAPPINGPORT_UpdateAllObjects(socket_connections_mutex_, server->socket_connections_, now);
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR != client) {
                    // Update all client-side connections and datagram ports
                    MAPPINGPORT_UpdateAllObjects(socket_connections_mutex_, client->socket_connections_, now);
                    MAPPINGPORT_UpdateAllObjects(socket_connections_mutex_, client->socket_datagram_ports_, now);
                }

                return true;
            }

            /** @brief Generates a non-zero connection identifier. */
            int VirtualEthernetMappingPort::NewId() noexcept {
                static std::atomic<unsigned int> aid = /*ATOMIC_FLAG_INIT*/RandomNext();   // Start with random value

                for (;;) {
                    int id = ++aid;        // Increment atomically
                    if (id != 0) {         // Zero is reserved as invalid
                        return id;
                    }
                }
            }

            /** @brief Constructs server-side stream connection state object. */
            VirtualEthernetMappingPort::Server::Connection::Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Server>& server, int connection_id, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                : IAsynchronousWriteIoQueue(mapping_port->buffer_allocator_)   // Base class initialization
                , connection_stated_(0)                   // Initial state: 0 = not connected
                , server_(server)                         // Store parent server
                , connection_id_(connection_id)           // Store connection ID
                , mapping_port_(mapping_port)             // Store parent mapping port
                , socket_(socket)                         // Store TCP socket
                , timeout_(0) {                           // Timeout will be set by Update()
                linklayer_ = mapping_port->linklayer_;     // Get linklayer reference
                configuration_ = mapping_port->configuration_; // Get configuration
                Update();                                 // Set initial timeout
            }

            /** @brief Refreshes timeout deadline based on connection stage. */
            void VirtualEthernetMappingPort::Server::Connection::Update() noexcept {
                UInt64 now = ppp::threading::Executors::GetTickCount();
                if (connection_stated_.load() < 3) {
                    timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                }
                else {
                    timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                }
            }

            /** @brief Destroys server connection and finalizes resources. */
            VirtualEthernetMappingPort::Server::Connection::~Connection() noexcept {
                Finalize(false);                           // Clean up without sending disconnect
            }

            /** @brief Initiates FRP-side connect request for accepted local socket. */
            bool VirtualEthernetMappingPort::Server::Connection::ConnectToFrpClient() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 0) {               // Must be in initial state
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionConnectStateInvalid);
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                // Ask linklayer to establish FRP connection to the client
                bool ok = linklayer_->DoFrpConnect(transmission,
                    connection_id_,
                    mapping_port_->in_,
                    mapping_port_->remote_port_,
                    nullof<YieldContext>());

                if (!ok) {
                    transmission->Dispose();               // Clean up transmission on failure
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                connection_stated_.exchange(1);            // State 1 = connecting
                return true;
            }

            /** @brief Sends stream payload to FRP peer. */
            bool VirtualEthernetMappingPort::Server::Connection::SendToFrpClient(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionSendInvalidPayload);
                }

                int connection_state = connection_stated_.load();
                if (connection_state != 3) {               // Must be in active state (3)
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionSendStateInvalid);
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                // Push data to FRP client via linklayer
                bool ok = linklayer_->DoFrpPush(transmission,
                    connection_id_,
                    mapping_port_->in_,
                    mapping_port_->remote_port_,
                    packet,
                    packet_size,
                    nullof<YieldContext>());

                if (ok) {
                    Update();                              // Refresh timeout on success
                }
                else {
                    transmission->Dispose();               // Clean up on failure
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                }

                return ok;
            }

            /** @brief Sends stream payload to local accepted TCP client. */
            bool VirtualEthernetMappingPort::Server::Connection::SendToFrpUser(const std::shared_ptr<Byte>& owner, const void* packet, int packet_size) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {               // Must be active
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionUserSendStateInvalid);
                }

                // Zero-copy when owner is available, otherwise fall back to memcpy.
                std::shared_ptr<Byte> messages = Copy(mapping_port_->buffer_allocator_, owner, packet, packet_size);
                if (NULLPTR == messages) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionUserSendBufferAllocFailed);
                }

                auto self = shared_from_this();
                // Queue asynchronous write to the TCP socket
                return WriteBytes(messages, packet_size,
                    [self, this](bool ok) noexcept {
                        if (ok) {
                            Update();                      // Refresh timeout on success
                        }
                        else {
                            Dispose();                     // Close on failure
                        }
                    });
            }

            /** @brief Performs asynchronous write on local TCP socket. */
            bool VirtualEthernetMappingPort::Server::Connection::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {               // Must be active
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionWriteStateInvalid);
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                // Perform async write on the TCP socket
                std::shared_ptr<IAsynchronousWriteIoQueue> self = shared_from_this();
                boost::asio::async_write(*socket_, boost::asio::buffer((Byte*)packet.get() + offset, packet_length),
                    [self, this, packet, packet_length, cb](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool ok = ec == boost::system::errc::success;
                        if (cb) {
                            cb(ok);
                        }
                    });
                return true;
            }

            /** @brief Finalizes server connection and optionally notifies peer disconnect. */
            void VirtualEthernetMappingPort::Server::Connection::Finalize(bool disconnect) noexcept {
                int connection_state = connection_stated_.exchange(4);   // Set state to 4 (dead)
                if (connection_state != 4) {               // If not already finalizing
                    if (!disconnect && connection_state == 3) {   // If active and not forced disconnect
                        ITransmissionPtr transmission = mapping_port_->GetTransmission();
                        if (NULLPTR != transmission) {
                            // Notify FRP client that we are disconnecting
                            bool ok = linklayer_->DoFrpDisconnect(transmission,
                                connection_id_,
                                mapping_port_->in_,
                                mapping_port_->remote_port_,
                                nullof<YieldContext>());

                            if (!ok) {
                                transmission->Dispose();
                            }
                        }
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
                    std::shared_ptr<Server> server = std::move(server_);

                    if (NULLPTR != socket) {
                        ppp::net::Socket::Closesocket(socket);   // Close TCP socket
                    }

                    if (NULLPTR != server) {
                        // Remove connection from server's dictionary
                        std::lock_guard<std::mutex> lock(mapping_port_->socket_connections_mutex_);
                        ppp::collections::Dictionary::TryRemove(server->socket_connections_, connection_id_);
                    }
                }
            }

            /** @brief Handles FRP connect acknowledgment for server-side connection. */
            bool VirtualEthernetMappingPort::Server::Connection::OnConnectOK(Byte error_code) noexcept {
                int except = 1;                              // Expected state: connecting (1)
                if (!connection_stated_.compare_exchange_strong(except, 2)) {   // Transition to state 2 (connected)
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionConnectAckStateInvalid);
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound);
                }

                if (error_code != 0) {                       // Connection failed
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                }

                except = 2;
                if (!connection_stated_.compare_exchange_strong(except, 3)) {   // Transition to state 3 (active)
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionActivateStateInvalid);
                }

                Update();                                    // Set timeout for active state
                // Allocate read buffer
                buffer_chunked_ = ppp::threading::BufferswapAllocator::MakeByteArray(mapping_port_->buffer_allocator_, PPP_TCP_BUFFER_SIZE);

                if (NULLPTR == buffer_chunked_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionReadBufferAllocFailed);
                }

                // Start forwarding data from FRP user to FRP client
                return ForwardFrpUserToFrpClient();
            }

            /** @brief Starts relay loop from local TCP user to FRP peer. */
            bool VirtualEthernetMappingPort::Server::Connection::ForwardFrpUserToFrpClient() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerConnectionRelayStateInvalid);
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                auto self = shared_from_this();
                // Async read from TCP socket
                socket->async_read_some(boost::asio::buffer(buffer_chunked_.get(), PPP_TCP_BUFFER_SIZE),
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        bool ok = false;
                        if (ec == boost::system::errc::success && sz > 0) {
                            ok = SendToFrpClient(buffer_chunked_.get(), sz);   // Forward data
                            if (ok) {
                                ForwardFrpUserToFrpClient();   // Continue reading
                            }
                        }

                        if (ok) {
                            Update();                        // Refresh timeout
                        }
                        else {
                            Dispose();                       // Close on error
                        }
                    });
                return true;
            }

            /** @brief Finds mapping instance by direction/protocol/remote-port key. */
            std::shared_ptr<VirtualEthernetMappingPort> VirtualEthernetMappingPort::FindMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept {
                uint32_t key = GetHashCode(in, tcp, remote_port);
                Ptr ptr;

                ppp::collections::Dictionary::TryGetValue(mappings, key, ptr);
                return ptr;
            }

            /** @brief Removes mapping instance by direction/protocol/remote-port key. */
            std::shared_ptr<VirtualEthernetMappingPort> VirtualEthernetMappingPort::DeleteMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept {
                uint32_t key = GetHashCode(in, tcp, remote_port);
                Ptr ptr;

                ppp::collections::Dictionary::TryRemove(mappings, key, ptr);
                return ptr;
            }

            /** @brief Adds mapping instance into keyed dictionary. */
            bool VirtualEthernetMappingPort::AddMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port, const Ptr& mapping_port) noexcept {
                if (NULLPTR == mapping_port) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortAddNullInstance);
                }

                uint32_t key = GetHashCode(in, tcp, remote_port);
                bool ok = ppp::collections::Dictionary::TryAdd(mappings, key, mapping_port);
                if (!ok) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                return true;
            }

            /** @brief Retrieves connection by ID from role table with disposal checks. */
            template <typename TConnectionPtr, typename TDisposed, typename TConnectionTable>
            static inline TConnectionPtr MAPPINGPORT_GetConnection(TDisposed& disposed_, TConnectionTable& table_, std::mutex& mutex_, int connection_id) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return NULLPTR;
                }

                auto table = table_;
                if (NULLPTR == table) {
                    return NULLPTR;
                }

                std::lock_guard<std::mutex> lock(mutex_);

                TConnectionPtr connection;
                if (!ppp::collections::Dictionary::TryGetValue(table->socket_connections_, connection_id, connection)) {
                    return NULLPTR;
                }

                if (NULLPTR != connection) {
                    return connection;
                }

                // Remove invalid entry
                ppp::collections::Dictionary::TryRemove(table->socket_connections_, connection_id);
                return NULLPTR;
            }

            /** @brief Retrieves server-side connection by connection ID. */
            VirtualEthernetMappingPort::Server::ConnectionPtr VirtualEthernetMappingPort::Server_GetConnection(int connection_id) noexcept {
                return MAPPINGPORT_GetConnection<Server::ConnectionPtr>(disposed_, server_, socket_connections_mutex_, connection_id);
            }

            /** @brief Retrieves client-side connection by connection ID. */
            VirtualEthernetMappingPort::Client::ConnectionPtr VirtualEthernetMappingPort::Client_GetConnection(int connection_id) noexcept {
                return MAPPINGPORT_GetConnection<Client::ConnectionPtr>(disposed_, client_, socket_connections_mutex_, connection_id);
            }

            /** @brief Retrieves client-side datagram port by NAT endpoint key. */
            VirtualEthernetMappingPort::Client::DatagramPortPtr VirtualEthernetMappingPort::Client_GetDatagramPort(const boost::asio::ip::udp::endpoint& nat_key) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return NULLPTR;
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return NULLPTR;
                }

                std::lock_guard<std::mutex> lock(socket_connections_mutex_);

                Client::DatagramPortPtr datagram_port;
                if (!ppp::collections::Dictionary::TryGetValue(client->socket_datagram_ports_, nat_key, datagram_port)) {
                    return NULLPTR;
                }

                if (NULLPTR != datagram_port) {
                    return datagram_port;
                }

                // Remove invalid entry
                ppp::collections::Dictionary::TryRemove(client->socket_datagram_ports_, nat_key);
                return NULLPTR;
            }

            /** @brief Constructs server role state and allocates receive buffer. */
            VirtualEthernetMappingPort::Server::Server(VirtualEthernetMappingPort* owner) noexcept
                : socket_udp_(*owner->context_)      // UDP socket with owner's IO context
                , socket_tcp_(*owner->context_) {    // TCP acceptor with owner's IO context
                // Get a cached buffer for UDP receive
                socket_source_buf_ = ppp::threading::Executors::GetCachedBuffer(owner->context_);
            }

            /** @brief Handles FRP connect acknowledgment in server role. */
            bool VirtualEthernetMappingPort::Server_OnFrpConnectOK(int connection_id, Byte error_code) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound);
                }

                bool ok = connection->OnConnectOK(error_code);
                if (!ok) {
                    connection->Dispose();             // Clean up if callback fails
                }

                return ok;
            }

            /** @brief Handles FRP disconnect event in server role. */
            bool VirtualEthernetMappingPort::Server_OnFrpDisconnect(int connection_id) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                    return false;
                }

                connection->OnDisconnect();            // Notify connection of disconnect
                return true;
            }

            /** @brief Handles FRP stream payload in server role. */
            bool VirtualEthernetMappingPort::Server_OnFrpPush(int connection_id, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound);
                }

                bool ok = connection->SendToFrpUser(owner, packet, packet_length);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
            }

            /** @brief Sends UDP payload from server role to local remote endpoint. */
            bool VirtualEthernetMappingPort::Server_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                bool opened = server->socket_udp_.is_open();
                if (!opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                }

                boost::system::error_code ec;
                // Send UDP datagram, converting IP version if necessary
                if (in_) {
                    server->socket_udp_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V6ToV4(sourceEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    server->socket_udp_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V4ToV6(sourceEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                }

                return true;
            }

            /**
             * @brief Accepts local TCP user socket and binds it to a new FRP connection.
             * @details The method allocates a connection ID, creates relay state,
             * starts FRP connect negotiation, and emits mapping logs on success.
             */
            bool VirtualEthernetMappingPort::Server_AcceptFrpUserSocket(const std::shared_ptr<Server>& server, const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }
                // FIXED: restored 'elif' per project convention
                elif(!ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                }
                else {
                    // Set TCP window sizes
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                auto self = shared_from_this();
                auto& connections = server->socket_connections_;
                // Try to find a free connection ID
                for (int i = ppp::net::IPEndPoint::MinPort; i < ppp::net::IPEndPoint::MaxPort; i++) {
                    int connection_id = NewId();
                    {
                        std::lock_guard<std::mutex> lock(socket_connections_mutex_);
                        if (ppp::collections::Dictionary::ContainsKey(connections, connection_id)) {
                            continue;
                        }
                    }

                    // Create a new connection object
                    auto connection = make_shared_object<Server::Connection>(self, server, connection_id, socket);
                    if (NULLPTR == connection) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortServerAcceptConnectionAllocFailed);
                    }

                    bool ok = connection->ConnectToFrpClient();   // Initiate FRP connection
                    if (ok) {
                        {
                            std::lock_guard<std::mutex> lock(socket_connections_mutex_);
                            ok = ppp::collections::Dictionary::TryAdd(connections, connection_id, connection);
                        }
                        while (ok) {
                            VirtualEthernetLoggerPtr logger = logger_;
                            if (NULLPTR == logger) {
                                break;
                            }

                            // Log the connection (local and remote endpoints)
                            boost::system::error_code ec;
                            boost::asio::ip::tcp::endpoint localEP = socket->local_endpoint(ec);
                            if (ec) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                                ok = false;
                                break;
                            }

                            boost::asio::ip::tcp::endpoint remoteEP = socket->remote_endpoint(ec);
                            if (ec) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                                ok = false;
                                break;
                            }

                            logger->MPConnect(linklayer_->GetId(), transmission, localEP, remoteEP);
                            break;
                        }
                    }

                    if (!ok) {
                        connection->Dispose();    // Clean up on failure
                    }

                    return ok;
                }

                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);   // No free connection ID found
            }

            /** @brief Sends UDP payload from server role to FRP peer via link layer. */
            bool VirtualEthernetMappingPort::Server_SendToFrpClient(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                }

                std::shared_ptr<VirtualEthernetLinklayer> linklayer = linklayer_;
                if (NULLPTR == linklayer) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                // Ask linklayer to send UDP datagram to FRP client
                bool ok = linklayer->DoFrpSendTo(transmission,
                    in_,
                    remote_port_,
                    sourceEP,
                    (Byte*)packet,
                    packet_length,
                    nullof<YieldContext>());

                if (ok) {
                    return ok;
                }

                transmission->Dispose();
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpRelayFailed);
            }

            /** @brief Starts FRP client mode and registers mapping entry. */
            bool VirtualEthernetMappingPort::OpenFrpClient(const boost::asio::ip::address& local_ip, int local_port) noexcept {
                // Validate ports
                if (remote_port_ <= ppp::net::IPEndPoint::MinPort || remote_port_ > ppp::net::IPEndPoint::MaxPort) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mapping_port", "network port invalid in OpenFrpClient remote_port=%d local_port=%d tcp=%d in=%d", remote_port_, local_port, tcp_ ? 1 : 0, in_ ? 1 : 0);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                if (local_port <= ppp::net::IPEndPoint::MinPort || local_port > ppp::net::IPEndPoint::MaxPort) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mapping_port", "network port invalid in OpenFrpClient local_port=%d remote_port=%d tcp=%d in=%d", local_port, remote_port_, tcp_ ? 1 : 0, in_ ? 1 : 0);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                if (server_) {          // Cannot be both server and client
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                if (client_) {          // Already a client
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                if (local_ip.is_multicast()) {   // Multicast not allowed
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                if (ppp::net::IPEndPoint::IsInvalid(local_ip)) {   // Invalid IP
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                // Create client object
                std::shared_ptr<Client> client = make_shared_object<Client>();
                if (NULLPTR == client) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientInstanceAllocFailed);
                }

                client->local_in_ = local_ip.is_v4();   // Store IP version
                client->local_ep_ = boost::asio::ip::udp::endpoint(local_ip, local_port);

                // Register this mapping port with the linklayer (FRP entry)
                bool ok = linklayer_->DoFrpEntry(transmission,
                    tcp_,
                    in_,
                    remote_port_,
                    nullof<YieldContext>());

                if (ok) {
                    client_ = client;
                    return true;
                }

                transmission->Dispose();
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
            }

            /** @brief Constructs client-side stream connection state. */
            VirtualEthernetMappingPort::Client::Connection::Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, int connection_id) noexcept
                : IAsynchronousWriteIoQueue(mapping_port->buffer_allocator_)   // Base class init
                , connection_stated_(0)                   // Initial state
                , client_(client)                         // Parent client
                , mapping_port_(mapping_port)             // Parent mapping port
                , connection_id_(connection_id)           // Unique ID
                , timeout_(0) {
                linklayer_ = mapping_port->linklayer_;
                configuration_ = mapping_port->configuration_;
                transmission_ = mapping_port->transmission_;
                Update();                                 // Set initial timeout
            }

            /** @brief Refreshes timeout deadline based on connection stage. */
            void VirtualEthernetMappingPort::Client::Connection::Update() noexcept {
                UInt64 now = ppp::threading::Executors::GetTickCount();
                if (connection_stated_.load() < 3) {
                    timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                }
                else {
                    timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                }
            }

            /** @brief Destroys client-side connection and finalizes resources. */
            VirtualEthernetMappingPort::Client::Connection::~Connection() noexcept {
                Finalize(false);
            }

            /** @brief Connects client role to local destination TCP service. */
            bool VirtualEthernetMappingPort::Client::Connection::ConnectToDestinationServer() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 0) {               // Must be initial
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionConnectStateInvalid);
                }

                if (socket_) {                             // Socket already exists
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionSocketAlreadyAllocated);
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound);
                }

                // Create a new TCP socket
                std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*mapping_port_->context_);
                if (NULLPTR == socket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionSocketAllocFailed);
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = client->local_ep_.address();
                // Open socket with appropriate IP version
                if (local_ip.is_v4()) {
                    socket->open(boost::asio::ip::tcp::v4(), ec);
                }
                else {
                    socket->open(boost::asio::ip::tcp::v6(), ec);
                }

                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                }

                int handle = socket->native_handle();
                // Apply socket options
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, local_ip.is_v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);
                ppp::net::Socket::SetWindowSizeIfNotZero(handle, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                socket->set_option(boost::asio::ip::tcp::socket::reuse_address(true), ec);
                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                }

                socket->set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec);
                socket->set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(configuration_->tcp.fast_open), ec);

                socket_ = socket;
                connection_stated_.exchange(1);            // State 1 = connecting

                auto self = shared_from_this();
                // Asynchronously connect to the local destination
                socket->async_connect(boost::asio::ip::tcp::endpoint(local_ip, client->local_ep_.port()),
                    [self, this](boost::system::error_code ec) noexcept {
                        bool ok = OnConnectedOK(ec == boost::system::errc::success);
                        if (!ok) {
                            Dispose();
                        }
                    });
                return true;
            }

            /** @brief Finalizes client connection and optionally notifies peer disconnect. */
            void VirtualEthernetMappingPort::Client::Connection::Finalize(bool disconnect) noexcept {
                std::shared_ptr<ITransmission> transmission = std::move(transmission_);

                int connection_state = connection_stated_.exchange(4);   // Set state to dead
                if (connection_state != 4) {
                    if (!disconnect && connection_state == 3) {   // If active and not forced disconnect
                        if (NULLPTR != transmission) {
                            // Notify FRP server of disconnect
                            bool ok = linklayer_->DoFrpDisconnect(transmission,
                                connection_id_,
                                mapping_port_->in_,
                                mapping_port_->remote_port_,
                                nullof<YieldContext>());

                            if (!ok) {
                                transmission->Dispose();
                            }
                        }
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
                    std::shared_ptr<Client> client = std::move(client_);

                    if (NULLPTR != socket) {
                        ppp::net::Socket::Closesocket(socket);   // Close TCP socket
                    }

                    if (NULLPTR != client) {
                        // A late finalizer must not erase a replacement using the same id.
                        std::lock_guard<std::mutex> lock(mapping_port_->socket_connections_mutex_);
                        MappingPortConnectReentrancy::EraseIfOwner(
                            client->socket_connections_, connection_id_, this);
                    }
                }
            }

            /** @brief Handles async connect result and sends FRP connect acknowledgment. */
            bool VirtualEthernetMappingPort::Client::Connection::OnConnectedOK(bool ok) noexcept {
                int except = 1;                                  // Expected state: connecting
                if (!connection_stated_.compare_exchange_strong(except, 2)) {   // Transition to state 2 (connected)
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionConnectAckStateInvalid);
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound);
                }
                else {
                    ITransmissionPtr transmission = transmission_;
                    if (NULLPTR != transmission) {
                        Byte error_code = ok ? 0 : 255;          // 0 = success, 255 = failure
                        // Notify FRP server of connection result
                        bool ok = linklayer_->DoFrpConnectOK(transmission,
                            connection_id_,
                            mapping_port_->in_,
                            mapping_port_->remote_port_,
                            error_code,
                            nullof<YieldContext>());

                        if (!ok) {
                            transmission->Dispose();
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        }
                    }
                }

                except = 2;
                if (!connection_stated_.compare_exchange_strong(except, 3)) {   // Transition to state 3 (active)
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionActivateStateInvalid);
                }

                if (!ok) {                                      // Connection failed
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                }

                Update();                                       // Set active timeout
                // Allocate read buffer
                buffer_chunked_ = ppp::threading::BufferswapAllocator::MakeByteArray(mapping_port_->buffer_allocator_, PPP_TCP_BUFFER_SIZE);

                if (NULLPTR == buffer_chunked_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionReadBufferAllocFailed);
                }

                // Start reading from destination server socket
                return Loopback();
            }

            /** @brief Starts relay loop from destination socket back to FRP peer. */
            bool VirtualEthernetMappingPort::Client::Connection::Loopback() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionRelayStateInvalid);
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                auto self = shared_from_this();
                // Async read from destination server
                socket->async_read_some(boost::asio::buffer(buffer_chunked_.get(), PPP_TCP_BUFFER_SIZE),
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        bool ok = false;
                        if (ec == boost::system::errc::success && sz > 0) {
                            ITransmissionPtr transmission = transmission_;
                            if (NULLPTR != transmission) {
                                // Push data to FRP server
                                ok = linklayer_->DoFrpPush(
                                    transmission,
                                    connection_id_,
                                    mapping_port_->in_,
                                    mapping_port_->remote_port_,
                                    buffer_chunked_.get(),
                                    sz,
                                    nullof<YieldContext>());

                                if (ok) {
                                    ok = Loopback();            // Continue reading
                                }
                                else {
                                    transmission->Dispose();
                                }
                            }
                        }

                        if (ok) {
                            Update();                           // Refresh timeout
                        }
                        else {
                            Dispose();                          // Close on error
                        }
                    });
                return true;
            }

            /** @brief Sends FRP stream payload to local destination TCP service. */
            bool VirtualEthernetMappingPort::Client::Connection::SendToDestinationServer(const std::shared_ptr<Byte>& owner, const void* packet, int packet_size) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {                    // Must be active
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionSendStateInvalid);
                }

                // Zero-copy when owner is available, otherwise fall back to memcpy.
                std::shared_ptr<Byte> messages = Copy(mapping_port_->buffer_allocator_, owner, packet, packet_size);
                if (NULLPTR == messages) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionSendBufferAllocFailed);
                }

                auto self = shared_from_this();
                // Queue asynchronous write
                return WriteBytes(messages, packet_size,
                    [self, this](bool ok) noexcept {
                        if (ok) {
                            Update();
                        }
                        else {
                            Dispose();
                        }
                    });
            }

            /** @brief Performs asynchronous write on destination TCP socket. */
            bool VirtualEthernetMappingPort::Client::Connection::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientConnectionWriteStateInvalid);
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                std::shared_ptr<IAsynchronousWriteIoQueue> self = shared_from_this();
                boost::asio::async_write(*socket_, boost::asio::buffer((Byte*)packet.get() + offset, packet_length),
                    [self, this, packet, packet_length, cb](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool ok = ec == boost::system::errc::success;
                        if (cb) {
                            cb(ok);
                        }
                    });
                return true;
            }

            /** @brief Handles inbound FRP connect request in client role. */
            bool VirtualEthernetMappingPort::Client_OnFrpConnect(int connection_id) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULLPTR != connection) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);                            // Already exists
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }
                else {
                    auto self = shared_from_this();
                    // Create a new client connection object
                    connection = make_shared_object<Client::Connection>(self, client, connection_id);
                    if (NULLPTR == connection) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientOnFrpConnectConnectionAllocFailed);
                    }
                }

                // Publish before starting async_connect because start may synchronously
                // dispose/finalize and remove this exact owner from the table.
                bool published = false;
                bool ok = MappingPortConnectReentrancy::PublishThenStart(
                    [this, &client, &connection, connection_id, &published]() noexcept {
                        std::lock_guard<std::mutex> lock(socket_connections_mutex_);
                        published = ppp::collections::Dictionary::TryAdd(
                            client->socket_connections_, connection_id, connection);
                        return published;
                    },
                    [&connection]() noexcept {
                        return connection->ConnectToDestinationServer();
                    },
                    [this, &client, &connection, connection_id]() noexcept {
                        std::lock_guard<std::mutex> lock(socket_connections_mutex_);
                        return MappingPortConnectReentrancy::IsOwner(
                            client->socket_connections_, connection_id, connection.get());
                    },
                    [&connection]() noexcept {
                        connection->Dispose();
                    });

                if (!published) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }
                return ok;
            }

            /** @brief Handles inbound FRP disconnect in client role. */
            bool VirtualEthernetMappingPort::Client_OnFrpDisconnect(int connection_id) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                    return false;
                }

                connection->OnDisconnect();
                return true;
            }

            /** @brief Handles inbound FRP stream payload in client role. */
            bool VirtualEthernetMappingPort::Client_OnFrpPush(int connection_id, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound);
                }

                bool ok = connection->SendToDestinationServer(owner, packet, packet_length);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
            }

            /**
             * @brief Handles inbound FRP UDP payload in client role.
             * @details Reuses or lazily creates a NAT-keyed datagram port instance,
             * then forwards payload to local destination endpoint.
             */
            bool VirtualEthernetMappingPort::Client_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                // Try to get an existing datagram port for this NAT endpoint
                Client::DatagramPortPtr datagram_port = Client_GetDatagramPort(sourceEP);
                if (NULLPTR != datagram_port) {
                    return datagram_port->SendTo(packet, packet_length, client->local_ep_);
                }
                else {
                    auto self = shared_from_this();
                    // Create a new datagram port
                    datagram_port = make_shared_object<Client::DatagramPort>(self, client, sourceEP);
                    if (NULLPTR == datagram_port) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientDatagramPortAllocFailed);
                    }
                }

                // Insert the placeholder before opening the socket: the receive loop started by
                // Open() may dispose the port and remove it from the table first.
                bool ok;
                {
                    std::lock_guard<std::mutex> lock(socket_connections_mutex_);
                    ok = ppp::collections::Dictionary::TryAdd(client->socket_datagram_ports_, sourceEP, datagram_port);
                }

                if (ok) {
                    ok = datagram_port->Open();             // Open UDP socket and start loopback
                    if (!ok) {
                        datagram_port->Dispose();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    }

                    ok = datagram_port->SendTo(packet, packet_length, client->local_ep_);
                    if (ok) {
                        return true;
                    }
                }

                datagram_port->Dispose();
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpRelayFailed);
            }

            /** @brief Constructs client role state with default address-family marker. */
            VirtualEthernetMappingPort::Client::Client() noexcept
                : local_in_(false) {
                // Empty
            }

            /** @brief Constructs datagram relay port bound to one NAT endpoint key. */
            VirtualEthernetMappingPort::Client::DatagramPort::DatagramPort(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, const boost::asio::ip::udp::endpoint& natEP) noexcept
                : disposed_(FALSE)
                , socket_(*mapping_port->context_)         // UDP socket with owner's IO context
                , timeout_(0)
                , configuration_(mapping_port->configuration_)
                , mapping_port_(mapping_port)
                , client_(client)
                , linklayer_(mapping_port->linklayer_)
                , transmission_(mapping_port->transmission_) {
                nat_ep_ = natEP;                           // Store NAT endpoint
                buffer_chunked_ = ppp::threading::Executors::GetCachedBuffer(mapping_port->context_);   // Allocate buffer
                Update();                                  // Set initial timeout
            }

            /** @brief Refreshes inactive timeout deadline. */
            void VirtualEthernetMappingPort::Client::DatagramPort::Update() noexcept {
                UInt64 now = ppp::threading::Executors::GetTickCount();
                timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
            }

            /** @brief Destroys datagram relay port and releases socket resources. */
            VirtualEthernetMappingPort::Client::DatagramPort::~DatagramPort() noexcept {
                Dispose();
            }

            /** @brief Disposes datagram relay port and unregisters NAT key. */
            void VirtualEthernetMappingPort::Client::DatagramPort::Dispose() noexcept {
                int disposed = disposed_.exchange(TRUE);
                if (disposed != TRUE) {
                    std::shared_ptr<Client> client = std::move(client_);
                    if (NULLPTR != client) {
                        // Remove from client's dictionary
                        std::lock_guard<std::mutex> lock(mapping_port_->socket_connections_mutex_);
                        ppp::collections::Dictionary::TryRemove(client->socket_datagram_ports_, nat_ep_);
                    }

                    ppp::net::Socket::Closesocket(socket_);   // Close UDP socket
                }
            }

            /** @brief Sends UDP payload from local datagram socket to FRP peer. */
            bool VirtualEthernetMappingPort::Client::DatagramPort::SendToDestinationServer(const void* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                // Ask linklayer to send UDP datagram to FRP server
                bool ok = linklayer_->DoFrpSendTo(transmission,
                    mapping_port_->in_,
                    mapping_port_->remote_port_,
                    nat_ep_,
                    (Byte*)packet,
                    packet_length,
                    nullof<YieldContext>());

                if (!ok) {
                    transmission->Dispose();
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpRelayFailed);
                }

                return ok;
            }

            /** @brief Starts/continues async receive loop on datagram relay socket. */
            bool VirtualEthernetMappingPort::Client::DatagramPort::Loopback() noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket_.is_open();
                if (false == opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }

                std::shared_ptr<DatagramPort> self = shared_from_this();
                // Async receive UDP datagram
                socket_.async_receive_from(boost::asio::buffer(buffer_chunked_.get(), PPP_UDP_BUFFER_SIZE), source_ep_,
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::success) {
                            bool ok = false;
                            if (sz > 0) {
                                ok = SendToDestinationServer(buffer_chunked_.get(), sz);
                            }

                            if (ok) {
                                Update();                // Refresh timeout on success
                            }
                            else {
                                Dispose();               // Clean up on failure
                            }
                        }

                        Loopback();                      // Continue receiving
                    });
                return true;
            }

            /** @brief Opens datagram relay socket and starts loopback flow. */
            bool VirtualEthernetMappingPort::Client::DatagramPort::Open() noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                bool opened = socket_.is_open();
                if (opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingPortClientDatagramPortOpenStateInvalid);
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                boost::asio::ip::address local_ip = client->local_ep_.address();
                // Open UDP socket bound to any address on an ephemeral port
                if (local_ip.is_v4()) {
                    opened = ppp::net::Socket::OpenSocket(socket_, boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
                }
                else {
                    opened = ppp::net::Socket::OpenSocket(socket_, boost::asio::ip::address_v6::any(), ppp::net::IPEndPoint::MinPort);
                }

                if (opened) {
                    // Set UDP window sizes
                    ppp::net::Socket::SetWindowSizeIfNotZero(
                        socket_.native_handle(),
                        configuration_->udp.cwnd,
                        configuration_->udp.rwnd);
                    opened = Loopback();   // Start receive loop
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                }

                return opened;
            }

            /** @brief Sends UDP payload to local destination endpoint via relay socket. */
            bool VirtualEthernetMappingPort::Client::DatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                }

                boost::system::error_code ec;
                // Send UDP datagram, converting IP version if needed
                if (client->local_in_) {
                    socket_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V6ToV4(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    socket_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V4ToV6(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                }

                Update();    // Refresh timeout on success
                return true;
            }
        }
    }
}
