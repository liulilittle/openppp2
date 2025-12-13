#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
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

namespace ppp {
    namespace app {
        namespace protocol {
            static constexpr int PPP_UDP_BUFFER_SIZE = 65000;
            static constexpr int PPP_TCP_BUFFER_SIZE = PPP_UDP_BUFFER_SIZE;

            VirtualEthernetMappingPort::VirtualEthernetMappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                : disposed_(FALSE)
                , linklayer_(linklayer)
                , transmission_(transmission)
                , tcp_(tcp)
                , in_(in)
                , remote_port_(remote_port)
                , context_(linklayer->GetContext()) {
                configuration_ = linklayer->GetConfiguration();
                buffer_allocator_ = configuration_->GetBufferAllocator();
            }

            VirtualEthernetMappingPort::~VirtualEthernetMappingPort() noexcept {
                Finalize();
            }

            std::shared_ptr<boost::asio::io_context> VirtualEthernetMappingPort::GetContext() noexcept {
                return context_;
            }

            std::shared_ptr<VirtualEthernetLinklayer> VirtualEthernetMappingPort::GetLinklayer() noexcept {
                return linklayer_;
            }

            VirtualEthernetMappingPort::ITransmissionPtr VirtualEthernetMappingPort::GetTransmission() noexcept {
                return transmission_;
            }

            bool VirtualEthernetMappingPort::ProtocolIsTcpNetwork() noexcept {
                return tcp_;
            }

            bool VirtualEthernetMappingPort::ProtocolIsUdpNetwork() noexcept {
                return !tcp_;
            }

            bool VirtualEthernetMappingPort::ProtocolIsNetworkV4() noexcept {
                return in_;
            }

            bool VirtualEthernetMappingPort::ProtocolIsNetworkV6() noexcept {
                return !in_;
            }

            int VirtualEthernetMappingPort::GetRemotePort() noexcept {
                return remote_port_;
            }

            void VirtualEthernetMappingPort::Finalize() noexcept {
                int disposed = disposed_.exchange(TRUE);
                transmission_.reset();

                if (disposed != TRUE) {
                    std::shared_ptr<Server> server = std::move(server_); 
                    server_.reset();

                    std::shared_ptr<Client> client = std::move(client_); 
                    client_.reset();

                    if (NULL != server) {
                        ppp::net::Socket::Closesocket(server->socket_udp_);
                        ppp::net::Socket::Closesocket(server->socket_tcp_);

                        ppp::collections::Dictionary::ReleaseAllObjects(server->socket_connections_);
                    }

                    if (NULL != client) {
                        ppp::collections::Dictionary::ReleaseAllObjects(client->socket_connections_);
                        ppp::collections::Dictionary::ReleaseAllObjects(client->socket_datagram_ports_);
                    }
                }
            }

            void VirtualEthernetMappingPort::Dispose() noexcept {
                Finalize();
            }

#if defined(VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET)
#error "Compiler macro "OPENNETWORKSOCKET" definition conflict found, please check the project C/C++ code implementation for problems."
#else
#define VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(SERVER_OBJ, PROTOCOL, SOCKET_OBJECT)           \
                auto& socket = SOCKET_OBJECT;                                                              \
                if (socket.is_open()) {                                                                    \
                    return false;                                                                          \
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
                    return false;                                                                          \
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
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                socket.set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec);          \
                socket.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(  \
                    configuration_->tcp.fast_open), ec);                                                   \
                                                                                                           \
                socket.bind(PROTOCOL::endpoint(address, remote_port_), ec);                                \
                if (ec) {                                                                                  \
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                auto local_ep = socket.local_endpoint(ec);                                                 \
                if (local_ep.port() != remote_port_) {                                                     \
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                SERVER_OBJ->socket_endpoint_ =                                                             \
                    ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(                                \
                            ppp::net::IPEndPoint::ToEndPoint(local_ep));                                   

            bool VirtualEthernetMappingPort::OpenNetworkSocketDatagram() noexcept {
                std::shared_ptr<Server> server = server_;
                if (NULL == server) {
                    return false;
                }

                VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(server, boost::asio::ip::udp, server->socket_udp_);
                return true;
            }

            bool VirtualEthernetMappingPort::OpenNetworkSocketStream() noexcept {
                std::shared_ptr<Server> server = server_;
                if (NULL == server) {
                    return false;
                }

                VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(server, boost::asio::ip::tcp, server->socket_tcp_);
                return true;
            }
#undef VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET
#endif

            bool VirtualEthernetMappingPort::OpenFrpServer(const VirtualEthernetLoggerPtr& logger) noexcept {
                if (remote_port_ <= ppp::net::IPEndPoint::MinPort || remote_port_ > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (client_) {
                    return false;
                }

                if (server_) {
                    return false;
                }
                
                std::shared_ptr<Server> server = make_shared_object<Server>(this);
                if (!server) {
                    return false;
                }
                
                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                server_ = server;
                logger_ = logger;

                if (tcp_) {
                    bool opened = OpenNetworkSocketStream();
                    if (!opened) {
                        return false;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::tcp::acceptor& acceptor = server->socket_tcp_;
                    acceptor.listen(configuration_->tcp.backlog, ec);

                    if (ec) {
                        return false;
                    }

                    std::shared_ptr<VirtualEthernetMappingPort> self = shared_from_this();
                    return ppp::net::Socket::AcceptLoopbackAsync(acceptor, 
                        [self, this, server](const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept {
                            return Server_AcceptFrpUserSocket(server, context, socket);
                        });
                }
                else {
                    bool opened = OpenNetworkSocketDatagram();
                    if (!opened) {
                        return false;
                    }

                    return LoopbackFrpServer();
                }
            }

            boost::asio::ip::tcp::endpoint VirtualEthernetMappingPort::BoundEndPointOfFrpServer() noexcept {
                std::shared_ptr<Server> server = server_;
                if (server) {
                    return server->socket_endpoint_;
                }

                return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
            }

            bool VirtualEthernetMappingPort::LoopbackFrpServer() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULL == server) {
                    return false;
                }

                bool opened = server->socket_udp_.is_open();
                if (!opened) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetMappingPort> self = shared_from_this();
                server->socket_udp_.async_receive_from(boost::asio::buffer(server->socket_source_buf_.get(), PPP_UDP_BUFFER_SIZE), server->socket_source_ep_,
                    [self, this, server](boost::system::error_code ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                boost::asio::ip::udp::endpoint natEP = ppp::net::Ipep::V6ToV4(server->socket_source_ep_);
                                Server_SendToFrpClient(server->socket_source_buf_.get(), sz, natEP);
                            }
                        }

                        LoopbackFrpServer();
                    });
                return true;
            }

            bool VirtualEthernetMappingPort::Update(UInt64 now) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                std::shared_ptr<Server> server = server_; 
                if (NULL != server) {
                    ppp::collections::Dictionary::UpdateAllObjects(server->socket_connections_, now);
                }

                std::shared_ptr<Client> client = client_; 
                if (NULL != client) {
                    ppp::collections::Dictionary::UpdateAllObjects(client->socket_connections_, now);
                    ppp::collections::Dictionary::UpdateAllObjects(client->socket_datagram_ports_, now);
                }

                return true;
            }

            int VirtualEthernetMappingPort::NewId() noexcept {
                static std::atomic<unsigned int> aid = /*ATOMIC_FLAG_INIT*/RandomNext();

                for (;;) {
                    int id = ++aid;
                    if (id != 0) {
                        return id;
                    }
                }
            }

            VirtualEthernetMappingPort::Server::Connection::Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Server>& server, int connection_id, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                : IAsynchronousWriteIoQueue(mapping_port->buffer_allocator_)
                , connection_stated_(0)
                , server_(server)
                , connection_id_(connection_id)
                , mapping_port_(mapping_port)
                , socket_(socket)
                , timeout_(0) {
                linklayer_ = mapping_port->linklayer_;
                configuration_ = mapping_port->configuration_;
                Update();
            }

            VirtualEthernetMappingPort::Server::Connection::~Connection() noexcept {
                Finalize(false);
            }

            bool VirtualEthernetMappingPort::Server::Connection::ConnectToFrpClient() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 0) {
                    return false;
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULL == transmission) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULL == server) {
                    return false;
                }

                bool ok = linklayer_->DoFrpConnect(transmission,
                    connection_id_, 
                    mapping_port_->in_, 
                    mapping_port_->remote_port_,
                    nullof<YieldContext>());

                if (!ok) {
                    transmission->Dispose();
                    return false;
                }

                connection_stated_.exchange(1);
                return true;
            }

            bool VirtualEthernetMappingPort::Server::Connection::SendToFrpClient(const void* packet, int packet_size) noexcept {
                if (NULL == packet || packet_size < 1) {
                    return false;
                }

                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULL == transmission) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULL == server) {
                    return false;
                }

                bool ok = linklayer_->DoFrpPush(transmission, 
                    connection_id_, 
                    mapping_port_->in_,
                    mapping_port_->remote_port_,
                    packet, 
                    packet_size, 
                    nullof<YieldContext>());

                if (ok) {
                    Update();
                }
                else {
                    transmission->Dispose();
                }

                return ok;
            }

            bool VirtualEthernetMappingPort::Server::Connection::SendToFrpUser(const void* packet, int packet_size) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<Byte> messages = Copy(mapping_port_->buffer_allocator_, packet, packet_size);
                if (NULL == messages) {
                    return false;
                }

                auto self = shared_from_this();
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

            bool VirtualEthernetMappingPort::Server::Connection::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULL == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
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

            void VirtualEthernetMappingPort::Server::Connection::Finalize(bool disconnect) noexcept {
                int connection_state = connection_stated_.exchange(4);
                if (connection_state != 4) {
                    if (!disconnect && connection_state == 3) {
                        ITransmissionPtr transmission = mapping_port_->GetTransmission();
                        if (NULL != transmission) {
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
                    socket_.reset();

                    std::shared_ptr<Server> server = std::move(server_);
                    server_.reset();

                    if (NULL != socket) {
                        ppp::net::Socket::Closesocket(socket);
                    }

                    if (NULL != server) {
                        ppp::collections::Dictionary::TryRemove(server->socket_connections_, connection_id_);
                    }
                }
            }

            bool VirtualEthernetMappingPort::Server::Connection::OnConnectOK(Byte error_code) noexcept {
                int except = 1;
                if (!connection_stated_.compare_exchange_strong(except, 2)) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULL == server) {
                    return false;
                }

                if (error_code != 0) {
                    return false;
                }

                except = 2;
                if (!connection_stated_.compare_exchange_strong(except, 3)) {
                    return false;
                }

                Update();
                buffer_chunked_ = ppp::threading::BufferswapAllocator::MakeByteArray(mapping_port_->buffer_allocator_, PPP_TCP_BUFFER_SIZE);

                if (NULL == buffer_chunked_) {
                    return false;
                }

                return ForwardFrpUserToFrpClient();
            }

            bool VirtualEthernetMappingPort::Server::Connection::ForwardFrpUserToFrpClient() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULL == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                socket->async_read_some(boost::asio::buffer(buffer_chunked_.get(), PPP_TCP_BUFFER_SIZE),
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        bool ok = false;
                        if (ec == boost::system::errc::success && sz > 0) {
                            ok = SendToFrpClient(buffer_chunked_.get(), sz);
                            if (ok) {
                                ForwardFrpUserToFrpClient();
                            }
                        }

                        if (ok) {
                            Update();
                        }
                        else {
                            Dispose();
                        }
                    });
                return true;
            }

            std::shared_ptr<VirtualEthernetMappingPort> VirtualEthernetMappingPort::FindMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept {
                uint32_t key = GetHashCode(in, tcp, remote_port);
                Ptr ptr;

                ppp::collections::Dictionary::TryGetValue(mappings, key, ptr);
                return ptr;
            }

            std::shared_ptr<VirtualEthernetMappingPort> VirtualEthernetMappingPort::DeleteMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept {
                uint32_t key = GetHashCode(in, tcp, remote_port);
                Ptr ptr;

                ppp::collections::Dictionary::TryRemove(mappings, key, ptr);
                return ptr;
            }

            bool VirtualEthernetMappingPort::AddMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port, const Ptr& mapping_port) noexcept {
                if (NULL == mapping_port) {
                    return false;
                }

                uint32_t key = GetHashCode(in, tcp, remote_port);
                return ppp::collections::Dictionary::TryAdd(mappings, key, mapping_port);
            }

            template <typename TConnectionPtr, typename TDisposed, typename TConnectionTable>
            static inline TConnectionPtr MAPPINGPORT_GetConnection(TDisposed& disposed_, TConnectionTable& table_, int connection_id) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return NULL;
                }

                auto table = table_;
                if (NULL == table) {
                    return NULL;
                }

                TConnectionPtr connection;
                if (!ppp::collections::Dictionary::TryGetValue(table->socket_connections_, connection_id, connection)) {
                    return NULL;
                }

                if (NULL != connection) {
                    return connection;
                }

                ppp::collections::Dictionary::TryRemove(table->socket_connections_, connection_id);
                return NULL;
            }

            VirtualEthernetMappingPort::Server::ConnectionPtr VirtualEthernetMappingPort::Server_GetConnection(int connection_id) noexcept {
                return MAPPINGPORT_GetConnection<Server::ConnectionPtr>(disposed_, server_, connection_id);
            }

            VirtualEthernetMappingPort::Client::ConnectionPtr VirtualEthernetMappingPort::Client_GetConnection(int connection_id) noexcept {
                return MAPPINGPORT_GetConnection<Client::ConnectionPtr>(disposed_, client_, connection_id);
            }

            VirtualEthernetMappingPort::Client::DatagramPortPtr VirtualEthernetMappingPort::Client_GetDatagramPort(const boost::asio::ip::udp::endpoint& nat_key) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return NULL;
                }

                std::shared_ptr<Client> client = client_;
                if (NULL == client) {
                    return NULL;
                }

                Client::DatagramPortPtr datagram_port;
                if (!ppp::collections::Dictionary::TryGetValue(client->socket_datagram_ports_, nat_key, datagram_port)) {
                    return NULL;
                }
                
                if (NULL != datagram_port) {
                    return datagram_port;
                }

                ppp::collections::Dictionary::TryRemove(client->socket_datagram_ports_, nat_key);
                return NULL;
            }

            VirtualEthernetMappingPort::Server::Server(VirtualEthernetMappingPort* owner) noexcept
                : socket_udp_(*owner->context_)
                , socket_tcp_(*owner->context_) {
                socket_source_buf_ = ppp::threading::Executors::GetCachedBuffer(owner->context_);
            }

            bool VirtualEthernetMappingPort::Server_OnFrpConnectOK(int connection_id, Byte error_code) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULL == connection) {
                    return false;
                }

                bool ok = connection->OnConnectOK(error_code);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
            }

            bool VirtualEthernetMappingPort::Server_OnFrpDisconnect(int connection_id) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULL == connection) {
                    return false;
                }

                connection->OnDisconnect();
                return true;
            }

            bool VirtualEthernetMappingPort::Server_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULL == connection) {
                    return false;
                }

                bool ok = connection->SendToFrpUser(packet, packet_length);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
            }

            bool VirtualEthernetMappingPort::Server_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULL == server) {
                    return false;
                }

                bool opened = server->socket_udp_.is_open();
                if (!opened) {
                    return false;
                }

                boost::system::error_code ec;
                if (in_) {
                    server->socket_udp_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V6ToV4(sourceEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    server->socket_udp_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V4ToV6(sourceEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    return false;
                }

                return true;
            }

            bool VirtualEthernetMappingPort::Server_AcceptFrpUserSocket(const std::shared_ptr<Server>& server, const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }
                elif(!ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo)) {
                    return false;
                }
                else {
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                }

                ITransmissionPtr transmission = transmission_;
                if (!transmission) {
                    return false;
                }

                auto self = shared_from_this();
                auto& connections = server->socket_connections_;
                for (int i = ppp::net::IPEndPoint::MinPort; i < ppp::net::IPEndPoint::MaxPort; i++) {
                    int connection_id = NewId();
                    if (ppp::collections::Dictionary::ContainsKey(connections, connection_id)) {
                        continue;
                    }

                    auto connection = make_shared_object<Server::Connection>(self, server, connection_id, socket);
                    if (NULL == connection) {
                        return false;
                    }

                    bool ok = connection->ConnectToFrpClient();
                    if (ok) {
                        ok = ppp::collections::Dictionary::TryAdd(connections, connection_id, connection);
                        while (ok) {
                            VirtualEthernetLoggerPtr logger = logger_;
                            if (NULL == logger) {
                                break;
                            }

                            boost::system::error_code ec;
                            boost::asio::ip::tcp::endpoint localEP = socket->local_endpoint(ec);
                            if (ec) {
                                ok = false;
                                break;
                            }

                            boost::asio::ip::tcp::endpoint remoteEP = socket->remote_endpoint(ec);
                            if (ec) {
                                ok = false;
                                break;
                            }

                            logger->MPConnect(linklayer_->GetId(), transmission, localEP, remoteEP);
                            break;
                        }
                    }

                    if (!ok) {
                        connection->Dispose();
                    }

                    return ok;
                }

                return false;
            }

            bool VirtualEthernetMappingPort::Server_SendToFrpClient(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetLinklayer> linklayer = linklayer_;
                if (NULL == linklayer) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (!transmission) {
                    return false;
                }

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
                return false;
            }

            bool VirtualEthernetMappingPort::OpenFrpClient(const boost::asio::ip::address& local_ip, int local_port) noexcept {
                if (remote_port_ <= ppp::net::IPEndPoint::MinPort || remote_port_ > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                if (local_port <= ppp::net::IPEndPoint::MinPort || local_port > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                if (server_) {
                    return false;
                }

                if (client_) {
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                if (local_ip.is_multicast()) {
                    return false;
                }

                if (ppp::net::IPEndPoint::IsInvalid(local_ip)) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (!transmission) {
                    return false;
                }

                std::shared_ptr<Client> client = make_shared_object<Client>();
                if (!client) {
                    return false;
                }

                client_ = client;
                client->local_in_ = local_ip.is_v4();
                client->local_ep_ = boost::asio::ip::udp::endpoint(local_ip, local_port);

                bool ok = linklayer_->DoFrpEntry(transmission,
                    tcp_,
                    in_,
                    remote_port_,
                    nullof<YieldContext>());

                if (ok) {
                    return true;
                }

                transmission->Dispose();
                return false;
            }

            VirtualEthernetMappingPort::Client::Connection::Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, int connection_id) noexcept
                : IAsynchronousWriteIoQueue(mapping_port->buffer_allocator_)
                , connection_stated_(0)
                , client_(client)
                , mapping_port_(mapping_port)
                , connection_id_(connection_id)
                , timeout_(0) {
                linklayer_ = mapping_port->linklayer_;
                configuration_ = mapping_port->configuration_;
                transmission_ = mapping_port->transmission_;
                Update();
            }

            VirtualEthernetMappingPort::Client::Connection::~Connection() noexcept {
                Finalize(false);
            }

            bool VirtualEthernetMappingPort::Client::Connection::ConnectToDestinationServer() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 0) {
                    return false;
                }

                if (socket_) {
                    return false;
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULL == transmission) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULL == client) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*mapping_port_->context_);
                if (NULL == socket) {
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = client->local_ep_.address();
                if (local_ip.is_v4()) {
                    socket->open(boost::asio::ip::tcp::v4(), ec);
                }
                else {
                    socket->open(boost::asio::ip::tcp::v6(), ec);
                }

                if (ec) {
                    return false;
                }

                int handle = socket->native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, local_ip.is_v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);
                ppp::net::Socket::SetWindowSizeIfNotZero(handle, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                socket->set_option(boost::asio::ip::tcp::socket::reuse_address(true), ec);
                if (ec) {
                    return false;
                }

                socket->set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec);
                socket->set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(configuration_->tcp.fast_open), ec);

                socket_ = socket;
                connection_stated_.exchange(1);

                auto self = shared_from_this();
                socket->async_connect(boost::asio::ip::tcp::endpoint(local_ip, client->local_ep_.port()),
                    [self, this](boost::system::error_code ec) noexcept {
                        bool ok = OnConnectedOK(ec == boost::system::errc::success);
                        if (!ok) {
                            Dispose();
                        }
                    });
                return true;
            }

            void VirtualEthernetMappingPort::Client::Connection::Finalize(bool disconnect) noexcept {
                std::shared_ptr<ITransmission> transmission = std::move(transmission_);
                transmission_.reset();

                int connection_state = connection_stated_.exchange(4);
                if (connection_state != 4) {
                    if (!disconnect && connection_state == 3) {
                        if (NULL != transmission) {
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
                    socket_.reset();

                    std::shared_ptr<Client> client = std::move(client_);
                    client_.reset();

                    if (NULL != socket) {
                        ppp::net::Socket::Closesocket(socket);
                    }

                    if (NULL != client) {
                        ppp::collections::Dictionary::TryRemove(client->socket_connections_, connection_id_);
                    }
                }
            }

            bool VirtualEthernetMappingPort::Client::Connection::OnConnectedOK(bool ok) noexcept {
                int except = 1;
                if (!connection_stated_.compare_exchange_strong(except, 2)) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULL == client) {
                    return false;
                }
                else {
                    ITransmissionPtr transmission = transmission_;
                    if (NULL != transmission) {
                        Byte error_code = ok ? 0 : 255;
                        bool ok = linklayer_->DoFrpConnectOK(transmission,
                            connection_id_,
                            mapping_port_->in_,
                            mapping_port_->remote_port_,
                            error_code,
                            nullof<YieldContext>());

                        if (!ok) {
                            transmission->Dispose();
                            return false;
                        }
                    }
                }

                except = 2;
                if (!connection_stated_.compare_exchange_strong(except, 3)) {
                    return false;
                }

                if (!ok) {
                    return false;
                }

                Update();
                buffer_chunked_ = ppp::threading::BufferswapAllocator::MakeByteArray(mapping_port_->buffer_allocator_, PPP_TCP_BUFFER_SIZE);

                if (NULL == buffer_chunked_) {
                    return false;
                }

                return Loopback();
            }

            bool VirtualEthernetMappingPort::Client::Connection::Loopback() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULL == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                socket->async_read_some(boost::asio::buffer(buffer_chunked_.get(), PPP_TCP_BUFFER_SIZE),
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        bool ok = false;
                        if (ec == boost::system::errc::success && sz > 0) {
                            ITransmissionPtr transmission = transmission_;
                            if (NULL != transmission) {
                                ok = linklayer_->DoFrpPush(
                                    transmission,
                                    connection_id_,
                                    mapping_port_->in_,
                                    mapping_port_->remote_port_,
                                    buffer_chunked_.get(),
                                    sz,
                                    nullof<YieldContext>());

                                if (ok) {
                                    ok = Loopback();
                                }
                                else {
                                    transmission->Dispose();
                                }
                            }
                        }

                        if (ok) {
                            Update();
                        }
                        else {
                            Dispose();
                        }
                    });
                return true;
            }

            bool VirtualEthernetMappingPort::Client::Connection::SendToDestinationServer(const void* packet, int packet_size) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<Byte> messages = Copy(mapping_port_->buffer_allocator_, packet, packet_size);
                if (NULL == messages) {
                    return false;
                }

                auto self = shared_from_this();
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

            bool VirtualEthernetMappingPort::Client::Connection::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULL == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
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

            bool VirtualEthernetMappingPort::Client_OnFrpConnect(int connection_id) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULL != connection) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULL == client) {
                    return false;
                }
                else {
                    auto self = shared_from_this();
                    connection = make_shared_object<Client::Connection>(self, client, connection_id);
                    if (NULL == connection) {
                        return false;
                    }
                }

                bool ok = connection->ConnectToDestinationServer();
                if (ok) {
                    ok = ppp::collections::Dictionary::TryAdd(client->socket_connections_, connection_id, connection);
                }

                if (!ok) {
                    connection->Dispose();
                }
                return ok;
            }

            bool VirtualEthernetMappingPort::Client_OnFrpDisconnect(int connection_id) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULL == connection) {
                    return false;
                }

                connection->OnDisconnect();
                return true;
            }

            bool VirtualEthernetMappingPort::Client_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULL == connection) {
                    return false;
                }

                bool ok = connection->SendToDestinationServer(packet, packet_length);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
            }

            bool VirtualEthernetMappingPort::Client_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULL == client) {
                    return false;
                }

                Client::DatagramPortPtr datagram_port = Client_GetDatagramPort(sourceEP);
                if (NULL != datagram_port) {
                    return datagram_port->SendTo(packet, packet_length, client->local_ep_);
                }
                else {
                    auto self = shared_from_this();
                    datagram_port = make_shared_object<Client::DatagramPort>(self, client, sourceEP);
                    if (NULL == datagram_port) {
                        return false;
                    }
                }

                bool ok = datagram_port->Open();
                if (!ok) {
                    datagram_port->Dispose();
                    return false;
                }

                ok = ppp::collections::Dictionary::TryAdd(client->socket_datagram_ports_, sourceEP, datagram_port);
                if (ok) {
                    ok = datagram_port->SendTo(packet, packet_length, client->local_ep_);
                    if (ok) {
                        return true;
                    }
                }

                datagram_port->Dispose();
                return false;
            }

            VirtualEthernetMappingPort::Client::Client() noexcept
                : local_in_(false) {

            }

            VirtualEthernetMappingPort::Client::DatagramPort::DatagramPort(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, const boost::asio::ip::udp::endpoint& natEP) noexcept
                : disposed_(FALSE)
                , socket_(*mapping_port->context_)
                , timeout_(0)
                , configuration_(mapping_port->configuration_)
                , mapping_port_(mapping_port)
                , client_(client)
                , linklayer_(mapping_port->linklayer_)
                , transmission_(mapping_port->transmission_) {
                nat_ep_ = natEP;
                buffer_chunked_ = ppp::threading::Executors::GetCachedBuffer(mapping_port->context_);
                Update();
            }

            VirtualEthernetMappingPort::Client::DatagramPort::~DatagramPort() noexcept {
                Dispose();
            }

            void VirtualEthernetMappingPort::Client::DatagramPort::Dispose() noexcept {
                int disposed = disposed_.exchange(TRUE);
                if (disposed != TRUE) {
                    std::shared_ptr<Client> client = std::move(client_); 
                    client_.reset();

                    if (NULL != client) {
                        ppp::collections::Dictionary::TryRemove(client->socket_datagram_ports_, nat_ep_);
                    }

                    ppp::net::Socket::Closesocket(socket_);
                }
            }

            bool VirtualEthernetMappingPort::Client::DatagramPort::SendToDestinationServer(const void* packet, int packet_length) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }
                
                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULL == transmission) {
                    return false;
                }

                bool ok = linklayer_->DoFrpSendTo(transmission,
                    mapping_port_->in_,
                    mapping_port_->remote_port_,
                    nat_ep_,
                    (Byte*)packet,
                    packet_length,
                    nullof<YieldContext>());

                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            bool VirtualEthernetMappingPort::Client::DatagramPort::Loopback() noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    return false;
                }

                std::shared_ptr<DatagramPort> self = shared_from_this();
                socket_.async_receive_from(boost::asio::buffer(buffer_chunked_.get(), PPP_UDP_BUFFER_SIZE), source_ep_,
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::success) {
                            bool ok = false;
                            if (sz > 0) {
                                ok = SendToDestinationServer(buffer_chunked_.get(), sz);
                            }

                            if (ok) {
                                Update();
                            }
                            else {
                                Dispose();
                            }
                        }

                        Loopback();
                    });
                return true;
            }

            bool VirtualEthernetMappingPort::Client::DatagramPort::Open() noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (opened) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULL == client) {
                    return false;
                }

                boost::asio::ip::address local_ip = client->local_ep_.address();
                if (local_ip.is_v4()) {
                    opened = ppp::net::Socket::OpenSocket(socket_, boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
                }
                else {
                    opened = ppp::net::Socket::OpenSocket(socket_, boost::asio::ip::address_v6::any(), ppp::net::IPEndPoint::MinPort);
                }

                if (opened) {
                    ppp::net::Socket::SetWindowSizeIfNotZero(
                        socket_.native_handle(), 
                        configuration_->udp.cwnd, 
                        configuration_->udp.rwnd);
                    opened = Loopback();
                }
                
                return opened;
            }

            bool VirtualEthernetMappingPort::Client::DatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULL == client) {
                    return false;
                }

                boost::system::error_code ec;
                if (client->local_in_) {
                    socket_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V6ToV4(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    socket_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V4ToV6(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    return false;
                }

                Update();
                return true;
            }
        }
    }
}