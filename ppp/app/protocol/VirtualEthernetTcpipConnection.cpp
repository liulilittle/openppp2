#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace protocol {
            VirtualEthernetTcpipConnection::VirtualEthernetTcpipConnection(
                const AppConfigurationPtr&                              configuration, 
                const ContextPtr&                                       context,
                const Int128&                                           id,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                : disposed_(false)
                , connected_(false)
                , configuration_(configuration)
                , context_(context)
                , id_(id)
                , socket_(socket) {
                
            }

            std::shared_ptr<VirtualEthernetTcpipConnection> VirtualEthernetTcpipConnection::GetReference() noexcept {
                return shared_from_this();
            }

            VirtualEthernetTcpipConnection::ContextPtr VirtualEthernetTcpipConnection::GetContext() noexcept {
                return context_;
            }

            VirtualEthernetTcpipConnection::AppConfigurationPtr VirtualEthernetTcpipConnection::GetConfiguration() noexcept {
                return configuration_;
            }

            Int128 VirtualEthernetTcpipConnection::GetId() noexcept {
                return id_;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> VirtualEthernetTcpipConnection::GetSocket() noexcept {
                return socket_;
            }

            VirtualEthernetTcpipConnection::ITransmissionPtr VirtualEthernetTcpipConnection::GetTransmission() noexcept {
                return transmission_;
            }

            bool VirtualEthernetTcpipConnection::IsLinked() noexcept {
                if (disposed_) {
                    return false;
                }

                return connected_;
            }

            class STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST final : public VirtualEthernetLinklayer {
                friend class VirtualEthernetTcpipConnection;

            public:
                STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST(
                    VirtualEthernetTcpipConnection*             connection,
                    const AppConfigurationPtr&                  configuration,
                    const ContextPtr&                           context,
                    const Int128&                               id) noexcept
                    : VirtualEthernetLinklayer(configuration, context, id)
                    , ConnectId(0)
                    , ConnectOK(false)
                    , ErrorCode(0)
                    , Connect(false) {
                    connection_ = connection;
                }

            public:
                int                                                         ConnectId;
                bool                                                        ConnectOK;
                Byte                                                        ErrorCode;
                bool                                                        Connect;
                ppp::string                                                 Host;
                boost::asio::ip::tcp::endpoint                              Destination;

            public:
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept {
                    return connection_->GetFirewall();
                }
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override {
                    Host = destinationHost;
                    return true;
                }
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override {
                    Connect = true;
                    ConnectId = connection_id;
                    Destination = destinationEP;
                    return true;
                }
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override {
                    ConnectOK = true;
                    ErrorCode = error_code;
                    ConnectId = connection_id;
                    return true;
                }

            private:
                VirtualEthernetTcpipConnection*                             connection_;
            };

            bool VirtualEthernetTcpipConnection::Connect(YieldContext& y, ITransmissionPtr& transmission, const ppp::string& host, int port) noexcept {
                typedef VirtualEthernetLinklayer::ERROR_CODES ERROR_CODES;

                if (NULL == transmission) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (connected_) {
                    return false;
                }
                
                Update();

                auto connector = make_shared_object<STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST>(this, configuration_, context_, id_);
                if (NULL == connector) {
                    return false;
                }
                
                if (!connector->DoConnect(transmission, RandomNext(1, INT_MAX), host, port, y)) {
                    return false;
                }

                int packet_size = 0;
                std::shared_ptr<Byte> packet = transmission->Read(y, packet_size);
                if (NULL == packet || packet_size < 1) {
                    return false;
                }

                if (!connector->PacketInput(transmission, packet.get(), packet_size, y)) {
                    return false;
                }

                if (!connector->ConnectOK) {
                    return false;
                }

                ERROR_CODES err = (ERROR_CODES)connector->ErrorCode;
                if (err != ERROR_CODES::ERRORS_SUCCESS) {
                    return false;
                }

                connected_ = true;
                transmission_ = transmission;

                Update();
                return true;
            }

            bool VirtualEthernetTcpipConnection::Accept(YieldContext& y, ITransmissionPtr& transmission, const VirtualEthernetLoggerPtr& logger) noexcept {
                typedef VirtualEthernetLinklayer::ERROR_CODES ERROR_CODES;

                if (NULL == transmission) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (connected_) {
                    return false;
                }

                Update();

                int packet_size = -1;
                std::shared_ptr<Byte> packet = transmission->Read(y, packet_size);
                if (NULL == packet || packet_size < 1) {
                    return false;
                }

                auto connector = make_shared_object<STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST>(this, configuration_, context_, id_);
                if (NULL == connector) {
                    return false;
                }

                if (!connector->PacketInput(transmission, packet.get(), packet_size, y)) {
                    return false;
                }

                boost::asio::ip::tcp::endpoint& destinationEP = connector->Destination;
                if (!connector->Connect) {
                    return false;
                }

                boost::system::error_code ec;
                socket_->open(destinationEP.protocol(), ec);
                if (ec) {
                    return false;
                }

                boost::asio::ip::address destinationIP = destinationEP.address();
#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
                // IPV6 does not need to be linked, because VPN is IPV4, 
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (destinationIP.is_v4() && !destinationIP.is_loopback()) {
                    if (auto protector_network = ProtectorNetwork; NULL != protector_network) {
                        if (!protector_network->Protect(socket_->native_handle(), y)) {
                            return false;
                        }
                    }
                }
#endif

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                ppp::net::Socket::AdjustSocketOptional(*socket_, destinationIP.is_v4(), configuration->tcp.fast_open, configuration->tcp.turbo);

                bool ok = ppp::coroutines::asio::async_connect(*socket_, destinationEP, y);
                if (NULL != logger) {
                    logger->Connect(GetId(), transmission, socket_->local_endpoint(ec), destinationEP, connector->Host);
                }

                if (disposed_) {
                    connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_CONNECT_CANCEL, y);
                    return false;
                }
                
                if (ok) {
                    ok = connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_SUCCESS, y);
                    if (!ok) {
                        return false;
                    }
                }
                else {
                    connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_CONNECT_TO_DESTINATION, y);
                    return false;
                }
                
                connected_ = true;
                transmission_ = transmission;
                
                Update();
                return true;
            }

            void VirtualEthernetTcpipConnection::Finalize() noexcept {
                disposed_ = true; {
                    ITransmissionPtr transmission = std::move(transmission_);
                    if (NULL != transmission) {
                        transmission_.reset();
                        transmission->Dispose();
                    }

                    ppp::net::Socket::Closesocket(socket_);
                }
            }

            VirtualEthernetTcpipConnection::~VirtualEthernetTcpipConnection() noexcept {
                Finalize();
            }

            void VirtualEthernetTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            bool VirtualEthernetTcpipConnection::Run(YieldContext& y) noexcept {
                if (!ReceiveTransmissionToSocket()) {
                    return false;
                }

                Update();
                return ForwardTransmissionToSocket(y);
            }

            bool VirtualEthernetTcpipConnection::SendBufferToPeer(YieldContext& y, const void* packet, int packet_length) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (!connected_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                return transmission->Write(y, packet, packet_length);
            }

            bool VirtualEthernetTcpipConnection::ForwardSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size, int bytes_transferred) noexcept {
                if (NULL == buffer || buffer_size < 1 || bytes_transferred < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (!connected_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                auto self = shared_from_this();
                return transmission->Write(buffer.get(), bytes_transferred, 
                    [self, this, buffer, buffer_size](bool ok) noexcept {
                        ForwardSocketToTransmissionOK(ok, buffer, buffer_size);
                    });
            }

            bool VirtualEthernetTcpipConnection::ReceiveSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept {
                if (NULL == buffer || buffer_size < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (!connected_) {
                    return false;
                }

                auto self = shared_from_this();
                socket_->async_read_some(boost::asio::buffer(buffer.get(), buffer_size),
                    [self, this, buffer, buffer_size](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        int bytes_transferred = std::max<int>(ec ? -1 : sz, -1);
                        if (bytes_transferred < 1) {
                            Dispose();
                        }
                        elif(ForwardSocketToTransmission(buffer, buffer_size, bytes_transferred)) {
                            Update();
                        }
                        else {
                            Dispose();
                        }
                    });
                return true;
            }

            bool VirtualEthernetTcpipConnection::ReceiveTransmissionToSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                if (!connected_) {
                    return false;
                }

                auto allocator = configuration_->GetBufferAllocator();
                auto buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
                if (NULL == buffer) {
                    return false;
                }

                return ReceiveSocketToTransmission(buffer, PPP_BUFFER_SIZE);
            }

            bool VirtualEthernetTcpipConnection::ForwardTransmissionToSocket(YieldContext& y) noexcept {
                if (!connected_) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                bool any = false;
                while (!disposed_) {
                    ITransmissionPtr transmission = transmission_;
                    if (NULL == transmission) {
                        break;
                    }

                    int packet_length = 0;
                    std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                    if (NULL == packet || packet_length < 1) {
                        break;
                    }

                    any = true;
                    Update();

                    bool ok = ppp::coroutines::asio::async_write(*socket_, boost::asio::buffer(packet.get(), packet_length), y);
                    if (ok) {
                        Update();
                    }
                    else {
                        break;
                    }
                }

                return any;
            }
        }
    }
}