#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>

#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                VEthernetLocalProxyConnection::VEthernetLocalProxyConnection(const VEthernetLocalProxySwitcherPtr& proxy, const VEthernetExchangerPtr& exchanger, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                    : disposed_(false)
                    , context_(context)
                    , strand_(strand)
                    , timeout_(0)
                    , exchanger_(exchanger)
                    , socket_(socket)
                    , configuration_(proxy->GetConfiguration())
                    , proxy_(proxy)
                    , allocator_(configuration_->GetBufferAllocator()) {
                    Update();
                }

                VEthernetLocalProxyConnection::~VEthernetLocalProxyConnection() noexcept {
                    Finalize();
                }

                void VEthernetLocalProxyConnection::Dispose() noexcept {
                    std::shared_ptr<VEthernetLocalProxyConnection> self = shared_from_this();
                    ppp::threading::Executors::ContextPtr context = context_;
                    ppp::threading::Executors::StrandPtr strand = strand_;

                    auto finalize = 
                        [self, this, context, strand]() noexcept {
                            Finalize();
                        };

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_; 
                    if (NULL != socket) {
                        boost::asio::post(socket->get_executor(), finalize);
                    }
                    else {
                        ppp::threading::Executors::Post(context, strand, finalize);
                    }
                }

                void VEthernetLocalProxyConnection::Finalize() noexcept {
                    for (;;) {
                        std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                        connection_.reset();

                        std::shared_ptr<RinetdConnection> connection_rinetd = std::move(connection_rinetd_); 
                        connection_rinetd_.reset();

                        std::shared_ptr<vmux::vmux_skt> connection_mux = std::move(connection_mux_);
                        connection_mux_.reset();

                        if (NULL != connection) {
                            connection->Dispose();
                        }

                        if (NULL != connection_rinetd) {
                            connection_rinetd->Dispose();
                        }

                        if (NULL != connection_mux) {
                            connection_mux->close();
                        }

                        ppp::net::Socket::Closesocket(socket_);
                        break;
                    }

                    disposed_ = true;
                    proxy_->ReleaseConnection(this);
                }

                bool VEthernetLocalProxyConnection::Run(YieldContext& y) noexcept {
                    bool ok = this->Handshake(y);
                    if (!ok) {
                        return false;
                    }
                    elif(disposed_) {
                        return false;
                    }
                    elif(VirtualEthernetTcpipConnectionPtr connection = this->connection_; NULL != connection) {
                        this->Update();
                        return connection->Run(y);
                    }
                    elif(std::shared_ptr<RinetdConnection> connection = this->connection_rinetd_; NULL != connection) {
                        this->Update();
                        return connection->Run();
                    }
                    elif(std::shared_ptr<vmux::vmux_skt> connection = this->connection_mux_; NULL != connection) {
                        this->Update();
                        return connection->run();
                    }
                    else {
                        return false;
                    }
                }

                bool VEthernetLocalProxyConnection::SendBufferToPeer(YieldContext& y, const void* messages, int messages_size) noexcept {
                    if (NULL == messages || messages_size < 1) {
                        return false;
                    }

                    if (disposed_) {
                        return false;
                    }

                    VirtualEthernetTcpipConnectionPtr V = this->connection_; 
                    if (NULL != V) {
                        return V->SendBufferToPeer(y, messages, messages_size);
                    }

                    std::shared_ptr<RinetdConnection> R = this->connection_rinetd_;
                    if (NULL != R) {
                        std::shared_ptr<boost::asio::ip::tcp::socket> socket = R->GetRemoteSocket(); 
                        if (NULL == socket) {
                            return false;
                        }

                        return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(messages, messages_size), y);
                    }
                    
                    std::shared_ptr<vmux::vmux_skt> K = this->connection_mux_;
                    if (NULL != K) {
                        return K->send_to_peer_yield(messages, messages_size, y);
                    }

                    return false;
                }
 
                bool VEthernetLocalProxyConnection::ConnectBridgeToPeer(const std::shared_ptr<ppp::app::protocol::AddressEndPoint>& destinationEP, YieldContext& y) noexcept {
                    using VEthernetTcpipConnection = ppp::app::protocol::templates::TVEthernetTcpipConnection<VEthernetLocalProxyConnection>;
                    
                    if (NULL == destinationEP) {
                        return false;
                    }

                    auto configuration = exchanger_->GetConfiguration();
                    if (NULL == configuration) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULL == socket || !socket->is_open()) {
                        return false;
                    }

                    auto self = shared_from_this();
                    if (auto switcher = exchanger_->GetSwitcher(); NULL != switcher) {
                        if (auto tap = switcher->GetTap(); NULL != tap && tap->IsHostedNetwork()) {
                            boost::system::error_code ec;
                            boost::asio::ip::address address = StringToAddress(destinationEP->Host.data(), ec);
                            if (ec) {
                                address = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::tcp>(destinationEP->Host.data(), destinationEP->Port, y).address();
                            }

                            if (ppp::net::IPEndPoint::IsInvalid(address)) {
                                return false;
                            }

                            int rinetd_status = VEthernetNetworkTcpipConnection::Rinetd(self,
                                exchanger_,
                                context_,
                                strand_,
                                configuration,
                                socket,
                                boost::asio::ip::tcp::endpoint(address, destinationEP->Port),
                                connection_rinetd_,
                                y);
                            if (rinetd_status < 1) {
                                return rinetd_status == 0;
                            }

                            destinationEP->Host = address.to_string();
                            destinationEP->Type = address.is_v4() ? ppp::app::protocol::AddressType::IPv4 : ppp::app::protocol::AddressType::IPv6;
                        }
                    }

                    int mux_status = VEthernetNetworkTcpipConnection::Mux(self, exchanger_, destinationEP->Host, destinationEP->Port, socket, connection_mux_, y);
                    if (mux_status < 1) {
                        return mux_status == 0;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger_->ConnectTransmission(context_, strand_, y);
                    if (NULL == transmission) {
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context_, strand_, exchanger_->GetId(), socket);
                    if (NULL == connection) {
                        IDisposable::DisposeReferences(transmission);
                        return false;
                    }

#if defined(_LINUX)
                    auto switcher = exchanger_->GetSwitcher(); 
                    if (NULL != switcher) {
                        connection->ProtectorNetwork = switcher->GetProtectorNetwork();
                    }
#endif

                    bool ok = connection->Connect(y, transmission, destinationEP->Host, destinationEP->Port);
                    if (!ok) {
                        IDisposable::DisposeReferences(connection, transmission);
                        return false;
                    }

                    this->connection_ = std::move(connection);
                    return true;
                }

                std::shared_ptr<ppp::app::protocol::AddressEndPoint> VEthernetLocalProxyConnection::GetAddressEndPointByProtocol(const ppp::string& host, int port) noexcept {
                    if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                        return NULL;
                    }

                    if (host.empty()) {
                        return NULL;
                    }

                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> destinationEP = make_shared_object<ppp::app::protocol::AddressEndPoint>();
                    if (NULL == destinationEP) {
                        return NULL;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(host, ec);

                    if (ec) {
                        destinationEP->Type = ppp::app::protocol::AddressType::Domain;
                    }
                    elif(address.is_v4()) {
                        destinationEP->Type = ppp::app::protocol::AddressType::IPv4;
                    }
                    elif(address.is_v6()) {
                        destinationEP->Type = ppp::app::protocol::AddressType::IPv6;
                    }
                    else {
                        return NULL;
                    }

                    destinationEP->Host = host;
                    destinationEP->Port = port;
                    return destinationEP;
                }

                void VEthernetLocalProxyConnection::Update() noexcept {
                    bool linked = false;
                    if (VirtualEthernetTcpipConnectionPtr connection = connection_; NULL != connection) {
                        linked = connection->IsLinked();
                    }
                    elif(std::shared_ptr<RinetdConnection> connection = connection_rinetd_; NULL != connection) {
                        linked = connection->IsLinked();
                    }
                    elif(std::shared_ptr<vmux::vmux_skt> connection = connection_mux_; NULL != connection) {
                        linked = connection->is_connected();
                    }

                    uint64_t now = Executors::GetTickCount();
                    if (linked) {
                        timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                    }
                    else {
                        timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                    }
                }
            }
        }
    }
}