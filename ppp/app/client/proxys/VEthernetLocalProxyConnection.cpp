#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetNetworkTcpipForwarding.inl>
#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file VEthernetLocalProxyConnection.cpp
 * @brief Implements local proxy connection lifecycle and bridge establishment.
 * @author OpenPPP Contributors
 * @license GPL-3.0
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief Builds a local proxy connection and initializes its timeout state.
                 */
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

                /**
                 * @brief Defers cleanup onto socket executor or fallback strand.
                 */
                void VEthernetLocalProxyConnection::Dispose() noexcept {
                    std::shared_ptr<VEthernetLocalProxyConnection> self = shared_from_this();
                    ppp::threading::Executors::ContextPtr context = context_;
                    ppp::threading::Executors::StrandPtr strand = strand_;

                    auto finalize =
                        [self, this, context, strand]() noexcept {
                            Finalize();
                        };

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                    if (NULLPTR != socket) {
                        boost::asio::post(socket->get_executor(), finalize);
                    }
                    else {
                        ppp::threading::Executors::Post(context, strand, finalize);
                    }
                }

                /**
                 * @brief Releases active bridge channels, closes socket, and unregisters self.
                 */
                void VEthernetLocalProxyConnection::Finalize() noexcept {
                    for (;;) {
                        std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                        std::shared_ptr<RinetdConnection> connection_rinetd = std::move(connection_rinetd_);
                        std::shared_ptr<vmux::vmux_skt> connection_mux = std::move(connection_mux_);

#if defined(_IPHONE)
                        if (ios_child_transmission_slot_held_) {
                            ios_child_transmission_slot_held_ = false;
                            uint64_t slot_generation = ios_child_transmission_slot_generation_;
                            ios_child_transmission_slot_generation_ = 0;
                            if (NULLPTR != exchanger_) {
                                exchanger_->ReleaseIosChildTransmissionSlot(slot_generation);
                            }
                        }
#endif

                        if (NULLPTR != connection) {
                            connection->Dispose();
                        }

                        if (NULLPTR != connection_rinetd) {
                            connection_rinetd->Dispose();
                        }

                        if (NULLPTR != connection_mux) {
                            connection_mux->close();
                        }

                        if (NULLPTR != exchanger_) {
                            boost::system::error_code ec;
                            boost::asio::ip::tcp::endpoint remote_endpoint = socket_ ? socket_->remote_endpoint(ec) : boost::asio::ip::tcp::endpoint();
                            if (!ec && remote_endpoint.port() > ppp::net::IPEndPoint::MinPort) {
                                exchanger_->ReleaseDatagramHandler(boost::asio::ip::udp::endpoint(remote_endpoint.address(), remote_endpoint.port()));
                            }
                        }

                        ppp::net::Socket::Closesocket(socket_);
                        break;
                    }

                    disposed_.store(true, std::memory_order_release);
                    proxy_->ReleaseConnection(this);
                }

                /**
                 * @brief Executes handshake first, then runs whichever bridge type is active.
                 */
                bool VEthernetLocalProxyConnection::Run(YieldContext& y) noexcept {
                    bool ok = this->Handshake(y);
                    if (!ok) {
                        return false;
                    }
                    elif(disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }
                    elif(VirtualEthernetTcpipConnectionPtr connection = this->connection_; NULLPTR != connection) {
                        this->Update();
                        return connection->Run(y);
                    }
                    elif(std::shared_ptr<RinetdConnection> connection = this->connection_rinetd_; NULLPTR != connection) {
                        this->Update();
                        return connection->Run();
                    }
                    elif(std::shared_ptr<vmux::vmux_skt> connection = this->connection_mux_; NULLPTR != connection) {
                        this->Update();
                        return connection->run();
                    }
                    else {
                        return RunAfterHandshakeWithoutBridge(y);
                    }
                }

                /** @brief Default no-bridge handler reports a missing transport. */
                bool VEthernetLocalProxyConnection::RunAfterHandshakeWithoutBridge(YieldContext& y) noexcept {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                /**
                 * @brief Writes outgoing payload to the currently selected bridge backend.
                 */
                bool VEthernetLocalProxyConnection::SendBufferToPeer(YieldContext& y, const void* messages, int messages_size) noexcept {
                    if (NULLPTR == messages || messages_size < 1) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetLocalProxyConnectionSendInvalidPayload);
                    }

                    if (disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    VirtualEthernetTcpipConnectionPtr V = this->connection_;
                    if (NULLPTR != V) {
                        return V->SendBufferToPeer(y, messages, messages_size);
                    }

                    std::shared_ptr<RinetdConnection> R = this->connection_rinetd_;
                    if (NULLPTR != R) {
                        std::shared_ptr<boost::asio::ip::tcp::socket> socket = R->GetRemoteSocket();
                        if (NULLPTR == socket) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                        }

                        bool ok = ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(messages, messages_size), y);
                        if (!ok) {
                            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                            }
                        }
                        return ok;
                    }

                    std::shared_ptr<vmux::vmux_skt> K = this->connection_mux_;
                    if (NULLPTR != K) {
                        return K->send_to_peer_yield(messages, messages_size, y);
                    }

                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                /**
                 * @brief Creates a bridge path in priority order: rinetd, mux, then transmission tunnel.
                 */
                bool VEthernetLocalProxyConnection::ConnectBridgeToPeer(const std::shared_ptr<ppp::app::protocol::AddressEndPoint>& destinationEP, YieldContext& y) noexcept {
                    using VEthernetTcpipConnection = ppp::app::protocol::templates::TVEthernetTcpipConnection<VEthernetLocalProxyConnection>;

                    if (NULLPTR == destinationEP) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    }

                    auto configuration = exchanger_->GetConfiguration();
                    if (NULLPTR == configuration) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULLPTR == socket || !socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    }

                    auto self = shared_from_this();
                    if (auto switcher = exchanger_->GetSwitcher(); NULLPTR != switcher) {
                        if (auto tap = switcher->GetTap(); NULLPTR != tap &&
                            (tap->IsHostedNetwork() || switcher->ProxyOnly(NULLPTR))) {
                            /**
                             * @brief Native bypass mode prefers direct rinetd bridge after DNS resolution.
                             */
                            boost::system::error_code ec;
                            boost::asio::ip::address address = StringToAddress(destinationEP->Host.data(), ec);
                            if (ec) {
                                address = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::tcp>(destinationEP->Host.data(), destinationEP->Port, y).address();
                            }

                            if (ppp::net::IPEndPoint::IsInvalid(address)) {
                                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                            }

                            int rinetd_status = VEthernetNetworkTcpipConnection::Rinetd(self,
                                exchanger_,
                                context_,
                                strand_,
                                configuration,
                                socket,
                                boost::asio::ip::tcp::endpoint(address, destinationEP->Port),
                                false,
                                connection_rinetd_,
                                y);
                            if (rinetd_status < 1) {
                                if (rinetd_status < 0) {
                                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                                    }
                                }
                                return rinetd_status == 0;
                            }

                            destinationEP->Host = address.to_string();
                            destinationEP->Type = address.is_v4() ? ppp::app::protocol::AddressType::IPv4 : ppp::app::protocol::AddressType::IPv6;
                        }
                    }

                    /**
                     * @brief Attempt vmux fast path before creating a full transmission tunnel.
                     */
                    int mux_status = VEthernetNetworkTcpipConnection::Mux(self, exchanger_, destinationEP->Host, destinationEP->Port, socket, connection_mux_, y);
                    if (mux_status < 1) {
                        if (mux_status < 0) {
                            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                            }
                        }
                        return mux_status == 0;
                    }

#if defined(_IPHONE)
                    uint64_t ios_child_slot_generation = 0;
                    std::shared_ptr<ppp::transmissions::ITransmission> transmission =
                        exchanger_->ConnectTransmission(context_, strand_, y, &ios_child_slot_generation);
#else
                    std::shared_ptr<ppp::transmissions::ITransmission> transmission =
                        exchanger_->ConnectTransmission(context_, strand_, y);
#endif
                    if (NULLPTR == transmission) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context_, strand_, exchanger_->GetId(), socket);
                    if (NULLPTR == connection) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        IDisposable::DisposeReferences(transmission);
#if defined(_IPHONE)
                        exchanger_->ReleaseIosChildTransmissionSlot(ios_child_slot_generation);
#endif
                        return false;
                    }

#if defined(_LINUX)
                    auto switcher = exchanger_->GetSwitcher();
                    if (NULLPTR != switcher) {
                        connection->ProtectorNetwork = switcher->GetProtectorNetwork();
                    }
#endif

                    bool ok = connection->Connect(y, transmission, destinationEP->Host, destinationEP->Port);
                    if (!ok) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                        IDisposable::DisposeReferences(connection, transmission);
#if defined(_IPHONE)
                        exchanger_->ReleaseIosChildTransmissionSlot(ios_child_slot_generation);
#endif
                        return false;
                    }

#if defined(_IPHONE)
                    if (ios_child_slot_generation != 0) {
                        ios_child_transmission_slot_held_ = true;
                        ios_child_transmission_slot_generation_ = ios_child_slot_generation;
                    }
#endif
                    this->connection_ = std::move(connection);
                    return true;
                }

                /**
                 * @brief Parses destination host/port and infers address type.
                 */
                std::shared_ptr<ppp::app::protocol::AddressEndPoint> VEthernetLocalProxyConnection::GetAddressEndPointByProtocol(const ppp::string& host, int port) noexcept {
                    if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid, std::shared_ptr<ppp::app::protocol::AddressEndPoint>(NULLPTR));
                    }

                    if (host.empty()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, std::shared_ptr<ppp::app::protocol::AddressEndPoint>(NULLPTR));
                    }

                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> destinationEP = make_shared_object<ppp::app::protocol::AddressEndPoint>();
                    if (NULLPTR == destinationEP) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, std::shared_ptr<ppp::app::protocol::AddressEndPoint>(NULLPTR));
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(host, ec);

                    if (ec) {
                        ppp::string endpoint = host;
                        ppp::string parsed_host;
                        int parsed_port = port;
                        if (ppp::net::Ipep::ParseEndPoint(endpoint, parsed_host, parsed_port)) {
                            address = StringToAddress(parsed_host, ec);
                            if (!ec && parsed_port > ppp::net::IPEndPoint::MinPort && parsed_port <= ppp::net::IPEndPoint::MaxPort) {
                                port = parsed_port;
                            }
                        }
                    }

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
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, std::shared_ptr<ppp::app::protocol::AddressEndPoint>(NULLPTR));
                    }

                    destinationEP->Host = host;
                    destinationEP->Port = port;
                    return destinationEP;
                }

                /**
                 * @brief Extends connection timeout using linked or connect timeout policy.
                 */
                void VEthernetLocalProxyConnection::Update() noexcept {
                    bool linked = false;
                    if (VirtualEthernetTcpipConnectionPtr connection = connection_; NULLPTR != connection) {
                        linked = connection->IsLinked();
                    }
                    elif(std::shared_ptr<RinetdConnection> connection = connection_rinetd_; NULLPTR != connection) {
                        linked = connection->IsLinked();
                    }
                    elif(std::shared_ptr<vmux::vmux_skt> connection = connection_mux_; NULLPTR != connection) {
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
