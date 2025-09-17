#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/proxies/sniproxy.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

using ppp::app::protocol::VirtualEthernetPacket;
using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;
using ppp::threading::Executors;
using ppp::coroutines::YieldContext;
using ppp::collections::Dictionary;

namespace ppp {
    namespace transmissions {
        typedef ITransmission::AppConfigurationPtr      AppConfigurationPtr;

        bool                                            Transmission_Handshake_Nop(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept;
    }

    namespace app {
        namespace server {
            VirtualEthernetSwitcher::VirtualEthernetSwitcher(const AppConfigurationPtr& configuration) noexcept
                : disposed_(false)
                , configuration_(configuration)
                , context_(Executors::GetDefault())
                , static_echo_socket_(*context_)
                , static_echo_bind_port_(IPEndPoint::MinPort) {
                
                boost::asio::ip::udp::udp::endpoint dnsserverEP = ParseDNSEndPoint(configuration_->udp.dns.redirect);
                dnsserverEP_ = dnsserverEP;

                interfaceIP_ = Ipep::ToAddress(configuration_->ip.interface_, true);
                statistics_ = make_shared_object<ppp::transmissions::ITransmissionStatistics>();

                if (configuration->key.protocol.size() && configuration->key.protocol_key.size() && configuration->key.transport.size() && configuration->key.transport_key.size()) {
                    if (Ciphertext::Support(configuration->key.protocol) && Ciphertext::Support(configuration->key.transport)) {
                        static_echo_protocol_ = make_shared_object<Ciphertext>(configuration->key.protocol, configuration->key.protocol_key);
                        static_echo_transport_ = make_shared_object<Ciphertext>(configuration->key.transport, configuration->key.transport_key);
                    }
                }

                static_echo_buffers_ = ppp::threading::Executors::GetCachedBuffer(context_);
            }

            VirtualEthernetSwitcher::~VirtualEthernetSwitcher() noexcept {
                Finalize();
            }

            bool VirtualEthernetSwitcher::Run() noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                bool bany = false;
                for (int categories = NetworkAcceptorCategories_Min; categories < NetworkAcceptorCategories_Max; categories++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[categories];
                    if (NULL == acceptor) {
                        continue;
                    }

                    bool bok = Socket::AcceptLoopbackAsync(acceptor, 
                        [self, this, acceptor, categories](const Socket::AsioContext& context, const Socket::AsioTcpSocket& socket) noexcept {
                            if (!Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo)) {
                                return false;
                            }

                            ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                            return !disposed_ && Accept(context, socket, categories);
                        });

                    if (bok) {
                        bany = true;
                    }
                    else {
                        Socket::Closesocket(acceptor);
                        acceptors_[categories] = NULL;
                    }
                }
                return bany;
            }

            static constexpr int STATUS_ERROR = -1;
            static constexpr int STATUS_RUNING = +1;
            static constexpr int STATUS_RUNNING_SWAP = +0;

            int VirtualEthernetSwitcher::Run(const ContextPtr& context, const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_) {
                    return STATUS_ERROR;
                }
        
                bool mux = false;
                Int128 session_id = transmission->HandshakeClient(y, mux);
                if (session_id == 0) {
                    return STATUS_ERROR;
                }

                if (!mux) {
                    return Connect(transmission, session_id, y);
                }

                VirtualEthernetManagedServerPtr managed_server = managed_server_;
                if (NULL == managed_server) {
                    return Establish(transmission, session_id, NULL, y) ? STATUS_RUNING : STATUS_ERROR;
                }
                
                VirtualEthernetExchanger* exchanger = GetExchanger(session_id).get(); 
                if (NULL != exchanger) {
                    return Establish(transmission, session_id, NULL, y) ? STATUS_RUNING : STATUS_ERROR;
                }

                auto self = shared_from_this();
                return managed_server->AuthenticationToManagedServer(session_id,
                    [self, this, transmission, session_id, context](bool ok, VirtualEthernetManagedServer::VirtualEthernetInformationPtr& i) noexcept {
                        auto allocator = transmission->BufferAllocator;
                        if (ok) {
                            ok = YieldContext::Spawn(allocator.get(), *context,
                                [self, this, context, transmission, session_id, i](YieldContext& y) noexcept {
                                    if (y) {
                                        Establish(transmission, session_id, i, y);
                                    }

                                    transmission->Dispose();
                                });
                        }

                        if (!ok) {
                            transmission->Dispose();
                        }
                    }) ? STATUS_RUNNING_SWAP : STATUS_ERROR;
            }

            bool VirtualEthernetSwitcher::Accept(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int categories) noexcept {
                if (categories == NetworkAcceptorCategories_CDN1 || categories == NetworkAcceptorCategories_CDN2) {
                    std::shared_ptr<ppp::net::proxies::sniproxy> sniproxy = make_shared_object<ppp::net::proxies::sniproxy>(categories == NetworkAcceptorCategories_CDN1 ? 0 : 1,
                        configuration_,
                        context,
                        socket);
                    if (NULL == sniproxy) {
                        return false;
                    }

                    bool ok = sniproxy->handshake();
                    if (!ok) {
                        sniproxy->close();
                    }

                    return ok;
                }
                else {
                    ITransmissionPtr transmission = Accept(categories, context, socket);
                    if (NULL == transmission) {
                        return false;
                    }

                    auto allocator = transmission->BufferAllocator;
                    auto self = shared_from_this();
                    return YieldContext::Spawn(allocator.get(), *context,
                        [self, this, context, transmission](YieldContext& y) noexcept {
                            int status = Run(context, transmission, y);
                            if (status != STATUS_RUNNING_SWAP) {
                                if (status < STATUS_RUNNING_SWAP) {
                                    FlowerArrangement(
                                        transmission, 
                                        y);
                                }

                                transmission->Dispose();
                            }
                        });
                }
            }

            bool VirtualEthernetSwitcher::FlowerArrangement(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (NULL == transmission) {
                    return false;
                }
                
                return ppp::transmissions::Transmission_Handshake_Nop(configuration_, transmission.get(), y);
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::GetExchanger(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULL;
                }

                return Dictionary::FindObjectByKey(exchangers_, session_id);
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::AddNewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                VirtualEthernetExchangerPtr newExchanger;
                VirtualEthernetExchangerPtr oldExchanger;

                bool ok = false;
                if (NULL != transmission) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return NULL;
                    }

                    newExchanger = NewExchanger(transmission, session_id);
                    if (NULL == newExchanger) {
                        return NULL;
                    }

                    if (newExchanger->Open()) {
                        VirtualEthernetExchangerPtr& tmpExchanger = exchangers_[session_id];
                        ok = true;
                        oldExchanger = tmpExchanger;
                        tmpExchanger = newExchanger;
                    }
                }

                IDisposable::Dispose(oldExchanger);
                if (ok) {
                    return newExchanger;
                }

                IDisposable::Dispose(newExchanger);
                return NULL;
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::NewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }

                auto self = shared_from_this();
                return make_shared_object<VirtualEthernetExchanger>(self, configuration_, transmission, session_id);
            }

            bool VirtualEthernetSwitcher::Establish(const ITransmissionPtr& transmission, const Int128& session_id, const VirtualEthernetInformationPtr& i, YieldContext& y) noexcept {
                if (NULL == transmission) {
                    return false;
                }

                VirtualEthernetExchangerPtr channel = AddNewExchanger(transmission, session_id);
                if (NULL == channel) {
                    return false;
                }

                bool run = true;
                if (NULL != i) {
                    run = channel->DoInformation(transmission, *i, y);
                    if (run) {
                        run = i->Valid();
                    }
                }

                if (run) {
                    VirtualEthernetLoggerPtr logger = GetLogger(); 
                    if (NULL != logger) {
                        logger->Vpn(session_id, transmission);
                    }

                    run = channel->Run(transmission, y);
                }

                DeleteExchanger(channel.get());
                return run;
            }

            VirtualEthernetSwitcher::FirewallPtr VirtualEthernetSwitcher::NewFirewall() noexcept {
                return make_shared_object<Firewall>();
            }

            int VirtualEthernetSwitcher::Connect(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept {
                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                if (y) {
                    VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                    if (NULL == exchanger) {
                        return STATUS_ERROR;
                    }

                    ITransmissionPtr owner = exchanger->GetTransmission();
                    if (NULL != owner) {
                        std::shared_ptr<ITransmissionStatistics> left = owner->Statistics;
                        std::shared_ptr<ITransmissionStatistics> reft = transmission->Statistics;
                        if (left != reft) {
                            if (NULL != reft) {
                                left->IncomingTraffic += reft->IncomingTraffic;
                                left->OutgoingTraffic += reft->OutgoingTraffic;
                            }

                            transmission->Statistics = left;
                        }
                    }
                }

                auto self = shared_from_this();
                auto run =
                    [self, this](const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept {
                        VirtualEthernetNetworkTcpipConnectionPtr connection = AddNewConnection(transmission, session_id);
                        if (NULL == connection) {
                            return -1;
                        }
                        elif(connection->Run(y)) {
                            if (connection->IsMux()) {
                                SynchronizedObjectScope scope(syncobj_);
                                if (Dictionary::RemoveValueByKey(connections_, (void*)connection.get())) {
                                    return 0;
                                }
                                else {
                                    return -1; // The rear check, which is beyond the expected design, is roughly possible that the switch is being released.
                                }
                            }

                            return 1;
                        }
                        else {
                            return -1;
                        }
                    };

                // Transfer the current link to the scheduler for processing, if the transfer succeeds.
                if (transmission->ShiftToScheduler()) {
                    ppp::threading::Executors::ContextPtr scheduler = transmission->GetContext();
                    ppp::threading::Executors::StrandPtr strand = transmission->GetStrand();
                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;

                    return YieldContext::Spawn(allocator.get(), *scheduler, strand.get(),
                        [scheduler, strand, run, transmission, session_id](YieldContext& y) noexcept {
                            int status = run(transmission, session_id, y);
                            if (status != 0) {
                                transmission->Dispose();
                            }
                        }) ? STATUS_RUNNING_SWAP : STATUS_ERROR;
                }
                else {
                    int status = run(transmission, session_id, y);
                    if (status < 0) {
                        return STATUS_ERROR;
                    }
                    elif(status > 0) {
                        return STATUS_RUNING;
                    }
                    else {
                        return STATUS_RUNNING_SWAP;
                    }
                }
            }

            VirtualEthernetSwitcher::VirtualEthernetNetworkTcpipConnectionPtr VirtualEthernetSwitcher::AddNewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                std::shared_ptr<VirtualEthernetNetworkTcpipConnection> connection = NewConnection(transmission, session_id);
                if (NULL == connection) {
                    return NULL;
                }
                else {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return NULL;
                    }

                    if (Dictionary::TryAdd(connections_, connection.get(), connection)) {
                        return connection;
                    }
                }

                connection->Dispose();
                return NULL;
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::DeleteExchanger(VirtualEthernetExchanger* exchanger) noexcept {
                VirtualEthernetExchangerPtr channel;
                if (NULL != exchanger) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (auto tail = exchangers_.find(exchanger->GetId()); tail != exchangers_.end()) {
                        const VirtualEthernetExchangerPtr& p = tail->second;
                        if (p.get() == exchanger) {
                            channel = std::move(tail->second);
                            exchangers_.erase(tail);
                        }
                    }
                }

                if (channel) {
                    channel->Dispose();
                }
                return channel;
            }

            VirtualEthernetSwitcher::VirtualEthernetNetworkTcpipConnectionPtr VirtualEthernetSwitcher::NewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }

                std::shared_ptr<VirtualEthernetSwitcher> self = shared_from_this();
                return make_shared_object<VirtualEthernetNetworkTcpipConnection>(self, session_id, transmission);
            }

            VirtualEthernetSwitcher::VirtualEthernetLoggerPtr VirtualEthernetSwitcher::NewLogger() noexcept {
                ppp::string& log = configuration_->server.log;
                if (log.empty()) {
                    return NULL;
                }

                VirtualEthernetLoggerPtr logger = make_shared_object<VirtualEthernetLogger>(context_, log);
                if (NULL == logger) {
                    return NULL;
                }

                if (logger->Valid()) {
                    return logger;
                }

                IDisposable::Dispose(logger);
                return NULL;
            }

            bool VirtualEthernetSwitcher::CreateAllAcceptors() noexcept {
                if (disposed_) {
                    return false;
                }

                int acceptor_ports[NetworkAcceptorCategories_Max];
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[i];
                    if (NULL != acceptor) {
                        return false;
                    }

                    acceptor_ports[i] = IPEndPoint::MinPort;
                }

                boost::asio::ip::address interface_ips[] = { GetInterfaceIP(), boost::asio::ip::address_v6::any(), boost::asio::ip::address_v4::any() };
                acceptor_ports[NetworkAcceptorCategories_Tcpip] = configuration_->tcp.listen.port;
                acceptor_ports[NetworkAcceptorCategories_WebSocket] = configuration_->websocket.listen.ws;
                acceptor_ports[NetworkAcceptorCategories_WebSocketSSL] = configuration_->websocket.listen.wss;
                acceptor_ports[NetworkAcceptorCategories_CDN1] = configuration_->cdn[0];
                acceptor_ports[NetworkAcceptorCategories_CDN2] = configuration_->cdn[1];

                bool bany = false;
                auto& cfg = configuration_->tcp;
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    int port = acceptor_ports[i];
                    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                        continue;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(*context_);
                    if (NULL == acceptor) {
                        return false;
                    }

                    for (boost::asio::ip::address& interface_ip : interface_ips) {
                        if (Socket::OpenAcceptor(*acceptor, interface_ip, port, cfg.backlog, cfg.fast_open, cfg.turbo)) {
                            Socket::SetWindowSizeIfNotZero(acceptor->native_handle(), cfg.cwnd, cfg.rwnd);
                            bany |= true;
                            acceptors_[i] = std::move(acceptor);
                            break;
                        }
                        elif(!Socket::Closesocket(*acceptor)) {
                            return false;
                        }
                    }
                }
                return bany;
            }

            bool VirtualEthernetSwitcher::Open(const ppp::string& firewall_rules) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }

                if (timeout_) {
                    return false;
                }

                bool ok = CreateAllAcceptors() &&
                    CreateAlwaysTimeout() &&
                    CreateFirewall(firewall_rules) &&
                    OpenManagedServerIfNeed() &&
                    OpenNamespaceCacheIfNeed() &&
                    OpenDatagramSocket();
                if (ok) {
                    OpenLogger();
                }

                return ok;
            }

            bool VirtualEthernetSwitcher::OpenNamespaceCacheIfNeed() noexcept {
                int ttl = configuration_->udp.dns.ttl;
                if (ttl > 0) {
                    VirtualEthernetNamespaceCachePtr cache = NewNamespaceCache(ttl);
                    if (NULL == cache) {
                        return false;
                    }

                    namespace_cache_ = std::move(cache);
                }

                return true;
            }

            bool VirtualEthernetSwitcher::OpenLogger() noexcept {
                VirtualEthernetLoggerPtr logger = NewLogger();
                if (NULL == logger) {
                    return false;
                }

                logger_ = std::move(logger);
                return true;
            }

            bool VirtualEthernetSwitcher::OpenDatagramSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                int bind_port = configuration_->udp.listen.port;
                if (bind_port <= IPEndPoint::MinPort || bind_port > IPEndPoint::MaxPort) {
                    return true;
                }

                boost::asio::ip::address interface_ip = GetInterfaceIP();
                boost::asio::ip::udp::endpoint bind_endpoint(interface_ip, bind_port);

                bool ok = VirtualEthernetPacket::OpenDatagramSocket(static_echo_socket_, interface_ip, bind_port, bind_endpoint);
                if (!ok) {
                    return false;
                }
                else {
                    ppp::net::Socket::SetWindowSizeIfNotZero(static_echo_socket_.native_handle(), configuration_->udp.cwnd, configuration_->udp.rwnd);
                }

                boost::system::error_code ec;
                boost::asio::ip::udp::endpoint localEP = static_echo_socket_.local_endpoint(ec);
                if (ec) {
                    return false;
                }

                static_echo_bind_port_ = localEP.port();
                return LoopbackDatagramSocket();
            }

            bool VirtualEthernetSwitcher::LoopbackDatagramSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                bool opened = static_echo_socket_.is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                static_echo_socket_.async_receive_from(boost::asio::buffer(static_echo_buffers_.get(), PPP_BUFFER_SIZE), static_echo_source_ep_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::operation_canceled) {
                            return false;
                        }

                        if (disposed_) {
                            return false;
                        }

                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration_->GetBufferAllocator();
                                std::shared_ptr<VirtualEthernetPacket> packet = 
                                    VirtualEthernetPacket::Unpack(configuration_, allocator, static_echo_protocol_, static_echo_transport_, static_echo_buffers_.get(), sz);
                                if (NULL != packet) {
                                    StaticEchoPacketInput(allocator, packet, sz, static_echo_source_ep_);
                                }
                            }
                        }
                        
                        return LoopbackDatagramSocket();
                    });
                return true;
            }

            bool VirtualEthernetSwitcher::StaticEchoPacketInput(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                VirtualEthernetExchangerPtr exchanger;
                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP || packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    Int128 guid;
                    if (!StaticEchoQuery(packet->Id, guid)) {
                        return false;
                    }

                    SynchronizedObjectScope scope(syncobj_);
                    if (!ppp::collections::Dictionary::TryGetValue(exchangers_, guid, exchanger)) {
                        return false;
                    }
                }
                else {
                    return false;
                }

                auto statistics = exchanger->GetStatistics(); 
                if (NULL != statistics) {
                    statistics->AddIncomingTraffic(packet_length);
                }

                exchanger->static_echo_source_ep_ = sourceEP;
                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    return exchanger->StaticEchoSendToDestination(packet);
                }
                elif(packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    return exchanger->StaticEchoEchoToDestination(packet, sourceEP);
                }
                else {
                    return true;
                }
            }

            Int128 VirtualEthernetSwitcher::StaticEchoUnallocated(int allocated_id) noexcept {
                if (allocated_id < 1) {
                    return false;
                }

                Int128 session_id;
                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::TryRemove(static_echo_allocateds_, allocated_id, session_id) ? session_id : 0;
            }

            bool VirtualEthernetSwitcher::StaticEchoQuery(int allocated_id, Int128& session_id) noexcept {
                session_id = 0;
                if (allocated_id < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::TryGetValue(static_echo_allocateds_, allocated_id, session_id);
            }

            bool VirtualEthernetSwitcher::StaticEchoAllocated(Int128 session_id, int& allocated_id, int& remote_port) noexcept {
                remote_port = IPEndPoint::MinPort;
                if (session_id == 0) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                int bind_port = static_echo_bind_port_;
                if (bind_port <= IPEndPoint::MinPort || bind_port > IPEndPoint::MaxPort) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (allocated_id != 0) {
                    if (!Dictionary::ContainsKey(static_echo_allocateds_, allocated_id)) {
                        return false;
                    }

                    remote_port = bind_port;
                    return true;
                }
                
                for (int i = ppp::net::IPEndPoint::MinPort; i < ppp::net::IPEndPoint::MaxPort; i++) {
                    int generate_id = VirtualEthernetPacket::NewId();
                    if (generate_id < 1) {
                        continue;
                    }

                    if (Dictionary::ContainsKey(static_echo_allocateds_, generate_id)) {
                        continue;
                    }

                    bool ok = Dictionary::TryAdd(static_echo_allocateds_, generate_id, session_id);
                    if (ok) {
                        remote_port  = bind_port;
                        allocated_id = generate_id;
                    }

                    return ok;
                }

                return false;
            }

            bool VirtualEthernetSwitcher::OpenManagedServerIfNeed() noexcept {
                if (configuration_->server.node < 1 || configuration_->server.backend.empty()) {
                    return true;
                }

                if (disposed_) {
                    return false;
                }

                VirtualEthernetManagedServerPtr server = NewManagedServer();
                if (NULL == server) {
                    return false;
                }

                auto self = shared_from_this();
                return server->TryVerifyUriAsync(configuration_->server.backend,
                    [self, this, server](bool ok) noexcept {
                        if (ok) {
                            SynchronizedObjectScope scope(syncobj_);
                            ok = false;
                            if (!disposed_) {
                                ok = server->ConnectToManagedServer(configuration_->server.backend);
                                if (ok) {
                                    managed_server_ = server;
                                }
                            }
                        }

                        if (!ok) {
                            server->Dispose();
                        }
                    });
            }

            VirtualEthernetSwitcher::ITransmissionPtr VirtualEthernetSwitcher::Accept(int categories, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                if (NULL == context || NULL == socket) {
                    return NULL;
                }

                std::shared_ptr<ppp::transmissions::ITransmission> transmission;
                if (categories == NetworkAcceptorCategories_Tcpip) {
                    ppp::threading::Executors::StrandPtr strand;
                    transmission = make_shared_object<ppp::transmissions::ITcpipTransmission>(context, strand, socket, configuration_);
                }
                elif(categories == NetworkAcceptorCategories_WebSocket) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::IWebsocketTransmission>(context, socket);
                }
                elif(categories == NetworkAcceptorCategories_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::ISslWebsocketTransmission>(context, socket);
                }

                if (NULL == transmission) {
                    return NULL;
                }

                transmission->Statistics = NewStatistics();
                return transmission;
            }

            void VirtualEthernetSwitcher::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            bool VirtualEthernetSwitcher::IsDisposed() noexcept {
                return disposed_;
            }

            VirtualEthernetSwitcher::VirtualEthernetNamespaceCachePtr VirtualEthernetSwitcher::NewNamespaceCache(int ttl) noexcept {
                if (ttl < 1) {
                    return NULL;
                }

                return make_shared_object<VirtualEthernetNamespaceCache>(ttl);
            }
            
            VirtualEthernetSwitcher::ITransmissionStatisticsPtr VirtualEthernetSwitcher::NewStatistics() noexcept {
                class NetworkStatistics final : public ppp::transmissions::ITransmissionStatistics {
                public:
                    NetworkStatistics(const ITransmissionStatisticsPtr& owner) noexcept
                        : ITransmissionStatistics()
                        , owner_(owner) {

                    }

                public:
                    virtual uint64_t                                    AddIncomingTraffic(uint64_t incoming_traffic) noexcept {
                        owner_->AddIncomingTraffic(incoming_traffic);
                        return ITransmissionStatistics::AddIncomingTraffic(incoming_traffic);
                    }
                    virtual uint64_t                                    AddOutgoingTraffic(uint64_t outcoming_traffic) noexcept {
                        owner_->AddOutgoingTraffic(outcoming_traffic);
                        return ITransmissionStatistics::AddOutgoingTraffic(outcoming_traffic);
                    }

                private:
                    ITransmissionStatisticsPtr                          owner_;
                };

                VirtualEthernetManagedServerPtr server = managed_server_;
                if (NULL == server) {
                    return statistics_;
                }
                else {
                    return make_shared_object<NetworkStatistics>(statistics_);
                }
            }

            VirtualEthernetSwitcher::VirtualEthernetManagedServerPtr VirtualEthernetSwitcher::NewManagedServer() noexcept {
                std::shared_ptr<VirtualEthernetSwitcher> self = shared_from_this();
                return make_shared_object<VirtualEthernetManagedServer>(self);
            }

            template <typename TProtocol>
            static bool CancelAllResolver(std::shared_ptr<boost::asio::ip::basic_resolver<TProtocol>>& resolver) noexcept {
                std::shared_ptr<boost::asio::ip::basic_resolver<TProtocol>> i = std::move(resolver);
                if (NULL == i) {
                    return false;
                }

                boost::asio::post(i->get_executor(),
                    [i]() noexcept {
                        ppp::net::Socket::Cancel(*i);
                    });
                return true;
            }

            void VirtualEthernetSwitcher::Finalize() noexcept {
                std::shared_ptr<boost::asio::ip::tcp::resolver> tresolver;
                std::shared_ptr<boost::asio::ip::udp::resolver> uresolver;

                VirtualEthernetNamespaceCachePtr cache;
                NatInformationTable nats;
                VirtualEthernetLoggerPtr logger;
                VirtualEthernetExchangerTable exchangers;
                VirtualEthernetNetworkTcpipConnectionTable connections;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    CloseAllAcceptors();

                    cache = std::move(namespace_cache_);
                    namespace_cache_.reset();

                    nats = std::move(nats_);
                    nats_.clear();

                    logger = std::move(logger_);
                    logger_.reset();

                    exchangers = std::move(exchangers_);
                    exchangers_.clear();

                    connections = std::move(connections_);
                    connections_.clear();

                    static_echo_allocateds_.clear();
                    break;
                }

                disposed_ = true;
                CloseAlwaysTimeout();

                CancelAllResolver(tresolver);
                CancelAllResolver(uresolver);

                Dictionary::ReleaseAllObjects(exchangers);
                Dictionary::ReleaseAllObjects(connections);

                if (NULL != cache) {
                    cache->Clear();
                }
                
                if (NULL != logger) {
                    IDisposable::Dispose(logger);
                }
            }

            void VirtualEthernetSwitcher::CloseAllAcceptors() noexcept {
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = std::move(acceptors_[i]);
                    if (NULL == acceptor) {
                        continue;
                    }

                    Socket::Closesocket(acceptor);
                    if (NULL != acceptor) {
                        acceptors_[i] = NULL;
                    }
                }
            }

            bool VirtualEthernetSwitcher::CloseAlwaysTimeout() noexcept {
                TimerPtr timeout = std::move(timeout_);
                timeout_.reset();
                
                if (timeout) {
                    timeout->Dispose();
                    return true;
                }
                else {
                    return false;
                }
            }

            bool VirtualEthernetSwitcher::CreateFirewall(const ppp::string& firewall_rules) noexcept {
                if (disposed_) {
                    return false;
                }

                FirewallPtr firewall = NewFirewall();
                if (NULL == firewall) {
                    return false;
                }

                firewall_ = firewall;
                firewall->LoadWithFile(firewall_rules);
                return true;
            }

            bool VirtualEthernetSwitcher::CreateAlwaysTimeout() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<Timer> timeout = make_shared_object<Timer>(context_);
                if (!timeout) {
                    return false;
                }

                auto self = shared_from_this();
                timeout->TickEvent = 
                    [self, this](Timer* sender, Timer::TickEventArgs& e) noexcept {
                        UInt64 now = Executors::GetTickCount();
                        OnTick(now);
                    };

                bool ok = timeout->SetInterval(1000) && timeout->Start();
                if (ok) {
                    timeout_ = timeout;
                    return true;
                }
                
                timeout->Dispose();
                return false;
            }

            void VirtualEthernetSwitcher::TickAllExchangers(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                ppp::collections::Dictionary::UpdateAllObjects2(exchangers_, now);
            }

            void VirtualEthernetSwitcher::TickAllConnections(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                Dictionary::UpdateAllObjects(connections_, now);
            }

            bool VirtualEthernetSwitcher::OnTick(UInt64 now) noexcept {
                if (disposed_) {
                    return false;
                }

                TickAllExchangers(now);
                TickAllConnections(now);

                VirtualEthernetNamespaceCachePtr cache = namespace_cache_;
                if (NULL != cache) {
                    cache->Update();
                }

                VirtualEthernetManagedServerPtr server = managed_server_; 
                if (NULL != server) {
                    server->Update(now);
                }

                return true;
            }

            bool VirtualEthernetSwitcher::OnInformation(const Int128& session_id, const std::shared_ptr<VirtualEthernetInformation>& info, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                if (NULL == exchanger) {
                    return false;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULL == transmission) {
                    return false;
                }

                bool bok = false;
                if (NULL != info) {
                    bok = exchanger->DoInformation(transmission, *info, y);
                    if (bok) {
                        bok = info->Valid();
                    }
                }

                if (!bok) {
                    transmission->Dispose();
                }
                
                return bok;
            }

            bool VirtualEthernetSwitcher::DeleteConnection(const VirtualEthernetNetworkTcpipConnection* connection) noexcept {
                VirtualEthernetNetworkTcpipConnectionPtr ntcp;
                if (connection) {
                    SynchronizedObjectScope scope(syncobj_);
                    Dictionary::RemoveValueByKey(connections_, (void*)connection, &ntcp);
                }

                if (ntcp) {
                    ntcp->Dispose();
                    return true;
                }

                return false;
            }

            boost::asio::ip::udp::endpoint VirtualEthernetSwitcher::ParseDNSEndPoint(const ppp::string& dnserver_endpoint) noexcept {
                boost::asio::ip::address dnsserverIP = boost::asio::ip::address_v4::any();
                int dnsserverPort = PPP_DNS_SYS_PORT;
                if (dnserver_endpoint.empty()) {
                    return boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                }

                boost::asio::ip::udp::udp::endpoint dnsserverEP = Ipep::ParseEndPoint(dnserver_endpoint);
                dnsserverPort = dnsserverEP.port();
                if (dnsserverPort <= IPEndPoint::MinPort || dnsserverPort > IPEndPoint::MaxPort) {
                    dnsserverPort = PPP_DNS_SYS_PORT;
                }

                dnsserverIP = dnsserverEP.address();
                dnsserverEP = boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                if (IPEndPoint::IsInvalid(dnsserverEP.address())) {
                    dnsserverIP = boost::asio::ip::address_v4::any();
                }
                elif(dnsserverIP.is_multicast()) {
                    dnsserverIP = boost::asio::ip::address_v4::any();
                }

                dnsserverEP = boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                return dnsserverEP;
            }

            boost::asio::ip::tcp::endpoint VirtualEthernetSwitcher::GetLocalEndPoint(NetworkAcceptorCategories categories) noexcept {
                boost::system::error_code ec;
                if (categories == NetworkAcceptorCategories_Udpip) {
                    if (static_echo_socket_.is_open()) {
                        boost::asio::ip::udp::endpoint localEP = static_echo_socket_.local_endpoint(ec);
                        if (ec == boost::system::errc::success) {
                            return boost::asio::ip::tcp::endpoint(localEP.address(), localEP.port());
                        }
                    }
                }
                elif(categories >= NetworkAcceptorCategories_Min && categories < NetworkAcceptorCategories_Max) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[categories];
                    if (NULL != acceptor) {
                        if (acceptor->is_open()) {
                            boost::asio::ip::tcp::endpoint localEP = acceptor->local_endpoint(ec);
                            if (ec == boost::system::errc::success) {
                                return localEP;
                            }
                        }
                    }
                }

                return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint::Any(IPEndPoint::MinPort));
            }

            VirtualEthernetSwitcher::NatInformationPtr VirtualEthernetSwitcher::FindNatInformation(uint32_t ip) noexcept {
                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return NULL;
                }

                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::FindObjectByKey(nats_, ip);
            }

            VirtualEthernetSwitcher::NatInformationPtr VirtualEthernetSwitcher::AddNatInformation(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, uint32_t ip, uint32_t mask) noexcept {
                if (IPEndPoint::IsInvalid(IPEndPoint(mask, IPEndPoint::MinPort))) {
                    return NULL;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return NULL;
                }

                if (exchanger->IsDisposed()) {
                    return NULL;
                }

                // Creating a nat information entry mapping does not mean that the mapping will be added to the nats.
                NatInformationPtr nat = make_shared_object<NatInformation>();
                if (NULL == nat) {
                    return NULL;
                }

                nat->Exchanger = exchanger;
                nat->IPAddress = ip;
                nat->SubmaskAddress = mask;

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULL;
                }

                // If ip addresses conflict, do not directly conflict like traditional routers, 
                // And abandon the mapping between IP and Ethernet electrical ports.
                auto kv = nats_.emplace(ip, nat);
                if (kv.second) {
                    return nat;
                }

                NatInformationTable::iterator tail = kv.first;
                NatInformationTable::iterator endl = nats_.end();
                if (tail == endl) {
                    return NULL;
                }

                NatInformationPtr& raw = tail->second;
                std::shared_ptr<VirtualEthernetExchanger>& raw_exchanger = raw->Exchanger;
                if (raw_exchanger->IsDisposed()) {
                    raw = nat;
                    return nat;
                }
                else {
                    return NULL;
                }
            }

            bool VirtualEthernetSwitcher::DeleteNatInformation(VirtualEthernetExchanger* key, uint32_t ip) noexcept {
                if (NULL == key) {
                    return false;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }

                NatInformationTable::iterator tail = nats_.find(ip);
                NatInformationTable::iterator endl = nats_.end();
                if (tail == endl) {
                    return false;
                }

                NatInformationPtr& nat = tail->second;
                std::shared_ptr<VirtualEthernetExchanger>& exchanger = nat->Exchanger;
                if (key != exchanger.get()) {
                    return false;
                }

                nats_.erase(tail);
                return true;
            }

            int VirtualEthernetSwitcher::GetAllExchangerNumber() noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return static_cast<int>(exchangers_.size());
            }
        }
    }
}