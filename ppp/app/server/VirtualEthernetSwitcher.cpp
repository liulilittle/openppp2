#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/proxies/sniproxy.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;
using ppp::threading::Executors;
using ppp::coroutines::YieldContext;
using ppp::collections::Dictionary;

namespace ppp {
    namespace app {
        namespace server {
            VirtualEthernetSwitcher::VirtualEthernetSwitcher(const AppConfigurationPtr& configuration) noexcept
                : disposed_(false)
                , configuration_(configuration)
                , context_(Executors::GetDefault()) {
                boost::asio::ip::udp::udp::endpoint dnsserverEP = ParseDNSEndPoint(configuration_->udp.dns.redirect);
                dnsserverEP_ = dnsserverEP;
                interfaceIP_ = Ipep::ToAddress(configuration_->ip.interface_, true);
                statistics_ = make_shared_object<ppp::transmissions::ITransmissionStatistics>();
            }

            VirtualEthernetSwitcher::~VirtualEthernetSwitcher() noexcept {
                Finalize();
            }

            int VirtualEthernetSwitcher::GetNode() noexcept {
                return configuration_->server.node;
            }

            boost::asio::ip::address VirtualEthernetSwitcher::GetInterfaceIP() noexcept {
                return interfaceIP_;
            }

            boost::asio::ip::udp::endpoint VirtualEthernetSwitcher::GetDnsserverEndPoint() noexcept {
                return dnsserverEP_;
            }

            VirtualEthernetSwitcher::AppConfigurationPtr VirtualEthernetSwitcher::GetConfiguration() noexcept {
                return configuration_;
            }

            std::shared_ptr<VirtualEthernetSwitcher> VirtualEthernetSwitcher::GetReference() noexcept {
                return shared_from_this();
            }

            VirtualEthernetSwitcher::FirewallPtr VirtualEthernetSwitcher::GetFirewall() noexcept {
                return firewall_;
            }

            VirtualEthernetSwitcher::ContextPtr VirtualEthernetSwitcher::GetContext() noexcept {
                return context_;
            }

            VirtualEthernetSwitcher::VirtualEthernetManagedServerPtr VirtualEthernetSwitcher::GetManagedServer() noexcept {
                return server_;
            }

            VirtualEthernetSwitcher::SynchronizedObject& VirtualEthernetSwitcher::GetSynchronizedObject() noexcept {
                return syncobj_;
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

                    bool b = Socket::AcceptLoopbackAsync(acceptor,
                        make_shared_object<Socket::AcceptLoopbackCallback>(
                            [self, this, acceptor, categories](const Socket::AsioContext& context, const Socket::AsioTcpSocket& socket) noexcept {
                                return !disposed_ && Accept(context, socket, categories);
                            }));
                    if (b) {
                        bany = true;
                    }
                    else {
                        Socket::Closesocket(acceptor);
                        acceptors_[categories] = NULL;
                    }
                }
                return bany;
            }

            bool VirtualEthernetSwitcher::Accept(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int categories) noexcept {
                if (categories == NetworkAcceptorCategories_CDN1 || categories == NetworkAcceptorCategories_CDN2) {
                    auto sniproxy = make_shared_object<ppp::net::proxies::sniproxy>(categories == NetworkAcceptorCategories_CDN1 ? 0 : 1,
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
                        [self, this, transmission, context](YieldContext& y) noexcept {
                            bool bok = false;
                            if (disposed_) {
                                transmission->Dispose();
                                return bok;
                            }

                            bool mux = false;
                            Int128 session_id = transmission->HandshakeClient(y, mux);
                            if (session_id) {
                                if (mux) {
                                    VirtualEthernetManagedServerPtr server = server_;
                                    if (NULL == server) {
                                        bok = Establish(transmission, session_id, NULL, y);
                                    }
                                    elif(VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id); NULL != exchanger) {
                                        bok = Establish(transmission, session_id, NULL, y);
                                    }
                                    else {
                                        bok = server->AuthenticationToManagedServer(session_id,
                                            [self, this, transmission, session_id, context](bool bok, VirtualEthernetManagedServer::VirtualEthernetInformationPtr& i) noexcept {
                                                if (bok) {
                                                    bok = YieldContext::Spawn(*context,
                                                        [self, this, transmission, session_id, i](YieldContext& y) noexcept {
                                                            if (y) {
                                                                Establish(transmission, session_id, i, y);
                                                            }

                                                            transmission->Dispose();
                                                        });
                                                }

                                                if (!bok) {
                                                    transmission->Dispose();
                                                }
                                            });

                                        if (bok) {
                                            return bok;
                                        }
                                    }
                                }
                                else {
                                    bok = Connect(transmission, session_id, y);
                                }
                            }

                            transmission->Dispose();
                            return bok;
                        });
                }
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::GetExchanger(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULL;
                }

                return Dictionary::FindObjectByKey(exchangers_, session_id);
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::AddNewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                VirtualEthernetExchangerPtr channel;
                if (NULL != transmission) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return NULL;
                    }

                    channel = Dictionary::FindObjectByKey(exchangers_, session_id);
                    if (NULL == channel) {
                        channel = NewExchanger(transmission, session_id);
                        if (NULL == channel) {
                            return NULL;
                        }

                        if (channel->Open()) {
                            auto r = exchangers_.emplace(session_id, channel);
                            if (r.second) {
                                return channel;
                            }
                        }
                    }
                }

                if (NULL != channel) {
                    channel->Dispose();
                }
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

                bool bok = channel->Open();
                if (bok && NULL != i) {
                    bok = channel->DoInformation(transmission, *i, y);
                }

                if (bok) {
                    bok = channel->Run(transmission, y);
                }

                DeleteExchanger(channel.get());
                return bok;
            }

            VirtualEthernetSwitcher::FirewallPtr VirtualEthernetSwitcher::NewFirewall() noexcept {
                return make_shared_object<Firewall>();
            }

            bool VirtualEthernetSwitcher::Connect(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept {
                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                if (y) {
                    VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                    if (NULL == exchanger) {
                        return false;
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

                VirtualEthernetNetworkTcpipConnectionPtr connection = AddNewConnection(transmission, session_id);
                if (NULL == connection) {
                    return false;
                }

                bool ok = connection->Run(y);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
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

                    auto r = connections_.emplace(connection.get(), connection);
                    if (r.second) {
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
                    auto tail = exchangers_.find(exchanger->GetId());
                    auto endl = exchangers_.end();
                    if (tail != endl) {
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

            bool VirtualEthernetSwitcher::CreateAllAcceptors() noexcept {
                int acceptor_ports[NetworkAcceptorCategories_Max];
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[i];
                    if (NULL != acceptor) {
                        return false;
                    }

                    acceptor_ports[i] = IPEndPoint::MinPort;
                }

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

                    boost::asio::ip::address bind_ips[] = {
                            interfaceIP_,
                            boost::asio::ip::address_v6::any(),
                            boost::asio::ip::address_v4::any()
                    };
                    for (boost::asio::ip::address& bind_ip : bind_ips) {
                        bool opened = Socket::OpenAcceptor(*acceptor, bind_ip, port, cfg.backlog, cfg.fast_open, cfg.turbo);
                        if (!opened) {
                            boost::system::error_code ec;
                            acceptor->close(ec);

                            if (ec) {
                                return false;
                            }
                        }
                        else {
                            bany |= true;
                            acceptors_[i] = std::move(acceptor);
                            break;
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
                    OpenManagedServerIfNeed();
                return ok;
            }

            bool VirtualEthernetSwitcher::OpenManagedServerIfNeed() noexcept {
                if (configuration_->server.node < 1 || configuration_->server.backend.empty()) {
                    return true;
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
                                    server_ = server;
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
                    transmission = make_shared_object<ppp::transmissions::ITcpipTransmission>(context, socket, configuration_);
                }
                elif(categories == NetworkAcceptorCategories_WebSocket) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::IWebsocketTransmission>(context, socket);
                }
                elif(categories == NetworkAcceptorCategories_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::ISslWebsocketTransmission>(context, socket);
                }

                if (NULL != transmission) {
                    transmission->Statistics = NewStatistics();
                }
                return transmission;
            }

            void VirtualEthernetSwitcher::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(std::bind(&VirtualEthernetSwitcher::Finalize, self));
            }

            bool VirtualEthernetSwitcher::IsDisposed() noexcept {
                return disposed_;
            }

            VirtualEthernetSwitcher::ITransmissionStatisticsPtr& VirtualEthernetSwitcher::GetStatistics() noexcept {
                return statistics_;
            }

            VirtualEthernetSwitcher::ITransmissionStatisticsPtr VirtualEthernetSwitcher::NewStatistics() noexcept {
                class NetworkStatistics : public ppp::transmissions::ITransmissionStatistics {
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

                VirtualEthernetManagedServerPtr server = server_;
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

            void VirtualEthernetSwitcher::Finalize() noexcept {
                exchangeof(disposed_, true); {
                    VirtualEthernetExchangerTable exchangers;
                    VirtualEthernetNetworkTcpipConnectionTable connections; {
                        SynchronizedObjectScope scope(syncobj_);
                        CloseAllAcceptors();

                        exchangers = std::move(exchangers_);
                        exchangers_.clear();

                        connections = std::move(connections_);
                        connections_.clear();
                    }

                    Dictionary::ReleaseAllObjects(exchangers);
                    Dictionary::ReleaseAllObjects(connections);
                }

                CloseAlwaysTimeout();
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
                if (timeout) {
                    timeout_.reset();
                    timeout->Dispose();
                    return true;
                }
                else {
                    return false;
                }
            }

            bool VirtualEthernetSwitcher::CreateFirewall(const ppp::string& firewall_rules) noexcept {
                FirewallPtr firewall = NewFirewall();
                if (NULL == firewall) {
                    return false;
                }

                firewall_ = firewall;
                firewall->LoadWithFile(firewall_rules);
                return true;
            }

            bool VirtualEthernetSwitcher::CreateAlwaysTimeout() noexcept {
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULL == context) {
                    return false;
                }

                auto timeout = make_shared_object<Timer>(context);
                if (!timeout) {
                    return false;
                }

                auto self = shared_from_this();
                timeout->TickEvent = make_shared_object<Timer::TickEventHandler>(
                    [self, this](Timer* sender, Timer::TickEventArgs& e) noexcept {
                        UInt64 now = Executors::GetTickCount();
                        OnTick(now);
                    });

                bool ok = timeout->SetInterval(1000) && timeout->Start();
                if (ok) {
                    timeout_ = timeout;
                    return true;
                }
                else {
                    timeout->Dispose();
                    return false;
                }
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

                if (VirtualEthernetManagedServerPtr server = server_; NULL != server) {
                    server->Update(now);
                }
                return true;
            }

            bool VirtualEthernetSwitcher::OnInformation(const Int128& session_id, const std::shared_ptr<VirtualEthernetInformation>& info) noexcept {
                return false;
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
                int dnsserverPort = PPP_DNS_DEFAULT_PORT;
                if (dnserver_endpoint.empty()) {
                    return boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                }

                boost::asio::ip::udp::udp::endpoint dnsserverEP = Ipep::ParseEndPoint(dnserver_endpoint);
                dnsserverPort = dnsserverEP.port();
                if (dnsserverPort <= IPEndPoint::MinPort || dnsserverPort > IPEndPoint::MaxPort) {
                    dnsserverPort = PPP_DNS_DEFAULT_PORT;
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
                if (categories >= NetworkAcceptorCategories_Min && categories < NetworkAcceptorCategories_Max) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[categories];
                    if (NULL != acceptor) {
                        if (acceptor->is_open()) {
                            boost::system::error_code ec;
                            boost::asio::ip::tcp::endpoint localEP = acceptor->local_endpoint(ec);
                            if (ec == boost::system::errc::success) {
                                return localEP;
                            }
                        }
                    }
                }
                return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint::Any(IPEndPoint::MinPort));
            }
        }
    }
}