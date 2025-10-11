#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>

#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>

#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                VEthernetLocalProxySwitcher::VEthernetLocalProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept
                    : disposed_(false)
                    , exchanger_(exchanger)
                    , context_(ppp::threading::Executors::GetDefault())
                    , configuration_(exchanger->GetConfiguration()) {

                }

                VEthernetLocalProxySwitcher::~VEthernetLocalProxySwitcher() noexcept {
                    Finalize();
                }

                void VEthernetLocalProxySwitcher::Finalize() noexcept {
                    VEthernetLocalProxyConnectionTable connections;
                    for (;;) {
                        SynchronizedObjectScope scope(syncobj_);
                        connections = std::move(connections_);
                        connections_.clear();
                        break;
                    }

                    std::shared_ptr<ppp::threading::Timer> timeout = std::move(timeout_); 
                    timeout_.reset();

                    std::shared_ptr<ppp::net::SocketAcceptor> acceptor = std::move(acceptor_); 
                    acceptor_.reset();

                    if (NULL != timeout) {
                        timeout->Dispose();
                    }

                    if (NULL != acceptor) {
                        acceptor->Dispose();
                    }

                    disposed_ = true;
                    ppp::collections::Dictionary::ReleaseAllObjects(connections);
                }

                void VEthernetLocalProxySwitcher::Update(UInt64 now) noexcept {
                    SynchronizedObjectScope scope(syncobj_);
                    ppp::collections::Dictionary::UpdateAllObjects(connections_, now);
                }

                void VEthernetLocalProxySwitcher::Dispose() noexcept {
                    auto self = shared_from_this();
                    boost::asio::post(*context_, 
                        [self, this]() noexcept {
                            Finalize();
                        });
                }

                bool VEthernetLocalProxySwitcher::Open() noexcept {
                    using NetworkState = VEthernetExchanger::NetworkState;

                    if (NULL != acceptor_) {
                        return false;
                    }

                    std::shared_ptr<ppp::net::SocketAcceptor> acceptor;
                    if (disposed_) {
                        return false;
                    }
                    else {
                        int bind_port = configuration_->client.http_proxy.port;
                        boost::asio::ip::address bind_ips[] = {
                                MyLocalEndPoint(bind_port),
                                boost::asio::ip::address_v6::any(),
                                boost::asio::ip::address_v4::any()
                            };
                        if (bind_port <= ppp::net::IPEndPoint::MinPort || bind_port > ppp::net::IPEndPoint::MaxPort) {
                            return false;
                        }

                        for (boost::asio::ip::address& interfaceIP : bind_ips) {
                            if (interfaceIP.is_multicast()) {
                                continue;
                            }

                            bool bip = interfaceIP.is_v4() || interfaceIP.is_v6();
                            if (!bip) {
                                continue;
                            }

                            if (!interfaceIP.is_unspecified() && ppp::net::IPEndPoint::IsInvalid(interfaceIP)) {
                                continue;
                            }

                            std::shared_ptr<ppp::net::SocketAcceptor> t = ppp::net::SocketAcceptor::New();
                            if (NULL == t) {
                                return false;
                            }

                            ppp::string address_string = ppp::net::Ipep::ToAddressString<ppp::string>(interfaceIP);
                            if (!t->Open(address_string.data(), bind_port, configuration_->tcp.backlog)) {
                                continue;
                            }

                            acceptor = std::move(t);
                            break;
                        }

                        if (NULL == acceptor) {
                            return false;
                        }
                    }

                    int sockfd = acceptor->GetHandle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(sockfd, false);
                    ppp::net::Socket::SetTypeOfService(sockfd);
                    ppp::net::Socket::SetSignalPipeline(sockfd, false);
                    ppp::net::Socket::SetWindowSizeIfNotZero(sockfd, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                    auto self = shared_from_this();
                    acceptor->AcceptSocket = 
                        [self, this](ppp::net::SocketAcceptor*, ppp::net::SocketAcceptor::AcceptSocketEventArgs& e) noexcept {
                            int sockfd = e.Socket;
                            while (!disposed_) {
                                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                                if (NULL == exchanger) {
                                    break;
                                }

                                NetworkState network_state = exchanger->GetNetworkState();
                                if (network_state != NetworkState::NetworkState_Established) {
                                    break;
                                }

                                ppp::threading::Executors::ContextPtr context;
                                ppp::threading::Executors::StrandPtr strand;
                                context = ppp::threading::Executors::SelectScheduler(strand);
                                
                                if (NULL == context) {
                                    break;
                                }

                                return ppp::threading::Executors::Post(context, strand, 
                                    std::bind(&VEthernetLocalProxySwitcher::ProcessAcceptSocket, self, context, strand, sockfd));
                            }

                            ppp::net::Socket::Closesocket(sockfd);
                            return false;
                        };

                    bool bok = CreateAlwaysTimeout();
                    if (!bok) {
                        acceptor->Dispose();
                        return false;
                    }

                    acceptor_ = std::move(acceptor);
                    return bok;
                }

                void VEthernetLocalProxySwitcher::ReleaseConnection(VEthernetLocalProxyConnection* connection) noexcept {
                    if (NULL != connection) {
                        auto self = shared_from_this();
                        std::shared_ptr<boost::asio::io_context> context = GetContext();
                        boost::asio::post(*context, 
                            [self, this, connection]() noexcept {
                                RemoveConnection(connection);
                            });
                    }
                }

                bool VEthernetLocalProxySwitcher::RemoveConnection(VEthernetLocalProxyConnection* connection) noexcept {
                    VEthernetLocalProxyConnectionPtr r; 
                    if (NULL != connection) {
                        SynchronizedObjectScope scope(syncobj_);
                        r = ppp::collections::Dictionary::ReleaseObjectByKey(connections_, connection); 
                    }

                    return NULL != r;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetLocalProxySwitcher::NewSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept {
                    if (NULL == context) {
                        return NULL;
                    }

                    boost::asio::ip::tcp::endpoint remoteEP = ppp::net::Socket::GetRemoteEndPoint(sockfd);
                    boost::system::error_code ec = boost::asio::error::operation_aborted;

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand ?
                        make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
                    try {
                        if (NULL == socket) {
                            return NULL;
                        }
                        else {
                            socket->assign(remoteEP.protocol(), sockfd, ec);
                        }
                    }
                    catch (const std::exception&) {}

                    if (ec) {
                        ppp::net::Socket::Closesocket(sockfd);
                        return NULL;
                    }
                    
                    ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo);
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                    return socket;
                }

                bool VEthernetLocalProxySwitcher::AddConnection(const std::shared_ptr<VEthernetLocalProxyConnection>& connection) noexcept {
                    if (NULL == connection) {
                        return false;
                    }
                    
                    SynchronizedObjectScope scope(syncobj_);
                    return ppp::collections::Dictionary::TryAdd(connections_, connection.get(), connection);
                }

                bool VEthernetLocalProxySwitcher::ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept {
                    if (NULL == context) {
                        ppp::net::Socket::Closesocket(sockfd);
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = NewSocket(context, strand, sockfd);
                    if (NULL == socket) {
                        return false;
                    }

                    std::shared_ptr<VEthernetLocalProxyConnection> connection = NewConnection(context, strand, socket);
                    if (NULL == connection) {
                        return false;
                    }

                    bool bok = false;
                    for (;;) {
                        bok = AddConnection(connection);
                        if (!bok) {
                            break;
                        }

                        auto allocator = GetBufferAllocator();
                        auto self = shared_from_this();

                        bok = ppp::coroutines::YieldContext::Spawn(allocator.get(), *context, strand.get(),
                            [self, this, context, strand, connection](ppp::coroutines::YieldContext& y) noexcept {
                                bool bok = connection->Run(y);
                                if (!bok) {
                                    connection->Dispose();
                                }
                            });

                        break;
                    }
                    
                    if (!bok) {
                        if (RemoveConnection(connection.get())) {
                            connection->Dispose(); 
                        }
                    }

                    return bok;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetLocalProxySwitcher::GetBufferAllocator() noexcept {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = configuration_;
                    return NULL != configuration ? configuration->GetBufferAllocator() : NULL;
                }

                bool VEthernetLocalProxySwitcher::CreateAlwaysTimeout() noexcept {
                    if (disposed_) {
                        return false;
                    }

                    auto self = shared_from_this();
                    auto timeout = make_shared_object<ppp::threading::Timer>(context_);
                    if (!timeout) {
                        return false;
                    }

                    timeout_ = timeout;
                    timeout->TickEvent = 
                        [self, this](ppp::threading::Timer* sender, ppp::threading::Timer::TickEventArgs& e) noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            Update(now);
                        };
                    return timeout->SetInterval(1000) && timeout->Start();
                }

                boost::asio::ip::tcp::endpoint VEthernetLocalProxySwitcher::GetLocalEndPoint() noexcept {
                    std::shared_ptr<ppp::net::SocketAcceptor> acceptor = acceptor_;
                    if (NULL != acceptor) {
                        return ppp::net::Socket::GetLocalEndPoint(acceptor->GetHandle());
                    }

                    return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
                }
            }
        }
    }
}