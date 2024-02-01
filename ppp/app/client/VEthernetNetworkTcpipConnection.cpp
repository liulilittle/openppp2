#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace client {
            VEthernetNetworkTcpipConnection::VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context) noexcept
                : TapTcpClient(context)
                , exchanger_(exchanger) {
                Update();
            }

            VEthernetNetworkTcpipConnection::~VEthernetNetworkTcpipConnection() noexcept {
                Finalize();
            }

            void VEthernetNetworkTcpipConnection::Finalize() noexcept {
                if (std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_); NULL != connection) {
                    connection_.reset();
                    connection->Dispose();
                }

                if (std::shared_ptr<RinetdConnection> connection_rinetd = std::move(connection_rinetd_); NULL != connection_rinetd) {
                    connection_rinetd_.reset();
                    connection_rinetd->Dispose();
                }
            }

            void VEthernetNetworkTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
                TapTcpClient::Dispose();
            }

            std::shared_ptr<VEthernetExchanger> VEthernetNetworkTcpipConnection::GetExchanger() noexcept {
                return exchanger_;
            }

            bool VEthernetNetworkTcpipConnection::ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept {
                using VEthernetTcpipConnection = ppp::app::protocol::templates::VEthernetTcpipConnection<TapTcpClient>;

                // Create a link and correctly establish a link between remote peers, 
                // Indicating whether to use VPN link or Rinetd local loopback forwarding.
                do {
                    if (IsDisposed()) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULL == context) {
                        return false;
                    }

                    auto configuration = exchanger_->GetConfiguration();
                    if (NULL == configuration) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULL == socket) {
                        return false;
                    }

                    boost::asio::ip::tcp::endpoint remoteEP = GetRemoteEndPoint();
                    if (auto switcher = exchanger_->GetSwitcher(); NULL != switcher) {
                        if (switcher->IsBypassIpAddress(remoteEP.address())) {
                            class VEthernetRinetdConnection : public RinetdConnection {
                            public:
                                VEthernetRinetdConnection(
                                    const std::shared_ptr<TapTcpClient>&                            owner,
                                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration, 
                                    const std::shared_ptr<boost::asio::io_context>&                 context, 
                                    const std::shared_ptr<boost::asio::ip::tcp::socket>&            local_socket) noexcept 
                                    : RinetdConnection(configuration, context, local_socket) 
                                    , owner_(owner) {
                                        
                                }
                            
                            public:
                                virtual void                                                        Dispose() noexcept override {
                                    std::shared_ptr<TapTcpClient> owner = std::move(owner_);
                                    if (NULL != owner) {
                                        owner_.reset();
                                        owner->Dispose();
                                    }

                                    RinetdConnection::Dispose();
                                }
                                virtual void                                                        Update() noexcept override {
                                    std::shared_ptr<TapTcpClient> owner = owner_;
                                    if (NULL != owner) {
                                        owner->Update();
                                    }
                                }

                            private:
                                std::shared_ptr<TapTcpClient>                                       owner_;
                            };

                            std::shared_ptr<VEthernetRinetdConnection> connection_rinetd = 
                                make_shared_object<VEthernetRinetdConnection>(shared_from_this(), configuration, context, socket);
                            if (NULL == connection_rinetd) {
                                return false;
                            }

#ifdef _LINUX
                            connection_rinetd->ProtectorNetwork = switcher->GetProtectorNetwork();
#endif

                            bool run_ok = connection_rinetd->Run(remoteEP);
                            if (!run_ok) {
                                return false;
                            }
                            
                            connection_rinetd_ = std::move(connection_rinetd);
                            break;
                        }
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger_->ConnectTransmission(context, y);
                    if (NULL == transmission) {
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(shared_from_this(), configuration, context, exchanger_->GetId(), socket);
                    if (NULL == connection) {
                        IDisposable::DisposeReferences(transmission);
                        return false;
                    }

#ifdef _LINUX
                    if (auto switcher = exchanger_->GetSwitcher(); NULL != switcher) {
                        connection->ProtectorNetwork = switcher->GetProtectorNetwork();
                    }
#endif

                    bool ok = connection->Connect(y, transmission, ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP), remoteEP.port());
                    if (!ok) {
                        IDisposable::DisposeReferences(connection, transmission);
                        return false;
                    }

                    connection_ = std::move(connection);
                } while (false);

                // If the connection is interrupted while the coroutine is working, 
                // Or closed during other asynchronous processes or coroutines, do not perform meaningless processing.
                if (IsDisposed()) {
                    return false;
                }

                // If the link is relayed through the VPN remote switcher, then run the VPN link relay subroutine.
                if (std::shared_ptr<VirtualEthernetTcpipConnection> connection = connection_; NULL != connection) {
                    bool ok = connection->Run(y);
                    IDisposable::DisposeReferences(connection);
                    return ok;
                }
                
                // If rinetd local loopback link forwarding is not used, failure will be returned, 
                // Otherwise the link to the peer will be processed successfully.
                return NULL != connection_rinetd_;
            }

            bool VEthernetNetworkTcpipConnection::Establish() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();

                return ppp::coroutines::YieldContext::Spawn(*context,
                    [self, this](ppp::coroutines::YieldContext& y) noexcept {
                        ConnectToPeer(y);
                    });
            }

            bool VEthernetNetworkTcpipConnection::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
                if (NULL == socket) {
                    return false;
                }

                auto configuration = exchanger_->GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }
                else {
                    boost::system::error_code ec;
                    socket->set_option(boost::asio::ip::tcp::no_delay(configuration->tcp.turbo), ec);
                }

                return TapTcpClient::EndAccept(socket, natEP);
            }
        }
    }
}