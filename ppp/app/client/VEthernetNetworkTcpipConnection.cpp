#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#include <ppp/IDisposable.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/rinetd/RinetdConnection.h>

#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace client {
            VEthernetNetworkTcpipConnection::VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept
                : TapTcpClient(context, strand)
                , exchanger_(exchanger) {
                Update();
            }

            VEthernetNetworkTcpipConnection::~VEthernetNetworkTcpipConnection() noexcept {
                Finalize();
            }

            void VEthernetNetworkTcpipConnection::Finalize() noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_); 
                connection_.reset();

                std::shared_ptr<RinetdConnection> connection_rinetd = std::move(connection_rinetd_); 
                connection_rinetd_.reset();

                if (NULL != connection) {
                    connection->Dispose();
                }

                if (NULL != connection_rinetd) {
                    connection_rinetd->Dispose();
                }
            }

            void VEthernetNetworkTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::Post(GetContext(), GetStrand(),
                    [self, this]() noexcept {
                        Finalize();
                    });
                TapTcpClient::Dispose();
            }

            bool VEthernetNetworkTcpipConnection::Loopback(ppp::coroutines::YieldContext& y) noexcept {
                // If the connection is interrupted while the coroutine is working, 
                // Or closed during other asynchronous processes or coroutines, do not perform meaningless processing.
                if (IsDisposed()) {
                    return false;
                }

                // If rinetd local loopback link forwarding is not used, failure will be returned, 
                // Otherwise the link to the peer will be processed successfully.
                if (std::shared_ptr<RinetdConnection> connection_rinetd = connection_rinetd_; NULL != connection_rinetd) {
                    return connection_rinetd->Run();
                }

                // If the link is relayed through the VPN remote switcher, then run the VPN link relay subroutine.
                if (std::shared_ptr<VirtualEthernetTcpipConnection> connection = connection_; NULL != connection) {
                    bool ok = connection->Run(y);
                    IDisposable::DisposeReferences(connection);
                    return ok;
                }

                return false;
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

                    std::shared_ptr<AppConfiguration> configuration = exchanger_->GetConfiguration();
                    if (NULL == configuration) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULL == socket) {
                        return false;
                    }

                    auto self = shared_from_this();
                    auto strand = GetStrand();
                    boost::asio::ip::tcp::endpoint remoteEP = GetRemoteEndPoint();

                    int rinetd_status = Rinetd(self, exchanger_, context, strand, configuration, socket, remoteEP, connection_rinetd_, y);
                    if (rinetd_status < 1) {
                        return rinetd_status == 0;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger_->ConnectTransmission(context, strand, y);
                    if (NULL == transmission) {
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context, strand, exchanger_->GetId(), socket);
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

                    bool ok = connection->Connect(y, transmission, ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP), remoteEP.port());
                    if (!ok) {
                        IDisposable::DisposeReferences(connection, transmission);
                        return false;
                    }

                    connection_ = std::move(connection);
                } while (false);
                return true;
            }

            bool VEthernetNetworkTcpipConnection::Establish() noexcept {
                return Spawn(
                    [this](ppp::coroutines::YieldContext& y) noexcept {
                        if (IsLwip()) {
                            return ConnectToPeer(y) && Loopback(y);
                        }

                        return Loopback(y);
                    });
            }

            bool VEthernetNetworkTcpipConnection::BeginAccept() noexcept {
                if (IsLwip()) {
                    return !IsDisposed();
                }

                return Spawn(
                    [this](ppp::coroutines::YieldContext& y) noexcept {
                        return ConnectToPeer(y) && AckAccept();
                    });
            }

            bool VEthernetNetworkTcpipConnection::Spawn(const ppp::function<bool(ppp::coroutines::YieldContext&)>& coroutine) noexcept {
                if (IsDisposed()) {
                    return false;
                }

                if (NULL == coroutine) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger_->GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                auto self = shared_from_this();
                auto context = GetContext();
                auto strand = GetStrand();
                auto allocator = configuration->GetBufferAllocator();

                return ppp::coroutines::YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, strand, coroutine](ppp::coroutines::YieldContext& y) noexcept {
                        bool ok = coroutine(y);
                        if (!ok) {
                            Dispose();
                        }
                    });
            }

            bool VEthernetNetworkTcpipConnection::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
                if (NULL == socket) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger_->GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }
                
                ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration->tcp.turbo);
                return TapTcpClient::EndAccept(socket, natEP);
            }
        }
    }
}