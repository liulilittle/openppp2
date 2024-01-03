#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace client {
            VEthernetNetworkTcpipConnection::VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context) noexcept
                : TapTcpClient(context)
                , exchanger_(exchanger) {

            }

            VEthernetNetworkTcpipConnection::~VEthernetNetworkTcpipConnection() noexcept {
                Finalize();
            }

            void VEthernetNetworkTcpipConnection::Finalize() noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                if (connection) {
                    connection_.reset();
                    connection->Dispose();
                }
            }

            void VEthernetNetworkTcpipConnection::Dispose() noexcept {
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                auto self = shared_from_this();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
                TapTcpClient::Dispose();
            }

            std::shared_ptr<VEthernetExchanger> VEthernetNetworkTcpipConnection::GetExchanger() noexcept {
                return exchanger_;
            }

            std::shared_ptr<VEthernetNetworkTcpipConnection::VirtualEthernetTcpipConnection> VEthernetNetworkTcpipConnection::ConnectConnection(ppp::coroutines::YieldContext& y) noexcept {
                using VEthernetTcpipConnection = ppp::app::protocol::templates::VEthernetTcpipConnection<TapTcpClient>;

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULL == context) {
                    return NULL;
                }

                auto configuration = exchanger_->GetConfiguration();
                if (NULL == configuration) {
                    return NULL;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                if (NULL == socket) {
                    return NULL;
                }

                std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger_->ConnectTransmission(context, y);
                if (NULL == transmission) {
                    return NULL;
                }

                auto self = shared_from_this();
                std::shared_ptr<VEthernetTcpipConnection> connection =
                    make_shared_object<VEthernetTcpipConnection>(self, configuration, context, exchanger_->GetId(), socket);
                if (NULL == connection) {
                    IDisposable::DisposeReferences(transmission);
                    return NULL;
                }

                boost::asio::ip::tcp::endpoint remoteEP = GetRemoteEndPoint();
                bool ok = connection->Connect(y, transmission, ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP), remoteEP.port());
                if (!ok) {
                    IDisposable::DisposeReferences(connection, transmission);
                    return NULL;
                }

                return connection;
            }

            bool VEthernetNetworkTcpipConnection::Establish() noexcept {
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                auto self = shared_from_this();
                return ppp::coroutines::YieldContext::Spawn(*context,
                    [self, this](ppp::coroutines::YieldContext& y) noexcept {
                        if (!IsDisposed()) {
                            std::shared_ptr<VirtualEthernetTcpipConnection> connection = ConnectConnection(y);
                            connection_ = connection;

                            if (NULL != connection) {
                                connection->Run(y);
                                connection->Dispose();
                            }
                        }
                    });
            }
        }
    }
}