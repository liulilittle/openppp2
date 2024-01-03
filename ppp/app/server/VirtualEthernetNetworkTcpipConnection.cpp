#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace server {
            std::shared_ptr<boost::asio::io_context> VirtualEthernetNetworkTcpipConnection::GetContext() noexcept {
                return context_;
            }

            Int128 VirtualEthernetNetworkTcpipConnection::GetId() noexcept {
                return id_;
            }

            VirtualEthernetNetworkTcpipConnection::ITransmissionPtr VirtualEthernetNetworkTcpipConnection::GetTransmission() noexcept {
                return transmission_;
            }
            
            VirtualEthernetNetworkTcpipConnection::AppConfigurationPtr VirtualEthernetNetworkTcpipConnection::GetConfiguration() noexcept {
                return configuration_;
            }

            std::shared_ptr<VirtualEthernetSwitcher> VirtualEthernetNetworkTcpipConnection::GetSwitcher() noexcept {
                return switcher_;
            }

            VirtualEthernetNetworkTcpipConnection::VirtualEthernetNetworkTcpipConnection(
                const std::shared_ptr<VirtualEthernetSwitcher>& switcher,
                const Int128&                                   id,
                const ITransmissionPtr&                         transmission) noexcept
                : disposed_(false)
                , id_(id)
                , timeout_(0)
                , context_(transmission->GetContext())
                , switcher_(switcher)
                , transmission_(transmission)
                , configuration_(transmission->GetConfiguration()) {
                
            }

            VirtualEthernetNetworkTcpipConnection::~VirtualEthernetNetworkTcpipConnection() noexcept {
                Finalize();
            }

            void VirtualEthernetNetworkTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            void VirtualEthernetNetworkTcpipConnection::Finalize() noexcept {
                exchangeof(disposed_, true); {
                    std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                    if (NULL != connection) {
                        connection_.reset();
                        connection->Dispose();
                    }

                    ITransmissionPtr transmission = std::move(transmission_);
                    if (NULL != transmission) {
                        transmission_.reset();
                        transmission->Dispose();
                    }
                }

                switcher_->DeleteConnection(this);
            }

            bool VirtualEthernetNetworkTcpipConnection::Run(ppp::coroutines::YieldContext& y) noexcept {
                auto connection = AcceptConnection(y);
                if (NULL == connection) {
                    return false;
                }
                elif(disposed_) {
                    return false;
                }
                else {
                    connection_ = connection;
                    return connection->Run(y);
                }
            }

            std::shared_ptr<VirtualEthernetNetworkTcpipConnection::VirtualEthernetTcpipConnection> VirtualEthernetNetworkTcpipConnection::AcceptConnection(ppp::coroutines::YieldContext& y) noexcept {
                using VEthernetTcpipConnection = ppp::app::protocol::templates::VEthernetTcpipConnection<VirtualEthernetNetworkTcpipConnection>;

                if (disposed_) {
                    return NULL;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return NULL;
                }

                AppConfigurationPtr configuration = configuration_;
                if (NULL == configuration) {
                    return NULL;
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULL == context) {
                    return NULL;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
                if (NULL == socket) {
                    return NULL;
                }

                auto self = shared_from_this();
                std::shared_ptr<VEthernetTcpipConnection> connection =
                    make_shared_object<VEthernetTcpipConnection>(self, configuration, context, id_, socket);
                if (NULL == connection) {
                    return NULL;
                }

                bool ok = connection->Accept(y, transmission);
                if (!ok) {
                    connection->Dispose();
                    return NULL;
                }

                return connection;
            }

            void VirtualEthernetNetworkTcpipConnection::Update() noexcept {
                using Executors = ppp::threading::Executors;

                std::shared_ptr<VirtualEthernetTcpipConnection> connection = connection_;
                if (NULL != connection && connection->IsLinked()) {
                    timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                }
                else {
                    timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.connect.timeout * 1000;;
                }
            }
        }
    }
}