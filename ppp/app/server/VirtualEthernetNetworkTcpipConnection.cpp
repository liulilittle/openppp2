#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace server {
            VirtualEthernetNetworkTcpipConnection::VirtualEthernetNetworkTcpipConnection(
                const std::shared_ptr<VirtualEthernetSwitcher>& switcher,
                const Int128&                                   id,
                const ITransmissionPtr&                         transmission) noexcept
                : disposed_(false)
                , id_(id)
                , timeout_(0)
                , context_(transmission->GetContext())
                , strand_(transmission->GetStrand())
                , switcher_(switcher)
                , transmission_(transmission)
                , configuration_(transmission->GetConfiguration()) {
                Update();
            }

            VirtualEthernetNetworkTcpipConnection::~VirtualEthernetNetworkTcpipConnection() noexcept {
                Finalize();
            }

            void VirtualEthernetNetworkTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::Post(context_, strand_,
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            void VirtualEthernetNetworkTcpipConnection::Finalize() noexcept {
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

                disposed_ = true;
                switcher_->DeleteConnection(this);
            }

            bool VirtualEthernetNetworkTcpipConnection::Run(ppp::coroutines::YieldContext& y) noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = AcceptConnection(y);
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
                class VirtualEthernetTcpipConnection final : public ppp::app::protocol::templates::VEthernetTcpipConnection<VirtualEthernetNetworkTcpipConnection> {
                public:
                    VirtualEthernetTcpipConnection(
                        const std::shared_ptr<VirtualEthernetNetworkTcpipConnection>&   connection,
                        const AppConfigurationPtr&                                      configuration,
                        const ContextPtr&                                               context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const Int128&                                                   id,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept
                        : VEthernetTcpipConnection(connection, configuration, context, strand, id, socket) {

                    }

                public:
                    virtual std::shared_ptr<ppp::net::Firewall>                         GetFirewall() noexcept {
                        std::shared_ptr<VirtualEthernetNetworkTcpipConnection> connection = GetConnection();
                        std::shared_ptr<VirtualEthernetSwitcher> switcher = connection->GetSwitcher();
                        return switcher->GetFirewall();
                    }

                private:
                    FirewallPtr                                                         firewall_;
                };

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

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand_ ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand_) : make_shared_object<boost::asio::ip::tcp::socket>(*context_);
                if (NULL == socket) {
                    return NULL;
                }
                
                auto self = shared_from_this();
                std::shared_ptr<VirtualEthernetTcpipConnection> connection =
                    make_shared_object<VirtualEthernetTcpipConnection>(self, configuration, context_, strand_, id_, socket);
                if (NULL == connection) {
                    return NULL;
                }

                bool ok = connection->Accept(y, transmission, switcher_->GetLogger());
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