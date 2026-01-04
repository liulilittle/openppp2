#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

namespace ppp {
    namespace app {
        namespace server {
            VirtualEthernetNetworkTcpipConnection::VirtualEthernetNetworkTcpipConnection(
                const std::shared_ptr<VirtualEthernetSwitcher>& switcher,
                const Int128&                                   id,
                const ITransmissionPtr&                         transmission) noexcept
                : disposed_(false)
                , mux_(false)
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
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        Finalize();
                    });
            }

            void VirtualEthernetNetworkTcpipConnection::Finalize() noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_); 
                connection_.reset();

                ITransmissionPtr transmission = std::move(transmission_); 
                transmission_.reset();

                if (NULLPTR != connection) {
                    connection->Dispose();
                }

                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                disposed_ = true;
                switcher_->DeleteConnection(this);
            }

            bool VirtualEthernetNetworkTcpipConnection::Run(ppp::coroutines::YieldContext& y) noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = AcceptConnection(y);
                if (NULLPTR == connection) {
                    return false;
                }
                elif(disposed_) {
                    return false;
                }
                else {
                    connection_ = connection;
                    return mux_ || connection->Run(y);
                }
            }

            std::shared_ptr<VirtualEthernetNetworkTcpipConnection::VirtualEthernetTcpipConnection> VirtualEthernetNetworkTcpipConnection::AcceptConnection(ppp::coroutines::YieldContext& y) noexcept {
                class VirtualEthernetTcpipConnection final : public ppp::app::protocol::templates::TVEthernetTcpipConnection<VirtualEthernetNetworkTcpipConnection> {
                public:
                    VirtualEthernetTcpipConnection(
                        const std::shared_ptr<VirtualEthernetNetworkTcpipConnection>&   connection,
                        const AppConfigurationPtr&                                      configuration,
                        const ContextPtr&                                               context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const Int128&                                                   id,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept
                        : TVEthernetTcpipConnection(connection, configuration, context, strand, id, socket) {

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
                    return NULLPTR;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                AppConfigurationPtr configuration = configuration_;
                if (NULLPTR == configuration) {
                    return NULLPTR;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand_ ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand_) : make_shared_object<boost::asio::ip::tcp::socket>(*context_);
                if (NULLPTR == socket) {
                    return NULLPTR;
                }
                
                auto self = shared_from_this();
                std::shared_ptr<VirtualEthernetTcpipConnection> connection =
                    make_shared_object<VirtualEthernetTcpipConnection>(self, configuration, context_, strand_, id_, socket);
                if (NULLPTR == connection) {
                    return NULLPTR;
                }

                bool ok = 
                    connection->Accept(y, transmission, switcher_->GetLogger(),
                        [this, &connection, &y](uint32_t vlan, uint32_t seq, uint32_t ack) noexcept {
                            mux_ = true;
                            return AcceptMuxLinklayer(connection, vlan, seq, ack, y);
                        });
                if (!ok) {
                    connection->Dispose();
                    return NULLPTR;
                }

                return connection;
            }

            bool VirtualEthernetNetworkTcpipConnection::AcceptMuxLinklayer(const std::shared_ptr<VirtualEthernetTcpipConnection>& connection, uint32_t vlan, uint32_t seq, uint32_t ack, ppp::coroutines::YieldContext& y) noexcept {
                std::shared_ptr<VirtualEthernetExchanger> exchanger = switcher_->GetExchanger(id_);
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<vmux::vmux_net> mux = exchanger->GetMux();
                if (NULLPTR == mux) {
                    return false;
                }
                elif(mux->Vlan != vlan) {
                    return false;
                }
                elif(mux->is_established()) {
                    return false;
                }
                elif(!mux->ftt(seq, ack)) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetNetworkTcpipConnection> self = shared_from_this();
                return mux->do_yield(y,
                    [self, this, mux, connection, exchanger, vlan, seq, ack]() noexcept -> bool {
                        vmux::vmux_net::vmux_linklayer_ptr linklayer;
                        auto handling = 
                            [&]() noexcept {
                                ppp::coroutines::YieldContext& y_null = nullof<ppp::coroutines::YieldContext>();
                                return exchanger->DoMuxON(connection->GetTransmission(), vlan, seq, ack, y_null);
                            };
                        if (mux->add_linklayer(connection, linklayer, handling)) {
                            linklayer->server = self;
                            return true;
                        }

                        return false;
                    });
            }

            void VirtualEthernetNetworkTcpipConnection::Update() noexcept {
                using Executors = ppp::threading::Executors;

                std::shared_ptr<VirtualEthernetTcpipConnection> connection = connection_;
                if (NULLPTR != connection && connection->IsLinked()) {
                    timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                }
                else {
                    timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.connect.timeout * 1000;
                }
            }
        }
    }
}