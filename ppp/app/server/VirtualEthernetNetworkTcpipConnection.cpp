#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/mux/MuxTransportAdapter.h>
#include <ppp/app/mux/MuxCoordinator.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

/**
 * @file VirtualEthernetNetworkTcpipConnection.cpp
 * @brief Implements session transport acceptance and mux link attachment.
 */

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Constructs a server-side session transport wrapper.
             * @param switcher Parent switcher that owns connection registration.
             * @param id Session identifier.
             * @param transmission Underlying transmission channel.
             */
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

            /** @brief Finalizes resources during object destruction. */
            VirtualEthernetNetworkTcpipConnection::~VirtualEthernetNetworkTcpipConnection() noexcept {
                Finalize();
            }

            /**
             * @brief Schedules cleanup on the connection strand/context.
             */
            void VirtualEthernetNetworkTcpipConnection::Dispose() noexcept {
                Dispose(ppp::function<void()>());
            }

            void VirtualEthernetNetworkTcpipConnection::Dispose(
                ppp::function<void()> completion) noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand, completion = std::move(completion)]() noexcept {
                        Finalize();
                        if (completion) {
                            completion();
                        }
                    });
            }

            /**
             * @brief Releases active protocol/transmission handles and unregisters self.
             */
            void VirtualEthernetNetworkTcpipConnection::Finalize() noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_); 
                ITransmissionPtr transmission = std::move(transmission_); 

                if (NULLPTR != connection) {
                    connection->Dispose();
                }

                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                disposed_ = true;
                switcher_->DeleteConnection(this);
            }

            /**
             * @brief Accepts and runs a protocol connection for this session.
             * @param y Coroutine context for accept/run operations.
             * @return true when run succeeds or mux takeover is active; otherwise false.
             */
            bool VirtualEthernetNetworkTcpipConnection::Run(ppp::coroutines::YieldContext& y) noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = AcceptConnection(y);
                if (NULLPTR == connection) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                    return false;
                }
                elif(disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }
                else {
                    connection_ = connection;
                    return mux_ || connection->Run(y);
                }
            }

            /**
             * @brief Creates a protocol connection object and performs accept handshake.
             * @param y Coroutine context used for handshake I/O.
             * @return Shared protocol connection on success; null otherwise.
             */
            std::shared_ptr<VirtualEthernetNetworkTcpipConnection::VirtualEthernetTcpipConnection> VirtualEthernetNetworkTcpipConnection::AcceptConnection(ppp::coroutines::YieldContext& y) noexcept {
                /**
                 * @brief Session-specialized TCP/IP connection implementation.
                 */
                class VirtualEthernetTcpipConnection final : public ppp::app::protocol::templates::TVEthernetTcpipConnection<VirtualEthernetNetworkTcpipConnection> {
                public:
                    /**
                     * @brief Constructs a protocol connection bound to outer session context.
                     */
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
                    /**
                     * @brief Retrieves firewall rules from the owning switcher.
                     * @return Shared firewall object used for connection filtering.
                     */
                    virtual std::shared_ptr<ppp::net::Firewall>                         GetFirewall() noexcept {
                        std::shared_ptr<VirtualEthernetNetworkTcpipConnection> connection = GetConnection();
                        std::shared_ptr<VirtualEthernetSwitcher> switcher = connection->GetSwitcher();
                        return switcher->GetFirewall();
                    }

                private:
                    FirewallPtr                                                         firewall_;
                };

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return NULLPTR;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return NULLPTR;
                }

                AppConfigurationPtr configuration = configuration_;
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigLoadFailed);
                    return NULLPTR;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand_ ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand_) : make_shared_object<boost::asio::ip::tcp::socket>(*context_);
                if (NULLPTR == socket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }
                
                auto self = shared_from_this();
                std::shared_ptr<VirtualEthernetTcpipConnection> connection =
                    make_shared_object<VirtualEthernetTcpipConnection>(self, configuration, context_, strand_, id_, socket);
                if (NULLPTR == connection) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionCreateFailed);
                    return NULLPTR;
                }

                /**
                 * @brief Accept callback may switch this connection into mux mode.
                 */
                bool ok = 
                    connection->Accept(y, transmission, switcher_->GetLogger(),
                        [this, &connection, &y](uint32_t vlan, uint32_t seq, uint32_t ack) noexcept {
                            mux_ = true;
                            return AcceptMuxLinklayer(connection, vlan, seq, ack, y);
                        });
                if (!ok) {
                    connection->Dispose();
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                    return NULLPTR;
                }

                return connection;
            }

            /**
             * @brief Validates mux handshake and registers a linklayer binding.
             * @param connection Newly accepted protocol connection.
             * @param vlan Negotiated mux vlan.
             * @param seq Negotiated sequence number.
             * @param ack Negotiated acknowledgement number.
             * @param y Coroutine context for mux suspension points.
             * @return true if the mux linklayer is attached; otherwise false.
             */
            bool VirtualEthernetNetworkTcpipConnection::AcceptMuxLinklayer(const std::shared_ptr<VirtualEthernetTcpipConnection>& connection, uint32_t vlan, uint32_t seq, uint32_t ack, ppp::coroutines::YieldContext& y) noexcept {
                std::shared_ptr<VirtualEthernetExchanger> exchanger = switcher_->GetExchanger(id_);
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                    return false;
                }

                std::shared_ptr<vmux::vmux_net> mux =
                    exchanger->GetMuxCoordinator()->Session();
                if (NULLPTR == mux) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                    return false;
                }
                elif(mux->Vlan != vlan) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                    return false;
                }
                elif(!mux->ftt(seq, ack)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                    return false;
                }

                std::shared_ptr<VirtualEthernetNetworkTcpipConnection> self = shared_from_this();
                /**
                 * @brief Yield into mux scheduler while installing connection callbacks.
                 */
                return mux->do_yield(y,
                    [self, this, mux, connection, exchanger, vlan, seq, ack]() noexcept -> bool {
                        vmux::vmux_net::vmux_linklayer_ptr linklayer;
                        auto handling = 
                            [&]() noexcept {
                                ppp::coroutines::YieldContext& y_null = nullof<ppp::coroutines::YieldContext>();
                                return exchanger->DoMuxON(connection->GetTransmission(), vlan, seq, ack, y_null);
                            };
                        auto transport = ppp::app::mux::MakeMuxTransport(
                            connection, [self]() noexcept { self->Dispose(); });
                        if (mux->add_linklayer(transport, linklayer, handling)) {
                            return true;
                        }

                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    });
            }

            /**
             * @brief Updates timeout according to connect vs linked state.
             */
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
