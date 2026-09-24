#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/ClientUnderlyingSocketProtector.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/mux/MuxCoordinator.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/Ipep.h>

namespace ppp {
    namespace app {
        namespace client {

            template <class TReference>
            int VEthernetNetworkTcpipConnection::Rinetd(
                const std::shared_ptr<TReference>&                      reference,
                const std::shared_ptr<VEthernetExchanger>&              exchanger,
                const std::shared_ptr<boost::asio::io_context>&         context,
                const ppp::threading::Executors::StrandPtr&             strand,
                const std::shared_ptr<AppConfiguration>&                configuration,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                const boost::asio::ip::tcp::endpoint&                   remoteEP,
                bool                                                    force,
                std::shared_ptr<RinetdConnection>&                      out,
                ppp::coroutines::YieldContext&                          y) noexcept {

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = exchanger->GetSwitcher();
                if (NULLPTR == switcher) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    return -1;
                }

                if (!force && !switcher->IsBypassIpAddress(remoteEP.address())) {
                    return 1;
                }

                class VEthernetRinetdConnection final : public RinetdConnection {
                public:
                    VEthernetRinetdConnection(
                        const std::shared_ptr<TReference>&                              owner,
                        const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            local_socket) noexcept
                            : RinetdConnection(configuration, context, strand, local_socket)
                            , owner_(owner) {
                    }
                    virtual ~VEthernetRinetdConnection() noexcept {
                        Finalize();
                    }

                    virtual void Dispose() noexcept override {
                        RinetdConnection::Dispose();
                    }

                    virtual void Update() noexcept override {
                        std::shared_ptr<TReference> owner = owner_;
                        if (NULLPTR != owner) {
                            owner->Update();
                        }
                    }

                private:
                    void Finalize() noexcept {
                        std::shared_ptr<TReference> owner = std::move(owner_);
                        if (NULLPTR != owner) {
                            owner->Dispose();
                        }
                    }

                    std::shared_ptr<TReference> owner_;
                };

                std::shared_ptr<VEthernetRinetdConnection> connection_rinetd =
                    make_shared_object<VEthernetRinetdConnection>(reference, configuration, context, strand, socket);
                if (NULLPTR == connection_rinetd) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return -1;
                }

                std::shared_ptr<ClientNetworkInterface> underlying_network_interface;
#if !defined(_ANDROID) && !defined(_IPHONE) && !defined(IPHONE)
                underlying_network_interface = switcher->GetUnderlyingNetworkInterface();
#endif

                std::shared_ptr<ppp::net::ProtectorNetwork> protector_network;
#if defined(_LINUX)
                protector_network = switcher->GetProtectorNetwork();
                connection_rinetd->ProtectorNetwork = protector_network;
#endif

                if (force) {
                    connection_rinetd->RemoteSocketProtectorRequired = true;
                    connection_rinetd->ProtectRemoteSocket =
                        BuildClientUnderlyingSocketProtector(
                            remoteEP.address().is_v4(),
                            underlying_network_interface,
                            protector_network);
                }

                bool run_ok = connection_rinetd->Open(remoteEP, y);
                if (!run_ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                    return -1;
                }

                out = std::move(connection_rinetd);
                return 0;
            }

            template <class TReference>
            int VEthernetNetworkTcpipConnection::Mux(
                const std::shared_ptr<TReference>&                      reference,
                const std::shared_ptr<VEthernetExchanger>&              exchanger,
                const ppp::string&                                      host,
                const int                                               port,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                std::shared_ptr<vmux::vmux_skt>&                        out,
                ppp::coroutines::YieldContext&                          y) noexcept {

                typedef VEthernetExchanger::NetworkState NetworkState;
                typedef std::shared_ptr<vmux::vmux_skt> VmuxSktPtr;

                if (auto mux = exchanger->GetMuxCoordinator()->Session(); NULLPTR != mux) {
                    auto network_state = exchanger->GetMuxNetworkState();
                    if (network_state == NetworkState::NetworkState_Established) {
                        std::shared_ptr<VmuxSktPtr> pmux_connection = make_shared_object<VmuxSktPtr>();
                        if (NULLPTR == pmux_connection) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            return -1;
                        }

                        if (!mux->connect_yield(
                            y,
                            reference->GetContext(),
                            reference->GetStrand(),
                            socket,
                            host,
                            port,
                            pmux_connection)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                            return -1;
                        }
                        else {
                            reference->Update();
                        }

                        VmuxSktPtr mux_connection = *pmux_connection;
                        if (NULLPTR == mux_connection) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                            return -1;
                        }

                        mux_connection->disposed_event =
                            [reference](vmux::vmux_skt*) noexcept {
                                reference->Dispose();
                            };
                        mux_connection->active_event =
                            [reference](vmux::vmux_skt*, bool success) noexcept {
                                if (success) {
                                    reference->Update();
                                }
                                else {
                                    reference->Dispose();
                                }
                            };

                        out = mux_connection;
                        return 0;
                    }
                }

                return 1;
            }

            template <class TReference>
            int VEthernetNetworkTcpipConnection::Mux(
                const std::shared_ptr<TReference>&                      reference,
                const std::shared_ptr<VEthernetExchanger>&              exchanger,
                const boost::asio::ip::tcp::endpoint&                   remoteEP,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                std::shared_ptr<vmux::vmux_skt>&                        out,
                ppp::coroutines::YieldContext&                          y) noexcept {

                ppp::string host = ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP);
                return Mux(reference, exchanger, host, remoteEP.port(), socket, out, y);
            }

        }
    }
}
