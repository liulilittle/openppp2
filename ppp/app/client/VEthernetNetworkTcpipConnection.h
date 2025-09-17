#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkTcpipConnection : public ppp::ethernet::VNetstack::TapTcpClient {
            public:
                typedef ppp::app::protocol::VirtualEthernetTcpipConnection  VirtualEthernetTcpipConnection;
                typedef ppp::net::rinetd::RinetdConnection                  RinetdConnection;
                typedef ppp::configurations::AppConfiguration               AppConfiguration;

            public:
                VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept;
                virtual ~VEthernetNetworkTcpipConnection() noexcept;

            public:
                std::shared_ptr<VEthernetExchanger>                         GetExchanger() noexcept { return exchanger_; }
                virtual void                                                Dispose() noexcept override;

            public:
                template <class TReference>
                static int                                                  Rinetd(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const std::shared_ptr<boost::asio::io_context>&         context,
                    const ppp::threading::Executors::StrandPtr&             strand,
                    const std::shared_ptr<AppConfiguration>&                configuration,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    const boost::asio::ip::tcp::endpoint&                   remoteEP, 
                    std::shared_ptr<RinetdConnection>&                      out,
                    ppp::coroutines::YieldContext&                          y) noexcept {

                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = exchanger->GetSwitcher();
                    if (NULL == switcher) {
                        return -1;
                    }

                    bool bypass_ip_address_ok = switcher->IsBypassIpAddress(remoteEP.address());
                    if (!bypass_ip_address_ok) {
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

                    public:
                        virtual void                                                        Dispose() noexcept override {
                            RinetdConnection::Dispose();
                        }
                        virtual void                                                        Update() noexcept override {
                            std::shared_ptr<TReference> owner = owner_;
                            if (NULL != owner) {
                                owner->Update();
                            }
                        }

                    private:
                        void                                                                Finalize() noexcept {
                            std::shared_ptr<TReference> owner = std::move(owner_);
                            owner_.reset();

                            if (NULL != owner) {
                                owner->Dispose();
                            }
                        }

                    private:
                        std::shared_ptr<TReference>                                         owner_;
                    };

                    std::shared_ptr<VEthernetRinetdConnection> connection_rinetd = 
                        make_shared_object<VEthernetRinetdConnection>(reference, configuration, context, strand, socket);
                    if (NULL == connection_rinetd) {
                        return -1;
                    }

#if defined(_LINUX)
                    connection_rinetd->ProtectorNetwork = switcher->GetProtectorNetwork();
#endif

                    bool run_ok = connection_rinetd->Open(remoteEP, y);
                    if (!run_ok) {
                        return -1;
                    }

                    out = std::move(connection_rinetd);
                    return 0;
                }

                template <class TReference>
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const ppp::string&                                      host,
                    const int                                               port,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept {

                    typedef VEthernetExchanger::NetworkState NetworkState;
                    typedef std::shared_ptr<vmux::vmux_skt> VmuxSktPtr;

                    if (auto mux = exchanger->GetMux(); NULL != mux) {
                        auto network_state = exchanger->GetMuxNetworkState();
                        if (network_state == NetworkState::NetworkState_Established) {
                            std::shared_ptr<VmuxSktPtr> pmux_connection = make_shared_object<VmuxSktPtr>();
                            if (NULL == pmux_connection) {
                                return -1;
                            }
                            elif(!mux->connect_yield(
                                y, 
                                reference->GetContext(),
                                reference->GetStrand(),
                                socket, 
                                host,
                                port,
                                pmux_connection)) {
                                return -1;
                            }
                            else {
                                reference->Update();
                            }
                            
                            VmuxSktPtr mux_connection = *pmux_connection;
                            if (NULL == mux_connection) {
                                return -1;
                            }

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
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const boost::asio::ip::tcp::endpoint&                   remoteEP, 
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept {

                    ppp::string host = ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP);
                    return Mux(reference, exchanger, host, remoteEP.port(), socket, out, y); /* https://www.youtube.com/watch?v=FdScisAHKBE */
                }

            protected:
                virtual bool                                                Establish() noexcept override;
                virtual bool                                                BeginAccept() noexcept override;
                virtual bool                                                EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept override;

            private:
                void                                                        Finalize() noexcept;
                bool                                                        Loopback(ppp::coroutines::YieldContext& y) noexcept;
                bool                                                        ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept;
                bool                                                        Spawn(const ppp::function<bool(ppp::coroutines::YieldContext&)>& coroutine) noexcept;

            private:
                std::shared_ptr<VEthernetExchanger>                         exchanger_;
                std::shared_ptr<VirtualEthernetTcpipConnection>             connection_;
                std::shared_ptr<RinetdConnection>                           connection_rinetd_;
                std::shared_ptr<vmux::vmux_skt>                             connection_mux_;                       
            };
        }
    }
}