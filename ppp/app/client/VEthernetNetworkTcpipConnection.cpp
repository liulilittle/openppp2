#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>

#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/rinetd/RinetdConnection.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

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

                std::shared_ptr<vmux::vmux_skt> connection_mux = std::move(connection_mux_);
                connection_mux_.reset();

                if (NULL != connection) {
                    connection->Dispose();
                }

                if (NULL != connection_rinetd) {
                    connection_rinetd->Dispose();
                }

                if (NULL != connection_mux) {
                    connection_mux->close();
                }
            }

            void VEthernetNetworkTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                auto socket = GetSocket(); 

                if (NULL != socket) {
                    boost::asio::post(socket->get_executor(), 
                        [self, this, socket]() noexcept {
                            Finalize();
                        });
                }
                else {
                    ppp::threading::Executors::ContextPtr context = GetContext();
                    ppp::threading::Executors::StrandPtr strand = GetStrand();

                    ppp::threading::Executors::Post(context, strand, 
                        [self, this, context, strand]() noexcept {
                            Finalize();
                        });
                }

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

                if (std::shared_ptr<vmux::vmux_skt> connection_mux = connection_mux_; NULL != connection_mux) {
                    return connection_mux->run();
                }

                return false;
            }

            bool VEthernetNetworkTcpipConnection::ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept {
                using VEthernetTcpipConnection = ppp::app::protocol::templates::TVEthernetTcpipConnection<TapTcpClient>;

                // Create a link and correctly establish a link between remote peers, 
                // Indicating whether to use VPN link or Rinetd local loopback forwarding.
                do {
                    std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                    if (NULL == exchanger) {
                        return false;
                    }

                    if (IsDisposed()) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULL == context) {
                        return false;
                    }

                    std::shared_ptr<AppConfiguration> configuration = exchanger->GetConfiguration();
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

                    int rinetd_status = Rinetd(self, exchanger, context, strand, configuration, socket, remoteEP, connection_rinetd_, y);
                    if (rinetd_status < 1) {
                        return rinetd_status == 0;
                    }

                    int mux_status = Mux(self, exchanger, remoteEP, socket, connection_mux_, y);
                    if (mux_status < 1) {
                        return mux_status == 0;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->ConnectTransmission(context, strand, y);
                    if (NULL == transmission) {
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context, strand, exchanger->GetId(), socket);
                    if (NULL == connection) {
                        IDisposable::DisposeReferences(transmission);
                        return false;
                    }

#if defined(_LINUX)
                    auto switcher = exchanger->GetSwitcher(); 
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

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
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

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger->GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                ppp::threading::Executors::ContextPtr context = GetContext();
                if (NULL == context) {
                    return false;
                }

                auto self = shared_from_this();
                ppp::threading::Executors::StrandPtr strand = GetStrand();

                auto post_work = 
                    [self, this, context, strand, coroutine, configuration]() noexcept {
                        auto spawn_work = 
                            [self, this, context, strand, coroutine](ppp::coroutines::YieldContext& y) noexcept {
                               bool ok = coroutine(y);
                               if (!ok) {
                                   Dispose();
                               }
                           };
                        
                        auto allocator = configuration->GetBufferAllocator();
                        bool spawned = ppp::coroutines::YieldContext::Spawn(allocator.get(), *context, strand.get(), spawn_work);
                        if (!spawned) {
                            IDisposable::Dispose(this);
                        }
                    };

                return ppp::threading::Executors::Post(context, strand, post_work);
            }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif

            bool VEthernetNetworkTcpipConnection::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
                if (NULL == socket) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger->GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }
                
                ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration->tcp.turbo);
                ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);

                return TapTcpClient::EndAccept(socket, natEP);
            }
        }
    }
}