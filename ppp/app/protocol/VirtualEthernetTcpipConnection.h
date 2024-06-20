#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/Firewall.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace app {
        namespace protocol {
            class VirtualEthernetTcpipConnection : public std::enable_shared_from_this<VirtualEthernetTcpipConnection> {
            public:
                typedef ppp::configurations::AppConfiguration                   AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                       AppConfigurationPtr;
                typedef ppp::net::Firewall                                      Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>                     FirewallPtr;
                typedef ppp::threading::Executors::StrandPtr                    StrandPtr;
                typedef std::shared_ptr<boost::asio::io_context>                ContextPtr;
                typedef ppp::coroutines::YieldContext                           YieldContext;
                typedef ppp::transmissions::ITransmission                       ITransmission;
                typedef std::shared_ptr<ITransmission>                          ITransmissionPtr;
                typedef ppp::app::protocol::VirtualEthernetLogger               VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>                  VirtualEthernetLoggerPtr;

#if defined(_LINUX)
            public:
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>             ProtectorNetworkPtr;

            public:
                ProtectorNetworkPtr                                             ProtectorNetwork;
#endif

            public:
                VirtualEthernetTcpipConnection(
                    const AppConfigurationPtr&                                  configuration,
                    const ContextPtr&                                           context,
                    const StrandPtr&                                            strand,
                    const Int128&                                               id,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&        socket) noexcept;
                virtual ~VirtualEthernetTcpipConnection() noexcept;

            public:
                bool                                                            IsLinked()          noexcept { return !disposed_ && connected_; }
                std::shared_ptr<VirtualEthernetTcpipConnection>                 GetReference()      noexcept { return shared_from_this(); }
                ContextPtr                                                      GetContext()        noexcept { return context_; }
                StrandPtr                                                       GetStrand()         noexcept { return strand_; }
                AppConfigurationPtr                                             GetConfiguration()  noexcept { return configuration_; }
                Int128                                                          GetId()             noexcept { return id_; }
                std::shared_ptr<boost::asio::ip::tcp::socket>                   GetSocket()         noexcept { return socket_; }
                ITransmissionPtr                                                GetTransmission()   noexcept { return transmission_; }

            public:
                virtual bool                                                    Connect(YieldContext& y, ITransmissionPtr& transmission, const ppp::string& host, int port) noexcept;
                virtual bool                                                    Accept(YieldContext& y, ITransmissionPtr& transmission, const VirtualEthernetLoggerPtr& logger) noexcept;
                virtual bool                                                    Run(YieldContext& y) noexcept;
                virtual void                                                    Dispose() noexcept;
                virtual std::shared_ptr<ppp::net::Firewall>                     GetFirewall() noexcept { return NULL; }
                virtual bool                                                    SendBufferToPeer(YieldContext& y, const void* packet, int packet_length) noexcept;

            protected:
                virtual void                                                    Update() noexcept = 0;

            private:
                void                                                            Finalize() noexcept;
                bool                                                            ReceiveTransmissionToSocket() noexcept;
                bool                                                            ForwardTransmissionToSocket(YieldContext& y) noexcept;
                bool                                                            ReceiveSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept;
                bool                                                            ForwardSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size, int bytes_transferred) noexcept;
                void                                                            ForwardSocketToTransmissionOK(bool ok, const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept {
                    if (ok) {
                        ok = ReceiveSocketToTransmission(buffer, buffer_size);
                    }

                    if (ok) {
                        Update();
                    }
                    else {
                        Dispose();
                    }
                }

            private:
#if defined(_WIN32)
                std::shared_ptr<ppp::net::QoSS>                                 qoss_;
#endif
                struct {
                    bool                                                        disposed_  : 1;
                    bool                                                        connected_ : 7;
                };
                AppConfigurationPtr                                             configuration_;
                ContextPtr                                                      context_;
                StrandPtr                                                       strand_;
                Int128                                                          id_        = 0;
                std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_;
                ITransmissionPtr                                                transmission_;
            };

            namespace templates {
                template <typename TConnection>
                class VEthernetTcpipConnection : public ppp::app::protocol::VirtualEthernetTcpipConnection {
                public:
                    VEthernetTcpipConnection(
                        const std::shared_ptr<TConnection>&                     connection,
                        const AppConfigurationPtr&                              configuration,
                        const ContextPtr&                                       context,
                        const ppp::threading::Executors::StrandPtr&             strand,
                        const Int128&                                           id,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                        : VirtualEthernetTcpipConnection(configuration, context, strand, id, socket)
                        , connection_(connection) {

                    }

                public:
                    virtual void                                                Dispose() noexcept override {
                        std::shared_ptr<TConnection> connection = std::move(connection_);
                        if (NULL != connection) {
                            connection_.reset();
                            connection->Dispose();
                        }

                        VirtualEthernetTcpipConnection::Dispose();
                    }

                protected:
                    virtual void                                                Update() noexcept override {
                        std::shared_ptr<TConnection> connection = connection_;
                        if (NULL != connection) {
                            connection->Update();
                        }
                    }
                    virtual std::shared_ptr<TConnection>                        GetConnection() noexcept { return connection_; }

                private:
                    std::shared_ptr<TConnection>                                connection_;
                };
            }
        }
    }
}