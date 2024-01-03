#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

namespace ppp {
    namespace app {
        namespace protocol {
            class VirtualEthernetTcpipConnection : public std::enable_shared_from_this<VirtualEthernetTcpipConnection> {
            public:
                typedef ppp::configurations::AppConfiguration                   AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                       AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission                       ITransmission;
                typedef std::shared_ptr<ITransmission>                          ITransmissionPtr;
                typedef std::shared_ptr<boost::asio::io_context>                ContextPtr;
                typedef ppp::coroutines::YieldContext                           YieldContext;

            public:
                VirtualEthernetTcpipConnection(
                    const AppConfigurationPtr&                                  configuration,
                    const ContextPtr&                                           context,
                    const Int128&                                               id,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&        socket) noexcept;

            public:
                bool                                                            IsLinked() noexcept;
                std::shared_ptr<VirtualEthernetTcpipConnection>                 GetReference() noexcept;
                ContextPtr                                                      GetContext() noexcept;
                AppConfigurationPtr                                             GetConfiguration() noexcept;
                Int128                                                          GetId() noexcept;
                std::shared_ptr<boost::asio::ip::tcp::socket>                   GetSocket() noexcept;
                ITransmissionPtr                                                GetTransmission() noexcept;

            public:
                virtual bool                                                    Connect(YieldContext& y, ITransmissionPtr& transmission, const ppp::string& host, int port) noexcept;
                virtual bool                                                    Accept(YieldContext& y, ITransmissionPtr& transmission) noexcept;
                virtual bool                                                    Run(YieldContext& y) noexcept;
                virtual void                                                    Dispose() noexcept;

            protected:
                virtual void                                                    Update() noexcept = 0;

            private:
                void                                                            Finalize() noexcept;
                bool                                                            ReceiveTransmissionToSocket() noexcept;
                bool                                                            ForwardTransmissionToSocket(YieldContext& y) noexcept;
                bool                                                            ReceiveSocketToTransmission(std::shared_ptr<Byte> buffer, int buffer_size) noexcept;
                bool                                                            ForwardSocketToTransmission(std::shared_ptr<Byte> buffer, int buffer_size, int bytes_transferred) noexcept;

            private:
                struct {
                    bool                                                        disposed_ : 1;
                    bool                                                        connected_ : 7;
                };
                AppConfigurationPtr                                             configuration_;
                ContextPtr                                                      context_;
                Int128                                                          id_;
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
                        const Int128&                                           id,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                        : VirtualEthernetTcpipConnection(configuration, context, id, socket)
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

                private:
                    std::shared_ptr<TConnection>                                connection_;
                };
            }
        }
    }
}