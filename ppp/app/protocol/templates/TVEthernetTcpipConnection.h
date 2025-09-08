#pragma once

#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace protocol {
            namespace templates {
                template <typename TConnection>
                class TVEthernetTcpipConnection : public ppp::app::protocol::VirtualEthernetTcpipConnection {
                public:
                    TVEthernetTcpipConnection(
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
                        connection_.reset();
                        
                        if (NULL != connection) {
                            connection->Dispose();
                        }

                        VirtualEthernetTcpipConnection::Dispose();
                    }
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