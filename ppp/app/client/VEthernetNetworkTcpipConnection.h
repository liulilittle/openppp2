#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            class VEthernetNetworkTcpipConnection : public ppp::ethernet::VNetstack::TapTcpClient {
                typedef ppp::app::protocol::VirtualEthernetTcpipConnection  VirtualEthernetTcpipConnection;

            public:
                VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context) noexcept;
                virtual ~VEthernetNetworkTcpipConnection() noexcept;

            public:
                std::shared_ptr<VEthernetExchanger>                         GetExchanger() noexcept;
                virtual void                                                Dispose() noexcept override;

            protected:
                virtual bool                                                Establish() noexcept;

            private:
                void                                                        Finalize() noexcept;
                std::shared_ptr<VirtualEthernetTcpipConnection>             ConnectConnection(ppp::coroutines::YieldContext& y) noexcept;

            private:
                std::shared_ptr<VEthernetExchanger>                         exchanger_;
                std::shared_ptr<VirtualEthernetTcpipConnection>             connection_;
            };
        }
    }
}