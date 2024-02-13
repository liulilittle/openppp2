#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            class VEthernetNetworkTcpipConnection : public ppp::ethernet::VNetstack::TapTcpClient {
                typedef ppp::app::protocol::VirtualEthernetTcpipConnection  VirtualEthernetTcpipConnection;
                typedef ppp::net::rinetd::RinetdConnection                  RinetdConnection;

            public:
                VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context) noexcept;
                virtual ~VEthernetNetworkTcpipConnection() noexcept;

            public:
                std::shared_ptr<VEthernetExchanger>                         GetExchanger() noexcept;
                virtual void                                                Dispose() noexcept override;

            protected:
                virtual bool                                                Establish() noexcept;
                virtual bool                                                EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept override;

            private:
                void                                                        Finalize() noexcept;
                bool                                                        ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept;

            private:
                std::shared_ptr<VEthernetExchanger>                         exchanger_;
                std::shared_ptr<VirtualEthernetTcpipConnection>             connection_;
                std::shared_ptr<RinetdConnection>                           connection_rinetd_;
            };
        }
    }
}