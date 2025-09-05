#pragma once

#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetSocksProxySwitcher;

                class VEthernetSocksProxyConnection : public VEthernetLocalProxyConnection {
                public:
                    typedef std::shared_ptr<VEthernetSocksProxySwitcher>                VEthernetSocksProxySwitcherPtr;

                public:
                    VEthernetSocksProxyConnection(const VEthernetSocksProxySwitcherPtr& proxy,
                        const VEthernetExchangerPtr&                                    exchanger, 
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;

                private:
                    int                                                                 SelectMethod(YieldContext& y, int& method) noexcept;
                    bool                                                                Replay(YieldContext& y, int k, int v) noexcept;
                    int                                                                 Authentication(YieldContext& y) noexcept;
                    bool                                                                Requirement(YieldContext& y, ppp::string& address, int& port, ppp::app::protocol::AddressType& address_type) noexcept;

                protected:
                    virtual bool                                                        Handshake(YieldContext& y) noexcept override;
                };
            }
        }
    }
}