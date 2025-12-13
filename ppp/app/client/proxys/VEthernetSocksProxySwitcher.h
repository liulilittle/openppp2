#pragma once

#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetSocksProxySwitcher : public VEthernetLocalProxySwitcher {
                public:
                    VEthernetSocksProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                protected:
                    virtual boost::asio::ip::address                        MyLocalEndPoint(int& bind_port) noexcept override;
                    virtual std::shared_ptr<VEthernetLocalProxyConnection>  NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                };
            }
        }
    }
}