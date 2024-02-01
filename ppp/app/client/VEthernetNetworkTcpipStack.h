#pragma once 

#include <ppp/ethernet/VEthernet.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            class VEthernetNetworkTcpipStack : public ppp::ethernet::VNetstack {
            public:
                const std::shared_ptr<VEthernetNetworkSwitcher>         Ethernet;

            public:
                VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept;

            protected:
                virtual uint64_t                                        GetMaxConnectTimeout() noexcept override;
                virtual uint64_t                                        GetMaxEstablishedTimeout() noexcept override;
                virtual std::shared_ptr<TapTcpClient>                   BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept override;
            
            private:
                std::shared_ptr<ppp::configurations::AppConfiguration>  configuration_;
            };
        }
    }
}