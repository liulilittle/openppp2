#pragma once 

#include <ppp/ethernet/VEthernet.h>
#include <ppp/ethernet/VNetstack.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            class VEthernetNetworkTcpipStack : public ppp::ethernet::VNetstack {
            public:
                VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept;

            protected:
                virtual std::shared_ptr<TapTcpClient>                   BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept override;

            public:
                const std::shared_ptr<VEthernetNetworkSwitcher>         Ethernet;
            };
        }
    }
}