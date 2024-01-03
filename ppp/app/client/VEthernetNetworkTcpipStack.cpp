#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/threading/Executors.h>

namespace ppp {
    namespace app {
        namespace client {
            VEthernetNetworkTcpipStack::VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept
                : VNetstack()
                , Ethernet(ethernet) {

            }

            std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient> VEthernetNetworkTcpipStack::BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                std::shared_ptr<VEthernetNetworkSwitcher> ethernet = this->Ethernet;
                if (NULL == ethernet) {
                    return NULL;
                }

                auto context = ppp::threading::Executors::GetExecutor();
                auto connection = make_shared_object<VEthernetNetworkTcpipConnection>(ethernet->GetExchanger(), context);
                if (NULL == connection) {
                    return NULL;
                }

                connection->Constructor(localEP, remoteEP);
                return connection;
            }
        }
    }
}