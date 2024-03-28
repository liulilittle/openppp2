#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/threading/Executors.h>

static constexpr int PPP_FAULT_TOLERANT_TIMEOUT = 3;

namespace ppp {
    namespace app {
        namespace client {
            VEthernetNetworkTcpipStack::VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept
                : VNetstack()
                , Ethernet(ethernet)
                , configuration_(ethernet->GetConfiguration()) {

            }

            std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient> VEthernetNetworkTcpipStack::BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                std::shared_ptr<VEthernetNetworkSwitcher> ethernet = this->Ethernet;
                if (NULL == ethernet) {
                    return NULL;
                }

                auto context = ppp::threading::Executors::GetExecutor();
                if (NULL == context) {
                    return NULL;
                }

                auto connection = make_shared_object<VEthernetNetworkTcpipConnection>(ethernet->GetExchanger(), context);
                if (NULL == connection) {
                    return NULL;
                }

                connection->Open(localEP, remoteEP);
                return connection;
            }

            uint64_t VEthernetNetworkTcpipStack::GetMaxConnectTimeout() noexcept {
                uint64_t tcp_connect_timeout = (uint64_t)configuration_->tcp.connect.timeout;
                return (tcp_connect_timeout + PPP_FAULT_TOLERANT_TIMEOUT) * 1000;
            }

            uint64_t VEthernetNetworkTcpipStack::GetMaxEstablishedTimeout() noexcept {
                uint64_t tcp_inactive_timeout = (uint64_t)configuration_->tcp.inactive.timeout;
                return (tcp_inactive_timeout + PPP_FAULT_TOLERANT_TIMEOUT) * 1000;
            }
        }
    }
}