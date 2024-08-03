#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/threading/Executors.h>

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

                ppp::threading::Executors::ContextPtr context = ppp::threading::Executors::GetScheduler();
                ppp::threading::Executors::StrandPtr strand;
                if (!ppp::threading::Executors::ShiftToScheduler(context, strand)) {
                    return NULL;
                }

                auto connection = make_shared_object<VEthernetNetworkTcpipConnection>(ethernet->GetExchanger(), context, strand);
                if (NULL == connection) {
                    return NULL;
                }

                connection->Open(localEP, remoteEP);
                return connection;
            }

            uint64_t VEthernetNetworkTcpipStack::GetMaxConnectTimeout() noexcept {
                uint64_t tcp_connect_timeout = (uint64_t)configuration_->tcp.connect.timeout;
                return (tcp_connect_timeout + 1) * 1000;
            }

            uint64_t VEthernetNetworkTcpipStack::GetMaxEstablishedTimeout() noexcept {
                uint64_t tcp_inactive_timeout = (uint64_t)configuration_->tcp.inactive.timeout;
                return (tcp_inactive_timeout + 1) * 1000;
            }
        }
    }
}