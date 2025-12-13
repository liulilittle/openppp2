#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                VEthernetHttpProxySwitcher::VEthernetHttpProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept 
                    : VEthernetLocalProxySwitcher(exchanger) {

                }
                
                std::shared_ptr<VEthernetLocalProxyConnection> VEthernetHttpProxySwitcher::NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                    std::shared_ptr<VEthernetHttpProxySwitcher> self = std::dynamic_pointer_cast<VEthernetHttpProxySwitcher>(shared_from_this());
                    std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();

                    return make_shared_object<VEthernetHttpProxyConnection>(self, exchanger, context, strand, socket);
                }

                boost::asio::ip::address VEthernetHttpProxySwitcher::MyLocalEndPoint(int& bind_port) noexcept {
                    std::shared_ptr<ppp::configurations::AppConfiguration>& configuration_ = GetConfiguration();
                    bind_port = configuration_->client.http_proxy.port;

                    return ppp::net::Ipep::ToAddress(configuration_->client.http_proxy.bind, true);
                }
            }
        }
    }
}