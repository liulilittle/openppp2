#pragma once

#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
            class VirtualEthernetExchanger;

            class VirtualInternetControlMessageProtocolStatic : public ppp::net::asio::InternetControlMessageProtocol {
            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;
                typedef std::shared_ptr<VirtualEthernetSwitcher>        VirtualEthernetSwitcherPtr;

            public:
                VirtualInternetControlMessageProtocolStatic(const VirtualEthernetExchangerPtr& exchanger, const AppConfigurationPtr& configuration, const std::shared_ptr<boost::asio::io_context>& context) noexcept;

            public:
                VirtualEthernetExchangerPtr                             GetExchanger()     noexcept { return exchanger_; }
                AppConfigurationPtr                                     GetConfiguration() noexcept;

            public:
                virtual bool                                            Output(
                    const IPFrame*                                      packet,
                    const IPEndPoint&                                   destinationEP) noexcept;

            private:
                VirtualEthernetSwitcherPtr                              switcher_;
                VirtualEthernetExchangerPtr                             exchanger_;
            };
        }
    }
}