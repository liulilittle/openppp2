#pragma once

#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetExchanger;

            class VirtualInternetControlMessageProtocol : public ppp::net::asio::InternetControlMessageProtocol {
            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                VirtualInternetControlMessageProtocol(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission) noexcept;

            public:
                VirtualEthernetExchangerPtr                             GetExchanger() noexcept;
                AppConfigurationPtr                                     GetConfiguration() noexcept;

            protected:
                virtual bool                                            Output(
                    const IPFrame*                                      packet,
                    const IPEndPoint&                                   destinationEP) noexcept;

            private:
                VirtualEthernetExchangerPtr                             exchanger_;
                ITransmissionPtr                                        transmission_;
            };
        }
    }
}