#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            class VEthernetDatagramPort : public std::enable_shared_from_this<VEthernetDatagramPort> {
                friend class VEthernetExchanger;
                friend class VEthernetNetworkSwitcher;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VEthernetExchanger>             VEthernetExchangerPtr;

            public:
                VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual ~VEthernetDatagramPort() noexcept;

            public:
                std::shared_ptr<VEthernetDatagramPort>                  GetReference() noexcept;
                VEthernetExchangerPtr                                   GetExchanger() noexcept;
                ContextPtr                                              GetContext() noexcept;
                AppConfigurationPtr                                     GetConfiguration() noexcept;
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept;

            public:
                virtual void                                            Dispose() noexcept;
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;

            protected:
                virtual void                                            OnMessage(void*, int, const boost::asio::ip::udp::endpoint&) noexcept;

            private:
                void                                                    Finalize() noexcept;
                void                                                    Update() noexcept {
                    UInt64 now = Executors::GetTickCount();
                    if (onlydns_) {
                        timeout_ = now + (UInt64)configuration_->udp.dns.timeout * 1000;
                    }
                    else {
                        timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                    }
                }
                void                                                    MarkFinalize() noexcept { finalize_ = true; }

            private:
                struct {
                    bool                                                disposed_ : 1;
                    bool                                                onlydns_ : 1;
                    bool                                                sendto_ : 1;
                    bool                                                finalize_ : 5;
                    UInt64                                              timeout_;
                };
                VEthernetExchangerPtr                                   exchanger_;
                ITransmissionPtr                                        transmission_;
                AppConfigurationPtr                                     configuration_;
                std::shared_ptr<Byte>                                   buffer_;
                boost::asio::ip::udp::endpoint                          sourceEP_;
            };
        }
    }
}