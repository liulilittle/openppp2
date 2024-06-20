#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
            class VirtualEthernetExchanger;

            class VirtualEthernetDatagramPort : public std::enable_shared_from_this<VirtualEthernetDatagramPort> {
                friend class                                            VirtualEthernetExchanger;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual ~VirtualEthernetDatagramPort() noexcept;

            public:
                std::shared_ptr<VirtualEthernetDatagramPort>            GetReference() noexcept      { return shared_from_this(); }
                VirtualEthernetExchangerPtr                             GetExchanger() noexcept      { return exchanger_; }
                ContextPtr                                              GetContext() noexcept        { return context_; }
                AppConfigurationPtr                                     GetConfiguration() noexcept  { return configuration_; }
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept  { return localEP_; }
                boost::asio::ip::udp::endpoint&                         GetSourceEndPoint() noexcept { return sourceEP_; }

            public:
                virtual void                                            Dispose() noexcept;
                virtual bool                                            Open() noexcept;
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }

            public:
                static bool                                             NamespaceQuery(
                    const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                    const void*                                         packet,
                    int                                                 packet_length) noexcept;
                static int                                              NamespaceQuery(
                    const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                    VirtualEthernetExchanger*                           exchanger,
                    const boost::asio::ip::udp::endpoint&               sourceEP,
                    const boost::asio::ip::udp::endpoint&               destinationEP,
                    const ppp::string&                                  domain,
                    const void*                                         packet,
                    int                                                 packet_length,
                    uint16_t                                            queries_type,
                    uint16_t                                            queries_clazz,
                    bool                                                static_transit) noexcept;

            private:
                void                                                    Finalize() noexcept;
                bool                                                    Loopback() noexcept;
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
                    bool                                                onlydns_  : 1;
                    bool                                                sendto_   : 1;
                    bool                                                in_       : 1;
                    bool                                                finalize_ : 4;
                    UInt64                                              timeout_  = 0;
                };
                std::shared_ptr<boost::asio::io_context>                context_;
                boost::asio::ip::udp::socket                            socket_;
                VirtualEthernetExchangerPtr                             exchanger_;
                ITransmissionPtr                                        transmission_;
                AppConfigurationPtr                                     configuration_;
                std::shared_ptr<Byte>                                   buffer_;
                boost::asio::ip::udp::endpoint                          localEP_;
                boost::asio::ip::udp::endpoint                          remoteEP_;
                boost::asio::ip::udp::endpoint                          sourceEP_;
            };
        }
    }
}