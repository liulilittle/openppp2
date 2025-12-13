#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetExchanger;
            class VirtualEthernetSwitcher;

            class VirtualEthernetDatagramPortStatic : public std::enable_shared_from_this<VirtualEthernetDatagramPortStatic> {
                friend class                                            VirtualEthernetExchanger;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                VirtualEthernetDatagramPortStatic(const VirtualEthernetExchangerPtr& exchanger, const std::shared_ptr<boost::asio::io_context>& context, uint32_t source_ip, int source_port) noexcept;
                virtual ~VirtualEthernetDatagramPortStatic() noexcept;

            public:
                std::shared_ptr<VirtualEthernetDatagramPortStatic>      GetReference() noexcept     { return shared_from_this(); }
                VirtualEthernetExchangerPtr                             GetExchanger() noexcept     { return exchanger_; }
                ContextPtr                                              GetContext() noexcept       { return context_; }
                AppConfigurationPtr                                     GetConfiguration() noexcept { return configuration_; }
                boost::asio::ip::udp::endpoint                          GetLocalEndPoint() noexcept { return localEP_; }
                boost::asio::ip::udp::endpoint                          GetSourceEndPoint() noexcept;

            public:
                virtual void                                            Dispose() noexcept;
                virtual bool                                            Open() noexcept;
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }
                static bool                                             Output(
                    VirtualEthernetSwitcher*                            switcher, 
                    VirtualEthernetExchanger*                           exchanger, 
                    const void*                                         messages, 
                    int                                                 message_length, 
                    const boost::asio::ip::udp::endpoint&               sourceEP,
                    const boost::asio::ip::udp::endpoint&               remoteEP) noexcept;
                static bool                                             Output(
                    VirtualEthernetSwitcher*                            switcher, 
                    VirtualEthernetExchanger*                           exchanger, 
                    uint32_t                                            source_ip,
                    int                                                 source_port,
                    const void*                                         messages, 
                    int                                                 message_length, 
                    const boost::asio::ip::udp::endpoint&               remoteEP) noexcept;

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
                bool                                                    Output(const void* messages, int message_length, const boost::asio::ip::udp::endpoint& remoteEP) noexcept;
                int                                                     NamespaceQuery(
                    const boost::asio::ip::udp::endpoint&               destinationEP,
                    const void*                                         packet,
                    int                                                 packet_length) noexcept; 

            private:
                struct {
                    bool                                                disposed_    : 1;
                    bool                                                in_          : 1;
                    bool                                                onlydns_     : 6;
                    uint32_t                                            source_ip_   = 0;
                    int                                                 source_port_ = 0;
                    UInt64                                              timeout_     = 0;
                };
                boost::asio::ip::udp::socket                            socket_;
                std::shared_ptr<VirtualEthernetSwitcher>                switcher_;
                VirtualEthernetExchangerPtr                             exchanger_;
                AppConfigurationPtr                                     configuration_;
                std::shared_ptr<Byte>                                   buffer_;
                std::shared_ptr<boost::asio::io_context>                context_;
                boost::asio::ip::udp::endpoint                          localEP_;
                boost::asio::ip::udp::endpoint                          sourceEP_;
            };
        }
    }
}