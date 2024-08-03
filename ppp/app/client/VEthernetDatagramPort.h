#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>

#if defined(_ANDROID)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetNetworkSwitcher;

            class VEthernetDatagramPort : public std::enable_shared_from_this<VEthernetDatagramPort> {
                friend class                                            VEthernetExchanger;
                friend class                                            VEthernetNetworkSwitcher;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                typedef std::shared_ptr<VEthernetExchanger>             VEthernetExchangerPtr;
                typedef std::shared_ptr<VEthernetNetworkSwitcher>       VEthernetNetworkSwitcherPtr;

#if defined(_ANDROID)
            public:
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>     ProtectorNetworkPtr;
                typedef struct {
                    std::shared_ptr<Byte>                               packet;
                    int                                                 packet_length = 0;
                    boost::asio::ip::udp::endpoint                      destinationEP;
                }                                                       Message;
                typedef ppp::list<Message>                              Messages;

            public:
                ProtectorNetworkPtr                                     ProtectorNetwork;
#endif

            public:
                VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual ~VEthernetDatagramPort() noexcept;

            public:
                std::shared_ptr<VEthernetDatagramPort>                  GetReference()     noexcept { return shared_from_this(); }
                VEthernetExchangerPtr                                   GetExchanger()     noexcept { return exchanger_; }
                ContextPtr                                              GetContext()       noexcept { return context_; }
                AppConfigurationPtr                                     GetConfiguration() noexcept { return configuration_; }
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept { return sourceEP_; }

            public:
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }
                virtual void                                            Dispose() noexcept;
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;

#if defined(_ANDROID)
            public:  
                bool                                                    Open(ppp::coroutines::YieldContext& y) noexcept;

            private: 
                bool                                                    Loopback() noexcept;
#endif

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
                    bool                                                onlydns_  : 1;
                    bool                                                sendto_   : 1;
                    bool                                                finalize_ : 5;
                    UInt64                                              timeout_  = 0;
                };
                SynchronizedObject                                      syncobj_;
                ContextPtr                                              context_;
                VEthernetNetworkSwitcherPtr                             switcher_;
                VEthernetExchangerPtr                                   exchanger_;
                ITransmissionPtr                                        transmission_;
                AppConfigurationPtr                                     configuration_;
                boost::asio::ip::udp::endpoint                          sourceEP_;
#if defined(_ANDROID)
                Messages                                                messages_;
                int                                                     opened_   = 0;
                boost::asio::ip::udp::socket                            socket_;
                std::shared_ptr<Byte>                                   buffer_;
                boost::asio::ip::udp::endpoint                          remoteEP_;
#endif
            };
        }
    }
}