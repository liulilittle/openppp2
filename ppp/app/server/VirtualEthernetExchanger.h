#pragma once

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
            class VirtualEthernetDatagramPort;
            class VirtualInternetControlMessageProtocol;

            class VirtualEthernetExchanger : public ppp::app::protocol::VirtualEthernetLinklayer {
                friend class VirtualEthernetDatagramPort;

            public:
                typedef ppp::app::protocol::VirtualEthernetInformation                  VirtualEthernetInformation;
                typedef std::shared_ptr<VirtualEthernetSwitcher>                        VirtualEthernetSwitcherPtr;
                typedef std::shared_ptr<VirtualEthernetDatagramPort>                    VirtualEthernetDatagramPortPtr;
                
            private:
                typedef ppp::threading::Timer                                           Timer;
                typedef std::shared_ptr<Timer>                                          TimerPtr;
                typedef std::weak_ptr<Timer::TimeoutEventHandler>                       TimeoutEventHandlerWeakPtr;
                typedef ppp::unordered_map<void*, TimeoutEventHandlerWeakPtr>           TimeoutEventHandlerTable;
                typedef ppp::net::Ipep                                                  Ipep;
                typedef std::weak_ptr<Ipep::GetAddressByHostNameCallback>               GetAddressByHostNameCallbackWeakPtr;
                typedef ppp::unordered_map<void*, GetAddressByHostNameCallbackWeakPtr>  GetAddressByHostNameCallbackTable;
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,
                    VirtualEthernetDatagramPortPtr>                                     VirtualEthernetDatagramPortTable;
                typedef std::shared_ptr<VirtualInternetControlMessageProtocol>          VirtualInternetControlMessageProtocolPtr;

            public:
                VirtualEthernetExchanger(
                    const VirtualEthernetSwitcherPtr&                                   switcher,
                    const AppConfigurationPtr&                                          configuration, 
                    const ITransmissionPtr&                                             transmission,
                    const Int128&                                                       id) noexcept;
                virtual ~VirtualEthernetExchanger() noexcept;

            public:
                virtual VirtualEthernetSwitcherPtr                                      GetSwitcher() noexcept;
                virtual bool                                                            Prepared() noexcept;
                virtual void                                                            Dispose() noexcept;
                virtual bool                                                            Update(UInt64 now) noexcept;
                virtual ITransmissionPtr                                                GetTransmission() noexcept;

            protected:
                virtual bool                                                            OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept override;
                virtual bool                                                            OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                            OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override;
                virtual bool                                                            OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override;
                virtual bool                                                            OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept override;
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept override;
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                            OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;

            protected:
                virtual VirtualInternetControlMessageProtocolPtr                        NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept;
                virtual VirtualEthernetDatagramPortPtr                                  NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual VirtualEthernetDatagramPortPtr                                  GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual VirtualEthernetDatagramPortPtr                                  ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                void                                                                    Finalize() noexcept;
                bool                                                                    DeleteTimeout(void* k) noexcept;
                bool                                                                    DeleteResolver(void* k) noexcept;
                bool                                                                    INTERNAL_RedirectDnsQuery(
                    const ITransmissionPtr&                                             transmission, 
                    const boost::asio::ip::udp::endpoint&                               sourceEP,
                    const boost::asio::ip::udp::endpoint&                               destinationEP,
                    Byte*                                                               packet, 
                    int                                                                 packet_length) noexcept;
                bool                                                                    INTERNAL_RedirectDnsQuery(
                    ITransmissionPtr                                                    transmission,
                    boost::asio::ip::udp::endpoint                                      redirectEP,
                    boost::asio::ip::udp::endpoint                                      sourceEP,
                    boost::asio::ip::udp::endpoint                                      destinationEP,
                    std::shared_ptr<Byte>                                               packet,
                    int                                                                 packet_length) noexcept;
                int                                                                     RedirectDnsQuery(
                    const ITransmissionPtr&                                             transmission, 
                    const boost::asio::ip::udp::endpoint&                               sourceEP, 
                    const boost::asio::ip::udp::endpoint&                               destinationEP, 
                    Byte*                                                               packet, 
                    int                                                                 packet_length) noexcept;

            private:
                bool                                                                    SendEchoToDestination(const ITransmissionPtr& transmission, Byte* packet, int packet_length) noexcept;

            private:
                bool                                                                    disposed_;
                VirtualEthernetSwitcherPtr                                              switcher_;
                TimeoutEventHandlerTable                                                timeouts_;
                VirtualInternetControlMessageProtocolPtr                                echo_;
                VirtualEthernetDatagramPortTable                                        datagrams_;
                GetAddressByHostNameCallbackTable                                       resolvers_;
                ITransmissionPtr                                                        transmission_;
            };
        }
    }
}