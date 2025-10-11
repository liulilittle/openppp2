#pragma once

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/mux/vmux_net.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Firewall.h>
#include <ppp/threading/Timer.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetManagedServer;
            class VirtualEthernetSwitcher;
            class VirtualEthernetDatagramPort;
            class VirtualEthernetDatagramPortStatic;
            class VirtualInternetControlMessageProtocol;
            class VirtualInternetControlMessageProtocolStatic;

            class VirtualEthernetExchanger : public ppp::app::protocol::VirtualEthernetLinklayer {
                friend class                                                                VirtualInternetControlMessageProtocolStatic;
                friend class                                                                VirtualEthernetSwitcher;
                friend class                                                                VirtualEthernetDatagramPort;
                friend class                                                                VirtualEthernetDatagramPortStatic;

            public:
                typedef ppp::app::protocol::VirtualEthernetInformation                      VirtualEthernetInformation;
                typedef std::shared_ptr<VirtualEthernetSwitcher>                            VirtualEthernetSwitcherPtr;
                typedef std::shared_ptr<VirtualEthernetDatagramPort>                        VirtualEthernetDatagramPortPtr;
                typedef std::shared_ptr<VirtualEthernetManagedServer>                       VirtualEthernetManagedServerPtr;

            private:    
                typedef std::mutex                                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                                 SynchronizedObjectScope;
                typedef ppp::threading::Timer                                               Timer;
                typedef std::shared_ptr<Timer>                                              TimerPtr;
                typedef ppp::net::Firewall                                                  Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>                                 FirewallPtr;
                typedef std::weak_ptr<Timer::TimeoutEventHandler>                           TimeoutEventHandlerWeakPtr;
                typedef ppp::unordered_map<void*, TimeoutEventHandlerWeakPtr>               TimeoutEventHandlerTable;
                typedef ppp::transmissions::ITransmissionStatistics                         ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                            ITransmissionStatisticsPtr;
                typedef ppp::net::Ipep                                                      Ipep;
                typedef ppp::app::protocol::VirtualEthernetLogger                           VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>                              VirtualEthernetLoggerPtr;
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,  
                    VirtualEthernetDatagramPortPtr>                                         VirtualEthernetDatagramPortTable;
                typedef std::shared_ptr<VirtualInternetControlMessageProtocol>              VirtualInternetControlMessageProtocolPtr;
                typedef ppp::app::protocol::VirtualEthernetMappingPort                      VirtualEthernetMappingPort;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                         VirtualEthernetMappingPortPtr;
                typedef ppp::unordered_map<uint32_t, VirtualEthernetMappingPortPtr>         VirtualEthernetMappingPortTable;
                typedef std::shared_ptr<VirtualEthernetDatagramPortStatic>                  VirtualEthernetDatagramPortStaticPtr;
                typedef ppp::unordered_map<uint64_t, VirtualEthernetDatagramPortStaticPtr>  VirtualEthernetDatagramPortStaticTable;

            public:
                VirtualEthernetExchanger(
                    const VirtualEthernetSwitcherPtr&                                       switcher,
                    const AppConfigurationPtr&                                              configuration, 
                    const ITransmissionPtr&                                                 transmission,
                    const Int128&                                                           id) noexcept;
                virtual ~VirtualEthernetExchanger() noexcept;   
    
            public: 
                virtual bool                                                                Update(UInt64 now) noexcept;
                virtual bool                                                                Open() noexcept;
                virtual void                                                                Dispose() noexcept;
                bool                                                                        IsDisposed() noexcept       { return disposed_; }
                VirtualEthernetSwitcherPtr                                                  GetSwitcher() noexcept      { return switcher_; }
                ITransmissionPtr                                                            GetTransmission() noexcept  { return transmission_; }
                VirtualEthernetManagedServerPtr                                             GetManagedServer() noexcept { return managed_server_; }
                ITransmissionStatisticsPtr                                                  GetStatistics() noexcept    { return statistics_; }
                std::shared_ptr<vmux::vmux_net>                                             GetMux() noexcept           { return mux_; }

            protected:  
                virtual bool                                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept override;
                virtual bool                                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept override;
                virtual bool                                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override;
                virtual bool                                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override;
                virtual bool                                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept override;
                virtual bool                                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept override;
                virtual bool                                                                OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                                OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept override;
                virtual bool                                                                OnStatic(const ITransmissionPtr& transmission, int session_id, int remote_port, YieldContext& y) noexcept override;
                virtual bool                                                                OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept override;

            protected:  
                virtual FirewallPtr                                                         GetFirewall() noexcept override;
                virtual VirtualInternetControlMessageProtocolPtr                            NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept;
                virtual VirtualEthernetDatagramPortPtr                                      NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual VirtualEthernetDatagramPortPtr                                      GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual VirtualEthernetDatagramPortPtr                                      ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
    
            private:    
                void                                                                        Finalize() noexcept;
                bool                                                                        DeleteTimeout(void* k) noexcept;
                bool                                                                        INTERNAL_RedirectDnsQuery(
                    const ITransmissionPtr&                                                 transmission, 
                    const boost::asio::ip::udp::endpoint&                                   sourceEP,
                    const boost::asio::ip::udp::endpoint&                                   destinationEP,
                    Byte*                                                                   packet, 
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;
                bool                                                                        INTERNAL_RedirectDnsQuery(
                    ITransmissionPtr                                                        transmission,
                    boost::asio::ip::udp::endpoint                                          redirectEP,
                    boost::asio::ip::udp::endpoint                                          sourceEP,
                    boost::asio::ip::udp::endpoint                                          destinationEP,
                    std::shared_ptr<Byte>                                                   packet,
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;
                int                                                                         RedirectDnsQuery(
                    const ITransmissionPtr&                                                 transmission, 
                    const boost::asio::ip::udp::endpoint&                                   sourceEP, 
                    const boost::asio::ip::udp::endpoint&                                   destinationEP, 
                    Byte*                                                                   packet, 
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;
    
            private:    
                bool                                                                        UploadTrafficToManagedServer() noexcept;
                bool                                                                        DoMuxEvents() noexcept;
                bool                                                                        Arp(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask) noexcept;
                bool                                                                        ForwardNatPacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept;
                bool                                                                        SendEchoToDestination(const ITransmissionPtr& transmission, Byte* packet, int packet_length) noexcept;
                bool                                                                        SendPacketToDestination(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
    
            private:    
                bool                                                                        StaticEcho(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                bool                                                                        StaticEchoReleasePort(uint32_t source_ip, int source_port) noexcept;
                bool                                                                        StaticEchoSendToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept;
                bool                                                                        StaticEchoEchoToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
    
            private:    
                VirtualEthernetMappingPortPtr                                               GetMappingPort(bool in, bool tcp, int remote_port) noexcept;
                VirtualEthernetMappingPortPtr                                               NewMappingPort(bool in, bool tcp, int remote_port) noexcept;
                bool                                                                        RegisterMappingPort(bool in, bool tcp, int remote_port) noexcept;
    
            private:    
                virtual bool                                                                DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept override;
                virtual bool                                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept override;
                virtual bool                                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept override;
                virtual bool                                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept override;
                virtual bool                                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept override;
    
            private:    
                bool                                                                        disposed_ = false;
                uint32_t                                                                    address_  = 0;
                VirtualEthernetSwitcherPtr                                                  switcher_;
                std::shared_ptr<Byte>                                                       buffer_;
                FirewallPtr                                                                 firewall_;
                TimeoutEventHandlerTable                                                    timeouts_;
                VirtualInternetControlMessageProtocolPtr                                    echo_;
                VirtualEthernetDatagramPortTable                                            datagrams_;
                ITransmissionPtr                                                            transmission_;
                VirtualEthernetManagedServerPtr                                             managed_server_;
                ITransmissionStatisticsPtr                                                  statistics_last_;
                VirtualEthernetMappingPortTable                                             mappings_;
                ITransmissionStatisticsPtr                                                  statistics_;
                std::shared_ptr<vmux::vmux_net>                                             mux_;

                SynchronizedObject                                                          static_echo_syncobj_;
                std::shared_ptr<VirtualInternetControlMessageProtocolStatic>                static_echo_;
                boost::asio::ip::udp::endpoint                                              static_echo_source_ep_;
                std::atomic<int>                                                            static_echo_session_id_ = 0;
                VirtualEthernetDatagramPortStaticTable                                      static_echo_datagram_ports_;
            };
        }
    }
}