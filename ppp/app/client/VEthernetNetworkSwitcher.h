 #pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/ethernet/VEthernet.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/transmissions/ITransmissionStatistics.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/dns/Rule.h>
#include <ppp/app/client/http/VEthernetHttpProxySwitcher.h>

#if defined(_WIN32)
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

#include <common/aggligator/aggligator.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetDatagramPort;

            class VEthernetNetworkSwitcher : public ppp::ethernet::VEthernet {
            private:
                friend class                                                        VEthernetExchanger;
                friend class                                                        VEthernetDatagramPort;

            private:    
                typedef struct {    
                    UInt64                                                          datetime;
                    IPFrame::IPFramePtr                                             packet;
                }                                                                   VEthernetIcmpPacket;
                typedef ppp::unordered_map<int, VEthernetIcmpPacket>                VEthernetIcmpPacketTable;
                typedef ppp::app::client::dns::Rule::Ptr                            DNSRulePtr;
                typedef ppp::unordered_map<ppp::string, DNSRulePtr>                 DNSRuleTable;
                typedef ppp::threading::Timer                                       Timer;
                typedef std::weak_ptr<Timer::TimeoutEventHandler>                   TimeoutEventHandlerWeakPtr;
                typedef ppp::unordered_map<void*, TimeoutEventHandlerWeakPtr>       TimeoutEventHandlerTable;
                typedef ppp::set<ppp::string>                                       LoadIPListFileSet;
                typedef std::shared_ptr<LoadIPListFileSet>                          LoadIPListFileSetPtr;
                typedef ppp::unordered_set<boost::asio::ip::address>                NicDnsServerAddresses;
                typedef ppp::unordered_map<int, NicDnsServerAddresses>              AllNicDnsServerAddresses;

            public: 
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                typedef ppp::app::client::http::VEthernetHttpProxySwitcher          VEthernetHttpProxySwitcher;
                typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;
                typedef ppp::function<void(VEthernetNetworkSwitcher*, UInt64)>      VEthernetTickEventHandler;
                typedef ppp::transmissions::ITransmissionStatistics                 ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                    ITransmissionStatisticsPtr;
                class NetworkInterface {    
                public: 
                    ppp::string                                                     Name;
#if !defined(_MACOS)    
                    ppp::string                                                     Id;
#endif  
                    int                                                             Index = -1;
                    ppp::vector<boost::asio::ip::address>                           DnsAddresses;

                public: 
                    NetworkInterface() noexcept;    
                    virtual ~NetworkInterface() noexcept = default;

                public: 
                    boost::asio::ip::address                                        IPAddress;
                    boost::asio::ip::address                                        GatewayServer;
                    boost::asio::ip::address                                        SubmaskAddress;

#if defined(_WIN32) 
                public: 
                    ppp::string                                                     Description;
#elif defined(_MACOS)   
                    ppp::unordered_map<uint32_t, uint32_t>                          DefaultRoutes;
#endif  
                };
                typedef ppp::net::native::RouteInformationTable                     RouteInformationTable;
                typedef std::shared_ptr<RouteInformationTable>                      RouteInformationTablePtr;
                typedef ppp::net::native::ForwardInformationTable                   ForwardInformationTable;
                typedef std::shared_ptr<ForwardInformationTable>                    ForwardInformationTablePtr;
#if defined(_WIN32)
                typedef lsp::PaperAirplaneController                                PaperAirplaneController;
                typedef std::shared_ptr<PaperAirplaneController>                    PaperAirplaneControllerPtr;
#elif defined(_LINUX)   
                typedef ppp::net::ProtectorNetwork                                  ProtectorNetwork;
                typedef std::shared_ptr<ProtectorNetwork>                           ProtectorNetworkPtr;
#endif

            public: 
                VEthernetTickEventHandler                                           TickEvent;

            public:
                VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;
                virtual ~VEthernetNetworkSwitcher() noexcept;

            public:
#if defined(_WIN32)
                PaperAirplaneControllerPtr                                          GetPaperAirplaneController() noexcept { return paper_airplane_ctrl_; }
                virtual bool                                                        SetHttpProxyToSystemEnv()    noexcept;
                virtual bool                                                        ClearHttpProxyToSystemEnv()  noexcept;
#elif defined(_LINUX)   
                ProtectorNetworkPtr                                                 GetProtectorNetwork()        noexcept { return protect_network_; }
#endif  
                std::shared_ptr<ppp::configurations::AppConfiguration>              GetConfiguration()           noexcept { return configuration_; }
                std::shared_ptr<VEthernetExchanger>                                 GetExchanger()               noexcept { return exchanger_; }
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>               GetQoS()                     noexcept { return qos_; }
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>        GetStatistics()              noexcept { return statistics_; }
                std::shared_ptr<VirtualEthernetInformation>                         GetInformation()             noexcept;
                VEthernetHttpProxySwitcherPtr                                       GetHttpProxy()               noexcept { return http_proxy_; }
                RouteInformationTablePtr                                            GetRib()                     noexcept { return rib_; }
                ForwardInformationTablePtr                                          GetFib()                     noexcept { return fib_; }
                std::shared_ptr<aggligator::aggligator>                             GetAggligator()              noexcept { return aggligator_; }
                bool                                                                IsBlockQUIC()                noexcept { return block_quic_; }
                bool                                                                IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept;

            public: 
                virtual bool                                                        LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept;
                bool                                                                StaticMode(bool* static_mode) noexcept;
#if defined(_ANDROID) || defined(_IPHONE)   
                void                                                                SetBypassIpList(ppp::string&& bypass_ip_list) noexcept;
#else   
                std::shared_ptr<NetworkInterface>                                   GetTapNetworkInterface()        noexcept { return tun_ni_; }
                std::shared_ptr<NetworkInterface>                                   GetUnderlyingNetowrkInterface() noexcept { return underlying_ni_; }
                virtual void                                                        PreferredNic(const ppp::string& nic) noexcept;
                virtual bool                                                        AddLoadIPList(const ppp::string& path) noexcept;
                virtual ppp::string                                                 GetRemoteUri() noexcept;
                virtual boost::asio::ip::tcp::endpoint                              GetRemoteEndPoint() noexcept;
#endif  
            public: 
                virtual bool                                                        Open(const std::shared_ptr<ITap>& tap) noexcept override;
                virtual void                                                        Dispose() noexcept override;
                virtual std::shared_ptr<ppp::threading::BufferswapAllocator>        GetBufferAllocator() noexcept override;
                virtual bool                                                        BlockQUIC(bool value) noexcept;

            protected:  
                virtual bool                                                        OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept override;
                virtual bool                                                        OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept override;
                virtual bool                                                        OnTick(uint64_t now) noexcept override;
                virtual bool                                                        OnUpdate(uint64_t now) noexcept override;
                virtual bool                                                        OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information) noexcept;

            protected:  
                virtual std::shared_ptr<VEthernetExchanger>                         NewExchanger() noexcept;
                virtual std::shared_ptr<ppp::ethernet::VNetstack>                   NewNetstack() noexcept override;
                virtual VEthernetHttpProxySwitcherPtr                               NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                virtual std::shared_ptr<ppp::transmissions::ITransmissionQoS>       NewQoS() noexcept;
                virtual ITransmissionStatisticsPtr                                  NewStatistics() noexcept;
#if defined(_WIN32) 
                virtual PaperAirplaneControllerPtr                                  NewPaperAirplaneController() noexcept;
#elif defined(_LINUX)   
                virtual ProtectorNetworkPtr                                         NewProtectorNetwork() noexcept;
#endif  
                virtual bool                                                        DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size) noexcept;

            protected:  
#if !defined(_ANDROID) && !defined(_IPHONE)     
                virtual void                                                        AddRoute() noexcept;
                virtual void                                                        DeleteRoute() noexcept;
#endif  
                virtual bool                                                        OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;
                virtual bool                                                        OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;

            private:    
#if !defined(_ANDROID) && !defined(_IPHONE) 
                bool                                                                FixUnderlyingNgw() noexcept;
                bool                                                                DeleteAllDefaultRoute() noexcept;
#else   
                bool                                                                AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept;
#endif  

            private:
                bool                                                                RedirectDnsServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;
                bool                                                                RedirectDnsServer(
                    ppp::coroutines::YieldContext&                                  y,
                    const std::shared_ptr<boost::asio::ip::udp::socket>&            socket,
                    const std::shared_ptr<Byte>&                                    buffer,
                    const ppp::app::client::dns::Rule::Ptr&                         rulePtr,
                    const std::shared_ptr<UdpFrame>&                                frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>&         messages,
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const boost::asio::ip::address&                                 destinationIP) noexcept;
                bool                                                                EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept;
                bool                                                                DeleteTimeout(void* k) noexcept;

            private:
                void                                                                ReleaseAllObjects() noexcept;
                void                                                                ReleaseAllPackets() noexcept;
                void                                                                ReleaseAllTimeouts() noexcept;

            private:    
#if !defined(_ANDROID) && !defined(_IPHONE)     
#if defined(_WIN32) 
                bool                                                                UsePaperAirplaneController() noexcept;
#endif  
                void                                                                AddRouteWithDnsServers() noexcept;
                void                                                                DeleteRouteWithDnsServers() noexcept;
                bool                                                                AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;
#if defined(_WIN32) 
                bool                                                                DeleteRoute(const std::shared_ptr<MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept;
#else   
                bool                                                                DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;
#endif  
                bool                                                                ProtectDefaultRoute() noexcept;
                bool                                                                LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif
                void                                                                Finalize() noexcept;
                bool                                                                AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept;
                
            private:    
                bool                                                                ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool                                                                TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool                                                                ERORTE(int ack_id) noexcept;
                
            private:
                bool                                                                PreparedAggregator() noexcept;
                bool                                                                IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept { return ip == gw ? true : htonl((ntohl(gw) & ntohl(mask)) + 1) == ip; }
                bool                                                                EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool                                                                EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

            private:    
                std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>               qos_;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>        statistics_;
                VEthernetIcmpPacketTable                                            icmppackets_;
                int                                                                 icmppackets_aid_ = 0;
                bool                                                                block_quic_      = false;
                bool                                                                static_mode_     = false;
                VEthernetHttpProxySwitcherPtr                                       http_proxy_;
                TimeoutEventHandlerTable                                            timeouts_;
                DNSRuleTable                                                        dns_rules_;
                RouteInformationTablePtr                                            rib_;
                ForwardInformationTablePtr                                          fib_;
                ppp::string                                                         server_ru_;
                boost::asio::ip::tcp::endpoint                                      server_ep_;
                std::shared_ptr<aggligator::aggligator>                             aggligator_;

#if !defined(_ANDROID) && !defined(_IPHONE) 
                SynchronizedObject                                                  prdr_;
#endif

#if defined(_LINUX)
                ProtectorNetworkPtr                                                 protect_network_;
#endif  

#if defined(_ANDROID) || defined(_IPHONE)   
                ppp::string                                                         bypass_ip_list_;
#else   
                bool                                                                route_added_   = false;
                LoadIPListFileSetPtr                                                ribs_;

                std::shared_ptr<NetworkInterface>                                   tun_ni_;
                std::shared_ptr<NetworkInterface>                                   underlying_ni_;
                ppp::string                                                         preferred_nic_;
                ppp::unordered_set<uint32_t>                                        dns_serverss_[2];
#if defined(_WIN32) 
                PaperAirplaneControllerPtr                                          paper_airplane_ctrl_;
                ppp::vector<MIB_IPFORWARDROW>                                       default_routes_;
                AllNicDnsServerAddresses                                            ni_dns_servers_;
#elif defined(_LINUX)   
                ppp::string                                                         ni_dns_servers_;
                ppp::vector<boost::asio::ip::address>                               ui_dns_servers_;
                RouteInformationTablePtr                                            default_routes_;
#endif
#endif
            };
        }
    }
}