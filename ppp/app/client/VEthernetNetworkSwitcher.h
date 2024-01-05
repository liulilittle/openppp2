 #pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>
#include <ppp/ethernet/VEthernet.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/transmissions/ITransmissionStatistics.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/http/VEthernetHttpProxySwitcher.h>

#ifdef _WIN32
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#elif _LINUX
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetDatagramPort;

            class VEthernetNetworkSwitcher : public ppp::ethernet::VEthernet {
                friend class VEthernetExchanger;
                friend class VEthernetDatagramPort;

            private:
                typedef struct {
                    UInt64                                                      datetime;
                    IPFrame::IPFramePtr                                         packet;
                }                                                               VEthernetIcmpPacket;
                typedef ppp::unordered_map<int, VEthernetIcmpPacket>            VEthernetIcmpPacketTable;

            public:
                typedef ppp::app::protocol::VirtualEthernetInformation          VirtualEthernetInformation;
                typedef ppp::app::client::http::VEthernetHttpProxySwitcher      VEthernetHttpProxySwitcher;
                typedef std::shared_ptr<VEthernetHttpProxySwitcher>             VEthernetHttpProxySwitcherPtr;
                typedef ppp::function<void(VEthernetNetworkSwitcher*, UInt64)>  VEthernetTickEventHandler;
                typedef ppp::transmissions::ITransmissionStatistics             ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                ITransmissionStatisticsPtr;
                class NetworkInterface {
                public:
                    ppp::string                                                 Name;
                    ppp::string                                                 Id;
                    int                                                         Index;
                    ppp::vector<boost::asio::ip::address>                       DnsAddresses;

                public:
                    NetworkInterface() noexcept;
                    virtual ~NetworkInterface() noexcept;
                    
                public:
                    boost::asio::ip::address                                    IPAddress;
                    boost::asio::ip::address                                    GatewayServer;
                    boost::asio::ip::address                                    SubmaskAddress;

#ifdef _WIN32
                public:
                    ppp::string                                                 Description;
#endif
                };
                typedef ppp::net::native::RouteInformationTable                 RouteInformationTable;
                typedef std::shared_ptr<RouteInformationTable>                  RouteInformationTablePtr;
                typedef ppp::net::native::ForwardInformationTable               ForwardInformationTable;
                typedef std::shared_ptr<ForwardInformationTable>                ForwardInformationTablePtr;
#ifdef _WIN32
                typedef lsp::PaperAirplaneController                            PaperAirplaneController;
                typedef std::shared_ptr<PaperAirplaneController>                PaperAirplaneControllerPtr;
#elif _LINUX
                typedef ppp::net::ProtectorNetwork                              ProtectorNetwork;
                typedef std::shared_ptr<ProtectorNetwork>                       ProtectorNetworkPtr;
#endif

            public:
                std::shared_ptr<VEthernetTickEventHandler>                      TickEvent;

            public:
                VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;
                virtual ~VEthernetNetworkSwitcher() noexcept;

            public:
                std::shared_ptr<ppp::configurations::AppConfiguration>          GetConfiguration() noexcept;
                std::shared_ptr<VEthernetExchanger>                             GetExchanger() noexcept;
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>           GetQoS() noexcept;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>&   GetStatistics() noexcept;
                std::shared_ptr<VirtualEthernetInformation>                     GetInformation() noexcept;
                VEthernetHttpProxySwitcherPtr                                   GetHttpProxy() noexcept;
                RouteInformationTablePtr                                        GetRib() noexcept;
                ForwardInformationTablePtr                                      GetFib() noexcept;
                bool                                                            IsBlockQUIC() noexcept;
#ifdef _WIN32
                PaperAirplaneControllerPtr                                      GetPaperAirplaneController() noexcept;
                virtual bool                                                    SetHttpProxyToSystemEnv() noexcept;
                virtual bool                                                    ClearHttpProxyToSystemEnv() noexcept;
#elif _LINUX
                ProtectorNetworkPtr                                             GetProtectorNetwork() noexcept;
#endif

            public:
                std::shared_ptr<NetworkInterface>                               GetTapNetworkInterface() noexcept;
                std::shared_ptr<NetworkInterface>                               GetUnderlyingNetowrkInterface() noexcept;

            public:
                virtual bool                                                    BlockQUIC(bool value) noexcept;
                virtual bool                                                    AddLoadIPList(const ppp::string& path) noexcept;

            public:
                virtual bool                                                    Constructor(const std::shared_ptr<ITap>& tap) noexcept override;
                virtual void                                                    Dispose() noexcept override;
                virtual std::shared_ptr<ppp::threading::BufferswapAllocator>    GetBufferAllocator() noexcept override;
                virtual ppp::string                                             GetRemoteUri() noexcept;
                virtual boost::asio::ip::tcp::endpoint                          GetRemoteEndPoint() noexcept;

            protected:
                virtual bool                                                    OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept override;
                virtual bool                                                    OnTick(uint64_t now) noexcept override;
                virtual bool                                                    OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information) noexcept;

            protected:
                virtual std::shared_ptr<VEthernetExchanger>                     NewExchanger() noexcept;
                virtual std::shared_ptr<ppp::ethernet::VNetstack>               NewNetstack() noexcept override;
                virtual VEthernetHttpProxySwitcherPtr                           NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                virtual std::shared_ptr<ppp::transmissions::ITransmissionQoS>   NewQoS() noexcept;
                virtual ITransmissionStatisticsPtr                              NewStatistics() noexcept;
#ifdef _WIN32
                virtual PaperAirplaneControllerPtr                              NewPaperAirplaneController() noexcept;
#elif _LINUX
                virtual ProtectorNetworkPtr                                     NewProtectorNetwork() noexcept;
#endif
                virtual bool                                                    DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size) noexcept;

            protected:
                virtual void                                                    AddRoute() noexcept;
                virtual void                                                    DeleteRoute() noexcept;

            private:
                void                                                            Finalize() noexcept;
                void                                                            ReleaseAllObjects(bool ctor) noexcept;
                bool                                                            OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;
                bool                                                            OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;

            private:
#ifdef _WIN32
                bool                                                            UsePaperAirplaneController() noexcept;
#endif
                void                                                            AddRouteWithDnsServers() noexcept;
                void                                                            DeleteRouteWithDnsServers() noexcept;
                bool                                                            AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept;
                bool                                                            LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;

            private:
                bool                                                            ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool                                                            TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool                                                            ERORTE(int ack_id) noexcept;
                bool                                                            IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept { return ip == gw ? true : htonl((ntohl(gw) & ntohl(mask)) + 1) == ip; }
                bool                                                            EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool                                                            EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

            private:
                typedef ppp::set<ppp::string>                                   LoadIPListFileSet;
                typedef std::shared_ptr<LoadIPListFileSet>                      LoadIPListFileSetPtr;
                typedef ppp::unordered_set<boost::asio::ip::address>            NicDnsServerAddresses;
                typedef ppp::unordered_map<int, NicDnsServerAddresses>          AllNicDnsServerAddresses;

            private:
                std::shared_ptr<VEthernetExchanger>                             exchanger_;
                std::shared_ptr<ppp::configurations::AppConfiguration>          configuration_;
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>           qos_;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>    statistics_;
                VEthernetIcmpPacketTable                                        icmppackets_;
                int                                                             icmppackets_aid_;
                bool                                                            block_quic_;
                bool                                                            route_added_;
                VEthernetHttpProxySwitcherPtr                                   http_proxy_;
                std::shared_ptr<NetworkInterface>                               tun_ni;
                std::shared_ptr<NetworkInterface>                               underlying_ni_;
                RouteInformationTablePtr                                        rib_;
                ForwardInformationTablePtr                                      fib_;
                LoadIPListFileSetPtr                                            ribs_;
                ppp::string                                                     server_ru_;
                boost::asio::ip::tcp::endpoint                                  server_ep_;
                ppp::unordered_set<uint32_t>                                    dns_servers_;
#ifdef _WIN32
                PaperAirplaneControllerPtr                                      paper_airplane_ctrl_;
                ppp::vector<MIB_IPFORWARDROW>                                   default_routes_;
                AllNicDnsServerAddresses                                        ni_dns_servers_;
#elif _LINUX
                ProtectorNetworkPtr                                             protect_network_;
                ppp::string                                                     ni_dns_servers_;
                ppp::vector<boost::asio::ip::address>                           ui_dns_servers_;
                RouteInformationTablePtr                                        default_routes_;
#endif
            };
        }
    }
}