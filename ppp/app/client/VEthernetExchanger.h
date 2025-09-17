#pragma once

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/mux/vmux_net.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/Int128.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/threading/Timer.h>
#include <ppp/auxiliary/UriAuxiliary.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;
            class VEthernetDatagramPort;

            class VEthernetExchanger : public ppp::app::protocol::VirtualEthernetLinklayer {
                friend class                                                            VEthernetDatagramPort;
                friend class                                                            VEthernetNetworkSwitcher;

            public:
                typedef std::shared_ptr<VEthernetNetworkSwitcher>                       VEthernetNetworkSwitcherPtr;
                typedef ppp::app::protocol::VirtualEthernetInformation                  VirtualEthernetInformation;
                typedef ppp::auxiliary::UriAuxiliary                                    UriAuxiliary;
                typedef UriAuxiliary::ProtocolType                                      ProtocolType;
                typedef ppp::threading::Timer                                           Timer;
                typedef std::shared_ptr<Timer>                                          TimerPtr;
                typedef ppp::unordered_map<void*, TimerPtr>                             TimerTable;
                typedef std::shared_ptr<VEthernetDatagramPort>                          VEthernetDatagramPortPtr;
                typedef ppp::threading::Executors::StrandPtr                            StrandPtr;
                typedef std::mutex                                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                             SynchronizedObjectScope;

            private:
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,
                    VEthernetDatagramPortPtr>                                           VEthernetDatagramPortTable;
                typedef ppp::app::protocol::VirtualEthernetMappingPort                  VirtualEthernetMappingPort;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                     VirtualEthernetMappingPortPtr;
                typedef ppp::unordered_map<uint32_t, VirtualEthernetMappingPortPtr>     VirtualEthernetMappingPortTable;
                typedef ppp::cryptography::Ciphertext                                   Ciphertext;
                typedef std::shared_ptr<Ciphertext>                                     CiphertextPtr;
                typedef std::shared_ptr<boost::asio::deadline_timer>                    DeadlineTimerPtr;
                typedef ppp::unordered_map<void*, DeadlineTimerPtr>                     DeadlineTimerTable;

            public:
                VEthernetExchanger(
                    const VEthernetNetworkSwitcherPtr&                                  switcher,
                    const AppConfigurationPtr&                                          configuration,
                    const ContextPtr&                                                   context,
                    const Int128&                                                       id) noexcept;
                virtual ~VEthernetExchanger() noexcept;

            public:
                typedef enum {
                    NetworkState_Connecting,
                    NetworkState_Established,
                    NetworkState_Reconnecting,
                }                                                                       NetworkState;

            public:
                NetworkState                                                            GetNetworkState()       noexcept { return network_state_.load(); }
                std::shared_ptr<Byte>                                                   GetBuffer()             noexcept { return buffer_; }
                std::shared_ptr<vmux::vmux_net>                                         GetMux()                noexcept { return mux_; }
                VEthernetNetworkSwitcherPtr                                             GetSwitcher()           noexcept { return switcher_; }
                std::shared_ptr<VirtualEthernetInformation>                             GetInformation()        noexcept { return information_; }
                ITransmissionPtr                                                        GetTransmission()       noexcept { return transmission_; }
                int                                                                     GetReconnectionCount()  noexcept { return reconnection_count_; }
                NetworkState                                                            GetMuxNetworkState()    noexcept;
                virtual bool                                                            Open()                  noexcept;
                virtual void                                                            Dispose()               noexcept;
                virtual ITransmissionPtr                                                ConnectTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept;
                
            public:
                template <typename F>
                void                                                                    Post(F&& f) noexcept {
#if defined(_ANDROID)
                    auto context = GetContext();
                    if (context) {
                        auto self = shared_from_this();
                        boost::asio::post(*context, 
                            [self, f]() noexcept {
                                f();
                            });
                    }
#else   
                    f();
#endif
                }

            public:
                virtual bool                                                            Nat(const void* packet, int packet_size) noexcept;
                virtual bool                                                            Echo(int ack_id) noexcept;
                virtual bool                                                            Echo(const void* packet, int packet_size) noexcept;
                virtual bool                                                            SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept;
                virtual bool                                                            Update() noexcept;
                bool                                                                    StaticEchoAllocated() noexcept;
                virtual bool                                                            GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept;

            protected:
                virtual bool                                                            OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept override;
                virtual bool                                                            OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                            OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept override;
                virtual bool                                                            OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                            OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override;
                virtual bool                                                            OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override;
                virtual bool                                                            OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept override;
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept override;
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                            OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                            OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept override;
                virtual bool                                                            OnStatic(const ITransmissionPtr& transmission, int session_id, int remote_port, YieldContext& y) noexcept override;
                virtual bool                                                            OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept override;

            protected:
                virtual VEthernetDatagramPortPtr                                        NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual VEthernetDatagramPortPtr                                        GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual VEthernetDatagramPortPtr                                        ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            protected:
                virtual ITransmissionPtr                                                NewTransmission(
                    const ContextPtr&                                                   context,
                    const StrandPtr&                                                    strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                    ProtocolType                                                        protocol_type,
                    const ppp::string&                                                  host,
                    const ppp::string&                                                  path) noexcept;
                virtual ITransmissionPtr                                                OpenTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept;

            protected:
                virtual std::shared_ptr<boost::asio::ip::tcp::socket>                   NewAsynchronousSocket(const ContextPtr& context, const StrandPtr& strand, const boost::asio::ip::tcp& protocol, ppp::coroutines::YieldContext& y) noexcept;
                virtual bool                                                            Loopback(const ContextPtr& context, YieldContext& y) noexcept;
                virtual bool                                                            PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                ITransmissionPtr                                                        OpenTransmission(const ContextPtr& context, YieldContext& y) noexcept {
                    StrandPtr strand;
                    return OpenTransmission(context, strand, y);
                }
                void                                                                    Finalize() noexcept;
                void                                                                    ExchangeToEstablishState() noexcept;
                void                                                                    ExchangeToConnectingState() noexcept;
                void                                                                    ExchangeToReconnectingState() noexcept;
                int                                                                     EchoLanToRemoteExchanger(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                bool                                                                    SendEchoKeepAlivePacket(UInt64 now, bool immediately) noexcept;
                bool                                                                    ReceiveFromDestination(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length) noexcept;
                VEthernetDatagramPortPtr                                                AddNewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                template <typename TTransmission>
                typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>/**/>::type
                inline                                                                  NewWebsocketTransmission(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const ppp::string& host, const ppp::string& path) noexcept {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    if (NULL == configuration) {
                        return NULL;
                    }

                    auto transmission = make_shared_object<TTransmission>(context, strand, socket, configuration);
                    if (NULL == transmission) {
                        return NULL;
                    }
                    
                    if (host.size() > 0 && path.size() > 0) {
                        transmission->Host = host;
                        transmission->Path = path;
                    }

                    return transmission;
                }

            private:
                VirtualEthernetMappingPortPtr                                           GetMappingPort(bool in, bool tcp, int remote_port) noexcept;
                VirtualEthernetMappingPortPtr                                           NewMappingPort(bool in, bool tcp, int remote_port) noexcept;
                bool                                                                    RegisterMappingPort(ppp::configurations::AppConfiguration::MappingConfiguration& mapping) noexcept;
                void                                                                    UnregisterAllMappingPorts() noexcept;
                bool                                                                    RegisterAllMappingPorts() noexcept;
                bool                                                                    ReleaseDeadlineTimer(const boost::asio::deadline_timer* deadline_timer) noexcept;
                bool                                                                    NewDeadlineTimer(const ContextPtr& context, int64_t timeout, const ppp::function<void(bool)>& event) noexcept;
                bool                                                                    Sleep(int64_t timeout, const ContextPtr& context, YieldContext& y) noexcept;
#if defined(_ANDROID)
                bool                                                                    AwaitJniAttachThread(const ContextPtr& context, YieldContext& y) noexcept;
#endif
                virtual bool                                                            DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept override;
                bool                                                                    DoMuxEvents() noexcept;
                bool                                                                    MuxConnectAllLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<vmux::vmux_net>& mux) noexcept;

            private:
                class StaticEchoDatagarmSocket final : public boost::asio::ip::udp::socket {
                public:
                    StaticEchoDatagarmSocket(boost::asio::io_context& context) noexcept 
                        : basic_datagram_socket(context)
                        , opened(false) {

                    }
                    virtual ~StaticEchoDatagarmSocket() noexcept {
                        boost::asio::ip::udp::socket* my = this;
                        destructor_invoked(my);
                    }

                public:
                    bool                                                                is_open(bool only_native = false) noexcept { return only_native ? basic_datagram_socket::is_open() : opened && basic_datagram_socket::is_open(); }

                public:
                    bool                                                                opened = false;
                };
                bool                                                                    StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;
                boost::asio::ip::udp::endpoint                                          StaticEchoGetRemoteEndPoint() noexcept;
                void                                                                    StaticEchoClean() noexcept;
                bool                                                                    StaticEchoNextTimeout() noexcept;
                bool                                                                    StaticEchoSwapAsynchronousSocket() noexcept;
                bool                                                                    StaticEchoGatewayServer(int ack_id) noexcept;
                int                                                                     StaticEchoYieldReceiveForm(Byte* incoming_packet, int incoming_traffic) noexcept;
                void                                                                    StaticEchoYieldReceiveForm(std::shared_ptr<StaticEchoDatagarmSocket>& socket, VEthernetExchanger* my, YieldContext& y, int* bytes_transferred) noexcept;
                bool                                                                    StaticEchoLoopbackSocket(const std::weak_ptr<StaticEchoDatagarmSocket>& socket_weak) noexcept;
                bool                                                                    StaticEchoOpenAsynchronousSocket(StaticEchoDatagarmSocket& socket, YieldContext& y) noexcept;
                bool                                                                    StaticEchoAllocatedToRemoteExchanger(YieldContext& y) noexcept;
                bool                                                                    StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
                bool                                                                    StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept;
                bool                                                                    StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept;
                bool                                                                    StaticEchoPacketInput(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept;
                std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>              StaticEchoReadPacket(const void* packet, int packet_length) noexcept;

            private:
                virtual bool                                                            OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                virtual bool                                                            OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept override;
                virtual bool                                                            OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept override;
                virtual bool                                                            OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept override;

            private:
                SynchronizedObject                                                      syncobj_;

                struct {
                    bool                                                                disposed_           : 1;
                    bool                                                                static_echo_input_  : 7;
                };

                std::shared_ptr<Byte>                                                   buffer_;            

                UInt64                                                                  sekap_last_         = 0;
                UInt64                                                                  sekap_next_         = 0;

                VEthernetNetworkSwitcherPtr                                             switcher_;
                std::shared_ptr<VirtualEthernetInformation>                             information_;
                VEthernetDatagramPortTable                                              datagrams_;
                ITransmissionPtr                                                        transmission_;
                std::atomic<NetworkState>                                               network_state_      = NetworkState_Connecting;
                VirtualEthernetMappingPortTable                                         mappings_;
                DeadlineTimerTable                                                      deadline_timers_;

                std::shared_ptr<vmux::vmux_net>                                         mux_;
                uint16_t                                                                mux_vlan_           = 0;
                
                int                                                                     reconnection_count_ = 0;

                struct {
                    boost::asio::ip::tcp::endpoint                                      remoteEP;
                    ppp::string                                                         hostname;
                    ppp::string                                                         address;
                    ppp::string                                                         path;
                    ppp::string                                                         server;
                    int                                                                 port                = 0;
                    ProtocolType                                                        protocol_type       = ProtocolType::ProtocolType_PPP;
                }                                                                       server_url_;

                CiphertextPtr                                                           static_echo_protocol_;
                CiphertextPtr                                                           static_echo_transport_;
                std::shared_ptr<StaticEchoDatagarmSocket>                               static_echo_sockets_[2];
                boost::asio::ip::udp::endpoint                                          static_echo_source_ep_;
                ppp::list<boost::asio::ip::udp::endpoint>                               static_echo_server_ep_balances_;
                ppp::unordered_set<boost::asio::ip::udp::endpoint>                      static_echo_server_ep_set_;
                
                uint64_t                                                                static_echo_timeout_     = 0;
                int                                                                     static_echo_session_id_  = 0;
                int                                                                     static_echo_remote_port_ = 0;
            };
        }
    }
}