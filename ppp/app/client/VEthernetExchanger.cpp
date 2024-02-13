#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
typedef ppp::collections::Dictionary                                Dictionary;
typedef ppp::auxiliary::StringAuxiliary                             StringAuxiliary;
typedef ppp::net::AddressFamily                                     AddressFamily;
typedef ppp::net::Socket                                            Socket;
typedef ppp::net::IPEndPoint                                        IPEndPoint;
typedef ppp::net::Ipep                                              Ipep;
typedef ppp::threading::Timer                                       Timer;
typedef ppp::threading::Executors                                   Executors;
typedef ppp::transmissions::ITransmission                           ITransmission;
typedef ppp::transmissions::ITcpipTransmission                      ITcpipTransmission;
typedef ppp::transmissions::IWebsocketTransmission                  IWebsocketTransmission;
typedef ppp::transmissions::ISslWebsocketTransmission               ISslWebsocketTransmission;

namespace ppp {
    namespace app {
        namespace client {
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT = 1000;
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT = 5000;
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT = SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT << 2;

            VEthernetExchanger::VEthernetExchanger(
                const VEthernetNetworkSwitcherPtr&      switcher,
                const AppConfigurationPtr&              configuration,
                const ContextPtr&                       context,
                const Int128&                           id) noexcept
                : VirtualEthernetLinklayer(configuration, context, id)
                , disposed_(false)
                , sekap_last_(0)
                , sekap_next_(0)
                , switcher_(switcher)
                , network_state_(NetworkState_Connecting) {

            }

            VEthernetExchanger::~VEthernetExchanger() noexcept {
                Finalize();
            }

            void VEthernetExchanger::Finalize() noexcept {
                exchangeof(disposed_, true); {
                    Dictionary::ReleaseAllObjects(datagrams_);
                    datagrams_.clear();

                    Dictionary::ReleaseAllObjects(mappings_);
                    mappings_.clear();

                    ITransmissionPtr transmission = std::move(transmission_);
                    if (transmission) {
                        transmission_.reset();
                        transmission->Dispose();
                    }
                }
            }

            void VEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            VEthernetExchanger::NetworkState VEthernetExchanger::GetNetworkState() noexcept {
                return network_state_.load();
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::NewTransmission(
                const ContextPtr&                                                   context,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                ProtocolType                                                        protocol_type,
                const ppp::string&                                                  host,
                const ppp::string&                                                  path) noexcept {

                ITransmissionPtr transmission;
                if (protocol_type == ProtocolType::ProtocolType_Http ||
                    protocol_type == ProtocolType::ProtocolType_WebSocket) {
                    transmission = NewWebsocketTransmission<IWebsocketTransmission>(context, socket, host, path);
                }
                elif(protocol_type == ProtocolType::ProtocolType_HttpSSL ||
                    protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ISslWebsocketTransmission>(context, socket, host, path);
                }
                else {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    transmission = make_shared_object<ITcpipTransmission>(context, socket, configuration);
                }

                if (NULL != transmission) {
                    transmission->QoS = switcher_->GetQoS();
                    transmission->Statistics = switcher_->GetStatistics();
                }
                return transmission;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetExchanger::NewAsynchronousSocket(const ContextPtr& context, const boost::asio::ip::tcp& protocol) noexcept {
                if (disposed_) {
                    return NULL;
                }

                if (!context) {
                    return NULL;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
                if (!socket) {
                    return NULL;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return NULL;
                }

                boost::system::error_code ec;
                socket->open(protocol, ec);

                bool in4 = protocol == boost::asio::ip::tcp::v4();
                if (ec) {
                    return NULL;
                }

                Socket::AdjustSocketOptional(*socket, in4, configuration->tcp.fast_open, configuration->tcp.turbo);
                return socket;
            }

            bool VEthernetExchanger::GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                std::shared_ptr<ppp::string> server_url = server_url_;
                if (server_url) {
                    server = UriAuxiliary::Parse(*server_url, hostname, address, path, port, protocol_type, *y);
                }
                else {
                    ppp::string& client_server_string = configuration->client.server;
                    if (client_server_string.empty()) {
                        return false;
                    }

                    server_url = make_shared_object<ppp::string>();
                    if (!server_url) {
                        return false;
                    }

                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, server_url.get(), *y);
                }

                if (server.empty()) {
                    return false;
                }

                if (hostname.empty()) {
                    return false;
                }

                if (address.empty()) {
                    return false;
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    return false;
                }

                IPEndPoint ipep(address.data(), port);
                if (IPEndPoint::IsInvalid(ipep)) {
                    return false;
                }
                elif(!server_url_) {
                    server_url_ = server_url;
                }

                remoteEP = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep);
                return true;
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::OpenTransmission(const ContextPtr& context, YieldContext& y) noexcept {
                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                if (!GetRemoteEndPoint(y.GetPtr(), hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return NULL;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (IPEndPoint::IsInvalid(remoteIP)) {
                    return NULL;
                }

                int remotePort = remoteEP.port();
                if (remotePort <= IPEndPoint::MinPort || remotePort > IPEndPoint::MaxPort) {
                    return NULL;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = NewAsynchronousSocket(context, remoteEP.protocol());
                if (!socket) {
                    return NULL;
                }

#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
                // IPV6 does not need to be linked, because VPN is IPV4, 
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (remoteIP.is_v4() && !remoteIP.is_loopback()) {
                    if (auto protector_network = switcher_->GetProtectorNetwork(); NULL != protector_network) {
                        if (!protector_network->Protect(socket->native_handle(), y)) {
                            return NULL;
                        }
                    }
                }
#endif

                if (!ppp::coroutines::asio::async_connect(*socket, remoteEP, y)) {
                    return NULL;
                }

                return NewTransmission(context, socket, protocol_type, hostname, path);
            }

            bool VEthernetExchanger::Open() noexcept {
                if (disposed_) {
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                ContextPtr context = GetContext();
                if (!context) {
                    return false;
                }

                auto self = shared_from_this();
                auto allocator = configuration->GetBufferAllocator();
                return YieldContext::Spawn(allocator.get(), *context,
                    [self, this, context](YieldContext& y) noexcept {
                        Loopback(context, y);
                    });
            }

            bool VEthernetExchanger::Update(UInt64 now) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this, now]() noexcept {
                        SendEchoKeepAlivePacket(now, false);
                        Dictionary::UpdateAllObjects(datagrams_, now);
                        Dictionary::UpdateAllObjects2(mappings_, now);
                    });
                return true;
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::ConnectTransmission(const ContextPtr& context, YieldContext& y) noexcept {
                if (NULL == context) {
                    return NULL;
                }

                if (disposed_) {
                    return NULL;
                }
                else {
                    // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                    ITransmissionPtr link = transmission_;
                    if (NULL == link) {
                        return NULL;
                    }
                }

                ITransmissionPtr transmission = OpenTransmission(context, y);
                if (NULL == transmission) {
                    return NULL;
                }

                bool ok = transmission->HandshakeServer(y, GetId(), false);
                if (!ok) {
                    transmission->Dispose();
                    return NULL;
                }

                return transmission;
            }

            bool VEthernetExchanger::Loopback(const ContextPtr& context, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                bool run_once = false;
                while (!disposed_) {
                    ExchangeToConnectingState(); {
                        ITransmissionPtr transmission = OpenTransmission(context, y);
                        if (transmission) {
                            if (transmission->HandshakeServer(y, GetId(), true)) {
                                if (y && EchoLanToRemoteExchanger(transmission, y) > -1) {
                                    ExchangeToEstablishState(); {
                                        transmission_ = transmission; {
                                            RegisterAllMappingPorts();
                                            if (Run(transmission, y)) {
                                                run_once = true;
                                            }

                                            UnregisterAllMappingPorts();
                                        }
                                        transmission_.reset();
                                    }
                                }
                            }

                            transmission->Dispose();
                            transmission.reset();
                        }
                    } ExchangeToReconnectingState();

                    uint64_t reconnections_timeout = (uint64_t)configuration->client.reconnections.timeout * 1000;
                    if (!ppp::coroutines::asio::async_sleep(y, context, reconnections_timeout)) {
                        break;
                    }
                }
                return run_once;
            }

            void VEthernetExchanger::ExchangeToEstablishState() noexcept {
                uint64_t now = Executors::GetTickCount();
                sekap_last_ = Executors::GetTickCount();
                sekap_next_ = now + RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT, SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT);
                network_state_.exchange(NetworkState_Established);
            }

            void VEthernetExchanger::ExchangeToConnectingState() noexcept {
                sekap_last_ = 0;
                sekap_next_ = 0;
                network_state_.exchange(NetworkState_Connecting);
            }

            void VEthernetExchanger::ExchangeToReconnectingState() noexcept {
                sekap_last_ = 0;
                sekap_next_ = 0;
                network_state_.exchange(NetworkState_Reconnecting);
            }

            bool VEthernetExchanger::RegisterAllMappingPorts() noexcept {
                if (disposed_) {
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                for (AppConfiguration::MappingConfiguration& mapping : configuration->client.mappings) {
                    RegisterMappingPort(mapping);
                }

                return true;
            }

            void VEthernetExchanger::UnregisterAllMappingPorts() noexcept {
                VirtualEthernetMappingPortTable mappings = std::move(mappings_);
                mappings_.clear();

                ppp::collections::Dictionary::ReleaseAllObjects(mappings);
            }

            VEthernetExchanger::VEthernetNetworkSwitcherPtr VEthernetExchanger::GetSwitcher() noexcept {
                return switcher_;
            }

            std::shared_ptr<VEthernetExchanger::VirtualEthernetInformation> VEthernetExchanger::GetInformation() noexcept {
                return information_;
            }

            bool VEthernetExchanger::OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                bool vnet = switcher_->IsVNet();
                if (vnet) {
                    return switcher_->Output(packet, packet_length);
                }
                else {
                    return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
                }
            }

            bool VEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULL == context) {
                    return false;
                }

                auto ei = make_shared_object<VirtualEthernetInformation>(information);
                if (NULL == ei) {
                    return false;
                }
                
                auto self = shared_from_this();
                context->post(
                    [self, this, ei]() noexcept {
                        information_ = ei;
                        if (!disposed_) {
                            switcher_->OnInformation(ei);
                        }
                    });
                return true;
            }

            bool VEthernetExchanger::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                if (ack_id != 0) {
                    switcher_->ERORTE(ack_id);
                }
                return true;
            }

            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                switcher_->Output(packet, packet_length);
                return true;
            }

            bool VEthernetExchanger::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                ReceiveFromDestination(sourceEP, destinationEP, packet, packet_length);
                return true;
            }

            bool VEthernetExchanger::ReceiveFromDestination(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length) noexcept {
                VEthernetDatagramPortPtr datagram = GetDatagramPort(sourceEP);
                if (NULL != datagram) {
                    if (NULL == packet || packet_length < 1) {
                        datagram->MarkFinalize();
                        datagram->Dispose();
                    }
                    else {
                        datagram->OnMessage(packet, packet_length, destinationEP);
                    }
                    return true;
                }
                else {
                    return false;
                }
            }

            bool VEthernetExchanger::SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept {
                if (NULL == packet || packet_size < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                VEthernetDatagramPortPtr datagram = AddNewDatagramPort(transmission, sourceEP);
                if (NULL == datagram) {
                    return false;
                }

                return datagram->SendTo(packet, packet_size, destinationEP);
            }

            bool VEthernetExchanger::Echo(int ack_id) noexcept {
                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                bool ok = DoEcho(transmission_, ack_id, nullof<YieldContext>());
                if (!ok) {
                    transmission_->Dispose();
                }

                return ok;
            }

            bool VEthernetExchanger::Echo(const void* packet, int packet_size) noexcept {
                if (NULL == packet || packet_size < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                bool ok = DoEcho(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            bool VEthernetExchanger::Nat(const void* packet, int packet_size) noexcept {
                if (NULL == packet || packet_size < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                bool ok = DoNat(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            int VEthernetExchanger::EchoLanToRemoteExchanger(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_) {
                    return -1;
                }

                bool vnet = switcher_->IsVNet();
                if (!vnet) {
                    return 0;
                }

                if (NULL == transmission) {
                    return -1;
                }

                std::shared_ptr<ppp::tap::ITap> tap = switcher_->GetTap();
                if (NULL == tap) {
                    return -1;
                }

                bool ok = DoLan(transmission, tap->IPAddress, tap->SubmaskAddress, y);
                if (ok) {
                    return 1;
                }

                transmission->Dispose();
                return -1;
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::GetTransmission() noexcept {
                return transmission_;
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::AddNewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }

                VEthernetDatagramPortPtr datagram = GetDatagramPort(sourceEP);
                if (NULL != datagram) {
                    return datagram;
                }

                if (disposed_) {
                    return NULL;
                }

                datagram = NewDatagramPort(transmission, sourceEP);
                if (NULL == datagram) {
                    return NULL;
                }

                auto r = datagrams_.emplace(sourceEP, datagram);
                if (!r.second) {
                    datagram->Dispose();
                    return NULL;
                }

                return datagram;
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = std::dynamic_pointer_cast<VEthernetExchanger>(shared_from_this());
                if (NULL == exchanger) { /* ??? */
                    return NULL;
                }

                return make_shared_object<VEthernetDatagramPort>(exchanger, transmission, sourceEP);
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::FindObjectByKey(datagrams_, sourceEP);
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::ReleaseObjectByKey(datagrams_, sourceEP);
            }

            bool VEthernetExchanger::SendEchoKeepAlivePacket(UInt64 now, bool immediately) noexcept {
                if (network_state_ != NetworkState_Established) {
                    return false;
                }

                UInt64 next = sekap_last_ + SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT;
                if (now >= next) {
                    ITransmissionPtr transmission = transmission_;
                    if (transmission) {
                        transmission->Dispose();
                        return false;
                    }
                }

                if (!immediately) {
                    if (now < sekap_next_) {
                        return false;
                    }
                }

                sekap_next_ = now + RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT, SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT);
                return Echo(0);
            }

            bool VEthernetExchanger::PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept {
                bool ok = VirtualEthernetLinklayer::PacketInput(transmission, p, packet_length, y);
                if (ok) {
                    if (network_state_ == NetworkState_Established) {
                        sekap_last_ = Executors::GetTickCount();
                    }
                }
                return ok;
            }

            bool VEthernetExchanger::RegisterMappingPort(ppp::configurations::AppConfiguration::MappingConfiguration& mapping) noexcept {
                if (disposed_) {
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = boost::asio::ip::address::from_string(mapping.local_ip.data(), ec);
                if (ec) {
                    return false;
                }

                boost::asio::ip::address remote_ip = boost::asio::ip::address::from_string(mapping.remote_ip.data(), ec);
                if (ec) {
                    return false;
                }

                bool in = remote_ip.is_v4();
                bool protocol_tcp_or_udp = mapping.protocol_tcp_or_udp;

                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULL != mapping_port) {
                    return false;
                }

                mapping_port = NewMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULL == mapping_port) {
                    return false;
                }

                bool ok = mapping_port->OpenFrpClient(local_ip, mapping.local_port);
                if (ok) {
                    ok = VirtualEthernetMappingPort::AddMappingPort(mappings_, in, protocol_tcp_or_udp, mapping.remote_port, mapping_port);
                }

                if (!ok) {
                    mapping_port->Dispose();
                }
                return ok;
            }

            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class MappingPort : public VirtualEthernetMappingPort {
                public:
                    MappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    virtual void Dispose() noexcept override {
                        VirtualEthernetMappingPort::Dispose();

                        if (std::shared_ptr<VirtualEthernetLinklayer> linklayer = GetLinklayer();  NULL != linklayer) {
                            VEthernetExchanger* exchanger = dynamic_cast<VEthernetExchanger*>(linklayer.get());
                            if (NULL != exchanger) {
                                VirtualEthernetMappingPort::DeleteMappingPort(exchanger->mappings_, ProtocolIsNetworkV4(), ProtocolIsTcpNetwork(), GetRemotePort());
                            }
                        }
                    }
                };

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return NULL;
                }

                auto self = shared_from_this();
                return make_shared_object<MappingPort>(self, transmission, tcp, in, remote_port);
            }

            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                return VirtualEthernetMappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
            }

            bool VEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Client_OnFrpSendTo(packet, packet_length, sourceEP);
                }

                return true;
            }

            bool VEthernetExchanger::OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Client_OnFrpConnect(connection_id);
                }

                return true;
            }

            bool VEthernetExchanger::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Client_OnFrpDisconnect(connection_id);
                }

                return true;
            }

            bool VEthernetExchanger::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Client_OnFrpPush(connection_id, packet, packet_length);
                }

                return true;
            }
        }
    }
}