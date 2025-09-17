#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
typedef ppp::app::protocol::VirtualEthernetPacket                   VirtualEthernetPacket;
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
            static constexpr int STATIC_ECHO_KEEP_ALIVED_ID              = IPEndPoint::NoneAddress - 1;

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
                , network_state_(NetworkState_Connecting)
                , static_echo_input_(false)
                , static_echo_timeout_(UINT64_MAX)
                , static_echo_session_id_(0)
                , static_echo_remote_port_(IPEndPoint::MinPort) {

                if (configuration->key.protocol.size() > 0 && configuration->key.protocol_key.size() > 0 && 
                    configuration->key.transport.size() > 0 && configuration->key.transport_key.size() > 0) {
                    if (Ciphertext::Support(configuration->key.protocol) && Ciphertext::Support(configuration->key.transport)) {
                        static_echo_protocol_ = make_shared_object<Ciphertext>(configuration->key.protocol, configuration->key.protocol_key);
                        static_echo_transport_ = make_shared_object<Ciphertext>(configuration->key.transport, configuration->key.transport_key);
                    }
                }
                
                buffer_                   = Executors::GetCachedBuffer(context);
                server_url_.port          = 0;
                server_url_.protocol_type = ProtocolType::ProtocolType_PPP;
            }

            VEthernetExchanger::~VEthernetExchanger() noexcept {
                Finalize();
            }

            void VEthernetExchanger::Finalize() noexcept {
                VirtualEthernetMappingPortTable mappings;
                VEthernetDatagramPortTable datagrams;
                ITransmissionPtr transmission;
                DeadlineTimerTable deadline_timers;
                std::shared_ptr<vmux::vmux_net> mux;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);

                    mappings = std::move(mappings_);
                    mappings_.clear();

                    datagrams = std::move(datagrams_);
                    datagrams_.clear();

                    transmission = std::move(transmission_);
                    transmission_.reset();

                    deadline_timers = std::move(deadline_timers_);
                    deadline_timers_.clear();
                    
                    mux_vlan_ = 0;
                    mux = std::move(mux_);
                    mux_.reset();
                    break;
                }

                StaticEchoClean();
                if (NULL != transmission) {
                    transmission->Dispose();
                }

                disposed_ = true;
                for (auto&& [_, deadline_timer] : deadline_timers) {
                    ppp::net::Socket::Cancel(*deadline_timer);
                }

                Dictionary::ReleaseAllObjects(mappings);
                Dictionary::ReleaseAllObjects(datagrams);

                if (NULL != mux) {
                    mux->close_exec();
                }
            }

            void VEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this, context]() noexcept {
                        Finalize();
                    });
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::NewTransmission(
                const ContextPtr&                                                   context,
                const StrandPtr&                                                    strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                ProtocolType                                                        protocol_type,
                const ppp::string&                                                  host,
                const ppp::string&                                                  path) noexcept {

                ITransmissionPtr transmission;
                if (protocol_type == ProtocolType::ProtocolType_Http ||
                    protocol_type == ProtocolType::ProtocolType_WebSocket) {
                    transmission = NewWebsocketTransmission<IWebsocketTransmission>(context, strand, socket, host, path);
                }
                elif(protocol_type == ProtocolType::ProtocolType_HttpSSL ||
                    protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ISslWebsocketTransmission>(context, strand, socket, host, path);
                }
                else {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    transmission = make_shared_object<ITcpipTransmission>(context, strand, socket, configuration);
                }

                if (NULL != transmission) {
                    transmission->QoS = switcher_->GetQoS();
                    transmission->Statistics = switcher_->GetStatistics();
                }
                
                return transmission;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetExchanger::NewAsynchronousSocket(const ContextPtr& context, const StrandPtr& strand, const boost::asio::ip::tcp& protocol, ppp::coroutines::YieldContext& y) noexcept {
                if (disposed_) {
                    return NULL;
                }

                if (!context) {
                    return NULL;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
                if (!socket) {
                    return NULL;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return NULL;
                }

                if (!ppp::coroutines::asio::async_open(y, *socket, protocol)) {
                    return NULL;
                }

                Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                Socket::AdjustSocketOptional(*socket, protocol == boost::asio::ip::tcp::v4(), configuration->tcp.fast_open, configuration->tcp.turbo);
                return socket;
            }

            bool VEthernetExchanger::GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                if (disposed_) {
                    return false;
                }

                if (server_url_.port > IPEndPoint::MinPort && server_url_.port <= IPEndPoint::MaxPort) {
                    remoteEP      = server_url_.remoteEP;
                    hostname      = server_url_.hostname;
                    address       = server_url_.address;
                    path          = server_url_.path;
                    server        = server_url_.server;
                    port          = server_url_.port;
                    protocol_type = server_url_.protocol_type;
                    return true;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                ppp::string& client_server_string = configuration->client.server;
                if (client_server_string.empty()) {
                    return false;
                }

                std::shared_ptr<ppp::transmissions::proxys::IForwarding> forwarding = switcher_->GetForwarding(); ;
                if (NULL != forwarding) {
                    ppp::string abs_url;
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, &abs_url, *y, false);
                }
                else {
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, *y);
                }

                if (server.empty()) {
                    return false;
                }

                if (hostname.empty()) {
                    return false;
                }

                if (NULL != forwarding) {
                    boost::asio::ip::tcp::endpoint forwarding_to_endpoint = forwarding->GetLocalEndPoint();
                    if (int forwarding_to_port = forwarding_to_endpoint.port(); forwarding_to_port > IPEndPoint::MinPort && forwarding_to_port < IPEndPoint::MaxPort) {
                        forwarding->SetRemoteEndPoint(hostname, port);
                        port = forwarding_to_port;
                        address = forwarding_to_endpoint.address().to_string();
                    }
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

                remoteEP                  = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep);
                server_url_.remoteEP      = remoteEP;
                server_url_.hostname      = hostname;
                server_url_.address       = address;
                server_url_.path          = path;
                server_url_.server        = server;
                server_url_.port          = port;
                server_url_.protocol_type = protocol_type;
                return true;
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::OpenTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept {
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

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = NewAsynchronousSocket(context, strand, remoteEP.protocol(), y);
                if (!socket) {
                    return NULL;
                }

#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
                // IPV6 does not need to be linked, because VPN is IPV4, 
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (remoteIP.is_v4() && !remoteIP.is_loopback()) {
                    auto protector_network = switcher_->GetProtectorNetwork(); 
                    if (NULL != protector_network) {
                        if (!protector_network->Protect(socket->native_handle(), y)) {
                            return NULL;
                        }
                    }
                }
#endif

                bool ok = ppp::coroutines::asio::async_connect(*socket, remoteEP, y);
                if (!ok) {
                    return NULL;
                }

                return NewTransmission(context, strand, socket, protocol_type, hostname, path);
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

            bool VEthernetExchanger::Update() noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this, context]() noexcept {
                        uint64_t now = ppp::threading::Executors::GetTickCount();
                        SendEchoKeepAlivePacket(now, false); 
                        DoMuxEvents();
                        DoKeepAlived(GetTransmission(), now);

                        for (;;) {
                            SynchronizedObjectScope scope(syncobj_);
                            Dictionary::UpdateAllObjects(datagrams_, now);
                            Dictionary::UpdateAllObjects2(mappings_, now);
                            break;
                        }
                    });
                return true;
            }

            bool VEthernetExchanger::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                if (disposed_) {
                    return false;
                }
                
                NetworkState network_state = GetNetworkState();
                if (network_state != NetworkState_Established) {
                    return true;
                }

                if (VirtualEthernetLinklayer::DoKeepAlived(transmission, now)) {
                    return true;
                }

                IDisposable::Dispose(transmission);
                return false;
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::ConnectTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept {
                if (NULL == context) {
                    return NULL;
                }

                if (disposed_) {
                    return NULL;
                }

                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                ITransmissionPtr owner_link = transmission_; 
                if (NULL == owner_link) {
                    return NULL;
                }

                ITransmissionPtr transmission = OpenTransmission(context, strand, y);
                if (NULL == transmission) {
                    return NULL;
                }

                bool noerror = transmission->HandshakeServer(y, GetId(), false);
                if (noerror) {
                    return transmission;
                }
                else {
                    transmission->Dispose();
                    return NULL;
                }
            }

#if defined(_ANDROID)
            bool VEthernetExchanger::AwaitJniAttachThread(const ContextPtr& context, YieldContext& y) noexcept {
                // On the Android platform, when the VPN tunnel transport layer is enabled, 
                // Ensure that the JVM thread has been attached to the PPP. Otherwise, the link cannot be protected, 
                // Resulting in loop problems and VPN loopback crashes.
                bool attach_ok = false;
                while (!disposed_) {
                    if (std::shared_ptr<ppp::net::ProtectorNetwork> protector = switcher_->GetProtectorNetwork(); NULL != protector) {
                        if (NULL != protector->GetContext() && NULL != protector->GetEnvironment()) {
                            attach_ok = true;
                            break;
                        }
                    }

                    bool sleep_ok = Sleep(10, context, y); // Poll.
                    if (!sleep_ok) {
                        break;
                    }
                }

                return attach_ok;
            }
#endif

            bool VEthernetExchanger::Loopback(const ContextPtr& context, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }
#if defined(_ANDROID)
                elif(!AwaitJniAttachThread(context, y)) {
                    return false;
                }
#endif
                bool run_once = false;
                while (!disposed_) {
                    ExchangeToConnectingState(); {
                        ITransmissionPtr transmission = OpenTransmission(context, y);
                        if (transmission) {
                            if (transmission->HandshakeServer(y, GetId(), true) && EchoLanToRemoteExchanger(transmission, y) > -1) {
                                ExchangeToEstablishState(); {
                                    transmission_ = transmission; {
                                        RegisterAllMappingPorts();
                                        if (StaticEchoAllocatedToRemoteExchanger(y) && Run(transmission, y)) {
                                            run_once = true;
                                            StaticEchoClean();
                                        }

                                        UnregisterAllMappingPorts();
                                    }
                                    transmission_.reset();
                                }
                            }

                            transmission->Dispose();
                            transmission.reset();
                        }
                    } ExchangeToReconnectingState();

                    int64_t reconnection_timeout = static_cast<int64_t>(configuration->client.reconnections.timeout) * 1000;
                    Sleep(reconnection_timeout, context, y);
                }
                return run_once;
            }

            bool VEthernetExchanger::DoMuxEvents() noexcept {
                bool successes = false;
                while (!disposed_) {
                    uint16_t max_connections = switcher_->mux_;
                    if (max_connections == 0) {
                        break;
                    }

                    if (network_state_.load() != NetworkState_Established) {
                        break;
                    }

                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULL == configuration) {
                        break;
                    }

                    std::shared_ptr<vmux::vmux_net> mux = mux_;
                    if (NULL != mux) {
                        bool breaking = true;
                        successes = true;

                        if (mux->Vlan != mux_vlan_) {
                            mux->close_exec();
                        }
                        elif(!mux->update()) {
                            int64_t reconnection_timeout = static_cast<int64_t>(configuration->client.reconnections.timeout) * 1000;
                            uint64_t mux_last = mux->get_last();

                            uint64_t now = mux->now_tick();
                            if (now >= (mux_last + (uint64_t)reconnection_timeout)) {
                                mux_.reset();
                                breaking = false;
                            }

                            mux->close_exec();
                        }

                        if (breaking) {
                            break;
                        }
                    }

                    ppp::threading::Executors::StrandPtr vmux_strand;
                    ppp::threading::Executors::ContextPtr vmux_context = ppp::threading::Executors::SelectScheduler(vmux_strand);
                    if (NULL == vmux_context) {
                        break;
                    }
                    else {
                        mux = make_shared_object<vmux::vmux_net>(vmux_context, vmux_strand, max_connections, false, (switcher_->mux_acceleration_ & PPP_MUX_ACCELERATION_LOCAL) != 0);
                        if (NULL == mux) {
                            break;
                        }
                    }

                    ITransmissionPtr vnet_transmission = GetTransmission();
                    if (NULL == vnet_transmission) {
                        break;
                    }

                    ppp::threading::Executors::ContextPtr vnet_context = GetContext();
                    if (NULL == vnet_context) {
                        break;
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> buffer_allocator = switcher_->GetBufferAllocator();
                    mux->AppConfiguration = configuration;
                    mux->BufferAllocator  = buffer_allocator;
#if defined(_LINUX)
                    mux->ProtectorNetwork = switcher_->GetProtectorNetwork();
#endif

                    for (;;) {
                        uint16_t vlan = (uint16_t)vmux::vmux_net::ftt_random_aid(1, UINT16_MAX);
                        if (vlan != 0 && vlan != mux_vlan_) {
                            mux_vlan_ = vlan;
                            mux->Vlan = vlan;
                            break;
                        }
                    }

                    std::shared_ptr<VirtualEthernetLinklayer> self = shared_from_this();
                    mux_ = mux;

                    successes = YieldContext::Spawn(buffer_allocator.get(), *vnet_context, 
                        [self, this, vnet_transmission, mux, vnet_context](YieldContext& y) noexcept {
                            bool ok = false;
                            if (!disposed_) {
                                uint16_t max_connections = mux->get_max_connections();
                                ok = DoMux(vnet_transmission, mux->Vlan, max_connections, (switcher_->mux_acceleration_ & PPP_MUX_ACCELERATION_REMOTE) != 0, y);
                            }

                            if (!ok) {
                                mux->close_exec();
                            }
                        });
                    break;
                }

                if (!successes) {
                    std::shared_ptr<vmux::vmux_net> mux = std::move(mux_);
                    mux_.reset();

                    if (NULL != mux) {
                        mux->close_exec();
                    }
                }

                return successes;
            }

            VEthernetExchanger::NetworkState VEthernetExchanger::GetMuxNetworkState() noexcept {
                if (disposed_) {
                    return NetworkState_Reconnecting;
                }

                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULL == mux) {
                    return NetworkState_Connecting;
                }

                if (mux->is_disposed()) {
                    return NetworkState_Reconnecting;
                }

                if (mux->is_established()) {
                    return NetworkState_Established;
                }

                return NetworkState_Connecting;
            }

            bool VEthernetExchanger::MuxConnectAllLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<vmux::vmux_net>& mux) noexcept {
                using ppp::app::protocol::VirtualEthernetTcpipConnection;
                
                std::shared_ptr<boost::asio::io_context> context = mux->get_context();
                if (NULL == context) {
                    return false;
                }

                auto self = shared_from_this();
                auto strand = mux->get_strand();

                return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, mux, context, strand](YieldContext& y) noexcept -> bool {
                        if (disposed_ || mux != mux_) {
                            mux->close_exec();
                            return false;
                        }

                        int max_connections = mux->get_max_connections();
                        int bok_connections = 0;

                        const uint32_t& tx_seq = mux->get_tx_seq();
                        const uint32_t& rx_ack = mux->get_rx_ack();
                        if (!mux->ftt(vmux::vmux_net::ftt_random_aid(1, INT32_MAX), vmux::vmux_net::ftt_random_aid(1, INT32_MAX))) {
                            mux->close_exec();
                            return false;
                        }

                        auto context = mux->get_context();
                        auto strand = mux->get_strand();
                        
                        for (int i = 0; i < max_connections; i++) {
                            if (disposed_ || mux != mux_) {
                                bok_connections = -1;
                                break;
                            }

                            if (mux->is_established()) {
                                return true;
                            }

                            ITransmissionPtr transmission = ConnectTransmission(context, strand, y);
                            if (NULL == transmission) {
                                break;
                            }

                            std::shared_ptr<boost::asio::ip::tcp::socket> default_socket;
                            std::shared_ptr<VirtualEthernetTcpipConnection> connection =
                                make_shared_object<VirtualEthernetTcpipConnection>(
                                    mux->AppConfiguration, context, strand, GetId(), default_socket);
                            if (NULL == connection) {
                                break;
                            }

                            // In this lightweight and simple vmux circuit switch, seq and ack are delivered by the client, and the server and client are opposite.
                            if (!connection->ConnectMux(y, transmission, mux->Vlan, rx_ack, tx_seq)) {
                                break;
                            }

                            bool bok = mux->do_yield(y,
                                [self, mux, connection]() noexcept -> bool {
                                    vmux::vmux_net::vmux_linklayer_ptr linklayer;
                                    vmux::vmux_net::vmux_native_add_linklayer_after_success_before_callback handling;
                                    return mux->add_linklayer(connection, linklayer, handling);
                                });

                            if (!bok) {
                                break;
                            }

                            bok_connections++;
                        }

                        if (bok_connections >= max_connections) {
                            return true;
                        }

                        mux->close_exec();
                        return false;
                    });
            }

            bool VEthernetExchanger::ReleaseDeadlineTimer(const boost::asio::deadline_timer* deadline_timer) noexcept {
                if (NULL == deadline_timer) {
                    return false;
                }

                DeadlineTimerPtr reference;
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    Dictionary::TryRemove(deadline_timers_, (void*)deadline_timer, reference);
                    break;
                }

                if (NULL == reference) {
                    return false;
                }

                Socket::Cancel(*reference);
                return true;
            }

            bool VEthernetExchanger::NewDeadlineTimer(const ContextPtr& context, int64_t timeout, const ppp::function<void(bool)>& event) noexcept {
                std::shared_ptr<boost::asio::deadline_timer> t = make_shared_object<boost::asio::deadline_timer>(*context);
                if (NULL == t) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }
                else {
                    timeout = std::max<int64_t>(1, timeout);
                }

                auto self = shared_from_this();
                boost::asio::deadline_timer* deadline_timer = t.get();

                t->expires_from_now(Timer::DurationTime(timeout));
                t->async_wait(
                    [self, this, deadline_timer, event](const boost::system::error_code& ec) noexcept {
                        ReleaseDeadlineTimer(deadline_timer);
                        event(ec == boost::system::errc::success);
                    });

                auto r = deadline_timers_.emplace(deadline_timer, std::move(t));
                if (r.second) {
                    return true;
                }

                Socket::Cancel(*t);
                return false;
            }

            void VEthernetExchanger::ExchangeToEstablishState() noexcept {
                uint64_t now = Executors::GetTickCount();
                sekap_last_ = Executors::GetTickCount();
                sekap_next_ = now + RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT, SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT);
                network_state_.exchange(NetworkState_Established);
                reconnection_count_ = 0;
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
                reconnection_count_++;
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
                VirtualEthernetMappingPortTable mappings; {
                    SynchronizedObjectScope scope(syncobj_);
                    mappings = std::move(mappings_);
                    mappings_.clear();
                }

                ppp::collections::Dictionary::ReleaseAllObjects(mappings);
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

            bool VEthernetExchanger::OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept {
                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULL != mux) {
                    bool successed = false;
                    if (vlan != 0 && max_connections > 0 && mux->Vlan == vlan && max_connections == mux->get_max_connections() && !mux->is_disposed()) {
                        bool established = mux->is_established();
                        successed = true;

                        if (!established) {
                            auto configuration = GetConfiguration();
                            auto allocator = configuration->GetBufferAllocator();
                        
                            successed = MuxConnectAllLinklayers(allocator, mux);
                        }
                    }
                    
                    if (!successed) {
                        mux->close_exec();
                    }
                }

                return true;
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
                boost::asio::post(*context, 
                    [self, this, context, ei]() noexcept {
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

            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, int session_id, int remote_port, YieldContext& y) noexcept {                
                if (remote_port < IPEndPoint::MinPort || remote_port > IPEndPoint::MaxPort) {
                    return false;
                }

                if (session_id < 0) {
                    return false;
                }

                // If the server does not support static tunneling, clean up the pre-prepared resources.
                if (remote_port == IPEndPoint::MinPort || session_id == 0) {
                    StaticEchoClean();
                }
                else {
                    static_echo_session_id_ = session_id;
                    static_echo_remote_port_ = remote_port;
                }

                return true;
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
                if (disposed_) {
                    return false;
                }

                VEthernetDatagramPortPtr datagram = GetDatagramPort(sourceEP);
                if (NULL != datagram) {
                    if (NULL != packet && packet_length > 0) {
                        datagram->OnMessage(packet, packet_length, destinationEP);
                    }
                    else {
                        datagram->MarkFinalize();
                        datagram->Dispose();
                    }
                }
                elif(NULL != packet && packet_length > 0) {
                    switcher_->DatagramOutput(sourceEP, destinationEP, packet, packet_length);
                }

                return true;
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

                bool ok = DoEcho(transmission, ack_id, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
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

                bool ok = true; 
                datagram = NewDatagramPort(transmission, sourceEP);

                if (NULL == datagram) {
                    return NULL;
                }
                else {
                    SynchronizedObjectScope scope(syncobj_);
                    auto r = datagrams_.emplace(sourceEP, datagram);
                    ok = r.second;
                }

                if (!ok) {
                    datagram->Dispose();
                    return NULL;
                }

                return datagram;
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }

                auto my = shared_from_this();
                std::shared_ptr<VEthernetExchanger> exchanger = std::dynamic_pointer_cast<VEthernetExchanger>(my);
                if (NULL == exchanger) { /* ??? */
                    return NULL;
                }

                return make_shared_object<VEthernetDatagramPort>(exchanger, transmission, sourceEP);
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::FindObjectByKey(datagrams_, sourceEP);
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                SynchronizedObjectScope scope(syncobj_);
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
                boost::asio::ip::address local_ip = StringToAddress(mapping.local_ip.data(), ec);
                if (ec) {
                    return false;
                }

                boost::asio::ip::address remote_ip = StringToAddress(mapping.remote_ip.data(), ec);
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
                    SynchronizedObjectScope scope(syncobj_);
                    ok = VirtualEthernetMappingPort::AddMappingPort(mappings_, in, protocol_tcp_or_udp, mapping.remote_port, mapping_port);
                }

                if (!ok) {
                    mapping_port->Dispose();
                }
                return ok;
            }

            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class VIRTUAL_ETHERNET_MAPPING_PORT final : public VirtualEthernetMappingPort {
                public:
                    VIRTUAL_ETHERNET_MAPPING_PORT(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    virtual void Dispose() noexcept override {
                        if (std::shared_ptr<VirtualEthernetLinklayer> linklayer = GetLinklayer();  NULL != linklayer) {
                            VEthernetExchanger* exchanger = dynamic_cast<VEthernetExchanger*>(linklayer.get());
                            if (NULL != exchanger) {
                                SynchronizedObjectScope scope(exchanger->syncobj_);
                                VirtualEthernetMappingPort::DeleteMappingPort(
                                    exchanger->mappings_, ProtocolIsNetworkV4(), ProtocolIsTcpNetwork(), GetRemotePort());
                            }
                        }

                        VirtualEthernetMappingPort::Dispose();
                    }
                };

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return NULL;
                }

                auto self = shared_from_this();
                return make_shared_object<VIRTUAL_ETHERNET_MAPPING_PORT>(self, transmission, tcp, in, remote_port);
            }

            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return VirtualEthernetMappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
            }

            bool VEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
#if defined(_ANDROID)
                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                std::shared_ptr<Byte> packet_managed = ppp::net::asio::IAsynchronousWriteIoQueue::Copy(configuration->GetBufferAllocator(), packet, packet_length);
                Post(
                    [this, packet_managed, sourceEP, packet_length, in, remote_port]() noexcept {
                        VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                        if (NULL != mapping_port) {
                            mapping_port->Client_OnFrpSendTo(packet_managed.get(), packet_length, sourceEP);
                        }
                    });
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Client_OnFrpSendTo(packet, packet_length, sourceEP);
                }
#endif
                return true;
            }

            bool VEthernetExchanger::OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
#if defined(_ANDROID)
                Post(
                    [this, in, remote_port, connection_id]() noexcept {
                        VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                        if (NULL != mapping_port) {
                            mapping_port->Client_OnFrpConnect(connection_id);
                        }
                    });
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Client_OnFrpConnect(connection_id);
                }
#endif
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

            void VEthernetExchanger::StaticEchoClean() noexcept {
                for (int i = 0; i < arraysizeof(static_echo_sockets_); i++) {
                    std::shared_ptr<StaticEchoDatagarmSocket>& r = static_echo_sockets_[i];
                    std::shared_ptr<StaticEchoDatagarmSocket> socket = std::move(r);
                    r.reset();

                    Socket::Closesocket(socket);
                }

                static_echo_input_       = false;
                static_echo_timeout_     = UINT64_MAX;
                static_echo_session_id_  = 0;
                static_echo_remote_port_ = IPEndPoint::MinPort;
            }

            bool VEthernetExchanger::StaticEchoAllocated() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<StaticEchoDatagarmSocket> socket = static_echo_sockets_[0];
                if (NULL == socket) {
                    return false;
                }

                return socket->is_open() && static_echo_timeout_ != 0 && static_echo_session_id_ != 0 && static_echo_remote_port_ != 0;
            }

            bool VEthernetExchanger::StaticEchoSwapAsynchronousSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                if (static_echo_timeout_ != UINT64_MAX && switcher_->StaticMode(NULL)) {
                    UInt64 now = ppp::threading::Executors::GetTickCount();
                    if (now >= static_echo_timeout_) {
                        std::shared_ptr<StaticEchoDatagarmSocket> socket = std::move(static_echo_sockets_[0]);
                        static_echo_sockets_[0] = std::move(static_echo_sockets_[1]);
                        static_echo_sockets_[1] = NULL;
                        
                        static_echo_input_ = false;
                        if (!StaticEchoNextTimeout()) {
                            return false;
                        }

                        auto self = shared_from_this();
                        auto notifiy_if_need = 
                            [self, this]() noexcept {
                                // Notifies the VPN server of domestic port changes for smoother dynamic switchover of virtual links.
                                if (!static_echo_input_ && static_echo_sockets_[0]) {
                                    StaticEchoGatewayServer(STATIC_ECHO_KEEP_ALIVED_ID);
                                }
                            };
                        
                        // Here do not close the socket immediately, delay one second, because the data sent by the VPN server may not reach the network card, 
                        // Reduce the packet loss rate during switching and improve the smoothness of the cross.
                        bool closesocket = true;
                        std::shared_ptr<boost::asio::io_context> context = GetContext();
                        if (NULL != context) {
                            int milliseconds = RandomNext(500, 1000);
                            std::shared_ptr<Timer> timeout = Timer::Timeout(context, milliseconds, 
                                [socket, notifiy_if_need](Timer*) noexcept {
                                    notifiy_if_need();
                                    Socket::Closesocket(socket);
                                });
                            if (NULL != timeout) {
                                closesocket = false;
                            }
                        }

                        // Handles whether you can delay closing the socket. If not, close the socket immediately.
                        if (closesocket) {
                            Socket::Closesocket(socket);
                        }

                        notifiy_if_need();
                        if (NULL == context) {
                            return false;
                        }

                        // Re-instance and try to open the Datagram Port.
                        socket = make_shared_object<StaticEchoDatagarmSocket>(*context);
                        if (NULL == socket) {
                            return false;
                        }

                        auto configuration = GetConfiguration();
                        auto allocator = configuration->GetBufferAllocator();
                        static_echo_sockets_[1] = socket;

                        return YieldContext::Spawn(allocator.get(), *context,
                            [self, this, socket, context](YieldContext& y) noexcept {
                                bool opened = StaticEchoOpenAsynchronousSocket(*socket, y);
                                if (opened) {
                                    StaticEchoLoopbackSocket(socket);
                                }
                            });
                    }
                }

                return true;
            }

            bool VEthernetExchanger::StaticEchoGatewayServer(int ack_id) noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<ppp::net::packet::IPFrame> packet = make_shared_object<ppp::net::packet::IPFrame>(); 
                if (NULL == packet) {
                    return false;
                }

                packet->AddressesFamily = AddressFamily::InterNetwork;
                packet->Destination = htonl(ack_id);
                packet->Id = ppp::net::packet::IPFrame::NewId();
                packet->Source = IPEndPoint::LoopbackAddress;
                packet->ProtocolType = ppp::net::native::ip_hdr::IP_PROTO_ICMP;
                ppp::app::protocol::VirtualEthernetPacket::FillBytesToPayload(packet.get());
            
                return StaticEchoPacketToRemoteExchanger(packet.get());
            }

            bool VEthernetExchanger::StaticEchoAllocatedToRemoteExchanger(YieldContext& y) noexcept {
                StaticEchoClean();
                if (disposed_) {
                    return false;
                }

                if (StaticEchoAllocated()) {
                    return true;
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULL == context) {
                    return false;
                }

                bool static_mode = switcher_->StaticMode(NULL);
                if (!static_mode) {
                    return true;
                }

                for (int i = 0; i < arraysizeof(static_echo_sockets_); i++) {
                    std::shared_ptr<StaticEchoDatagarmSocket>& socket = static_echo_sockets_[i];
                    if (NULL == socket) {
                        socket = make_shared_object<StaticEchoDatagarmSocket>(*context);
                        if (NULL == socket) {
                            return false;
                        }
                    }

                    if (socket->is_open(true)) {
                        continue;
                    }

                    bool opened = StaticEchoOpenAsynchronousSocket(*socket, y) && StaticEchoLoopbackSocket(socket);
                    if (!opened) {
                        socket.reset();
                        return false;
                    }
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULL == transmission) {
                    return false;
                }

                return DoStatic(transmission, y);
            }

            bool VEthernetExchanger::StaticEchoNextTimeout() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<StaticEchoDatagarmSocket> socket = static_echo_sockets_[0];
                if (NULL == socket) {
                    return false;
                }

                bool opened = socket->is_open(true);
                if (!opened) {
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                int min = std::max<int>(0, configuration->udp.static_.keep_alived[0]);
                int max = std::max<int>(0, configuration->udp.static_.keep_alived[1]);
                if (min == 0) {
                    min = PPP_UDP_KEEP_ALIVED_MIN_TIMEOUT;
                }

                if (max == 0) {
                    max = PPP_UDP_KEEP_ALIVED_MAX_TIMEOUT;
                }

                if (min > max) {
                    std::swap(min, max);
                }

                uint64_t tick = ppp::threading::Executors::GetTickCount();
                min = std::max<int>(1, min) * 1000;
                max = std::max<int>(1, max) * 1000;

                if (min == max) {
                    static_echo_timeout_ = tick + min;
                }
                else {
                    uint64_t next = RandomNext(min, max + 1);
                    static_echo_timeout_ = tick + next;
                }

                return true;
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept {
                if (NULL == packet || packet->AddressesFamily != AddressFamily::InterNetwork) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                int session_id = static_echo_session_id_;
                if (session_id < 1) {
                    return false;
                }

                int message_length = -1;
                std::shared_ptr<Byte> messages = VirtualEthernetPacket::Pack(configuration,
                    configuration->GetBufferAllocator(),
                    static_echo_protocol_,
                    static_echo_transport_,
                    session_id,
                    packet,
                    message_length);
                return StaticEchoPacketToRemoteExchanger(messages, message_length);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept {
                if (NULL == frame || frame->AddressesFamily != AddressFamily::InterNetwork) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                int session_id = static_echo_session_id_;
                if (session_id < 1) {
                    return false;
                }

                std::shared_ptr<ppp::net::packet::BufferSegment> payload_buffers = frame->Payload;
                if (NULL == payload_buffers) {
                    return false;
                }

                int packet_length = -1;
                uint32_t source_ip = frame->Source.GetAddress();
                uint32_t destination_ip = frame->Destination.GetAddress();
                std::shared_ptr<Byte> packet = VirtualEthernetPacket::Pack(configuration,
                    configuration->GetBufferAllocator(),
                    static_echo_protocol_,
                    static_echo_transport_,
                    session_id,
                    source_ip,
                    frame->Source.Port,
                    destination_ip,
                    frame->Destination.Port,
                    payload_buffers->Buffer.get(),
                    payload_buffers->Length,
                    packet_length);
                return StaticEchoPacketToRemoteExchanger(packet, packet_length);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                std::shared_ptr<StaticEchoDatagarmSocket> socket = static_echo_sockets_[0];
                if (NULL == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                boost::asio::ip::udp::endpoint serverEP = StaticEchoGetRemoteEndPoint();
                int serverPort = serverEP.port();

                if (serverPort > IPEndPoint::MinPort && serverPort <= IPEndPoint::MaxPort) {
                    std::shared_ptr<ppp::transmissions::ITransmissionStatistics> statistics = switcher_->GetStatistics();
                    boost::asio::post(socket->get_executor(),
                        [statistics, socket, packet, packet_length, serverEP]() noexcept {
                            boost::system::error_code ec;
                            socket->send_to(boost::asio::buffer(packet.get(), packet_length), serverEP,
                                boost::asio::socket_base::message_end_of_record, ec);

                            if (ec == boost::system::errc::success) {
                                if (NULL != statistics) {
                                    statistics->AddOutgoingTraffic(packet_length);
                                }
                            }
                        });
                    return true;
                }

                return false;
            }

            std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket> VEthernetExchanger::StaticEchoReadPacket(const void* packet, int packet_length) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return NULL;
                }

                if (disposed_) {
                    return NULL;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULL == configuration) {
                    return NULL;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration->GetBufferAllocator();
                return VirtualEthernetPacket::Unpack(configuration, 
                    allocator, static_echo_protocol_, static_echo_transport_, packet, packet_length);
            }

            bool VEthernetExchanger::StaticEchoPacketInput(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept {
                if (NULL == packet || disposed_) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration->GetBufferAllocator();
                static_echo_input_ = true;

                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    auto tap = switcher_->GetTap();
                    if (NULL == tap) {
                        return false;
                    }

                    std::shared_ptr<ppp::net::packet::UdpFrame> frame = packet->GetUdpPacket();
                    if (NULL == frame) {
                        return false;
                    }

                    std::shared_ptr<ppp::net::packet::IPFrame> ip = frame->ToIp(allocator);
                    if (NULL == ip) {
                        return false;
                    }
                    
                    if (configuration->udp.dns.cache && frame->Source.Port == PPP_DNS_SYS_PORT) {
                        auto payload = frame->Payload;
                        if (NULL != payload) {
                            ppp::net::asio::vdns::AddCache(payload->Buffer.get(), payload->Length);
                        }
                    }

                    return switcher_->Output(ip.get());
                }
                elif(packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    std::shared_ptr<ppp::net::packet::IPFrame> frame = packet->GetIPPacket(allocator);
                    if (NULL == frame) {
                        return false;
                    }

                    if (frame->ProtocolType == ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                        if (frame->Source == IPEndPoint::LoopbackAddress) {
                            int ack_id = ntohl(frame->Destination);
                            if (ack_id == 0 || ack_id == STATIC_ECHO_KEEP_ALIVED_ID) {
                                return false;
                            }

                            return switcher_->ERORTE(ack_id);
                        }
                    }

                    return switcher_->Output(frame.get());
                }
                else {
                    return false;
                }
            }

            int VEthernetExchanger::StaticEchoYieldReceiveForm(Byte* incoming_packet, int incoming_traffic) noexcept {
                std::shared_ptr<VirtualEthernetPacket> packet = StaticEchoReadPacket(incoming_packet, incoming_traffic);
                if (NULL != packet) {
                    StaticEchoPacketInput(packet);
                }

                auto statistics = switcher_->GetStatistics(); 
                if (NULL != statistics) {
                    statistics->AddIncomingTraffic(incoming_traffic);
                }

                return incoming_traffic;
            }

            void VEthernetExchanger::StaticEchoYieldReceiveForm(std::shared_ptr<StaticEchoDatagarmSocket>& socket, VEthernetExchanger* my, YieldContext& y, int* bytes_transferred) noexcept {
                socket->async_receive_from(boost::asio::buffer(my->buffer_.get(), PPP_BUFFER_SIZE), my->static_echo_source_ep_,
                    [my, bytes_transferred, &y](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        *bytes_transferred = my->StaticEchoYieldReceiveForm(
                            my->buffer_.get(), 
                            std::max<int>(-1, ec ? -1 : (int)sz));
                        y.R();
                    });
                y.Suspend();
            }

            bool VEthernetExchanger::Sleep(int64_t timeout, const ContextPtr& context, YieldContext& y) noexcept {
                using atomic_int = std::atomic<int>;

                std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                if (NULL == status) {
                    return false;
                }

                auto self = shared_from_this();
                context->post(
                    [self, this, context, timeout, status, &y]() noexcept {
                        bool ok = NewDeadlineTimer(context, timeout, 
                            [status, &y](bool b) noexcept {
                                ppp::coroutines::asio::R(y, *status, b);
                            });
                        
                        if (!ok) {
                            ppp::coroutines::asio::R(y, *status, false);
                        }
                    });

                y.Suspend();
                return status->load() > 0;
            }
            
            bool VEthernetExchanger::StaticEchoLoopbackSocket(const std::weak_ptr<StaticEchoDatagarmSocket>& socket_weak) noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULL == context) {
                    return false;
                }

                auto self = shared_from_this();
                auto configuration = GetConfiguration();
                auto allocator = configuration->GetBufferAllocator();

                return YieldContext::Spawn(allocator.get(), *context,
                    [self, this, context, socket_weak](YieldContext& y) noexcept -> bool {
                        for (;;) {
                            if (disposed_) {
                                break;
                            }
                            
                            std::shared_ptr<StaticEchoDatagarmSocket> socket = socket_weak.lock();
                            if (NULL == socket) {
                                return false;
                            }

                            bool openped = socket->is_open();
                            if (!openped) {
                                return false;
                            }

                            int bytes_transferred = 0;
                            if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = switcher_->GetQoS(); NULL != qos) {
                                qos->ReadBytes(y, PPP_BUFFER_SIZE, 
                                    [this, &socket, &bytes_transferred](YieldContext& y, int* length) noexcept -> std::shared_ptr<Byte> {
                                        StaticEchoYieldReceiveForm(socket, this, y, length);
                                        bytes_transferred = *length;
                                        return NULL;
                                    });
                            }
                            else {
                                StaticEchoYieldReceiveForm(socket, this, y, &bytes_transferred);
                            }

                            if (bytes_transferred > -1) {
                                continue;
                            }
                            else {
                                return false;
                            }
                        }
                        return true;
                    });
            }

            bool VEthernetExchanger::StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                boost::asio::ip::udp::endpoint destinationEP = Ipep::V4ToV6(remoteEP);
                boost::asio::ip::address destinationIP = destinationEP.address();
                if (!destinationIP.is_v6()) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                auto r = static_echo_server_ep_set_.emplace(destinationEP);
                if (!r.second) {
                    return false;
                }

                static_echo_server_ep_balances_.emplace_back(destinationEP);
                return true;
            }

            boost::asio::ip::udp::endpoint VEthernetExchanger::StaticEchoGetRemoteEndPoint() noexcept {
                std::shared_ptr<aggligator::aggligator> aggligator = switcher_->GetAggligator();
                if (NULL != aggligator) {
#if !defined(_ANDROID) && !defined(_IPHONE)
                    auto ni = switcher_->GetUnderlyingNetowrkInterface(); 
                    if (NULL != ni) {
                        boost::asio::ip::udp::endpoint ep = aggligator->client_endpoint(ni->IPAddress);
                        return Ipep::V4ToV6(ep);
                    }
#endif
                    return aggligator->client_endpoint(boost::asio::ip::address_v6::loopback());
                }

                boost::asio::ip::udp::endpoint destinationEP;
                do {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = static_echo_server_ep_balances_.begin();
                    auto endl = static_echo_server_ep_balances_.end();
                    if (tail == endl) {
                        destinationEP = boost::asio::ip::udp::endpoint(server_url_.remoteEP.address(), static_echo_remote_port_);
                        break;
                    }
                    
                    std::size_t server_addrsss_num = static_echo_server_ep_set_.size();
                    if (server_addrsss_num == 1) {
                        destinationEP = *static_echo_server_ep_balances_.begin();
                    }
                    else {
                        destinationEP = *tail;
                        static_echo_server_ep_balances_.erase(tail);
                        static_echo_server_ep_balances_.emplace_back(destinationEP);
                    }
                } while (false);
                return Ipep::V4ToV6(destinationEP);
            }

            bool VEthernetExchanger::StaticEchoOpenAsynchronousSocket(StaticEchoDatagarmSocket& socket, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                bool opened = socket.is_open(true);
                if (opened) {
                    return true;
                }

                if (server_url_.port <= IPEndPoint::MinPort || server_url_.port > IPEndPoint::MaxPort) {
                    return false;
                }   

                AppConfigurationPtr configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                opened = ppp::coroutines::asio::async_open<boost::asio::ip::udp::socket>(y, socket, boost::asio::ip::udp::v6()) && !disposed_;
                if (!opened) {
                    return false;
                }

                bool ok = false;
                for (;;) {
                    opened = Socket::OpenSocket(socket, boost::asio::ip::address_v6::any(), IPEndPoint::MinPort, opened);
                    if (!opened) {
                        break;
                    }
                    else {
                        Socket::SetWindowSizeIfNotZero(socket.native_handle(), configuration->udp.cwnd, configuration->udp.rwnd);
                    }
                    
#if defined(_ANDROID)
                    std::shared_ptr<aggligator::aggligator> aggligator = switcher_->GetAggligator();
                    if (NULL == aggligator) {
                        auto protector_network = switcher_->GetProtectorNetwork(); 
                        if (NULL != protector_network) {
                            opened = protector_network->Protect(socket.native_handle(), y);
                            if (!opened) {
                                break;
                            }
                        }
                    }
#endif
                    // Mark that the socket has been opened.
                    socket.opened = opened;

                    // Set the timeout period for closing and re-opening the socket next-timed.
                    ok = StaticEchoNextTimeout();
                    break;
                }

                if (!ok) {
                    Socket::Closesocket(socket);
                }

                return ok;
            }
        }
    }
}