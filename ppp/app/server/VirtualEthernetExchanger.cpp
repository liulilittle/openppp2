#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualInternetControlMessageProtocol.h>
#include <ppp/app/server/VirtualInternetControlMessageProtocolStatic.h>
#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>

typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
typedef ppp::collections::Dictionary                                Dictionary;
typedef ppp::net::AddressFamily                                     AddressFamily;
typedef ppp::net::Socket                                            Socket;
typedef ppp::net::Ipep                                              Ipep;
typedef ppp::threading::Timer                                       Timer;
typedef ppp::net::IPEndPoint                                        IPEndPoint;
typedef ppp::net::native::ip_hdr                                    ip_hdr;
typedef ppp::net::native::icmp_hdr                                  icmp_hdr;
typedef ppp::net::packet::IPFrame                                   IPFrame;
typedef ppp::net::packet::IcmpFrame                                 IcmpFrame;
typedef ppp::threading::Executors                                   Executors;
typedef ppp::collections::Dictionary                                Dictionary;

namespace ppp {
    namespace app {
        namespace server {
            VirtualEthernetExchanger::VirtualEthernetExchanger(
                const VirtualEthernetSwitcherPtr&                       switcher,
                const AppConfigurationPtr&                              configuration,
                const ITransmissionPtr&                                 transmission,
                const Int128&                                           id) noexcept 
                : VirtualEthernetLinklayer(configuration, transmission->GetContext(), id)
                , disposed_(false)
                , address_(IPEndPoint::NoneAddress)
                , switcher_(switcher)
                , transmission_(transmission)
                , static_echo_session_id_(0) {

                std::shared_ptr<boost::asio::io_context> context = transmission->GetContext();
                buffer_ = Executors::GetCachedBuffer(context);
                firewall_ = switcher->GetFirewall();
                managed_server_ = switcher->GetManagedServer();

                for (;;) {
                    ITransmissionPtr transmission = transmission_; 
                    if (NULL != transmission) {
                        std::shared_ptr<ITransmissionStatistics> statistics = transmission->Statistics;
                        if (NULL != statistics) {
                            statistics_ = statistics;
                            break;
                        }
                    }

                    statistics_ = switcher->GetStatistics();
                    break;
                }
            }

            VirtualEthernetExchanger::~VirtualEthernetExchanger() noexcept {
                Finalize();
            }

            void VirtualEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            void VirtualEthernetExchanger::Finalize() noexcept {
                for (;;) {
                    Dictionary::ReleaseAllObjects(datagrams_);
                    datagrams_.clear();

                    Dictionary::ReleaseAllObjects(mappings_);
                    mappings_.clear();

                    Timer::ReleaseAllTimeouts(timeouts_);
                    timeouts_.clear();

                    VirtualInternetControlMessageProtocolPtr echo = std::move(echo_); 
                    echo_.reset();

                    std::shared_ptr<VirtualInternetControlMessageProtocolStatic> static_echo = std::move(static_echo_); 
                    static_echo_.reset();

                    ITransmissionPtr transmission = std::move(transmission_); 
                    transmission_.reset();

                    std::shared_ptr<vmux::vmux_net> mux = std::move(mux_);
                    mux_.reset();

                    if (NULL != echo) {
                        echo->Dispose();
                    }

                    if (NULL != static_echo) {
                        static_echo->Dispose();
                    }

                    if (NULL != transmission) {
                        transmission->Dispose();
                    }

                    if (NULL != mux) {
                        mux->close_exec();
                    }

                    disposed_ = true;
                    break;
                }

                VirtualEthernetDatagramPortStaticTable static_echo_datagram_ports; {
                    SynchronizedObjectScope scope(static_echo_syncobj_);
                    static_echo_datagram_ports = std::move(static_echo_datagram_ports_);
                    static_echo_datagram_ports_.clear();
                }

                UploadTrafficToManagedServer();
                Dictionary::ReleaseAllObjects(static_echo_datagram_ports);

                switcher_->DeleteExchanger(this);
                switcher_->DeleteNatInformation(this, address_);
                switcher_->StaticEchoUnallocated(static_echo_session_id_.exchange(0));
            }

            VirtualEthernetExchanger::FirewallPtr VirtualEthernetExchanger::GetFirewall() noexcept {
                return firewall_;
            }

            bool VirtualEthernetExchanger::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            bool VirtualEthernetExchanger::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            bool VirtualEthernetExchanger::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            bool VirtualEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                DoEcho(transmission, ack_id, y);
                return true;
            }

            bool VirtualEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                SendEchoToDestination(transmission, packet, packet_length);
                return true;
            }

            bool VirtualEthernetExchanger::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                SendPacketToDestination(transmission, sourceEP, destinationEP, packet, packet_length, y);
                return true;
            }

            bool VirtualEthernetExchanger::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            bool VirtualEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            bool VirtualEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                StaticEcho(transmission, y);
                return true;
            }

            bool VirtualEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, int session_id, int remote_port, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            bool VirtualEthernetExchanger::OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept {
                bool err = true;
                for (;;) {
                    if (disposed_) {
                        break;
                    }

                    bool clean = vlan == 0 || max_connections == 0;
                    std::shared_ptr<vmux::vmux_net> mux = mux_;
                    if (NULL != mux) {
                        if (clean || mux->Vlan != vlan || mux->get_max_connections() != max_connections || mux->is_disposed()) {
                            mux_.reset();
                            mux->close_exec();
                        }
                        else {
                            break;
                        }
                    }

                    if (clean) {
                        break;
                    }

                    ppp::threading::Executors::StrandPtr vmux_strand;
                    ppp::threading::Executors::ContextPtr vmux_context = ppp::threading::Executors::SelectScheduler(vmux_strand);
                    if (NULL == vmux_context) {
                        break;
                    }

                    mux = make_shared_object<vmux::vmux_net>(vmux_context, vmux_strand, max_connections, true, acceleration);
                    if (NULL != mux) {
                        mux->Vlan = vlan;
                        mux->Firewall = GetFirewall();
                        mux->Logger = switcher_->GetLogger();
                        mux->AppConfiguration = switcher_->GetConfiguration();
                        mux->BufferAllocator = transmission->BufferAllocator;

                        if (mux->update()) {
                            err = false;
                            mux_ = mux;
                        }
                        else {
                            mux_.reset();
                            mux->close_exec();
                        }
                    }

                    break;
                }

                if (err) {
                    if (std::shared_ptr<vmux::vmux_net> mux = std::move(mux_); NULL != mux) {
                        mux_.reset();
                        mux->close_exec();
                    }

                    DoMux(transmission, 0, 0, false, y);
                }
                else {
                    DoMux(transmission, vlan, max_connections, acceleration, y);
                }

                return true;
            }

            bool VirtualEthernetExchanger::OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (configuration->server.subnet) {
                    ForwardNatPacketToDestination(packet, packet_length, y);
                }

                return true;
            }

            bool VirtualEthernetExchanger::OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (configuration->server.subnet) {
                    Arp(transmission, ip, mask);
                }

                return true;
            }

            bool VirtualEthernetExchanger::StaticEcho(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                int remote_port = IPEndPoint::MinPort;
                int allocated_id = 0;

                Int128 guid = GetId();
                if (switcher_->StaticEchoAllocated(guid, allocated_id, remote_port)) {
                    static_echo_session_id_.exchange(allocated_id);
                    return DoStatic(transmission, allocated_id, remote_port, y);
                }
                else {
                    return DoStatic(transmission, 0, IPEndPoint::MinPort, y);
                }
            }

            bool VirtualEthernetExchanger::Arp(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask) noexcept {
                using VES = VirtualEthernetSwitcher;

                if (disposed_) {
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULL == exchanger) {
                    return false;
                }

                VES::NatInformationPtr nat = switcher_->AddNatInformation(exchanger, ip, mask);
                if (NULL == nat) {
                    return false;
                }
            
                VirtualEthernetLoggerPtr logger = switcher_->GetLogger(); 
                if (NULL != logger) {
                    logger->Arp(GetId(), transmission, ip, mask);
                }

                address_ = ip;
                return true;
            }

            bool VirtualEthernetExchanger::DeleteTimeout(void* k) noexcept {
                if (NULL == k) {
                    return false;
                }
                else {
                    return Dictionary::RemoveValueByKey(timeouts_, k);
                }
            }

            bool VirtualEthernetExchanger::SendPacketToDestination(const ITransmissionPtr& transmission, 
                const boost::asio::ip::udp::endpoint&   sourceEP, 
                const boost::asio::ip::udp::endpoint&   destinationEP, 
                Byte*                                   packet, 
                int                                     packet_length, 
                YieldContext&                           y) noexcept {

                if (disposed_) {
                    return false;
                }

                bool fin = false;
                if (NULL == packet && packet_length != 0) {
                    return false;
                }
                elif(NULL == packet || packet_length < 1) {
                    fin = true;
                }

                int destinationPort = destinationEP.port();
                if (firewall_->IsDropNetworkPort(destinationPort, false)) {
                    return false;
                }

                boost::asio::ip::address destinationIP = destinationEP.address();
                if (firewall_->IsDropNetworkSegment(destinationIP)) {
                    return false;
                }
                
                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                if (destinationPort == PPP_DNS_SYS_PORT) {
                    uint16_t queries_type = 0;
                    uint16_t queries_clazz = 0;
                    ppp::string hostDomain = ppp::net::native::dns::ExtractHostY(packet, packet_length,
                        [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                            queries_type = type;
                            queries_clazz = clazz;
                            return true;
                        });

                    if (hostDomain.size() > 0) {
                        if (NULL != logger) {
                            logger->Dns(GetId(), transmission, hostDomain);
                        }

                        if (firewall_->IsDropNetworkDomains(hostDomain)) {
                            return false;
                        }
                    }

                    int status = VirtualEthernetDatagramPort::NamespaceQuery(switcher_, this, sourceEP, destinationEP, hostDomain, 
                        packet, packet_length, queries_type, queries_clazz, false);
                    if (status < 0) {
                        return false;
                    }
                    elif(status > 0) {
                        return true;
                    }

                    status = RedirectDnsQuery(transmission, sourceEP, destinationEP, packet, packet_length, false);
                    if (status > -1) {
                        return status != 0;
                    }
                }

                VirtualEthernetDatagramPortPtr datagram = GetDatagramPort(sourceEP);
                if (NULL != datagram) {
                    if (fin) {
                        datagram->MarkFinalize();
                        datagram->Dispose();
                        return true;
                    }
                    else {
                        return datagram->SendTo(packet, packet_length, destinationEP);
                    }
                }
                elif(fin) {
                    return false;
                }
                else {
                    datagram = NewDatagramPort(transmission, sourceEP);
                    if (NULL != datagram) {
                        bool ok = false;
                        if (auto r = datagrams_.emplace(sourceEP, datagram); r.second) {
                            ok = datagram->Open();
                            if (!ok) {
                                datagrams_.erase(r.first);
                            }
                        }

                        if (ok) {
                            if (NULL != logger) {
                                logger->Port(GetId(), transmission, datagram->GetSourceEndPoint(), datagram->GetLocalEndPoint());
                            }

                            return datagram->SendTo(packet, packet_length, destinationEP);
                        }
                        else {
                            datagram->Dispose();
                        }
                    }
                    return false;
                }
            }

            bool VirtualEthernetExchanger::INTERNAL_RedirectDnsQuery(
                ITransmissionPtr                                    transmission,
                boost::asio::ip::udp::endpoint                      redirectEP,
                boost::asio::ip::udp::endpoint                      sourceEP, 
                boost::asio::ip::udp::endpoint                      destinationEP,
                std::shared_ptr<Byte>                               packet,
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                if (disposed_) {
                    return false;
                }

                const std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }
                
                const auto context = transmission->GetContext();
                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*context);
                if (!socket) {
                    return false;
                }

                boost::system::error_code ec;
                socket->open(destinationEP.protocol(), ec);
                if (ec) {
                    return false;
                }

                int handle = socket->native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, destinationEP.protocol() == boost::asio::ip::udp::v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);

                socket->send_to(boost::asio::buffer(packet.get(), packet_length), redirectEP, 
                    boost::asio::socket_base::message_end_of_record, ec);
                if (ec) {
                    return false;
                }

                const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                    [socket_weak](Timer*) noexcept {
                        const std::shared_ptr<boost::asio::ip::udp::socket> socket = socket_weak.lock();
                        if (socket) {
                            Socket::Closesocket(socket);
                        }
                    });
                if (NULL == cb) {
                    return false;
                }

                const auto timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, *cb);
                if (NULL == timeout) {
                    return false;
                }
                
                if (!timeouts_.emplace(socket.get(), cb).second) {
                    return false;
                }

                const auto max_buffer_size = PPP_BUFFER_SIZE - sizeof(destinationEP);
                const auto self = shared_from_this();

                socket->async_receive_from(boost::asio::buffer(buffer_.get(), max_buffer_size),
                    *reinterpret_cast<boost::asio::ip::udp::endpoint*>(buffer_.get() + max_buffer_size),
                    [self, this, socket, sourceEP, timeout, static_transit, transmission, destinationEP](boost::system::error_code ec, size_t sz) noexcept {
                        DeleteTimeout(socket.get());
                        if (ec == boost::system::errc::success) {
                            int bytes_transferred = static_cast<int>(sz);
                            if (bytes_transferred > 0) {
                                if (static_transit) {
                                    VirtualEthernetDatagramPortStatic::Output(switcher_.get(), this, buffer_.get(), bytes_transferred, sourceEP, destinationEP);
                                }
                                elif(!DoSendTo(transmission, sourceEP, destinationEP, buffer_.get(), bytes_transferred, nullof<YieldContext>())) {
                                    transmission->Dispose();
                                }

                                AppConfigurationPtr configuration = GetConfiguration();
                                if (NULL != configuration && configuration->udp.dns.cache) {
                                    VirtualEthernetDatagramPort::NamespaceQuery(switcher_, buffer_.get(), bytes_transferred);
                                }
                            }
                        }

                        Socket::Closesocket(socket);
                        if (timeout) {
                            timeout->Stop();
                            timeout->Dispose();
                        }
                    });
                return true;
            }

            bool VirtualEthernetExchanger::INTERNAL_RedirectDnsQuery(
                const ITransmissionPtr&                             transmission, 
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                Byte*                                               packet, 
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                if (!packet || packet_length < 1) {
                    return false;
                }

                if (!transmission) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;
                const auto buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_length);
                if (NULL == buffer) {
                    return false;
                }
                else {
                    memcpy(buffer.get(), packet, packet_length);
                }

                const boost::asio::ip::udp::endpoint destination = destinationEP;
                const boost::asio::ip::udp::endpoint source = sourceEP;
                const ITransmissionPtr in = transmission;

                const auto configuration = GetConfiguration();
                const auto self = shared_from_this();
                const std::shared_ptr<boost::asio::io_context> context = in->GetContext();

                const Ipep::GetAddressByHostNameCallback cb = 
                    [self, this, buffer, packet_length, static_transit, source, in, destination, context](IPEndPoint* redirectEP) noexcept {
                        if (!redirectEP) {
                            return false;
                        }

                        boost::asio::ip::udp::endpoint redirect = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(*redirectEP);
                        boost::asio::post(*context, 
                            [self, this, buffer, packet_length, static_transit, source, in, destination, redirect]() noexcept {
                                return INTERNAL_RedirectDnsQuery(in, redirect, source, destination, buffer, packet_length, static_transit);
                            });
                        return true;
                    };

                return Ipep::GetAddressByHostName(*context, configuration->udp.dns.redirect, PPP_DNS_SYS_PORT, cb);
            }

            int VirtualEthernetExchanger::RedirectDnsQuery(
                const ITransmissionPtr&                             transmission,
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                Byte*                                               packet,
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
                if (configuration->udp.dns.redirect.empty()) {
                    return -1;
                }

                if (disposed_) {
                    return 0;
                }

                boost::asio::ip::udp::endpoint redirect_server = switcher_->GetDnsserverEndPoint();
                boost::asio::ip::address dnsserverIP = redirect_server.address();
                if (dnsserverIP.is_unspecified()) {
                    return INTERNAL_RedirectDnsQuery(transmission, sourceEP, destinationEP, packet, packet_length, static_transit);
                }

                boost::asio::ip::udp::endpoint dnsserverEP(dnsserverIP, PPP_DNS_SYS_PORT);
                return INTERNAL_RedirectDnsQuery(transmission,
                    dnsserverEP,
                    sourceEP,
                    destinationEP,
                    wrap_shared_pointer(packet), packet_length, static_transit);
            }

            bool VirtualEthernetExchanger::Update(UInt64 now) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this, now]() noexcept {
                        int session_id = static_echo_session_id_.load();
                        if (session_id != 0) {
                            SynchronizedObjectScope scope(static_echo_syncobj_);
                            Dictionary::UpdateAllObjects(static_echo_datagram_ports_, now);
                        }

                        UploadTrafficToManagedServer();
                        DoMuxEvents();
                        DoKeepAlived(GetTransmission(), now);

                        Dictionary::UpdateAllObjects(datagrams_, now);
                        Dictionary::UpdateAllObjects2(mappings_, now);
                    });
                return true;
            }

            bool VirtualEthernetExchanger::DoMuxEvents() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULL != mux) {
                    if (mux->update()) {
                        return true;
                    }

                    mux_.reset();
                    mux->close_exec();
                }

                return false;
            }

            bool VirtualEthernetExchanger::UploadTrafficToManagedServer() noexcept {
                VirtualEthernetManagedServerPtr server = managed_server_;
                if (NULL == server) {
                    return false;
                }
                
                bool link_is_available = server->LinkIsAvailable();
                if (!link_is_available) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                ITransmissionStatisticsPtr statistics = transmission->Statistics;
                if (NULL == statistics) {
                    return false;
                }
                
                statistics = statistics->Clone();
                if (NULL == statistics) {
                    return false;
                }

                int64_t rx = 0;
                int64_t tx = 0;

                ITransmissionStatisticsPtr statistics_last = statistics_last_;
                if (NULL != statistics_last) {
                    rx = statistics->IncomingTraffic - statistics_last->IncomingTraffic;
                    tx = statistics->OutgoingTraffic - statistics_last->OutgoingTraffic;
                }
                else {
                    rx = statistics->IncomingTraffic;
                    tx = statistics->OutgoingTraffic;
                }

                statistics_last_ = statistics;
                server->UploadTrafficToManagedServer(GetId(), rx, tx);
                return true;
            }

            bool VirtualEthernetExchanger::Open() noexcept {
                if (disposed_) {
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULL == exchanger) {
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULL == context) {
                    return false;
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULL == transmission) {
                    return false;
                }

                VirtualInternetControlMessageProtocolPtr echo = NewEchoTransmissions(transmission);
                if (NULL == echo) {
                    return false;
                }

                std::shared_ptr<VirtualInternetControlMessageProtocolStatic> static_echo = make_shared_object<VirtualInternetControlMessageProtocolStatic>(exchanger, configuration, context);
                if (NULL == static_echo) {
                    return false;
                }

                echo_ = std::move(echo);
                static_echo_ = std::move(static_echo);
                return true;
            }

            VirtualEthernetExchanger::VirtualInternetControlMessageProtocolPtr VirtualEthernetExchanger::NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                return make_shared_object<VirtualInternetControlMessageProtocol>(exchanger, transmission);
            }

            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }
                
                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                return make_shared_object<VirtualEthernetDatagramPort>(self, transmission, sourceEP);
            }

            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::FindObjectByKey(datagrams_, sourceEP);
            }

            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::ReleaseObjectByKey(datagrams_, sourceEP);
            }

            bool VirtualEthernetExchanger::SendEchoToDestination(const ITransmissionPtr& transmission, Byte* packet, int packet_length) noexcept {
                if (disposed_) {
                    return false;
                }

                VirtualInternetControlMessageProtocolPtr echo = echo_;
                if (NULL == echo) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = echo->BufferAllocator;
                std::shared_ptr<IPFrame> ip = IPFrame::Parse(allocator, packet, packet_length);
                if (NULL == ip) {
                    return false;
                }

                if (ip->ProtocolType != ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }

                boost::asio::ip::address destinationIP = Ipep::ToAddress(ip->Destination);
                if (firewall_->IsDropNetworkSegment(destinationIP)) {
                    return false;
                }

                std::shared_ptr<IcmpFrame> icmp = IcmpFrame::Parse(ip.get());
                if (NULL == icmp) {
                    return false;
                }

                return echo->Echo(ip, icmp, IPEndPoint(icmp->Destination, IPEndPoint::MinPort));
            }

            bool VirtualEthernetExchanger::ForwardNatPacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept {
                using VES = VirtualEthernetSwitcher;
                
                if (disposed_) {
                    return false;
                }

                ppp::net::native::ip_hdr* ip = ppp::net::native::ip_hdr::Parse(packet, packet_length);
                if (NULL == ip) {
                    return false;
                }

                VES::NatInformationPtr source = switcher_->FindNatInformation(ip->src);
                if (NULL == source) {
                    return false;
                }

                static const auto forward = 
                    [](VirtualEthernetSwitcher* switcher, uint32_t destination, Byte* packet, int packet_length, YieldContext& y) noexcept -> int {
                        VES::NatInformationPtr nat = switcher->FindNatInformation(destination);
                        if (NULL == nat) {
                            return 0;
                        }

                        uint32_t mask = nat->SubmaskAddress;
                        std::shared_ptr<VirtualEthernetExchanger>& exchanger = nat->Exchanger;

                        if ((destination & mask) != (nat->IPAddress & mask)) {
                            return 0;
                        }

                        ITransmissionPtr transmission = exchanger->GetTransmission(); 
                        if (NULL != transmission) {
                            if (exchanger->DoNat(transmission, packet, packet_length, y)) {
                                return 1;
                            }

                            transmission->Dispose();
                        }

                        return -1;
                    };

                if (uint32_t destination = ip->dest; destination != IPEndPoint::BroadcastAddress) {
                    return forward(switcher_.get(), destination, packet, packet_length, y) > 0;
                }
                else {
                    bool any = false;
                    uint32_t current = htonl(ip->src);
                    uint32_t mask = ntohl(source->SubmaskAddress);
                    uint32_t first = current & mask;
                    uint32_t boardcast = first | (~first & 0xff);

                    for (uint32_t address = first; address < boardcast; address++) {
                        if (current == address) {
                            continue;
                        }

                        int status = forward(switcher_.get(), htonl(address), packet, packet_length, y);
                        if (status < 0) {
                            break;
                        }

                        any |= status > 0;
                    }

                    return any;
                }
            }

            bool VirtualEthernetExchanger::OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (configuration->server.mapping) {
                    RegisterMappingPort(in, tcp, remote_port);
                }

                return true;
            }

            bool VirtualEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Server_OnFrpSendTo(packet, packet_length, sourceEP);
                }

                return true;
            }

            bool VirtualEthernetExchanger::OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Server_OnFrpConnectOK(connection_id, error_code);
                }

                return true;
            }

            bool VirtualEthernetExchanger::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Server_OnFrpDisconnect(connection_id);
                }

                return true;
            }

            bool VirtualEthernetExchanger::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULL != mapping_port) {
                    mapping_port->Server_OnFrpPush(connection_id, packet, packet_length);
                }

                return true;
            }

            bool VirtualEthernetExchanger::RegisterMappingPort(bool in, bool tcp, int remote_port) noexcept {
                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, tcp, remote_port);
                if (NULL != mapping_port) {
                    return false;
                }

                mapping_port = NewMappingPort(in, tcp, remote_port);
                if (NULL == mapping_port) {
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                bool ok = mapping_port->OpenFrpServer(logger);
                if (ok) {
                    ok = VirtualEthernetMappingPort::AddMappingPort(mappings_, in, tcp, remote_port, mapping_port);
                }

                if (ok) {
                    if (NULL != logger) {
                        logger->MPEntry(GetId(), transmission, mapping_port->BoundEndPointOfFrpServer(), tcp);
                    }
                }
                else {
                    mapping_port->Dispose();
                }
                return ok;
            }

            VirtualEthernetExchanger::VirtualEthernetMappingPortPtr VirtualEthernetExchanger::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class MappingPort : public VirtualEthernetMappingPort {
                public:
                    MappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    virtual void Dispose() noexcept override {
                        if (std::shared_ptr<VirtualEthernetLinklayer> linklayer = GetLinklayer();  NULL != linklayer) {
                            VirtualEthernetExchanger* exchanger = dynamic_cast<VirtualEthernetExchanger*>(linklayer.get());
                            if (NULL != exchanger) {
                                VirtualEthernetMappingPort::DeleteMappingPort(exchanger->mappings_, ProtocolIsNetworkV4(), ProtocolIsTcpNetwork(), GetRemotePort());
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
                return make_shared_object<MappingPort>(self, transmission, tcp, in, remote_port);
            }

            VirtualEthernetExchanger::VirtualEthernetMappingPortPtr VirtualEthernetExchanger::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                return VirtualEthernetMappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
            }

            bool VirtualEthernetExchanger::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                if (disposed_) {
                    return false;
                }
                
                if (VirtualEthernetLinklayer::DoKeepAlived(transmission, now)) {
                    return true;
                }

                IDisposable::Dispose(this);
                return false;
            }

            bool VirtualEthernetExchanger::StaticEchoEchoToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (disposed_) {
                    return false;
                }

                if (NULL == packet) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;
                std::shared_ptr<ppp::net::packet::IPFrame> ip = packet->GetIPPacket(allocator);
                if (NULL == ip) {
                    return false;
                }
                elif(ip->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }
                elif(ip->Source == IPEndPoint::LoopbackAddress) {
                    std::shared_ptr<VirtualInternetControlMessageProtocolStatic> echo = static_echo_;
                    if (NULL == echo) {
                        return false;
                    }

                    ppp::app::protocol::VirtualEthernetPacket::FillBytesToPayload(ip.get());
                    return echo->Output(ip.get(), IPEndPoint::ToEndPoint(sourceEP));
                }

                std::shared_ptr<ppp::net::packet::IcmpFrame> frame = ppp::net::packet::IcmpFrame::Parse(ip.get());
                if (NULL == ip || NULL == frame) {
                    return false;
                }

                std::shared_ptr<VirtualInternetControlMessageProtocolStatic> echo = static_echo_;
                if (NULL == echo) {
                    return false;
                }

                return echo->Echo(ip, frame, IPEndPoint::ToEndPoint(sourceEP));
            }

            bool VirtualEthernetExchanger::StaticEchoReleasePort(uint32_t source_ip, int source_port) noexcept {
                std::shared_ptr<VirtualEthernetDatagramPortStatic> datagram_port;
                if (source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    return false;
                }

                uint64_t key = MAKE_QWORD(source_ip, source_port);
                if (key) {
                    SynchronizedObjectScope scope(static_echo_syncobj_);
                    Dictionary::TryRemove(static_echo_datagram_ports_, key, datagram_port);
                }

                if (NULL == datagram_port) {
                    return false;
                }

                datagram_port->Dispose();
                return true;
            }

            bool VirtualEthernetExchanger::StaticEchoSendToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept {
                if (disposed_) {
                    return false;
                }

                if (NULL == packet) {
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<Byte> messages = packet->Payload;
                if (NULL == messages) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULL == transmission) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetDatagramPortStatic> datagram_port;
                int source_port = packet->SourcePort;
                uint32_t source_ip = packet->SourceIP;

                boost::asio::ip::address destinationIP = Ipep::ToAddress(packet->DestinationIP);
                boost::asio::ip::udp::endpoint destinationEP = boost::asio::ip::udp::endpoint(destinationIP, packet->DestinationPort);

                if (source_ip == IPEndPoint::AnyAddress || source_ip == IPEndPoint::NoneAddress) {
                    return false;
                }
                elif(source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    return false;
                }
                elif(packet->DestinationPort <= IPEndPoint::MinPort || packet->DestinationPort > IPEndPoint::MaxPort) {
                    return false;
                }
                elif(packet->DestinationIP == IPEndPoint::AnyAddress || packet->DestinationIP == IPEndPoint::NoneAddress) {
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger(); 
                if (packet->DestinationPort == PPP_DNS_SYS_PORT) {
                    uint16_t queries_type = 0;
                    uint16_t queries_clazz = 0;
                    ppp::string hostDomain = ppp::net::native::dns::ExtractHostY(messages.get(), packet->Length,
                        [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                            queries_type = type;
                            queries_clazz = clazz;
                            return true;
                        });

                    if (hostDomain.size() > 0) {
                        if (NULL != logger) {
                            logger->Dns(GetId(), transmission, hostDomain);
                        }

                        if (firewall_->IsDropNetworkDomains(hostDomain)) {
                            return false;
                        }
                    }

                    boost::asio::ip::udp::endpoint sourceEP =
                        IPEndPoint::ToEndPoint<boost::asio::ip::udp>(IPEndPoint(source_ip, source_port));

                    int status = VirtualEthernetDatagramPort::NamespaceQuery(switcher_, this, sourceEP, destinationEP, hostDomain, 
                        messages.get(), packet->Length, queries_type, queries_clazz, true);
                    if (status < 0) {
                        return false;
                    }
                    elif(status > 0) {
                        return true;
                    }

                    status = RedirectDnsQuery(transmission, sourceEP, destinationEP, messages.get(), packet->Length, true);
                    if (status > -1) {
                        return status != 0;
                    }
                }

                for (;;) {
                    bool ok = false;
                    bool nw = false;

                    uint64_t key = MAKE_QWORD(source_ip, source_port);
                    std::shared_ptr<boost::asio::io_context> context = GetContext(); 
                    if (NULL != context) {
                        SynchronizedObjectScope scope(static_echo_syncobj_);
                        ok = ppp::collections::Dictionary::TryGetValue(static_echo_datagram_ports_, key, datagram_port);

                        if (!ok) {
                            datagram_port = make_shared_object<VirtualEthernetDatagramPortStatic>(exchanger, context, source_ip, source_port);
                            if (NULL == datagram_port) {
                                return false;
                            }

                            nw = true;
                            ok = datagram_port->Open() && ppp::collections::Dictionary::TryAdd(static_echo_datagram_ports_, key, datagram_port);
                        }
                    }

                    if (nw) {
                        if (ok) {
                            if (NULL != logger) {
                                logger->Port(GetId(), transmission, datagram_port->GetSourceEndPoint(), datagram_port->GetLocalEndPoint());
                            }
                        }
                        else {
                            datagram_port->Dispose();
                            return false;
                        }
                    }

                    break;
                }

                if (NULL == datagram_port) {
                    return false;
                }

                return datagram_port->SendTo(messages.get(), packet->Length, destinationEP);
            }
        }
    }
}