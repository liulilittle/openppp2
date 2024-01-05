#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualInternetControlMessageProtocol.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
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
                const VirtualEthernetSwitcherPtr&                   switcher,
                const AppConfigurationPtr&                          configuration,
                const ITransmissionPtr&                             transmission,
                const Int128&                                       id) noexcept 
                : VirtualEthernetLinklayer(configuration, transmission->GetContext(), id)
                , disposed_(false)
                , switcher_(switcher)
                , transmission_(transmission) {
                firewall_ = switcher->GetFirewall();
            }

            VirtualEthernetExchanger::~VirtualEthernetExchanger() noexcept {
                Finalize();
            }

            void VirtualEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            void VirtualEthernetExchanger::Finalize() noexcept {
                exchangeof(disposed_, true); {
                    Dictionary::ReleaseAllObjects(datagrams_);
                    Dictionary::ReleaseAllCallbacks(timeouts_);
                    Dictionary::ReleaseAllCallbacks(resolvers_, reinterpret_cast<IPEndPoint*>(NULL));

                    VirtualInternetControlMessageProtocolPtr echo = std::move(echo_);
                    if (echo) {
                        echo_.reset();
                        echo->Dispose();
                    }

                    ITransmissionPtr transmission = std::move(transmission_);
                    if (transmission) {
                        transmission_.reset();
                        transmission->Dispose();
                    }

                    datagrams_.clear();
                    timeouts_.clear();
                    resolvers_.clear();
                }

                switcher_->DeleteExchanger(this);
            }

            VirtualEthernetExchanger::VirtualEthernetSwitcherPtr VirtualEthernetExchanger::GetSwitcher() noexcept {
                return switcher_;
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

            bool VirtualEthernetExchanger::DeleteTimeout(void* k) noexcept {
                if (NULL == k) {
                    return false;
                }
                else {
                    return Dictionary::RemoveValueByKey(timeouts_, k);
                }
            }

            bool VirtualEthernetExchanger::DeleteResolver(void* k) noexcept {
                if (NULL == k) {
                    return false;
                }
                else {
                    return Dictionary::RemoveValueByKey(resolvers_, k);
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
                elif(destinationPort == PPP_DNS_DEFAULT_PORT) {
                    ppp::string hostDomain = ppp::net::native::dns::ExtractHost(packet, packet_length);
                    if (hostDomain.size() > 0) {
                        if (firewall_->IsDropNetworkDomains(hostDomain)) {
                            return false;
                        }
                    }

                    if (RedirectDnsQuery(transmission, sourceEP, destinationEP, packet, packet_length) < 0) {
                        return false;
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
                        auto r = datagrams_.emplace(sourceEP, datagram);
                        if (r.second) {
                            ok = datagram->Open();
                            if (!ok) {
                                datagrams_.erase(r.first);
                            }
                        }

                        if (ok) {
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
                int                                                 packet_length) noexcept {

                const auto context = transmission->GetContext();
                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*context);
                if (!socket) {
                    return false;
                }

                boost::system::error_code ec;
                if (destinationEP.protocol() == boost::asio::ip::udp::v4()) {
                    socket->open(boost::asio::ip::udp::v4(), ec);
                }
                else {
                    socket->open(boost::asio::ip::udp::v6(), ec);
                }

                if (ec) {
                    return false;
                }

                socket->send_to(boost::asio::buffer(packet.get(), packet_length), redirectEP, 0, ec);
                if (ec) {
                    return false;
                }

                const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                const std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                const auto self = shared_from_this();
                const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                    [self, socket_weak] {
                        const std::shared_ptr<boost::asio::ip::udp::socket> socket = socket_weak.lock();
                        if (socket) {
                            Socket::Closesocket(socket);
                        }
                    });

                const auto timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, cb);
                if (NULL == timeout) {
                    return false;
                }
                
                if (!timeouts_.emplace(socket.get(), cb).second) {
                    return false;
                }
                 
                const auto buffer = Executors::GetCachedBuffer(context.get());
                const auto max_buffer_size = PPP_BUFFER_SIZE - sizeof(destinationEP);

                socket->async_receive_from(boost::asio::buffer(buffer.get(), max_buffer_size), 
                    *reinterpret_cast<boost::asio::ip::udp::endpoint*>(buffer.get() + max_buffer_size),
                    [self, this, socket, sourceEP, timeout, buffer, transmission, destinationEP](boost::system::error_code ec, size_t sz) noexcept {
                        DeleteTimeout(socket.get());
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                if (!DoSendTo(transmission, sourceEP, destinationEP, buffer.get(), (int)sz, nullof<YieldContext>())) {
                                    transmission->Dispose();
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
                int                                                 packet_length) noexcept {

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
                const auto resolver = make_shared_object<boost::asio::ip::udp::resolver>(*transmission->GetContext());

                const auto self = shared_from_this();
                const auto cb = make_shared_object<Ipep::GetAddressByHostNameCallback>(
                    [self, this, buffer, packet_length, source, in, destination, resolver](IPEndPoint* redirectEP) noexcept {
                        DeleteResolver(resolver.get());
                        if (!redirectEP) {
                            return false;
                        }

                        boost::asio::ip::udp::endpoint redirect = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(*redirectEP);
                        Executors::Post(in->GetContext(),
                            [self, this, buffer, packet_length, source, in, destination, redirect]() noexcept {
                                return INTERNAL_RedirectDnsQuery(in, redirect, source, destination, buffer, packet_length);
                            });
                        return true;
                    });

                bool ok = resolvers_.emplace(resolver.get(), cb).second;
                if (ok) {
                    Ipep::GetAddressByHostName(resolver, GetConfiguration()->udp.dns.redirect, PPP_DNS_DEFAULT_PORT, cb);
                }
                return ok;
            }

            int VirtualEthernetExchanger::RedirectDnsQuery(
                const ITransmissionPtr&                             transmission,
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                Byte*                                               packet,
                int                                                 packet_length) noexcept {

                std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
                if (configuration->udp.dns.redirect.empty()) {
                    return -1;
                }

                boost::asio::ip::udp::endpoint redirect_server = switcher_->GetDnsserverEndPoint();
                boost::asio::ip::address dnsserverIP = redirect_server.address();
                if (dnsserverIP.is_unspecified()) {
                    return INTERNAL_RedirectDnsQuery(transmission, sourceEP, destinationEP, packet, packet_length);
                }

                boost::asio::ip::udp::endpoint dnsserverEP(dnsserverIP, PPP_DNS_DEFAULT_PORT);
                return INTERNAL_RedirectDnsQuery(transmission,
                    dnsserverEP,
                    sourceEP,
                    destinationEP,
                    std::shared_ptr<Byte>(packet, [](Byte*) noexcept {}), packet_length);
            }

            bool VirtualEthernetExchanger::Update(UInt64 now) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->dispatch(
                    [self, this, now]() noexcept {
                        Dictionary::UpdateAllObjects(datagrams_, now);
                    });
                return true;
            }

            VirtualEthernetExchanger::ITransmissionPtr VirtualEthernetExchanger::GetTransmission() noexcept {
                return transmission_;
            }

            bool VirtualEthernetExchanger::Prepared() noexcept {
                if (disposed_) {
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

                echo_ = std::move(echo);
                return true;
            }

            VirtualEthernetExchanger::VirtualInternetControlMessageProtocolPtr VirtualEthernetExchanger::NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }

                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(GetReference());
                return make_shared_object<VirtualInternetControlMessageProtocol>(exchanger, transmission);
            }

            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULL == transmission) {
                    return NULL;
                }
                
                auto self = std::dynamic_pointer_cast<VirtualEthernetExchanger>(shared_from_this());
                return make_shared_object<VirtualEthernetDatagramPort>(self, transmission, sourceEP);
            }

            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::FindObjectByKey(datagrams_, sourceEP);
            }

            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::ReleaseObjectByKey(datagrams_, sourceEP);
            }

            bool VirtualEthernetExchanger::SendEchoToDestination(const ITransmissionPtr& transmission, Byte* packet, int packet_length) noexcept {
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
        }
    }
}