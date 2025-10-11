#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>
#include <ppp/IDisposable.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/io/File.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/net/asio/InternetControlMessageProtocol.h>

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#endif
#endif

using ppp::auxiliary::StringAuxiliary;
using ppp::collections::Dictionary;
using ppp::threading::Timer;
using ppp::threading::Executors;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::net::Ipep;
using ppp::net::native::ip_hdr;
using ppp::net::native::udp_hdr;
using ppp::net::native::icmp_hdr;
using ppp::net::packet::IPFlags;
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;
using ppp::net::packet::IcmpFrame;
using ppp::net::packet::IcmpType;
using ppp::net::packet::BufferSegment;
using ppp::transmissions::ITransmission;

namespace ppp {
    namespace app {
        namespace client {
            VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
                : VEthernet(context, lwip, vnet, mta)
                , configuration_(configuration)
                , icmppackets_aid_(0) {

#if !defined(_ANDROID) && !defined(_IPHONE)
                route_added_     = false;
#if defined(_LINUX)   
                protect_mode_    = false;
#endif
#endif
                static_mode_     = false;
                block_quic_      = false;
                icmppackets_aid_ = RandomNext();
            }

            VEthernetNetworkSwitcher::~VEthernetNetworkSwitcher() noexcept {
                Finalize();
            }

            VEthernetNetworkSwitcher::NetworkInterface::NetworkInterface() noexcept
                : Index(-1) {

            }

            std::shared_ptr<ppp::ethernet::VNetstack> VEthernetNetworkSwitcher::NewNetstack() noexcept {
                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetNetworkTcpipStack>(self);
            }

            bool VEthernetNetworkSwitcher::OnTick(uint64_t now) noexcept {
                if (!VEthernet::OnTick(now)) {
                    return false;
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_; 
                if (NULL != qos) {
                    qos->Update(now);
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_; 
                if (NULL != exchanger) {
                    exchanger->Update();
                }

                std::shared_ptr<IForwarding> forwarding = forwarding_; 
                if (NULL != forwarding) {
                    forwarding->Update(now);
                }

                ppp::vector<int> releases_icmppackets; 
                for (;;) {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    for (auto&& kv : icmppackets_) {
                        const VEthernetIcmpPacket& icmppacket = kv.second;
                        if (icmppacket.datetime > now) {
                            continue;
                        }

                        releases_icmppackets.emplace_back(kv.first);
                    }

                    for (int ack_id : releases_icmppackets) {
                        ppp::collections::Dictionary::RemoveValueByKey(icmppackets_, ack_id);
                    }

                    break;
                }

                VEthernetTickEventHandler tick_event = TickEvent; 
                if (tick_event) {
                    tick_event(this, now);
                }

                return true;
            }

            bool VEthernetNetworkSwitcher::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept {
                if (!vnet) {
                    return false;
                }

                if (proto != ppp::net::native::ip_hdr::IP_PROTO_TCP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_UDP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULL == tap) {
                    return false;
                }

                uint32_t destination = packet->dest;
                if (destination == tap->IPAddress || packet->src != tap->IPAddress) {
                    return false;
                }

                uint32_t gw = tap->GatewayServer;
                uint32_t mask = tap->SubmaskAddress;
                if (IPAddressIsGatewayServer(destination, gw, mask)) {
                    return false;
                }

                if (destination != ppp::net::native::ip_hdr::IP_ADDR_BROADCAST_VALUE) {
                    if ((destination & mask) != (gw & mask)) {
                        return false;
                    }
                }

                exchanger->Nat(packet, packet_length);
                return true;
            }

            bool VEthernetNetworkSwitcher::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                if (packet->ProtocolType == ip_hdr::IP_PROTO_UDP) {
                    return OnUdpPacketInput(packet);
                }
                elif(packet->ProtocolType == ip_hdr::IP_PROTO_ICMP) {
                    return OnIcmpPacketInput(packet);
                }
                else {
                    return false;
                }
            }

            bool VEthernetNetworkSwitcher::OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<UdpFrame> frame = UdpFrame::Parse(packet.get());
                if (NULL == frame) {
                    return false;
                }

                const std::shared_ptr<BufferSegment>& messages = frame->Payload;
                if (NULL == messages) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                // Check whether dns resolution packets need to be redirected.
                int destinationPort = frame->Destination.Port;
                if (destinationPort == PPP_DNS_SYS_PORT) {
                    if (RedirectDnsServer(exchanger, packet, frame, messages)) {
                        return true;
                    }
                }

                // If the current need to prohibit the transfer of QUIC IETF control protocol traffic, 
                // then the outgoing traffic sent to the 443 two ports through the UDP protocol can be directly discarded, 
                // simple and rough processing, if the remote sensing of all UDP port traffic, 
                // it will produce unnecessary burden and overhead on the performance of the program itself.
                if (block_quic_ && destinationPort == PPP_HTTPS_SYS_PORT) {
                    return false;
                }

                // If the VPN uses static transmission mode, ensure that the link is link ready.
                if (static_mode_) {
                    auto& static_ = configuration_->udp.static_;
                    if (static_.quic && destinationPort == PPP_HTTPS_SYS_PORT) {
                        if (exchanger->StaticEchoAllocated()) {
                            return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                        }
                    }
                    elif(static_.dns && destinationPort == PPP_DNS_SYS_PORT) {
                        if (exchanger->StaticEchoAllocated()) {
                            return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                        }
                    }
                    elif(exchanger->StaticEchoAllocated()) {
                        return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                    }
                }

                boost::asio::ip::udp::endpoint sourceEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                boost::asio::ip::udp::endpoint destinationEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Destination);
                return exchanger->SendTo(sourceEP, destinationEP, messages->Buffer.get(), messages->Length);
            }

            bool VEthernetNetworkSwitcher::ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::ER(packet, frame, ttl, allocator);
                if (NULL == reply) {
                    return false;
                }
                else {
                    return Output(reply.get());
                }
            }

            bool VEthernetNetworkSwitcher::TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::TE(packet, frame, source, allocator);
                if (NULL == reply) {
                    return false;
                }
                else {
                    return Output(reply.get());
                }
            }

            bool VEthernetNetworkSwitcher::ERORTE(int ack_id) noexcept {
                std::shared_ptr<IPFrame> packet;
                if (ack_id != 0) {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    bool ok = Dictionary::RemoveValueByKey(icmppackets_, ack_id, packet,
                        [](VEthernetIcmpPacket& value) noexcept {
                            return value.packet;
                        });
                    if (!ok) {
                        return false;
                    }
                }

                if (NULL == packet) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULL == tap) {
                    return false;
                }

                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
                if (NULL == frame) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                if (IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
                    int ttl = std::max<int>(1, static_cast<int>(frame->Ttl) - 1);
                    return ER(packet, frame, ttl, allocator);
                }
                else {
                    return TE(packet, frame, tap->GatewayServer, allocator);
                }
            }

            bool VEthernetNetworkSwitcher::OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULL == tap) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
                if (NULL == frame || frame->Ttl == 0) {
                    return false;
                }
                elif(IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                elif(frame->Ttl == 1) {
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                else {
                    int ttl = std::max<int>(0, static_cast<int>(packet->Ttl) - 1);
                    if (packet->Ttl < 1) {
                        return false;
                    }

                    frame->Ttl = ttl;
                    packet->Ttl = ttl;

                    return EchoOtherServer(exchanger, packet, allocator);
                }
            }

            bool VEthernetNetworkSwitcher::EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                if (NULL == exchanger) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet.get());
                if (NULL == messages) {
                    return false;
                }

                auto& static_ = configuration_->udp.static_;
                if ((static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                    return exchanger->StaticEchoPacketToRemoteExchanger(packet.get());
                }

                return exchanger->Echo(messages->Buffer.get(), messages->Length);
            }

            bool VEthernetNetworkSwitcher::EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                static constexpr int max_icmp_packets_aid = (1 << 24) - 1;
                
                if (NULL == exchanger) {
                    return false;
                }

                int ack_id = 0;
                do {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    if (IsDisposed()) {
                        return false;
                    }

                    VEthernetIcmpPacket e = { Executors::GetTickCount() + ppp::net::asio::InternetControlMessageProtocol::MAX_ICMP_TIMEOUT, packet };
                    for (;;) {
                        ack_id = ++icmppackets_aid_;
                        if (ack_id < 1) {
                            icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ack_id > max_icmp_packets_aid) {
                            icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ppp::collections::Dictionary::ContainsKey(icmppackets_, ack_id)) {
                            continue;
                        }

                        if (!ppp::collections::Dictionary::TryAdd(icmppackets_, ack_id, e)) {
                            return false;
                        }

                        auto& static_ = configuration_->udp.static_;
                        if ((static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                            break;
                        }
                        elif(exchanger->Echo(ack_id)) {
                            return true;
                        }

                        ppp::collections::Dictionary::TryRemove(icmppackets_, ack_id);
                        return false;
                    }
                } while (false);

                if (exchanger->StaticEchoGatewayServer(ack_id)) {
                    return true;
                }
                else {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    ppp::collections::Dictionary::TryRemove(icmppackets_, ack_id);
                    return false;
                }
            }

            void VEthernetNetworkSwitcher::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::dispatch(*context, 
                    [self, this, context]() noexcept {
                        Finalize();
                    });
                VEthernet::Dispose();
            }

            void VEthernetNetworkSwitcher::Finalize() noexcept {
                ReleaseAllObjects();
                ReleaseAllPackets();
                ReleaseAllTimeouts();
            }

            void VEthernetNetworkSwitcher::ReleaseAllPackets() noexcept {
                // Clear all ICMP packet container.
                SynchronizedObjectScope scope(GetSynchronizedObject());
                icmppackets_.clear();
            }

            void VEthernetNetworkSwitcher::ReleaseAllTimeouts() noexcept {
                TimeoutEventHandlerTable timeouts; {
                    // Clear all ICMP packet container.
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    timeouts = std::move(timeouts_);
                    timeouts_.clear();
                }

                // Release all timeout callbacks.
                Timer::ReleaseAllTimeouts(timeouts);
            }

#if defined(_ANDROID) || defined(_IPHONE)
            void VEthernetNetworkSwitcher::SetBypassIpList(ppp::string&& bypass_ip_list) noexcept {
                bypass_ip_list_ = std::move(bypass_ip_list);
            }
#endif

            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::NewQoS() noexcept {
                int64_t bandwidth = std::max<int64_t>(0, configuration_->client.bandwidth);
                if (bandwidth < 0) {
                    bandwidth *= (1024 >> 3); /* Kbps. */
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                return make_shared_object<ppp::transmissions::ITransmissionQoS>(context, bandwidth);
            }

            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::NewExchanger() noexcept {
                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                auto guid = StringAuxiliary::GuidStringToInt128(configuration->client.guid);
                if (guid == 0) {
                    return NULL;
                }

                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetExchanger>(self, configuration, GetContext(), guid);
            }

            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULL == exchanger) {
                    return NULL;
                }
                else {
                    return make_shared_object<VEthernetHttpProxySwitcher>(exchanger);
                }
            }

            VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULL == exchanger) {
                    return NULL;
                }
                else {
                    return make_shared_object<VEthernetSocksProxySwitcher>(exchanger);
                }
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetNetworkSwitcher::GetBufferAllocator() noexcept {
                return configuration_->GetBufferAllocator();
            }

            bool VEthernetNetworkSwitcher::DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching) noexcept {
                if (NULL == packet || packet_size < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                boost::asio::ip::address address = remoteEP.address();
                if (address.is_v4()) {
                    std::shared_ptr<BufferSegment> messages = make_shared_object<BufferSegment>();
                    if (NULL == messages) {
                        return false;
                    }

                    messages->Buffer = wrap_shared_pointer(reinterpret_cast<Byte*>(packet));
                    messages->Length = packet_size;

                    std::shared_ptr<UdpFrame> frame = make_shared_object<UdpFrame>();
                    if (NULL == frame) {
                        return false;
                    }

                    frame->AddressesFamily = AddressFamily::InterNetwork;
                    frame->Source = IPEndPoint::ToEndPoint(remoteEP);
                    frame->Destination = IPEndPoint::ToEndPoint(sourceEP);
                    frame->Payload = messages;

                    if (caching && configuration_->udp.dns.cache) {
                        int destinationPort = destinationEP.port();
                        if (destinationPort == PPP_DNS_SYS_PORT) {
                            ppp::net::asio::vdns::AddCache((Byte*)packet, packet_size);
                        }
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<IPFrame> ip = UdpFrame::ToIp(allocator, frame.get());
                    return Output(ip.get());
                }

                return false;
            }

            bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>& info) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULL != qos) {
                    int64_t bandwidth = static_cast<int64_t>(info->BandwidthQoS) * (1024 >> 3); /* Kbps. */
                    qos->SetBandwidth(bandwidth);
                }

                // If the user still has the remaining incoming/outgoing traffic and the expiration time is not reached, 
                // The VPN link is regarded as successful. Otherwise, the VPN link needs to be disconnected.
                if (info->Valid()) {
                    return true;
                }

                // If the VPN link needs to be disconnected, the client requires the active end, and the server forcibly disconnects. 
                // This prevents you from bypassing the disconnection problem by modifying the code of the client switch.
                std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->GetTransmission(); 
                if (NULL != transmission) {
                    transmission->Dispose();
                }
                
                return false;
            }

#if defined(_WIN32)
            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::NewPaperAirplaneController() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();
                if (NULL == exchanger) {
                    return NULL;
                }
                else {
                    return make_shared_object<PaperAirplaneController>(exchanger);
                }
            }
#elif defined(_LINUX)
            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::NewProtectorNetwork() noexcept {
#if defined(_ANDROID)
                // Embedding the so framework into the Android platform does not use sendfd/recvfd unix to share fd across processes, 
                // So you cannot pass in network cards or unix path names.
                ppp::string dev;
                return make_shared_object<ProtectorNetwork>(dev);
#else
                std::shared_ptr<NetworkInterface> ni = GetUnderlyingNetowrkInterface();
                if (NULL == ni) {
                    return NULL;
                }

                return make_shared_object<ProtectorNetwork>(ni->Name);
#endif
            }
#endif

            std::shared_ptr<VEthernetNetworkSwitcher::VirtualEthernetInformation> VEthernetNetworkSwitcher::GetInformation() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return NULL;
                }

                return exchanger->GetInformation();
            }
            
            VEthernetNetworkSwitcher::ITransmissionStatisticsPtr VEthernetNetworkSwitcher::NewStatistics() noexcept {
                return make_shared_object<ITransmissionStatistics>();
            }

#if defined(_WIN32)
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetNetworkInterface(const ppp::win32::network::AdapterInterfacePtr& ai, const ppp::win32::network::NetworkInterfacePtr& ni) noexcept {
                if (NULL == ai || NULL == ni) {
                    return NULL;
                }

                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> result = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                if (NULL == result) {
                    return NULL;
                }

                boost::system::error_code ec;
                result->Id = ni->Guid;
                result->Index = ai->IfIndex;
                result->Name = ni->ConnectionId;
                result->Description = ni->Description;
                Ipep::StringsTransformToAddresses(ni->DnsAddresses, result->DnsAddresses);

                result->IPAddress = StringToAddress(ai->Address.data(), ec);
                result->SubmaskAddress = StringToAddress(ai->Mask.data(), ec);
                result->GatewayServer = StringToAddress(ai->GatewayServer.data(), ec);
                return result;
            }

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetNetworkInterface(const ppp::win32::network::AdapterInterfacePtr& ai) noexcept {
                if (NULL == ai) {
                    return NULL;
                }

                auto ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(ai->IfIndex);
                return Windows_GetNetworkInterface(ai, ni);
            }

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetTapNetworkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULL;
                }

                ppp::vector<ppp::win32::network::AdapterInterfacePtr> interfaces;
                if (ppp::win32::network::GetAllAdapterInterfaces(interfaces)) {
                    for (auto&& ai : interfaces) {
                        if (ai->IfIndex == interface_index) {
                            return Windows_GetNetworkInterface(ai);
                        }
                    }
                }

                return NULL;
            }

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap, const ppp::string& nic) noexcept {
                auto [ai, ni] = ppp::win32::network::GetUnderlyingNetowrkInterface2(tap->GetId(), nic);
                return Windows_GetNetworkInterface(ai, ni);
            }
#elif !defined(_ANDROID) && !defined(_IPHONE)
            class UnixNetworkInterface final : public VEthernetNetworkSwitcher::NetworkInterface {
            public:
                ppp::string DnsResolveConfiguration;

            public:
                static bool SetDnsResolveConfiguration(const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& underlying_ni) noexcept {
                    if (NULL == underlying_ni) {
                        return false;
                    }

                    UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get());
                    if (NULL == ni) {
                        return false;
                    }

                    return ppp::unix__::UnixAfx::SetDnsResolveConfiguration(ni->DnsResolveConfiguration);
                }
            };

#if defined(_LINUX)
            static ppp::function<ppp::string(ppp::net::native::RouteEntry&)> Linux_GetNetworkInterfaceName(
                const std::shared_ptr<ppp::tap::ITap>&                              tap_if,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>&  tap_ni,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>&  underlying_ni,
                ppp::unordered_map<uint32_t, ppp::string>&                          nics) noexcept {

                auto f = 
                    [tap_if, tap_ni, underlying_ni, &nics](ppp::net::native::RouteEntry& entry) noexcept {
                        if (entry.NextHop == tap_if->GatewayServer) {
                            return tap_ni->Name;
                        }
                        
                        ppp::string nic;
                        if (Dictionary::TryGetValue(nics, entry.NextHop, nic)) {
                            if (!nic.empty()) {
                                return nic;
                            }
                        }

                        return underlying_ni->Name;
                    };
                return f;
            }
#endif

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Unix_GetTapNetworkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULL;
                }

                int dev_handle = (int)reinterpret_cast<std::intptr_t>(tap->GetHandle());
                if (dev_handle == -1) {
                    return NULL;
                }

                ppp::string interface_name;
#if defined(_MACOS)
                if (!ppp::darwin::tun::utun_get_if_name(dev_handle, interface_name)) {
                    return NULL;
                }
#else
                if (!ppp::tap::TapLinux::GetInterfaceName(dev_handle, interface_name)) {
                    return NULL;
                }
#endif

                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                if (NULL == ni) {
                    return NULL;
                }

                ni->Index = interface_index;
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->GatewayServer, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->IPAddress, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->SubmaskAddress, IPEndPoint::MinPort)).address();

#if defined(_MACOS)
                ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get()); 
                if (NULL != darwin_tap) {
                    ni->DnsAddresses = darwin_tap->GetDnsAddresses();
                }
#else
                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get()); 
                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);

                if (NULL != linux_tap) {
                    ni->DnsAddresses = linux_tap->GetDnsAddresses();
                }
#endif
                return ni;
            }

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Unix_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap, const ppp::string& nic) noexcept {
                std::shared_ptr<UnixNetworkInterface> ni = make_shared_object<UnixNetworkInterface>();
                if (NULL == ni) {
                    return NULL;
                }

#if defined(_MACOS)
                using NetworkInterface = ppp::tap::TapDarwin::NetworkInterface;

                ppp::vector<NetworkInterface::Ptr> network_interfaces;
                if (!ppp::tap::TapDarwin::GetAllNetworkInterfaces(network_interfaces)) {
                    return NULL;
                }

                NetworkInterface::Ptr network_interface = ppp::tap::TapDarwin::GetPreferredNetworkInterface2(network_interfaces, nic);
                if (NULL == network_interface) {
                    return NULL;
                }

                ni->Index = network_interface->Index;
                ni->Name = network_interface->Name;

                struct {
                    boost::asio::ip::address* address;
                    ppp::string* address_string;
                } addresses[] = {{&ni->GatewayServer, &network_interface->GatewayServer},
                    {&ni->IPAddress, &network_interface->IPAddress}, {&ni->SubmaskAddress, &network_interface->SubnetmaskAddress}};

                for (int i = 0; i < arraysizeof(addresses); i++) {
                    auto& r = addresses[i];
                    ppp::string* address_string = r.address_string;
                    if (address_string->empty()) {
                        continue;
                    }

                    boost::system::error_code ec;
                    *r.address = StringToAddress(address_string->data(), ec);
                    if (ec) {
                        return NULL;
                    }
                }

                ni->DefaultRoutes = std::move(network_interface->GatewayAddresses);
#else
                ppp::string interface_name;
                ppp::UInt32 ip, gw, mask;
                if (!ppp::tap::TapLinux::GetPreferredNetworkInterface(interface_name, ip, mask, gw, nic)) {
                    return NULL;
                }

                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);
                ni->Index = ppp::tap::TapLinux::GetInterfaceIndex(interface_name);
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(gw, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(ip, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(mask, IPEndPoint::MinPort)).address();
#endif

                ni->DnsResolveConfiguration = ppp::unix__::UnixAfx::GetDnsResolveConfiguration();
                ppp::unix__::UnixAfx::GetDnsAddresses(ni->DnsResolveConfiguration, ni->DnsAddresses);
                return ni;
            }
#endif

            bool VEthernetNetworkSwitcher::BlockQUIC(bool value) noexcept {
                // Set the status of the current VPN client switcher that needs to block QUIC traffic flags.
                block_quic_ = value;
                return true;
            }

#if defined(_WIN32)
            bool VEthernetNetworkSwitcher::SetHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to set the system HTTP proxy environment.
                auto http_proxy = GetHttpProxy();
                if (NULL == http_proxy) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::tcp::endpoint localEP = http_proxy->GetLocalEndPoint();
                int localPort = localEP.port();
                if (localPort <= IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::address localIP = localEP.address();
                if (IPEndPoint::IsInvalid(localIP)) {
                    localIP = boost::asio::ip::address_v4::loopback();
                }

                ppp::string server = ppp::net::Ipep::ToAddressString<ppp::string>(localIP) + ":" + stl::to_string<ppp::string>(localPort);
                ppp::string pac;
                bool bok = ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, true) &&
                    ppp::net::proxies::HttpProxy::SetSystemProxy(server) &&
                    ppp::net::proxies::HttpProxy::RefreshSystemProxy();
                if (!bok) {
                    return ClearHttpProxyToSystemEnv();
                }

                return bok;
            }

            bool VEthernetNetworkSwitcher::ClearHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to clear the system HTTP proxy environment.
                ppp::string server;
                ppp::string pac;
                return ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, false);
            }
#endif

#if defined(_ANDROID) || defined(_IPHONE)
            bool VEthernetNetworkSwitcher::AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept {
                RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                if (NULL == rib)  {
                    return false;
                }

                // Android requires the VPN to manage the routing table itself because it is a default gateway hybrid architecture.
                rib_ = rib;

                // Set up VPN subnet ip route.
                uint32_t cidr = ntohl(tap->SubmaskAddress);
                cidr = cidr & ntohl(tap->IPAddress);
                cidr = htonl(cidr);
                rib->AddRoute(cidr, IPEndPoint::NetmaskToPrefix(tap->SubmaskAddress), tap->GatewayServer);

                // Why does Android/APPLE-IOS load routing table information? 
                // This is to implement the IP diversion function of the HTTP proxy to prevent all traffic from going to the VPN server, 
                // Because there are some scenarios that do not want to go through the VPN server.
                if (ppp::string bypass_ip_list = std::move(bypass_ip_list_); bypass_ip_list.size() > 0) {
                    // IP address of the virtual network card is used here to make it inconsistent with the condition of determining
                    // The next hop gateway of the route in the IsBypassIpAddress function.
                    rib->AddAllRoutes(bypass_ip_list, IPEndPoint::LoopbackAddress);
                }

                // Add dns route set rules.
                uint32_t gws[] = {tap->GatewayServer, IPEndPoint::LoopbackAddress};
                ppp::unordered_set<uint32_t> dns_serverss_[2];
                for (auto&& dns_rules : dns_ruless_) {
                    for (auto& [_, r] : dns_rules) {
                        boost::asio::ip::address server = r->Server;
                        if (!server.is_v4()) {
                            continue;
                        }

                        uint32_t ip = htonl(server.to_v4().to_uint());
                        if (r->Nic) {
                            dns_serverss_[1].emplace(ip);
                        }
                        else {
                            dns_serverss_[0].emplace(ip);
                        }
                    }
                }

                // Compare two lists and remove duplicate ip addresses that appear in both lists.
                ppp::collections::Dictionary::DeduplicationList(dns_serverss_[1], dns_serverss_[0]);
                for (int i = 0; i < arraysizeof(gws); i++) {
                    uint32_t gw = gws[i];
                    for (auto& ip : dns_serverss_[i]) {
                        rib->AddRoute(ip, 32, gw);
                    }
                }

                // Add VPN remote server to IPList bypass route table iplist.
                return AddRemoteEndPointToIPList(Ipep::ToAddress(IPEndPoint::LoopbackAddress));
            }
#endif

            bool VEthernetNetworkSwitcher::PreparedAggregator() noexcept {
                std::shared_ptr<boost::asio::io_context> context = ppp::threading::Executors::GetDefault();
                if (NULL == context) {
                    return false;
                }

                std::shared_ptr<Byte> buffer = ppp::threading::Executors::GetCachedBuffer(context);
                if (NULL == buffer) {
                    return false;
                }

                std::shared_ptr<aggligator::aggligator> aggligator = 
                    make_shared_object<aggligator::aggligator>(*context, buffer, PPP_BUFFER_SIZE, PPP_AGGLIGATOR_CONGESTIONS);
                if (NULL == aggligator) {
                    return false;
                }

                aggligator_ = aggligator;
#if defined(_LINUX)
                aggligator->ProtectorNetwork = GetProtectorNetwork();
#endif
                aggligator->AppConfiguration = configuration_;
                aggligator->BufferswapAllocator = configuration_->GetBufferAllocator();
                return true;
            }

            bool VEthernetNetworkSwitcher::Open(const std::shared_ptr<ITap>& tap) noexcept {
#if !defined(_ANDROID) && !defined(_IPHONE)
                // Get and retrieve the current underlying Ethernet interface information!
#if defined(_WIN32)
                underlying_ni_ = Windows_GetUnderlyingNetowrkInterface(tap, preferred_nic_);
#else
                underlying_ni_ = Unix_GetUnderlyingNetowrkInterface(tap, preferred_nic_);
#endif

                // The physical hosting network interface required for the VPN overlap network is not allowed to construct and turn on the VPN service.
                if (auto underlying_ni = underlying_ni_; NULL != underlying_ni) {
                    boost::asio::ip::address& ngw = preferred_ngw_;
                    if (!IPEndPoint::IsInvalid(ngw)) {
                        underlying_ni->GatewayServer = ngw;
                    }
                }
                else {
                    return false;
                }

                // Compatibility by all means try to check and fix the gateway route of the physical network card once, 
                // Otherwise there will be no network with all kinds of chain problems!
                FixUnderlyingNgw();
#endif
                // Construction of VEtherent virtual Ethernet switcher processing framework.
                if (!VEthernet::Open(tap)) {
                    return false;
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_WIN32)
                // Get network interface information for TAP-Windows virtual Ethernet devices!
                tun_ni_ = Windows_GetTapNetworkInterface(tap);
#else
                // Get network interface information for Linux tun/tap virtual Ethernet devices!
                tun_ni_ = Unix_GetTapNetworkInterface(tap);
#endif

                // The vEthernet network switcher cannot be opened when the virtual network adapter device interface for the VPN startup link cannot be found!
                if (NULL == tun_ni_) {
                    return false;
                }
#endif

                // Initial a new network statistics.
                statistics_ = NewStatistics();

                // Instantiate the local QoS throughput speed control module!
                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = NewQoS();
                if (NULL == qos) {
                    return false;
                }

#if defined(_LINUX)
                // This section describes how to instantiate the physical network instance protector required by ppp to 
                // Prevent VPN virtual switcher crashes caused by IP route loopback.
                ProtectorNetworkPtr protector_network;
#if defined(_ANDROID)
                protector_network = NewProtectorNetwork();
                if (NULL == protector_network) {
                    return false;
                }
#else
                if (protect_mode_) {
                    protector_network = NewProtectorNetwork();
                }
#endif
#endif
                // Instantiate and open the internal virtual Ethernet switch that needs to be switcher to the remote.
                std::shared_ptr<VEthernetExchanger> exchanger = NewExchanger();
                if (NULL == exchanger) {
                    return false;
                }
                elif(!exchanger->Open()) {
                    IDisposable::DisposeReferences(qos, exchanger);
                    return false;
                }

                // Enable the local HTTP PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetHttpProxySwitcherPtr http_proxy = NewHttpProxy(exchanger);
                if (NULL == http_proxy) {
                    return false;
                }
                elif(http_proxy->Open()) {
                    http_proxy_ = std::move(http_proxy);
                }
                else {
                    http_proxy->Dispose();
                    http_proxy.reset();
                }

                // Enable the local SOCKS PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetSocksProxySwitcherPtr socks_proxy = NewSocksProxy(exchanger);
                if (NULL == socks_proxy) {
                    return false;
                }
                elif(socks_proxy->Open()) {
                    socks_proxy_ = std::move(socks_proxy);
                }
                else {
                    socks_proxy->Dispose();
                    socks_proxy.reset();
                }

                // Mounts the various service objects created and opened by the current constructor.
                qos_             = std::move(qos);
                exchanger_       = std::move(exchanger);

#if defined(_LINUX)
                protect_network_ = std::move(protector_network);
#endif

                // New the beast network bandwidth aggregator.
                if (static_mode_ && configuration_->udp.static_.aggligator > 0) {
                    if (!PreparedAggregator()) {
                        return false;
                    }
                }

#if defined(_ANDROID) || defined(_IPHONE)
                if (!AddAllRoute(tap)) {
                    IDisposable::DisposeReferences(qos, exchanger, http_proxy);
                    return false;
                }
#else
                // Load all IPList route table configuration files that need to be loaded.
                if (auto underlying_ni = underlying_ni_; NULL != underlying_ni) {
                    LoadAllIPListWithFilePaths(underlying_ni->GatewayServer);

                    // Add VPN remote server to IPList bypass route table iplist.
                    if (!AddRemoteEndPointToIPList(underlying_ni->GatewayServer)) {
                        return false;
                    }
                }
#endif

                // Attempt to load the routing table configuration if the routing table is configured correctly.
                if (RouteInformationTablePtr rib = rib_; NULL != rib) {
                    ForwardInformationTablePtr fib = make_shared_object<ForwardInformationTable>();
                    if (NULL != fib) {
                        fib->Fill(*rib);

                        if (fib->IsAvailable()) {
                            fib_ = fib;
                        }
                    }
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Add VPN route table information to the operating system.
                if (tap->IsHostedNetwork() && !exchangeof(route_added_, true)) {
#if defined(_WIN32)
                    // Use the Paper-Airplane NSP/LSP session layer forwarding plugins!
                    if (!UsePaperAirplaneController()) {
                        return false;
                    }
#endif

                    // VPN routes need to be configured for the operating system to configure the bearer network and overlapping network links.
                    AddRoute();

#if defined(_WIN32)
                    // Configure all network card DNS servers in the entire operating system, because not doing so will cause DNS Leak and DNS contamination problems only Windows.
                    auto tun_ni = tun_ni_; 
                    if (NULL != tun_ni) {
                        ppp::win32::network::SetAllNicsDnsAddresses(tun_ni->DnsAddresses, ni_dns_servers_);
                    }

                    // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after 
                    // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record 
                    // Available in the region where the VPN server is located.
                    ppp::tap::TapWindows::DnsFlushResolverCache();

                    // Delete the default route of a physical network card in a single attempt without a reason.
                    auto underlying_ni = underlying_ni_; 
                    if (NULL != underlying_ni) {
                        ppp::win32::network::DeleteAllDefaultGatewayRoutes(underlying_ni->GatewayServer);
                    }
#else
                    // Set tun/tap vnic binding dns servers list to the linux operating system configuration files.
                    auto tun_ni = tun_ni_; 
                    if (NULL != tun_ni) {
                        ppp::unix__::UnixAfx::SetDnsAddresses(tun_ni->DnsAddresses);
                    }
#endif
                    // Run the default gateway route protector.
                    ProtectDefaultRoute();
                }
#endif
                return true;
            }

#if defined(_WIN32)
            bool VEthernetNetworkSwitcher::UsePaperAirplaneController() noexcept {
                // Open the [PaperAirplane NSP/LSP] paper airplane server controller, 
                // Depending on the configuration and whether it is a CLI command line hosted network flag.
                if (configuration_->client.paper_airplane.tcp) {
                    PaperAirplaneControllerPtr controller = NewPaperAirplaneController();
                    if (NULL == controller) {
                        return false;
                    }

                    // Clean up resources constructed by the current function when opening the server side of the paper plane fails.
                    auto tun_ni = tun_ni_; 
                    if (NULL != tun_ni) {
                        auto tap = GetTap(); 
                        if (NULL != tap) {
                            if (!controller->Open(tun_ni->Index, tap->IPAddress, tap->SubmaskAddress)) {
                                IDisposable::DisposeReferences(controller);
                                return false;
                            }
                        }
                    }

                    // Open the paper plane successfully when you move the created instance on the local variable to 
                    // The virtual ethernet switch hosted fields.
                    paper_airplane_ctrl_ = std::move(controller);
                }
                return true;
            }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool VEthernetNetworkSwitcher::FixUnderlyingNgw() noexcept {
                auto ni = underlying_ni_;
                if (NULL == ni) {
                    return false;
                }

                auto gw = ni->GatewayServer; 
                if (gw.is_v4() && !IPEndPoint::IsInvalid(gw) && !gw.is_loopback()) {
                    uint32_t next_hop = htonl(gw.to_v4().to_uint());
#if defined(_WIN32)
                    // Repair physical ethernet route table information on windows platform!
                    ppp::win32::network::Router::Add(IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop, 1);
#elif defined(_MACOS)
                    ppp::darwin::tun::utun_add_route2(IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop);
#else
                    // Repair physical ethernet route table information on linux platform!
                    ppp::tap::TapLinux::AddRoute(ni->Name, IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop);
#endif
                    return true;
                }

                return false;
            }

            void VEthernetNetworkSwitcher::AddRoute() noexcept {
#if defined(_WIN32)
                // Find and delete all default route information!
                if (auto tap = GetTap(); NULL != tap) {
                    ppp::win32::network::DeleteAllDefaultGatewayRoutes(default_routes_, { tap->GatewayServer });
                }

                // Adds the loaded route table to the operating system.
                ppp::win32::network::AddAllRoutes(rib_);
#elif defined(_MACOS)
                // Delete all found default gateway routes.
                if (auto underlying_ni = GetUnderlyingNetowrkInterface(); NULL != underlying_ni) {
                    if (auto tap = GetTap(); NULL != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULL != darwin_tap && !darwin_tap->IsPromisc()) {
                            if (UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get()); NULL != ni) {
                                for (auto&& [ip, gw] : ni->DefaultRoutes) {
                                    ppp::darwin::tun::utun_del_route(ip, gw);
                                }
                            }
                        }
                    }

                    // Adds the loaded route table to the operating system.
                    ppp::tap::TapDarwin::AddAllRoutes(rib_);
                }
#else
                // Adds the loaded route table to the operating system.
                if (auto underlying_ni = GetUnderlyingNetowrkInterface(); NULL != underlying_ni) {
                    if (auto tap_ni = GetTapNetworkInterface(); NULL != tap_ni) {
                        // Find and delete all default route information.
                        if (auto tap = GetTap(); NULL != tap) {
                            // Find all default gateway routing lists and remove them, but only in non-promiscuous mode.
                            ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                            if (NULL != linux_tap && !linux_tap->IsPromisc()) {
                                RouteInformationTablePtr default_routes = ppp::tap::TapLinux::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                                default_routes_ = default_routes;

                                // Delete all default route table information found.
                                if (NULL != default_routes) {
                                    ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), default_routes);
                                }
                            }

                            // Add all routes configured in VPN/RIB to the operating system.
                            ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), rib_);
                        }
                    }
                }
#endif
                // Configure the DNS servers used by the virtual network adapter to route to the operating system.
                AddRouteWithDnsServers();
            }

            bool VEthernetNetworkSwitcher::DeleteAllDefaultRoute() noexcept {
                if (auto tap = GetTap(); NULL != tap) {
#if defined(_WIN32)
                    // Find and delete all disallowed windows gateway routes.
                    ppp::vector<MIB_IPFORWARDROW> default_routes;
                    ppp::win32::network::DeleteAllDefaultGatewayRoutes(default_routes, { tap->GatewayServer });
                    return true;
#else
#if defined(_MACOS)
                    auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
#else
                    auto unix_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
#endif
                    if (NULL != unix_tap && !unix_tap->IsPromisc()) {
#if defined(_MACOS)
                        // Find and delete all disallowed macos gateway routes.
                        auto rib = ppp::tap::TapDarwin::FindAllDefaultGatewayRoutes({ tap->GatewayServer }); 
                        if (NULL != rib) {
                            for (auto&& [ip, gw] : *rib) {
                                ppp::darwin::tun::utun_del_route(ip, gw);
                            }
                        }
#else
                        // Find and delete all disallowed linux gateway routes.
                        auto rib = ppp::tap::TapLinux::FindAllDefaultGatewayRoutes({ tap->GatewayServer }); 
                        if (NULL != rib) {
                            ppp::tap::TapLinux::DeleteAllRoutes2(rib);
                        }
#endif
                        return true;
                    }
#endif
                }
                return false;
            }

            void VEthernetNetworkSwitcher::DeleteRoute() noexcept {
#if defined(_WIN32)
                // Delete the loaded route table from the windows operating system.
                ppp::win32::network::DeleteAllRoutes(rib_);

                // Add and delete all windows default route information!
                ppp::win32::network::AddAllRoutes(default_routes_);

                // Force to set the network card gateway server, not just manually add the routing table, 
                // In the previous system can add routes, 
                // The system will automatically set the network card, but the latest WIN11 can not.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULL != ni) {
                    ppp::win32::network::SetDefaultIPGateway(ni->Index, { ni->GatewayServer });
                }
#elif defined(_MACOS)
                // Delete the loaded route table from the osx operating system.
                if (auto underlying_ni = GetUnderlyingNetowrkInterface(); NULL != underlying_ni) {
                    // Delete all rib route table information found.
                    ppp::tap::TapDarwin::DeleteAllRoutes(rib_);

                    // Add and delete all os-x default route information!
                    if (auto tap = GetTap(); NULL != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULL != darwin_tap && !darwin_tap->IsPromisc()) {
                            if (UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get()); NULL != ni) {
                                for (auto&& [ip, gw] : ni->DefaultRoutes) {
                                    ppp::darwin::tun::utun_add_route(ip, gw);
                                }
                            }
                        }
                    }
                }
#else
                // Delete the loaded route table from the linux operating system.
                if (auto underlying_ni = GetUnderlyingNetowrkInterface(); NULL != underlying_ni) {
                    if (auto tap_ni = GetTapNetworkInterface(); NULL != tap_ni) {
                        if (auto tap = GetTap(); NULL != tap) {
                            // Delete all rib route table information found.
                            ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), rib_);

                            // Add and delete all linux-t default route information!
                            if (auto default_routes = default_routes_; NULL != default_routes) {
                                ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), default_routes);
                            }
                        }
                    }
                }
#endif

                // Fix and restore physical nic next hop route settings.
                FixUnderlyingNgw();

                // Delete all vpn dns server routes from the operating system.
                DeleteRouteWithDnsServers();
            }

            ppp::string VEthernetNetworkSwitcher::GetRemoteUri() noexcept {
                return server_ru_;
            }

            void VEthernetNetworkSwitcher::PreferredNic(const ppp::string& nic) noexcept {
                preferred_nic_ = nic;
            }

            void VEthernetNetworkSwitcher::PreferredNgw(const boost::asio::ip::address& gw) noexcept {
                preferred_ngw_ = gw;
            }

            bool VEthernetNetworkSwitcher::AddLoadIPList(
                const ppp::string&                                              path, 
#if defined(_LINUX) 
                const ppp::string&                                              nic,
#endif  
                const boost::asio::ip::address&                                 gw,
                const ppp::string&                                              url) noexcept {

                using File = ppp::io::File;

                if (path.empty()) {
                    return false;
                }

                ppp::string fullpath = File::RewritePath(path.data());
                if (fullpath.empty()) {
                    return false;
                }

                fullpath = File::GetFullPath(path.data());
                if (fullpath.empty()) {
                    return false;
                }

                bool vbgp_url = ppp::net::http::HttpClient::VerifyUri(url, NULL, NULL, NULL, NULL);
                if (!vbgp_url && !File::Exists(fullpath.data())) {
                    return false;
                }
                
                uint32_t ngw = IPEndPoint::AnyAddress;
                if (
#if defined(_LINUX) 
                    !nic.empty() && 
#endif
                    gw.is_v4() && !IPEndPoint::IsInvalid(gw)) {
                    ngw = htonl(gw.to_v4().to_uint());
                }

                LoadIPListFileVectorPtr ribs = ribs_;
                if (NULL == ribs) {
                    ribs = make_shared_object<LoadIPListFileVector>();
                    ribs_ = ribs;
                }

                if (NULL == ribs) {
                    return false;
                }
                else {
                    auto tail = std::find_if(ribs->begin(), ribs->end(),
                        [&fullpath](const std::pair<ppp::string, uint32_t>& i) noexcept {
                            return i.first == fullpath;
                        });
                    if (tail != ribs->end()) {
                        return false;
                    }
                }

                if (vbgp_url) {
                    RouteIPListTablePtr vbgp = vbgp_;
                    if (NULL == vbgp)  {
                        vbgp = make_shared_object<RouteIPListTable>();
                        if (NULL == vbgp) {
                            return false;
                        }

                        vbgp_ = vbgp;
                    }

                    vbgp->emplace(std::make_pair(fullpath, url));
                }

#if defined(_LINUX) 
                if (ngw != IPEndPoint::AnyAddress) {
                    nics_.emplace(std::make_pair(ngw, nic));
                }
#endif
                
                ribs->emplace_back(std::make_pair(fullpath, ngw));
                return true;
            }

            bool VEthernetNetworkSwitcher::LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept {
                rib_ = NULL;
                fib_ = NULL;

                // Load all the route table iplist configuration files that need to be loaded.
                bool any = false;
                if (gw.is_v4()) {
                    // Obtain the numerical address of the next hop in the IP route table, which is a function implementation of the bypass-iplist.
                    boost::asio::ip::address_v4 in = gw.to_v4();
                    if (uint32_t next_hop = htonl(in.to_uint()); !IPEndPoint::IsInvalid(in)) {
                        if (LoadIPListFileVectorPtr ribs = std::move(ribs_); NULL != ribs) {
                            // Loop in all iplist route table configuration files.
                            RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                            if (NULL != rib) {
                                for (auto&& kv : *ribs) {
                                    const ppp::string& path = kv.first;
                                    const uint32_t ngw = kv.second != IPEndPoint::AnyAddress ? kv.second : next_hop;
                                    any |= rib->AddAllRoutesByIPList(path, ngw);
                                }

                                // Loading is considered valid only if any route is added.
                                if (any) {
                                    rib_ = rib;
                                }
                            }
                        }
                    }
                }

                // A value filled once can only be used once and then reset.
                ribs_.reset();
                return any;
            }

            void VEthernetNetworkSwitcher::AddRouteWithDnsServers() noexcept {
                // Clear the current cached dns server ip address list.
                for (auto& dns_servers : dns_serverss_) {
                    dns_servers.clear();
                }

                // Obtain the IP address list of the DNS server configured on the current physical bearer NIC and VPN virtual network adapter.
                auto add_dns_server_to_dns_servers =
                    [](const std::shared_ptr<NetworkInterface>& ni, ppp::unordered_set<uint32_t>& dns_servers) noexcept {
                        if (NULL == ni) {
                            return false;
                        }

                        uint32_t ips[2] = { IPEndPoint::AnyAddress, IPEndPoint::AnyAddress };
                        boost::asio::ip::address nips[] = { ni->IPAddress, ni->SubmaskAddress };
                        for (int i = 0; i < arraysizeof(nips); i++) {
                            boost::asio::ip::address& ip = nips[i];
                            if (ip.is_v4()) {
                                ips[i] = ip.to_v4().to_uint();
                            }
                        }

                        uint32_t rip = ips[0] & ips[1];
                        for (boost::asio::ip::address& ip : ni->DnsAddresses) {
                            if (ip.is_v6()) {
                                continue;
                            }

                            if (!ip.is_v4()) {
                                continue;
                            }

                            if (ip.is_multicast()) {
                                continue;
                            }

                            if (ip.is_loopback()) {
                                continue;
                            }

                            if (ip.is_unspecified()) {
                                continue;
                            }

                            if (IPEndPoint::IsInvalid(ip)) {
                                continue;
                            }

                            uint32_t dip = ip.to_v4().to_uint();
                            uint32_t tip = (dip & ips[1]);
                            if (tip == rip) {
                                continue;
                            }

                            dip = htonl(dip);
                            dns_servers.emplace(dip);
                        }
                        return true;
                    };

                add_dns_server_to_dns_servers(tun_ni_, dns_serverss_[0]);
                add_dns_server_to_dns_servers(underlying_ni_, dns_serverss_[1]);

                // Add dns route set rules.
                for (auto&& dns_rules : dns_ruless_) {
                    for (auto& [_, r] : dns_rules) {
                        boost::asio::ip::address server = r->Server;
                        if (!server.is_v4()) {
                            continue;
                        }

                        uint32_t ip = htonl(server.to_v4().to_uint());
                        if (r->Nic) {
                            dns_serverss_[1].emplace(ip);
                        }
                        else {
                            dns_serverss_[0].emplace(ip);
                        }
                    }
                }

                // Compare two lists and remove duplicate ip addresses that appear in both lists.
                ppp::collections::Dictionary::DeduplicationList(dns_serverss_[1], dns_serverss_[0]);

                // Add the routing gateway of these DNS as the vpn server, mainly to solve the problem of interference.
                if (std::shared_ptr<ITap> tap = GetTap(); NULL != tap) {
                    for (uint32_t ip : dns_serverss_[0]) {
                        AddRoute(ip, tap->GatewayServer, 32);
                    }
                }

                // Add the dns route table to the loopback settings of the physical nic.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULL != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
                        for (uint32_t ip : dns_serverss_[1]) {
                            AddRoute(ip, next_hop, 32);
                        }
                    }
                }
            }

            bool VEthernetNetworkSwitcher::AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
#if defined(_WIN32)
                MIB_IPFORWARDROW route;
                if (ppp::win32::network::Router::GetBestRoute(ip, route)) {
                    if (route.dwForwardDest == ip && route.dwForwardNextHop != gw) {
                        ppp::win32::network::Router::Delete(route);
                    }
                }

                // Add dns server list IP routing to the windows operating system.
                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                return ppp::win32::network::Router::Add(ip, mask, gw, 1);
#elif defined(_MACOS)
                // Add dns server list IP routing to the macos operating system.
                return ppp::darwin::tun::utun_add_route(ip, prefix, gw);
#else
                // If gateway is of a physical network card, it means that this is the NS route for physical network card.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULL != ni) {
                    boost::asio::ip::address next_hop = ni->GatewayServer;
                    if (next_hop.is_v4() && htonl(next_hop.to_v4().to_uint()) == gw) {
                        return ppp::tap::TapLinux::AddRoute(ni->Name, ip, 32, gw);
                    }
                }

                // Add dns server list IP routing to the linux operating system.
                std::shared_ptr<ppp::tap::ITap> tap = GetTap();
                if (NULL == tap) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                if (NULL == linux_tap) {
                    return false;
                }

                return linux_tap->AddRoute(ip, prefix, gw);
#endif
            }

#if defined(_WIN32)
            bool VEthernetNetworkSwitcher::DeleteRoute(const std::shared_ptr<MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept {
                // Delete the IP route for the dns server list added for the windows operating system.
                if (NULL == mib) {
                    return false;
                }

                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                return ppp::win32::network::Router::Delete(mib, ip, mask, gw);
            }
#else
            bool VEthernetNetworkSwitcher::DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
#if defined(_MACOS)
                // Delete the IP route for the dns server list added for the macos operating system.
                return ppp::darwin::tun::utun_del_route(ip, prefix, gw);
#else
                // // If gateway is of a physical network card, it means that this is the NS route for physical network card.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULL != ni) {
                    boost::asio::ip::address next_hop = ni->GatewayServer;
                    if (next_hop.is_v4() && htonl(next_hop.to_v4().to_uint()) == gw) {
                        return ppp::tap::TapLinux::DeleteRoute(ni->Name, ip, 32, gw);
                    }
                }

                // Delete the IP route for the dns server list added for the linux operating system.
                std::shared_ptr<ppp::tap::ITap> tap = GetTap();
                if (NULL == tap) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                if (NULL == linux_tap) {
                    return false;
                }

                return linux_tap->DeleteRoute(ip, prefix, gw);
#endif
            }
#endif

            void VEthernetNetworkSwitcher::DeleteRouteWithDnsServers() noexcept {
                // Delete all vpn dns server routes from the operating system.
                if (std::shared_ptr<ppp::tap::ITap> tap = GetTap(); NULL != tap) {
#if defined(_WIN32)
                    // Delete the IP route for the dns server list added for the windows operating system.
                    if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULL != mib) {
                        for (uint32_t ip : dns_serverss_[0]) {
                            DeleteRoute(mib, ip, tap->GatewayServer, 32);
                        }
                    }
#else
                    // Delete the IP route for the dns server list added for the macos operating system.
                    for (uint32_t ip : dns_serverss_[0]) {
                        DeleteRoute(ip, tap->GatewayServer, 32);
                    }
#endif
                }

                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULL != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
#if defined(_WIN32)
                        // Delete the IP route for the dns server list added for the windows operating system.
                        if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULL != mib) {
                            for (uint32_t ip : dns_serverss_[1]) {
                                DeleteRoute(mib, ip, next_hop, 32);
                            }
                        }
#else
                        // Delete the IP route for the dns server list added for the macos operating system.
                        for (uint32_t ip : dns_serverss_[1]) {
                            DeleteRoute(ip, next_hop, 32);
                        }
#endif
                    }
                }

                // Clear the current cached dns server ip address list.
                for (auto& dns_servers : dns_serverss_) {
                    dns_servers.clear();
                }
            }

            // Routes need to be protected on Windows to prevent third - party programs(such as network card drivers) 
            // From silently modifying the current gateway route and forcing out the VPN virtual gateway route.According to our observation, 
            // In some PC and network production environments, third - party programs will destroy VPN deployment routing table information 
            // At certain times.In PPP PRIVATE NETWORK™ 1, this NETWORK route protector exists by default, but PPP PRIVATE Network ™ 2 does 
            // Not currently exist, so a new implementation of this section is needed.
            bool VEthernetNetworkSwitcher::ProtectDefaultRoute() noexcept {
                auto tap = GetTap();
                if (NULL == tap) {
                    return false;
                }

#if !defined(_WIN32)
#if defined(_MACOS)
                auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
#else
                auto unix_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
#endif
                if (NULL == unix_tap || unix_tap->IsPromisc()) {
                    return false;
                }
#endif

                // Create a new network protection backend subthread.
                auto self = shared_from_this();
                std::thread([self, this]() noexcept {
                    auto prepare = [self, this]() noexcept {
                        // If the current VEthernet framework object instance is released, the process is break.
                        if (IsDisposed()) {
                            return false;
                        }

                        // If the route is not added to the system, the route pops out without setting the flag.
                        if (!route_added_) {
                            return false;
                        }

                        // Check whether the physical nic interface information still exists.
                        std::shared_ptr<NetworkInterface> underlying_ni = underlying_ni_;
                        if (NULL == underlying_ni) {
                            return false;
                        }

                        // If the physical network adapter gateway server is not IPV4, the process is displayed.
                        boost::asio::ip::address gw = underlying_ni->GatewayServer;
                        if (!gw.is_v4()) {
                            return false;
                        }

                        return true;
                    };

                    ppp::SetThreadName("protector");
                    for (;;) {
                        // Gets the current process processing start time.
                        uint64_t start = ppp::GetTickCount();

                        // If the pre-preparation check processing fails, just jump out of the loop because the object is being released.
                        bool ok = prepare();
                        if (!ok) {
                            break;
                        }

                        // Try to get the lock, if you can't get the lock, do not deal with it and wait for the next execution.
                        if (prdr_.try_lock()) {
                            ok = prepare();
                            if (ok) {
                                ok = DeleteAllDefaultRoute();
                            }

                            // Release the obtained prdr lock and decide whether to exit the process.
                            prdr_.unlock();
                            if (!ok) {
                                break;
                            }
                        }

                        // Calculate how much time the thread has to wait for sleep.
                        uint64_t now = ppp::GetTickCount();
                        uint64_t delta = 0;
                        if (now >= start) {
                            delta = 1000 - std::min<uint64_t>(1000, now - start);
                        }

                        // Check whether the default gateway route is faulty every second.
                        ppp::Sleep(delta);
                    }
                }).detach();
                return true;
            }
#endif

            bool VEthernetNetworkSwitcher::IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v4()) {
                    return false;
                }

                if (ip.is_unspecified()) {
                    return false;
                }

                if (ip.is_multicast()) {
                    return false;
                }

                if (ppp::net::IPEndPoint::IsInvalid(ip)) {
                    return false;
                }

                auto tap = GetTap();
                if (NULL == tap) {
                    return false;
                }

                uint32_t nip = htonl(ip.to_v4().to_uint());
#if defined(_ANDROID)
                // RIB
                if (auto fib = fib_; NULL != fib) {
                    uint32_t ngw = fib->GetNextHop(nip);
                    return ngw != tap->GatewayServer;
                }

                return false;
#elif defined(_WIN32)
                DWORD dwInterfaceIndex;
                if (!::GetBestInterface((IPAddr)nip, &dwInterfaceIndex)) {
                    return false;
                }

                return dwInterfaceIndex != (DWORD)tap->GetInterfaceIndex();
#else
                // OS X provides basic routing table processing so that the HTTP proxy provided by the VPN can route 
                // The traffic instead of having to deliver it to the VPN server for processing.
                // 
                // It is only supported when the VPN opens the network card promisbity mode, 
                // Which is to support the PC only a single network card can provide a reliable VPN virtual network 
                // For the local area network through the kernel SNAT mechanism.
                // 
                // Note: Google Android and Huawei HarmonyOS platforms (the VPN network adapter promiscuous mode must be enabled)
                // Snat: iptables -t nat -I POSTROUTING -s 192.168.0.24 -j SNAT --to-source 10.0.0.2
                return ppp::net::Socket::GetBestInterfaceIP(nip) != tap->IPAddress;
#endif
            }

            void VEthernetNetworkSwitcher::ReleaseAllObjects() noexcept {
#if !defined(_ANDROID) && !defined(_IPHONE)
                // Windows platform needs to set the prdr synchronization lock state to prevent the problem of multi-thread concurrent competition.
                SynchronizedObjectScope scope(prdr_);
#endif

                // Clear event bindings.
                TickEvent.reset();

                // Stop and release the http-proxy service.
                if (VEthernetHttpProxySwitcherPtr http_proxy = std::move(http_proxy_); NULL != http_proxy) {
                    http_proxy_.reset();
                    http_proxy->Dispose();
                }

                // Stop and release the socks-proxy service.
                if (VEthernetSocksProxySwitcherPtr socks_proxy = std::move(socks_proxy_); NULL != socks_proxy) {
                    socks_proxy_.reset();
                    socks_proxy->Dispose();
                }

                // Close and release the exchanger.
                if (std::shared_ptr<VEthernetExchanger> exchanger = std::move(exchanger_); NULL != exchanger) {
                    exchanger_.reset();
                    exchanger->Dispose();
                }

                // Shutdown and release the qos control module.
                if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = std::move(qos_);  NULL != qos) {
                    qos_.reset();
                    qos->Dispose();
                }

                // Close and release the aggligator.
                if (std::shared_ptr<aggligator::aggligator> aggligator = std::move(aggligator_); NULL != aggligator) {
                    aggligator_.reset();
                    aggligator->close();
                }

                // Close and release the forwarding.
                if (IForwardingPtr forwarding = std::move(forwarding_); NULL != forwarding) {
                    forwarding_.reset();
                    forwarding->Dispose();
                }

#if defined(_WIN32)
                // On Windows platforms, you need to try to turn off the [PaperAirplane NSP/LSP] server-side controller.
                if (PaperAirplaneControllerPtr controller = std::move(paper_airplane_ctrl_);  NULL != controller) {
                    paper_airplane_ctrl_.reset();
                    controller->Dispose();
                }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Delete VPN route table information configured in the operating system!
                if (exchangeof(route_added_, false)) {
                    // Delete routes entries configured by the VPN program from the operating system. 
                    DeleteRoute();

#if defined(_WIN32)
                    // Restore all dns servers addresses that have been configured when VPN routes are enabled.
                    ppp::win32::network::SetAllNicsDnsAddresses(ni_dns_servers_);

                    // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after 
                    // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record 
                    // Available in the region where the VPN server is located.
                    ppp::tap::TapWindows::DnsFlushResolverCache();
#else
                    // Restore the original linux /etc/resolve.conf to linux operating system configuration files.
                    UnixNetworkInterface::SetDnsResolveConfiguration(GetUnderlyingNetowrkInterface());
#endif
                }

                // To clean up the managed and unmanaged data currently held by the class, 
                // You need to go through the complete construct fill process again after the Release of this function.
                ribs_.reset(); 
                tun_ni_.reset();
                underlying_ni_.reset();
                
                // Clear the reference pointers of the held vBGP without making specific clarification, as this may pose thread safety issues.
                vbgp_ = NULL;

#if !defined(_MACOS)
                // Clear the routing table, forwarding table, and DNS server list of the network card, including cache.
                rib_ = NULL;
                fib_ = NULL;
#endif

                // Clear all route tables and forwarding tables held by the current object.
                LoadAllIPListWithFilePaths(boost::asio::ip::address_v4::any());
#endif

#if defined(_LINUX)
                // Release the network protector held by the current VPN local client switcher.
                if (auto protector = std::move(protect_network_); NULL != protector) {
                    protect_network_.reset();

                    // In android platform you need to request the DetachJNI function of the network protector.
#if defined(_ANDROID)
                    protector->DetachJNI();
#endif
                }
#endif
            }

            bool VEthernetNetworkSwitcher::DeleteTimeout(void* k) noexcept {
                if (NULL == k) {
                    return false;
                }

                SynchronizedObjectScope scope(GetSynchronizedObject());
                return Dictionary::RemoveValueByKey(timeouts_, k);
            }

            bool VEthernetNetworkSwitcher::EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept {
                if (NULL == k || NULL == timeout) {
                    return false;
                }

                SynchronizedObjectScope scope(GetSynchronizedObject());
                auto r = timeouts_.emplace(k, timeout);
                return r.second;
            }

            bool VEthernetNetworkSwitcher::LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept {
                if (rules.empty()) {
                    return false;
                }

                int events = 0;
                if (load_file_or_string) {
                    events = ppp::app::client::dns::Rule::LoadFile(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                }
                else {
                    events = ppp::app::client::dns::Rule::Load(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                }

                return events > 0;
            }

            bool VEthernetNetworkSwitcher::AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept {
                using ProtocolType = VEthernetExchanger::ProtocolType;

                // This function must be executed after the remote exchanger object has been created.
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                // Initialize and try the proxy forwarding object if the link does require proxy forwarding services.
                IForwardingPtr forwarding = make_shared_object<IForwarding>(GetContext(), configuration_);
                if (NULL == forwarding) {
                    return false;
                }
                elif(forwarding->Open()) {
                    forwarding_ = forwarding;
#if defined(_LINUX)
                    forwarding->ProtectorNetwork = GetProtectorNetwork();
#endif
                }
                else {
                    forwarding->Dispose();
                    forwarding.reset();
                }

                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                // Obtaining the IP endpoint address of the VPN remote server may involve synchronizing the network, as it may be in domain-name format.
                static constexpr ppp::coroutines::YieldContext* y = NULL;
                
                if (!exchanger->GetRemoteEndPoint(y, hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return false;
                }
                else {
                    server_ru_ = hostname;
                    server_ru_ += ":";
                    server_ru_ += stl::to_string<ppp::string>(NULL != forwarding ? forwarding->GetRemotePort() : port);
                    server_ru_ += "/";

                    if (protocol_type == ProtocolType::ProtocolType_Http || protocol_type == ProtocolType::ProtocolType_WebSocket) {
                        server_ru_ += "ppp+ws";
                    }
                    elif(protocol_type == ProtocolType::ProtocolType_HttpSSL || protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                        server_ru_ += "ppp+wss";
                    }
                    else {
                        server_ru_ += "ppp+tcp";
                    }

                    if (NULL != forwarding) {
                        remoteEP = forwarding->GetProxyEndPoint();
                    }
                }

                // Add the default IP address of the vpn virtual network adapter to the RIB route table.
                RouteInformationTablePtr rib = rib_;
                if (NULL == rib) {
                    rib = make_shared_object<RouteInformationTable>();
                    rib_ = rib;
                }

                // CIDR: 0.0.0.0/0; 0.0.0.0/1; 128.0.0.0/1
                if (NULL != rib) {
                    if (auto tap = GetTap(); NULL != tap) {
                        rib->AddRoute(IPEndPoint::AnyAddress, 0, tap->GatewayServer);
                        rib->AddRoute(IPEndPoint::AnyAddress, 1, tap->GatewayServer);
                        rib->AddRoute(inet_addr("128.0.0.0"), 1, tap->GatewayServer);
                    }
                }

                // Note that we only need to set IPV4 routes, not IPV6 routes.
                boost::asio::ip::address remoteIP = remoteEP.address();
                IPEndPoint serverEP = IPEndPoint::ToEndPoint(remoteEP);
                if (IPEndPoint::IsInvalid(serverEP)) {
                    return false;
                }
                elif(!remoteIP.is_v4()) {
                    return remoteIP.is_v6();
                }

                // Add IPV4 route table settings.
                auto fib_add_route_ipv4 =
                    [&rib, &gw](const boost::asio::ip::address& remoteIP) noexcept {
                        if (NULL != rib) {
                            if (gw.is_v4()) {
                                // First convert the IP addresses of both.
                                uint32_t ip = htonl(remoteIP.to_v4().to_uint());
                                uint32_t nx = htonl(gw.to_v4().to_uint());

                                // Add route information to rib!
                                return rib->AddRoute(ip, 32, nx);
                            }
                        }
                        return false;
                    };

                // Check whether the static tunnel specifies an IP address endpoint (required for transit).
                ppp::unordered_set<boost::asio::ip::tcp::endpoint> servers;
                auto StaticEchoAddRemoteEndPoint = 
                    [this, &servers, &fib_add_route_ipv4, &exchanger](const ppp::string& server_string) noexcept {
                        if (server_string.empty()) {
                            return false;
                        }

                        ppp::string host_string;
                        int port;

                        if (ppp::net::Ipep::ParseEndPoint(server_string, host_string, port) && (port > IPEndPoint::MinPort && port <= IPEndPoint::MaxPort)) {
                            if (IPEndPoint serverEP = ppp::net::Ipep::GetEndPoint(host_string, port); !IPEndPoint::IsInvalid(serverEP)) {
                                boost::asio::ip::udp::endpoint ep =
                                    IPEndPoint::ToEndPoint<boost::asio::ip::udp>(serverEP);
                                if (!serverEP.IsLoopback()) {
                                    fib_add_route_ipv4(ep.address());
                                }

                                if (aggligator_) {
                                    auto r = servers.emplace(
                                        IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(serverEP));
                                    return r.second;
                                }
                                else {
                                    return exchanger->StaticEchoAddRemoteEndPoint(ep);
                                }
                            }
                        }
                        return false;
                    };

                for (const ppp::string& server_string : configuration_->udp.static_.servers) {
                    StaticEchoAddRemoteEndPoint(server_string);
                }

                // Open the beast network bandwidth aggregator.
                if (std::shared_ptr<aggligator::aggligator> aggligator = aggligator_; NULL != aggligator) {
                    if (servers.empty()) {
                        aggligator_.reset();
                        aggligator->close();
                    }
                    elif(!aggligator->client_open(configuration_->udp.static_.aggligator, servers)) {
                        return false;
                    }
                }

                // The gateway address must be IPV4 or it is considered a failure because there is no V6 gateway serving the V4 address.
                return serverEP.IsLoopback() ? true : fib_add_route_ipv4(remoteIP);
            }

            bool VEthernetNetworkSwitcher::RedirectDnsServer(
                ppp::coroutines::YieldContext&                              y,
                const std::shared_ptr<boost::asio::ip::udp::socket>&        socket,
                const std::shared_ptr<Byte>&                                buffer,
                const boost::asio::ip::address&                             serverIP,
                const std::shared_ptr<UdpFrame>&                            frame,
                const std::shared_ptr<ppp::net::packet::BufferSegment>&     messages,
                const std::shared_ptr<boost::asio::io_context>&             context,
                const boost::asio::ip::address&                             destinationIP) noexcept {

                boost::system::error_code ec;
                boost::asio::ip::udp::endpoint serverEP(serverIP, frame->Destination.Port);

                bool opened = ppp::coroutines::asio::async_open(y, *socket, serverEP.protocol());
                if (!opened) {
                    return false;
                }

                int handle = socket->native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, serverIP.is_v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);

#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter.
                // IPV6 does not need to be linked, because VPN is IPV4,
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (serverIP.is_v4() && !serverIP.is_loopback()) {
                    if (IsBypassIpAddress(serverIP)) {
                        auto protector_network = GetProtectorNetwork(); 
                        if (NULL != protector_network) {
                            if (!protector_network->Protect(handle, y)) {
                                return false;
                            }
                        }
                    }
                }
#endif

                socket->send_to(boost::asio::buffer(messages->Buffer.get(), messages->Length), serverEP,
                    boost::asio::socket_base::message_end_of_record, ec);
                if (ec) {
                    return false;
                }

                const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                const std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                
                const auto self = shared_from_this();
                const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                    [self, socket_weak](Timer*) noexcept {
                        const std::shared_ptr<boost::asio::ip::udp::socket> socket = socket_weak.lock();
                        if (socket) {
                            ppp::net::Socket::Closesocket(socket);
                        }
                    });
                if (NULL == cb) {
                    return false;
                }

                const auto timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, *cb);
                if (NULL == timeout) {
                    return false;
                }

                if (!EmplaceTimeout(socket.get(), cb)) {
                    return false;
                }

                const auto max_buffer_size = PPP_BUFFER_SIZE - sizeof(serverEP);
                boost::asio::ip::udp::endpoint sourceEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                boost::asio::ip::udp::endpoint destinationEP(destinationIP, frame->Destination.Port);

                socket->async_receive_from(boost::asio::buffer(buffer.get(), max_buffer_size), *reinterpret_cast<boost::asio::ip::udp::endpoint*>(buffer.get() + max_buffer_size),
                    [self, this, socket, timeout, buffer, sourceEP, destinationEP](boost::system::error_code ec, size_t sz) noexcept {
                        DeleteTimeout(socket.get());
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                DatagramOutput(sourceEP, destinationEP, buffer.get(), sz);
                            }
                        }

                        ppp::net::Socket::Closesocket(socket);
                        if (timeout) {
                            timeout->Stop();
                            timeout->Dispose();
                        }
                    });
                return true;
            }

            bool VEthernetNetworkSwitcher::RedirectDnsServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, const std::shared_ptr<BufferSegment>& messages) noexcept {
                ::dns::Message m;
                if (m.decode(static_cast<uint8_t*>(messages->Buffer.get()), messages->Length) != ::dns::BufferResult::NoError) {
                    return false;
                }

                if (m.questions.empty()) {
                    return false;
                }
                
                boost::asio::ip::address destinationIP = Ipep::ToAddress(packet->Destination);
                ::dns::QuestionSection& qs = *m.questions.data();

                if (!ppp::net::asio::vdns::QueryCache2(qs.mName.data(), m, qs.mType == ::dns::RecordType::kA ?
                    ppp::net::asio::vdns::AddressFamily::kA : ppp::net::asio::vdns::AddressFamily::kAAAA).empty()) {

                    std::size_t dns_size = 0;
                    char dns_packet[PPP_MAX_DNS_PACKET_BUFFER_SIZE]; 

                    if (m.encode(dns_packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE, dns_size) == ::dns::BufferResult::NoError && dns_size > 0) {
                        return DatagramOutput(
                            IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source), 
                            boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT), dns_packet, dns_size, false);
                    }
                }

                boost::asio::ip::address serverIP;
                if (std::shared_ptr<ITap> tap = GetTap(); IPAddressIsGatewayServer(packet->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
                    auto& dnsServers = ppp::net::asio::vdns::servers;
                    if (dnsServers->empty()) {
                        return false;
                    }

                    serverIP = dnsServers->begin()->address();
                }
                else {
                    ppp::app::client::dns::Rule::Ptr rulePtr = ppp::app::client::dns::Rule::Get(stl::transform<ppp::string>(qs.mName), dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                    if (NULL == rulePtr) {
                        return false;
                    }

                    if (rulePtr->Server == destinationIP) {
                        return false;
                    }

                    serverIP = rulePtr->Server;
                }

                std::shared_ptr<boost::asio::io_context> context = exchanger->GetContext();
                if (NULL == context) {
                    return false;
                }

                std::shared_ptr<Byte> buffer = exchanger->GetBuffer();
                if (NULL == buffer) {
                    return false;
                }

                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*context);
                if (!socket) {
                    return false;
                }

                const auto self = shared_from_this();
                const auto allocator = configuration_->GetBufferAllocator();

                return ppp::coroutines::YieldContext::Spawn(allocator.get(), *context,
                    [self, this, socket, buffer, frame, messages, context, serverIP, destinationIP](ppp::coroutines::YieldContext& y) noexcept {
                        return RedirectDnsServer(y, socket, buffer, serverIP, frame, messages, context, destinationIP);
                    });
            }

            bool VEthernetNetworkSwitcher::StaticMode(bool* static_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = static_mode_;
                if (NULL != static_mode) {
                    static_mode_ = *static_mode;
                }

                return snow;
            }

            uint16_t VEthernetNetworkSwitcher::Mux(uint16_t* mux) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint16_t snow = mux_;
                if (NULL != mux) {
                    mux_ = *mux;
                }

                return snow;
            }

            uint8_t VEthernetNetworkSwitcher::MuxAcceleration(uint8_t* mux_acceleration) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint8_t snow = mux_acceleration_;
                if (NULL != mux_acceleration) {
                    mux_acceleration_ = *mux_acceleration;
                }

                return snow;
            }

            bool VEthernetNetworkSwitcher::OnUpdate(uint64_t now) noexcept {
                if (VEthernet::OnUpdate(now)) {
                    std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                    if (NULL != exchanger) {
                        exchanger->StaticEchoSwapAsynchronousSocket();
                    }
                }

                return false;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)   
#if defined(_LINUX)
            bool VEthernetNetworkSwitcher::ProtectMode(bool* protect_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = protect_mode_;
                if (NULL != protect_mode) {
                    protect_mode_ = *protect_mode;
                }

                return snow;
            }
#endif
#endif
        }
    }
}