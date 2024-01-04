#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/http/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/http/VEthernetHttpProxyConnection.h>
#include <ppp/IDisposable.h>
#include <ppp/io/File.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/StringAuxiliary.h>

#ifdef _WIN32
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#elif _LINUX
#include <linux/ppp/tap/TapLinux.h>
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
            VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
                : VEthernet(context, lwip)
                , configuration_(configuration)
                , icmppackets_aid_(RandomNext())
                , block_quic_(false) {

            }

            VEthernetNetworkSwitcher::~VEthernetNetworkSwitcher() noexcept {
                Finalize();
            }

            VEthernetNetworkSwitcher::NetworkInterface::NetworkInterface() noexcept
                : Index(-1) {
                // TODO: Your are code here.
            }

            VEthernetNetworkSwitcher::NetworkInterface::~NetworkInterface() noexcept {
                // TODO: Your are code here.
            }

            std::shared_ptr<ppp::ethernet::VNetstack> VEthernetNetworkSwitcher::NewNetstack() noexcept {
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(GetReference());
                return make_shared_object<VEthernetNetworkTcpipStack>(self);
            }

            bool VEthernetNetworkSwitcher::OnTick(uint64_t now) noexcept {
                if (!VEthernet::OnTick(now)) {
                    return false;
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULL != qos) {
                    qos->Update();
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL != exchanger) {
                    exchanger->Update(now);
                }

                ppp::vector<int> releases_icmppackets;
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

                std::shared_ptr<VEthernetTickEventHandler> tick_event = TickEvent;
                if (tick_event) {
                    (*tick_event)(this, now);
                }
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

                // If the current need to prohibit the transfer of QUIC control protocol traffic, 
                // then the outgoing traffic sent to the 80/443 two ports through the UDP protocol can be directly discarded, 
                // simple and rough processing, if the remote sensing of all UDP port traffic, 
                // it will produce unnecessary burden and overhead on the performance of the program itself.
                if (block_quic_) {
                    int destinationPort = frame->Destination.Port;
                    if (destinationPort == 443 || destinationPort == 80) {
                        return false;
                    }
                }

                boost::asio::ip::udp::endpoint sourceEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                boost::asio::ip::udp::endpoint destinationEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Destination);
                return exchanger->SendTo(sourceEP, destinationEP, messages->Buffer.get(), messages->Length);
            }

            bool VEthernetNetworkSwitcher::ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IcmpFrame> e = make_shared_object<IcmpFrame>();
                e->AddressesFamily = frame->AddressesFamily;
                e->Destination = frame->Source;
                e->Source = frame->Destination;
                e->Payload = frame->Payload;
                e->Type = IcmpType::ICMP_ER;
                e->Code = frame->Code;
                e->Ttl = static_cast<Byte>(ttl);
                e->Sequence = frame->Sequence;
                e->Identification = frame->Identification;

                std::shared_ptr<IPFrame> reply = e->ToIp(allocator);
                if (NULL == reply) {
                    return false;
                }
                else {
                    return Output(reply.get());
                }
            }

            bool VEthernetNetworkSwitcher::TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IcmpFrame> e = make_shared_object<IcmpFrame>();
                e->AddressesFamily = frame->AddressesFamily;
                e->Type = IcmpType::ICMP_TE;
                e->Code = 0;
                e->Ttl = UINT8_MAX;
                e->Sequence = 0;
                e->Identification = 0;
                e->Source = source;
                e->Destination = frame->Source;
                e->Payload = packet->ToArray(allocator);

                std::shared_ptr<IPFrame> reply = e->ToIp(allocator);
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
                    return TE(packet, frame, frame->Destination, allocator);
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
                    else {
                        packet->Ttl = ttl;
                    }
                    return EchoOtherServer(exchanger, packet, allocator);
                }
            }

            bool VEthernetNetworkSwitcher::EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet.get());
                if (NULL == messages) {
                    return false;
                }

                return exchanger->Echo(messages->Buffer.get(), messages->Length);
            }

            bool VEthernetNetworkSwitcher::EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                if (NULL == exchanger) {
                    return false;
                }

                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet.get());
                if (NULL == messages) {
                    return false;
                }

                VEthernetIcmpPacket e = { Executors::GetTickCount() + ppp::net::asio::InternetControlMessageProtocol::MAX_ICMP_TIMEOUT, packet };
                for (;;) {
                    static constexpr int max_icmppackets_aid = (1 << 24) - 1;

                    int ack_id = ++icmppackets_aid_;
                    if (ack_id < 0) {
                        icmppackets_aid_ = 0;
                        continue;
                    }

                    if (ack_id > max_icmppackets_aid) {
                        icmppackets_aid_ = 0;
                        continue;
                    }

                    if (ppp::collections::Dictionary::ContainsKey(icmppackets_, ack_id)) {
                        continue;
                    }

                    auto kv = icmppackets_.emplace(ack_id, e);
                    if (!kv.second) {
                        return false;
                    }

                    bool ok = exchanger->Echo(ack_id);
                    if (ok) {
                        return true;
                    }

                    icmppackets_.erase(kv.first);
                    return false;
                }
            }

            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::GetExchanger() noexcept {
                return exchanger_;
            }

            std::shared_ptr<ppp::configurations::AppConfiguration> VEthernetNetworkSwitcher::GetConfiguration() noexcept {
                return configuration_;
            }

            void VEthernetNetworkSwitcher::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
                VEthernet::Dispose();
            }

            void VEthernetNetworkSwitcher::Finalize() noexcept {
                icmppackets_.clear();
                TickEvent.reset();
                ReleaseAllObjects(false);
            }

            std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> VEthernetNetworkSwitcher::GetTapNetworkInterface() noexcept {
                return tun_ni;
            }

            std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> VEthernetNetworkSwitcher::GetUnderlyingNetowrkInterface() noexcept {
                return underlying_ni_;
            }

            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::NewQoS() noexcept {
                int64_t bandwidth = 0;
                return make_shared_object<ppp::transmissions::ITransmissionQoS>(bandwidth);
            }

            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::NewExchanger() noexcept {
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                auto guid = StringAuxiliary::GuidStringToInt128(configuration->client.guid);
                return make_shared_object<VEthernetExchanger>(self, configuration, context, guid);
            }

            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULL == exchanger) {
                    return NULL;
                }
                else {
                    return make_shared_object<VEthernetHttpProxySwitcher>(exchanger);
                }
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetNetworkSwitcher::GetBufferAllocator() noexcept {
                return configuration_->GetBufferAllocator();
            }

            bool VEthernetNetworkSwitcher::DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size) noexcept {
                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                boost::asio::ip::address address = remoteEP.address();
                if (address.is_v4()) {
                    std::shared_ptr<BufferSegment> messages = make_shared_object<BufferSegment>();
                    messages->Buffer = std::shared_ptr<Byte>(reinterpret_cast<Byte*>(packet), [](Byte*) noexcept {});
                    messages->Length = packet_size;

                    std::shared_ptr<UdpFrame> frame = make_shared_object<UdpFrame>();
                    frame->AddressesFamily = AddressFamily::InterNetwork;
                    frame->Source = IPEndPoint::ToEndPoint(remoteEP);
                    frame->Destination = IPEndPoint::ToEndPoint(sourceEP);
                    frame->Payload = messages;

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<IPFrame> ip = UdpFrame::ToIp(allocator, frame.get());
                    return Output(ip.get());
                }
                return false;
            }

            bool VEthernetNetworkSwitcher::ReplaceInformation(const std::shared_ptr<VirtualEthernetInformation>& info) noexcept {
                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULL != qos) {
                    int64_t bandwidth = static_cast<int64_t>(info->BandwidthQoS) * (1024 >> 3); /* kbps. */
                    qos->SetBandwidth(bandwidth);
                }
                return true;
            }

            VEthernetNetworkSwitcher::RouteInformationTablePtr VEthernetNetworkSwitcher::GetRib() noexcept {
                return rib_;
            }

            VEthernetNetworkSwitcher::ForwardInformationTablePtr VEthernetNetworkSwitcher::GetFib() noexcept {
                return fib_;
            }

            bool VEthernetNetworkSwitcher::IsBlockQUIC() noexcept {
                return block_quic_;
            }

#ifdef _WIN32
            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::GetPaperAirplaneController() noexcept {
                return paper_airplane_ctrl_;
            }

            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::NewPaperAirplaneController() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();
                if (NULL == exchanger) {
                    return NULL;
                }
                else {
                    return make_shared_object<PaperAirplaneController>(exchanger);
                }
            }
#elif _LINUX
            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::NewProtectorNetwork() noexcept {
                std::shared_ptr<NetworkInterface> ni = GetUnderlyingNetowrkInterface();
                if (NULL == ni) {
                    return NULL;
                }
                return make_shared_object<ProtectorNetwork>(ni->Name);
            }

            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::GetProtectorNetwork() noexcept {
                return protect_network_;
            }
#endif

            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::GetHttpProxy() noexcept {
                return http_proxy_;
            }

            std::shared_ptr<VEthernetNetworkSwitcher::VirtualEthernetInformation> VEthernetNetworkSwitcher::GetInformation() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return NULL;
                }

                return exchanger->GetInformation();
            }

            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::GetQoS() noexcept {
                return qos_;
            }

            VEthernetNetworkSwitcher::ITransmissionStatisticsPtr& VEthernetNetworkSwitcher::GetStatistics() noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                if (NULL == statistics_) {
                    statistics_ = NewStatistics();
                }
                return statistics_;
            }

            VEthernetNetworkSwitcher::ITransmissionStatisticsPtr VEthernetNetworkSwitcher::NewStatistics() noexcept {
                return make_shared_object<ITransmissionStatistics>();
            }

#ifdef _WIN32
            static bool Windows_BlockQUIC(bool value) noexcept {
                bool enabled = !value;
                if (!ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(enabled)) {
                    return false;
                }
                elif(ppp::net::proxies::HttpProxy::IsSupportExperimentalQuicProtocol() != enabled) {
                    return false;
                }
                return true;
            }

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetNetworkInterface(const ppp::win32::network::AdapterInterfacePtr& ai) noexcept {
                if (NULL == ai) {
                    return NULL;
                }

                auto ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(ai->IfIndex);
                if (NULL == ni) {
                    return NULL;
                }

                boost::system::error_code ec;
                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> result = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                result->Id = ni->Guid;
                result->Index = ai->IfIndex;
                result->Name = ni->ConnectionId;
                result->Description = ni->Description;
                Ipep::StringsTransformToAddresses(ni->DnsAddresses, result->DnsAddresses);

                result->IPAddress = boost::asio::ip::address::from_string(ai->Address.data(), ec);
                result->SubmaskAddress = boost::asio::ip::address::from_string(ai->Mask.data(), ec);
                result->GatewayServer = boost::asio::ip::address::from_string(ai->GatewayServer.data(), ec);
                return result;
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

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                auto ai = ppp::win32::network::GetUnderlyingNetowrkInterface(tap->GetId());
                return Windows_GetNetworkInterface(ai);
            }
#elif _LINUX
            class LinuxNetworkInterface : public VEthernetNetworkSwitcher::NetworkInterface {
            public:
                ppp::string DnsResolveConfiguration;

            public:
                static bool SetDnsResolveConfiguration(const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& underlying_ni) noexcept {
                    if (NULL == underlying_ni) {
                        return false;
                    }

                    LinuxNetworkInterface* ni = dynamic_cast<LinuxNetworkInterface*>(underlying_ni.get());
                    if (NULL == ni) {
                        return false;
                    }

                    return ppp::tap::TapLinux::SetDnsResolveConfiguration(ni->DnsResolveConfiguration);
                }
            };

            static ppp::function<ppp::string(ppp::net::native::RouteEntry&)> Linux_GetNetworkInterfaceName(
                const std::shared_ptr<ppp::tap::ITap>& tap_if,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& tap_ni,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& underlying_ni) noexcept {
                return
                    [tap_if, tap_ni, underlying_ni](ppp::net::native::RouteEntry& entry) noexcept {
                    return entry.NextHop == tap_if->GatewayServer ? tap_ni->Name : underlying_ni->Name;
                    };
            }

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Linux_GetTapNetworkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULL;
                }

                int dev_handle = (int)reinterpret_cast<std::intptr_t>(tap->GetHandle());
                if (dev_handle == -1) {
                    return NULL;
                }

                ppp::string interface_name;
                if (!ppp::tap::TapLinux::GetInterfaceName(dev_handle, interface_name)) {
                    return NULL;
                }

                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);
                ni->Index = interface_index;
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->GatewayServer, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->IPAddress, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->SubmaskAddress, IPEndPoint::MinPort)).address();
                if (ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get()); NULL != linux_tap) {
                    ni->DnsAddresses = linux_tap->GetDnsAddresses();
                }
                return ni;
            }

            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Linux_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                ppp::string interface_name;
                ppp::UInt32 ip, gw, mask;
                if (!ppp::tap::TapLinux::GetPreferredNetworkInterface(interface_name, ip, mask, gw)) {
                    return NULL;
                }

                std::shared_ptr<LinuxNetworkInterface> ni = make_shared_object<LinuxNetworkInterface>();
                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);
                ni->Name = interface_name;
                ni->Index = ppp::tap::TapLinux::GetInterfaceIndex(interface_name);
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(gw, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(ip, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(mask, IPEndPoint::MinPort)).address();
                ni->DnsResolveConfiguration = ppp::tap::TapLinux::GetDnsResolveConfiguration();
                ppp::tap::TapLinux::GetDnsAddresses(ni->DnsResolveConfiguration, ni->DnsAddresses);
                return ni;
            }
#endif

            bool VEthernetNetworkSwitcher::BlockQUIC(bool value) noexcept {
#ifdef _WIN32
                // Windows platform manages whether these browsers use the QUIC protocol by setting methods such as Edge/Chrome global policy.
                Windows_BlockQUIC(value);
#endif

                // Set the status of the current VPN client switcher that needs to block QUIC traffic flags.
                block_quic_ = value;
                return true;
            }

#ifdef _WIN32
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

            bool VEthernetNetworkSwitcher::Constructor(const std::shared_ptr<ITap>& tap) noexcept {
                // Release all object resources held by the current virtual network switcher.
                ReleaseAllObjects(true);

                // Get and retrieve the current underlying Ethernet interface information!
#ifdef _WIN32
                underlying_ni_ = Windows_GetUnderlyingNetowrkInterface(tap);
#elif _LINUX
                underlying_ni_ = Linux_GetUnderlyingNetowrkInterface(tap);
#endif

                // The physical hosting network interface required for the VPN overlap network is not allowed to construct and turn on the VPN service.
                if (NULL == underlying_ni_) {
                    return false;
                }

                // Compatibility by all means try to check and fix the gateway route of the physical network card once, 
                // Otherwise there will be no network with all kinds of chain problems!
                if (auto gw = underlying_ni_->GatewayServer; gw.is_v4() && !IPEndPoint::IsInvalid(gw) && !gw.is_loopback()) {
                    uint32_t dw = htonl(gw.to_v4().to_uint());
#ifdef _WIN32
                    // Repair physical ethernet route table information on windows platform!
                    ppp::win32::network::Router::Add(IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, dw, 1);
#elif _LINUX
                    // Repair physical ethernet route table information on linux platform!
                    ppp::tap::TapLinux::AddRoute(underlying_ni_->Name, IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, dw);
#endif
                }

                // Construction of VEtherent virtual Ethernet switcher processing framework.
                if (!VEthernet::Constructor(tap)) {
                    return false;
                }

#ifdef _WIN32
                // Get network interface information for TAP-Windows virtual Ethernet devices!
                tun_ni = Windows_GetTapNetworkInterface(tap);
#elif _LINUX
                // Get network interface information for Linux tun/tap virtual Ethernet devices!
                tun_ni = Linux_GetTapNetworkInterface(tap);
#endif

                // The vEthernet network switcher cannot be opened when the virtual network adapter device interface for the VPN startup link cannot be found!
                if (NULL == tun_ni) {
                    return false;
                }

                // Instantiate the local QoS throughput speed control module!
                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = NewQoS();
                if (NULL == qos) {
                    return false;
                }

#ifdef _LINUX
                // This section describes how to instantiate the physical network instance protector required by ppp to 
                // Prevent VPN virtual switcher crashes caused by IP route loopback.
                ProtectorNetworkPtr protector_network = NewProtectorNetwork();
                if (NULL == protector_network) {
                    return false;
                }
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
                elif(!http_proxy->Open()) {
                    IDisposable::DisposeReferences(qos, exchanger, http_proxy);
                    return false;
                }

                // Mounts the various service objects created and opened by the current constructor.
                qos_ = std::move(qos);
                exchanger_ = std::move(exchanger);
                http_proxy_ = std::move(http_proxy);

#ifdef _LINUX
                protect_network_ = std::move(protector_network);
#endif

                // Load all IPList route table configuration files that need to be loaded.
                LoadAllIPListWithFilePaths(underlying_ni_->GatewayServer);

                // Add VPN remote server to IPList bypass route table iplist.
                if (!AddRemoteEndPointToIPList(underlying_ni_->GatewayServer)) {
                    return false;
                }

                // Attempt to load the routing table configuration if the routing table is configured correctly.
                if (RouteInformationTablePtr rib = rib_; NULL != rib) {
                    ForwardInformationTablePtr fib = make_shared_object<ForwardInformationTable>();
                    fib->Fill(*rib);

                    if (fib->IsAvailable()) {
                        fib_ = fib;
                    }
                }

                // Add VPN route table information to the operating system.
                if (tap->IsHostedNetwork() && !exchangeof(route_added_, true)) {
#ifdef _WIN32
                    // Use the Paper-Airplane NSP/LSP session layer forwarding plugins!
                    if (!UsePaperAirplaneController()) {
                        return false;
                    }
#endif

                    // VPN routes need to be configured for the operating system to configure the bearer network and overlapping network links.
                    AddRoute();

#ifdef _WIN32
                    // Configure all network card DNS servers in the entire operating system, because not doing so will cause DNS Leak and DNS contamination problems only Windows.
                    ppp::win32::network::SetAllNicsDnsAddresses(tun_ni->DnsAddresses, ni_dns_servers_);

                    // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after 
                    // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record 
                    // Available in the region where the VPN server is located.
                    ppp::tap::TapWindows::DnsFlushResolverCache();
#elif _LINUX
                    // Set tun/tap vnic binding dns servers list to the linux operating system configuration files.
                    ppp::tap::TapLinux::SetDnsAddresses(tun_ni->DnsAddresses);
#endif
                }

                return true;
            }

#ifdef _WIN32
            bool VEthernetNetworkSwitcher::UsePaperAirplaneController() noexcept {
                // Open the [PaperAirplane NSP/LSP] paper airplane server controller, 
                // Depending on the configuration and whether it is a CLI command line hosted network flag.
                if (configuration_->client.paper_airplane.tcp) {
                    PaperAirplaneControllerPtr controller = NewPaperAirplaneController();
                    if (NULL == controller) {
                        return false;
                    }

                    // Clean up resources constructed by the current function when opening the server side of the paper plane fails.
                    if (!controller->Open(tun_ni->Index)) {
                        IDisposable::DisposeReferences(controller);
                        return false;
                    }

                    // Open the paper plane successfully when you move the created instance on the local variable to 
                    // The virtual ethernet switch hosted fields.
                    paper_airplane_ctrl_ = std::move(controller);
                }
                return true;
            }
#endif

            void VEthernetNetworkSwitcher::AddRoute() noexcept {
#ifdef _WIN32
                // Find and delete all default route information!
                if (auto tap = GetTap(); NULL != tap) {
                    ppp::win32::network::DeleteAllDefaultGatewayRoutes(default_routes_, { tap->GatewayServer });
                }

                // Adds the loaded route table to the operating system.
                ppp::win32::network::AddAllRoutes(rib_);
#elif _LINUX
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
                                    ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni), default_routes);
                                }
                            }

                            // Add all routes configured in VPN/RIB to the operating system.
                            ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni), rib_);
                        }
                    }
                }
#endif
                // Configure the DNS servers used by the virtual network adapter to route to the operating system.
                AddRouteWithDnsServers();
            }

            void VEthernetNetworkSwitcher::DeleteRoute() noexcept {
#ifdef _WIN32
                // Delete the loaded route table from the windows operating system.
                ppp::win32::network::DeleteAllRoutes(rib_);

                // Add and delete all windows default route information!
                ppp::win32::network::AddAllRoutes(default_routes_);
#elif _LINUX
                // Delete the loaded route table from the linux operating system.
                if (auto underlying_ni = GetUnderlyingNetowrkInterface(); NULL != underlying_ni) {
                    if (auto tap_ni = GetTapNetworkInterface(); NULL != tap_ni) {
                        if (auto tap = GetTap(); NULL != tap) {
                            // Delete all rib route table information found.
                            ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni), rib_);

                            // Add and delete all linux-t default route information!
                            if (auto default_routes = default_routes_; NULL != default_routes) {
                                ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni), default_routes);
                            }
                        }
                    }
                }
#endif
                // Delete all vpn dns server routes from the operating system.
                DeleteRouteWithDnsServers();
            }

            ppp::string VEthernetNetworkSwitcher::GetRemoteUri() noexcept {
                return server_ru_;
            }

            boost::asio::ip::tcp::endpoint VEthernetNetworkSwitcher::GetRemoteEndPoint() noexcept {
                return server_ep_;
            }

            bool VEthernetNetworkSwitcher::AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept {
                using ProtocolType = VEthernetExchanger::ProtocolType;

                // This function must be executed after the remote exchanger object has been created.
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULL == exchanger) {
                    return false;
                }

                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                // Obtaining the IP endpoint address of the VPN remote server may involve synchronizing the network, as it may be in domain-name format.
                if (!exchanger->GetRemoteEndPoint(NULL, hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return false;
                }
                else {
                    server_ep_ = remoteEP;
                    server_ru_ = hostname;
                    server_ru_ += ":";
                    server_ru_ += std::to_string(port);
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
                }

                // Add the default IP address of the vpn virtual network adapter to the RIB route table.
                RouteInformationTablePtr rib = rib_;
                if (NULL == rib) {
                    rib = make_shared_object<RouteInformationTable>();
                    rib_ = rib;
                }

                // CIDR: 0.0.0.0/0; 0.0.0.0/1; 128.0.0.0/1
                if (auto tap = GetTap(); NULL != tap) {
                    uint32_t mid = inet_addr("128.0.0.0");
                    rib->AddRoute(IPEndPoint::AnyAddress, 1, tap->GatewayServer);
                    rib->AddRoute(mid, 1, tap->GatewayServer);
                    rib->AddRoute(IPEndPoint::AnyAddress, 0, tap->GatewayServer);
                }

                // Note that we only need to set IPV4 routes, not IPV6 routes.
                boost::asio::ip::address remoteIP = remoteEP.address();
                if (!remoteIP.is_v4()) {
                    return true;
                }

                // The gateway address must be IPV4 or it is considered a failure because there is no V6 gateway serving the V4 address.
                bool ok = false;
                if (gw.is_v4()) {
                    // First convert the IP addresses of both.
                    uint32_t ip = htonl(remoteIP.to_v4().to_uint());
                    uint32_t nx = htonl(gw.to_v4().to_uint());

                    // Add route information to rib!
                    ok = rib->AddRoute(ip, 32, nx);
                }
                return ok;
            }

            bool VEthernetNetworkSwitcher::AddLoadIPList(const ppp::string& path) noexcept {
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

                if (!File::Exists(fullpath.data())) {
                    return false;
                }

                LoadIPListFileSetPtr ribs = ribs_;
                if (NULL == ribs) {
                    ribs = make_shared_object<LoadIPListFileSet>();
                    ribs_ = ribs;
                }

                auto r = ribs->emplace(fullpath);
                return r.second;
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
                        if (LoadIPListFileSetPtr ribs = std::move(ribs_); NULL != ribs) {
                            // Loop in all iplist route table configuration files.
                            RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                            for (auto&& path : *ribs) {
                                any = rib->AddAllRoutesByIPList(path, next_hop);
                            }

                            // Loading is considered valid only if any route is added.
                            if (any) {
                                rib_ = rib;
                            }
                        }
                    }
                }

                // A value filled once can only be used once and then reset.
                ribs_ = NULL;
                return any;
            }

            void VEthernetNetworkSwitcher::AddRouteWithDnsServers() noexcept {
                // Clear the current cached dns server ip address list.
                dns_servers_.clear();

                // Obtain the IP address list of the DNS server configured on the current physical bearer NIC and VPN virtual network adapter.
                do {
                    std::shared_ptr<NetworkInterface> nis[] = { tun_ni, underlying_ni_ };
                    for (std::shared_ptr<NetworkInterface> ni : nis) {
                        if (!ni) {
                            continue;
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
                            dns_servers_.emplace(dip);
                        }
                    }
                } while (false);

                // Add the routing gateway of these DNS as the vpn server, mainly to solve the problem of interference.
                if (std::shared_ptr<ITap> tap = GetTap(); NULL != tap) {
#ifdef _WIN32
                    // Add dns server list IP routing to the windows operating system.
                    for (uint32_t ip : dns_servers_) {
                        ppp::win32::network::Router::Add(ip, tap->GatewayServer, 1);
                    }
#elif _LINUX
                    // Add dns server list IP routing to the linux operating system.
                    if (ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get()); NULL != linux_tap) {
                        int prefix_mask = IPEndPoint::NetmaskToPrefix(tap->SubmaskAddress);
                        for (uint32_t ip : dns_servers_) {
                            linux_tap->AddRoute(ip, prefix_mask, tap->GatewayServer);
                        }
                    }
#endif
                }
            }

            void VEthernetNetworkSwitcher::DeleteRouteWithDnsServers() noexcept {
                // Delete all vpn dns server routes from the operating system.
                if (std::shared_ptr<ITap> tap = GetTap(); NULL != tap) {
#ifdef _WIN32
                    // Delete the IP route for the dns server list added for the windows operating system.
                    if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULL != mib) {
                        for (uint32_t ip : dns_servers_) {
                            ppp::win32::network::Router::Delete(mib, ip, tap->GatewayServer);
                        }
                    }
#elif _LINUX
                    // Delete the IP route for the dns server list added for the linux operating system.
                    if (ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get()); NULL != linux_tap) {
                        int prefix_mask = IPEndPoint::NetmaskToPrefix(tap->SubmaskAddress);
                        for (uint32_t ip : dns_servers_) {
                            linux_tap->DeleteRoute(ip, prefix_mask, tap->GatewayServer);
                        }
                    }
#endif
                }

                // Clear the current cached dns server ip address list.
                dns_servers_.clear();
            }

            void VEthernetNetworkSwitcher::ReleaseAllObjects(bool ctor) noexcept {
                // Stop and release the http-proxy service.
                if (VEthernetHttpProxySwitcherPtr http_proxy = std::move(http_proxy_); NULL != http_proxy) {
                    http_proxy_.reset();
                    http_proxy->Dispose();
                }

                // Close and release the open exchanger!
                if (std::shared_ptr<VEthernetExchanger> exchanger = std::move(exchanger_); NULL != exchanger) {
                    exchanger_.reset();
                    exchanger->Dispose();
                }

                // Shutdown and release the qos control module!
                if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = std::move(qos_);  NULL != qos) {
                    qos_.reset();
                    qos->Dispose();
                }

#ifdef _WIN32
                // On Windows platforms, you need to try to turn off the [PaperAirplane NSP/LSP] server-side controller.
                if (PaperAirplaneControllerPtr controller = std::move(paper_airplane_ctrl_);  NULL != controller) {
                    paper_airplane_ctrl_.reset();
                    controller->Dispose();
                }
#endif

                // Delete VPN route table information configured in the operating system!
                if (exchangeof(route_added_, false)) {
                    // Delete routes entries configured by the VPN program from the operating system. 
                    DeleteRoute();

#ifdef _WIN32
                    // Restore all dns servers addresses that have been configured when VPN routes are enabled.
                    ppp::win32::network::SetAllNicsDnsAddresses(ni_dns_servers_);

                    // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after 
                    // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record 
                    // Available in the region where the VPN server is located.
                    ppp::tap::TapWindows::DnsFlushResolverCache();
#elif _LINUX
                    // Restore the original linux /etc/resolve.conf to linux operating system configuration files.
                    LinuxNetworkInterface::SetDnsResolveConfiguration(GetUnderlyingNetowrkInterface());
#endif
                }

#ifdef _WIN32
                // Clear all windows default network route information in the current cache!
                default_routes_.clear();
#elif _LINUX
                // Clear all linux-t default network route information in the current cache!
                default_routes_.reset();
#endif

                // Clear all route tables and forwarding tables held by the current object.
                if (!ctor) {
                    LoadAllIPListWithFilePaths(boost::asio::ip::address_v4::any());
                }
            }
        }
    }
}