#include <ppp/app/client/ClientPacketDispatchHandler.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/QuicRejectRateLimiter.h>
#include <ppp/app/client/dns/DnsController.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/threading/Executors.h>

#if defined(_ANDROID)
#include <android/log.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#endif

using ppp::collections::Dictionary;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::net::Ipep;
using ppp::net::native::ip_hdr;
using ppp::net::native::udp_hdr;
using ppp::net::packet::BufferSegment;
using ppp::net::packet::IcmpFrame;
using ppp::net::packet::IcmpType;
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;
using ppp::telemetry::Level;
using ppp::threading::Executors;

namespace ppp {
    namespace app {
        namespace client {

            void ClientPacketDispatchHandler::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

            /** @brief Handles native IPv4 packet input and forwards eligible NAT traffic. */
            bool ClientPacketDispatchHandler::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept {
                if (!vnet) {
                    return false;
                }

                if (proto != ppp::net::native::ip_hdr::IP_PROTO_TCP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_UDP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = owner_->exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                uint32_t destination = packet->dest;
                if (destination == tap->IPAddress || packet->src != tap->IPAddress) {
                    return false;
                }

                uint32_t gw = tap->GatewayServer;
                uint32_t mask = tap->SubmaskAddress;
                if (owner_->IPAddressIsGatewayServer(destination, gw, mask)) {
                    return false;
                }

                if (destination != ppp::net::native::ip_hdr::IP_ADDR_BROADCAST_VALUE) {
                    if ((destination & mask) != (gw & mask)) {
                        return false;
                    }
                }

                // Clamp outbound TCP SYN MSS to the static tunnel budget and, when an
                // authenticated ICMP Fragmentation Needed was received, the learned PMTU.
                if (proto == ppp::net::native::ip_hdr::IP_PROTO_TCP) {
                    const int path_mtu = app::protocol::GetVirtualEthernetPathMtuCache().Lookup(
                        destination, Executors::GetTickCount());
                    app::protocol::ClampTcpMssIPv4(reinterpret_cast<Byte*>(packet), packet_length,
                        app::protocol::ComputeDynamicTcpMss(true,
                            app::protocol::kVEthernetTunnelOverhead, path_mtu));
                }

                exchanger->Nat(packet, packet_length);
                return true;
            }

            /** @brief Handles raw IPv6 packet input and forwards approved traffic. */
            bool ClientPacketDispatchHandler::OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept {
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    return false;
                }


                if (!IsApprovedIPv6Packet(packet, packet_length)) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    return false;
                }

                const app::protocol::VirtualEthernetIPv6PathMtuAddress path_mtu_destination =
                    app::protocol::VirtualEthernetIPv6PathMtuAddress::Create(destination);
                const int path_mtu = app::protocol::GetVirtualEthernetIPv6PathMtuCache().Lookup(
                    path_mtu_destination, Executors::GetTickCount());
                app::protocol::ClampTcpMssIPv6(packet, packet_length,
                    app::protocol::ComputeDynamicTcpMss(false, app::protocol::kVEthernetTunnelOverhead, path_mtu));

                std::shared_ptr<VEthernetExchanger> exchanger = owner_->exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                exchanger->Nat(packet, packet_length);
                return true;
            }

            /** @brief Validates IPv6 packet source and destination against assigned policy. */
            bool ClientPacketDispatchHandler::IsApprovedIPv6Packet(Byte* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    return false;
                }

                boost::asio::ip::address_v6::bytes_type src_bytes = source.to_bytes();
                if (src_bytes[0] == 0xfe && (src_bytes[1] & 0xc0) == 0x80) {
                    return false;
                }

                if (destination.is_unspecified() || destination.is_loopback() || destination.is_multicast()) {
                    return false;
                }

#if defined(_ANDROID) || defined(_IPHONE)
                return false;
#else
                const VEthernetNetworkSwitcher::VirtualEthernetInformationExtensions& approved = *owner_->information_extensions_;
                bool valid_mode = approved.AssignedIPv6Mode == VEthernetNetworkSwitcher::VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
                    approved.AssignedIPv6Mode == VEthernetNetworkSwitcher::VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                if (!owner_->address_manager_->Ipv6Applied() || !valid_mode || approved.AssignedIPv6AddressPrefixLength != ppp::ipv6::IPv6_MAX_PREFIX_LENGTH || !approved.AssignedIPv6Address.is_v6()) {
                    return false;
                }

                if (source != approved.AssignedIPv6Address.to_v6()) {
                    return false;
                }

                return true;
#endif
            }

            /** @brief Routes parsed IP frame to protocol-specific handlers. */
            bool ClientPacketDispatchHandler::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
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

            /** @brief Emits ICMP Port Unreachable so QUIC clients quickly fall back to TCP. */
            bool ClientPacketDispatchHandler::RejectBlockedQuic(const std::shared_ptr<ppp::net::packet::IPFrame>& packet, const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept {
                if (NULLPTR == packet || NULLPTR == frame) {
                    return false;
                }

                UInt64 now = Executors::GetTickCount();
                ppp::string key = owner_->quic_reject_limiter_->BuildKey(packet, frame);
                if (!key.empty()) {
                    ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->GetSynchronizedObject());
                    if (!owner_->quic_reject_limiter_->ShouldEmit(key, now)) {
                        return true;
                    }
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = owner_->GetBufferAllocator();
                std::shared_ptr<BufferSegment> original = IPFrame::ToArray(allocator, packet.get());
                if (NULLPTR == original || NULLPTR == original->Buffer) {
                    return false;
                }

                int ip_header_size = sizeof(ip_hdr);
                if (NULLPTR != packet->Options) {
                    ip_header_size += packet->Options->Length;
                }

                if (original->Length < ip_header_size + (int)sizeof(udp_hdr)) {
                    return false;
                }

                int quote_size = std::min<int>(original->Length, ip_header_size + (int)sizeof(udp_hdr));
                std::shared_ptr<BufferSegment> quote = make_shared_object<BufferSegment>(
                    wrap_shared_pointer(original->Buffer.get(), original->Buffer), quote_size);
                if (NULLPTR == quote) {
                    return false;
                }

                IcmpFrame icmp;
                icmp.Type = IcmpType::ICMP_DUR;
                icmp.Code = 3; // Port unreachable.
                icmp.Source = packet->Destination;
                icmp.Destination = packet->Source;
                icmp.Ttl = IPFrame::DefaultTtl;
                icmp.AddressesFamily = AddressFamily::InterNetwork;
                icmp.Payload = quote;

                std::shared_ptr<IPFrame> reply = IcmpFrame::ToIp(allocator, &icmp);
                if (NULLPTR == reply) {
                    return false;
                }

                return owner_->Output(reply.get());
            }

            /** @brief Handles UDP frame forwarding, DNS redirect, and static mode paths. */
            bool ClientPacketDispatchHandler::OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<UdpFrame> frame = UdpFrame::Parse(packet.get());
                if (NULLPTR == frame) {
                    return false;
                }

                const std::shared_ptr<BufferSegment>& messages = frame->Payload;
                if (NULLPTR == messages) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = owner_->exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                // Check whether dns resolution packets need to be redirected.
                int destinationPort = frame->Destination.Port;
                bool resolver_udp_flow = false;
                if (destinationPort == PPP_DNS_SYS_PORT) {
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE(
                        "dns_redirect udp53 input src_port=%d dst_port=%d payload=%d dst=%s",
                        (int)frame->Source.Port,
                        (int)frame->Destination.Port,
                        NULLPTR != messages ? (int)messages->Length : -1,
                        Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    const boost::asio::ip::udp::endpoint sourceEP =
                        IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                    const boost::asio::ip::udp::endpoint destEP(
                        Ipep::ToAddress(packet->Destination), PPP_DNS_SYS_PORT);
                    resolver_udp_flow = NULLPTR != owner_->dns_controller_ &&
                        owner_->dns_controller_->ConsumeUdpFlow(sourceEP.port(), destEP);
                    if (!resolver_udp_flow) {
                        if (NULLPTR != owner_->dns_controller_ &&
                            owner_->dns_controller_->HandleQuery(owner_->dns_session_, packet, frame, messages)) {
#if defined(_ANDROID)
    ANDROID_DNS_REDIRECT_TRACE( "dns_redirect udp53 handled");
#endif
                            return true;
                        }
                        if (NULLPTR != owner_->dns_controller_) {
                            owner_->dns_controller_->HandleResolverResponse(
                                owner_->dns_session_, messages, sourceEP, destEP, ppp::vector<Byte>{});
                        }
                        return true;
                    }
                }

                if (owner_->block_quic_ && destinationPort == PPP_HTTPS_SYS_PORT) {
                    // TODO: Also strip/ignore DNS HTTPS/SVCB records that advertise h3/alpn
                    // so clients avoid attempting QUIC before this packet-level reject path.
                    return RejectBlockedQuic(packet, frame);
                }

                routing::ResolvedDestination destination;
                if (!owner_->ResolveDestination(frame->Destination, destination)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpRelayFailed);
                }
                if (destination.is_fake_ip && !destination.is_resolved) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                boost::asio::ip::udp::endpoint destinationEP =
                    IPEndPoint::ToEndPoint<boost::asio::ip::udp>(destination.connect_endpoint);
                if (destinationEP.address().is_unspecified()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }
                if (destinationEP.port() <= IPEndPoint::MinPort ||
                    destinationEP.port() > IPEndPoint::MaxPort) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }
                frame->Destination = destination.connect_endpoint;

                // Direct policy must not enter the tunnel-only static echo path.
                if (owner_->static_mode_ && !resolver_udp_flow &&
                    destination.action != routing::RoutingAction::Direct) {
                    auto& static_ = owner_->configuration_->udp.static_;
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
                bool ok = exchanger->SendTo(
                    sourceEP, destinationEP, messages->Buffer.get(), messages->Length, destination.action);
                if (destinationEP.port() == PPP_DNS_SYS_PORT || !ok) {
                    ppp::telemetry::Log(Level::kInfo, "switcher", "UDP send source=%s:%u destination=%s:%u bytes=%d ok=%d error=%d",
                        sourceEP.address().to_string().c_str(),
                        sourceEP.port(),
                        destinationEP.address().to_string().c_str(),
                        destinationEP.port(),
                        messages->Length,
                        ok ? 1 : 0,
                        (int)ppp::diagnostics::GetLastErrorCode());
                }
                return ok;
            }

            /** @brief Sends ICMP Echo Reply generated from tracked packet context. */
            bool ClientPacketDispatchHandler::ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::ER(packet, frame, ttl, allocator);
                if (NULLPTR == reply) {
                    return false;
                }
                else {
                    return owner_->Output(reply.get());
                }
            }

            /** @brief Sends ICMP Time Exceeded generated from tracked packet context. */
            bool ClientPacketDispatchHandler::TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::TE(packet, frame, source, allocator);
                if (NULLPTR == reply) {
                    return false;
                }
                else {
                    return owner_->Output(reply.get());
                }
            }

            /** @brief Resolves ACK identifier and emits appropriate ICMP response packet. */
            bool ClientPacketDispatchHandler::ERORTE(int ack_id) noexcept {
                std::shared_ptr<IPFrame> packet;
                if (ack_id != 0) {
                    ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->GetSynchronizedObject());
                    bool ok = Dictionary::RemoveValueByKey(owner_->icmppackets_, ack_id, packet,
                        [](VEthernetNetworkSwitcher::VEthernetIcmpPacket& value) noexcept {
                            return value.packet;
                        });
                    if (!ok) {
                        return false;
                    }
                }

                if (NULLPTR == packet) {
                    return false;
                }

                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
                if (NULLPTR == frame) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = owner_->GetBufferAllocator();
                if (owner_->IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
                    int ttl = std::max<int>(1, static_cast<int>(frame->Ttl) - 1);
                    return ER(packet, frame, ttl, allocator);
                }
                else {
                    return TE(packet, frame, tap->GatewayServer, allocator);
                }
            }

            /** @brief Processes ICMP input and dispatches to gateway/other echo paths. */
            bool ClientPacketDispatchHandler::OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = owner_->exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = owner_->GetBufferAllocator();
                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_input dst=%s ttl=%d type=%d code=%d frame=%p",
                    Ipep::ToAddress(packet->Destination).to_string().c_str(),
                    packet->Ttl,
                    NULLPTR != frame ? (int)frame->Type : -1,
                    NULLPTR != frame ? (int)frame->Code : -1,
                    (void*)frame.get());
#endif
                if (NULLPTR == frame || frame->Ttl == 0) {
                    return false;
                }

                // ICMP control errors cannot use the echo state machine. Preserve a
                // validated raw error through PacketAction_NAT so its quoted packet and
                // RFC 1191 next-hop MTU reach the peer that owns the original flow.
                if (frame->Type != IcmpType::ICMP_ECHO && frame->Type != IcmpType::ICMP_ER) {
                    std::shared_ptr<BufferSegment> raw = IPFrame::ToArray(allocator, packet.get());
                    app::protocol::IcmpPathMtuError error;
                    if (NULLPTR == raw || NULLPTR == raw->Buffer ||
                        !app::protocol::TryParseIcmpPathMtuError(raw->Buffer.get(), raw->Length, error) ||
                        error.OuterSource != tap->IPAddress || error.QuotedDestination != tap->IPAddress ||
                        error.OuterDestination == tap->IPAddress) {
                        ppp::telemetry::Count("pmtu.error_rejected", 1);
                        return false;
                    }

                    ppp::telemetry::Count("pmtu.error_forwarded", 1);
                    return exchanger->Nat(raw->Buffer.get(), raw->Length);
                }

                elif(owner_->IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_gateway dst=%s", Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                elif(frame->Ttl == 1) {
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_ttl1 dst=%s", Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                else {
                    int ttl = std::max<int>(0, static_cast<int>(packet->Ttl) - 1);
                    if (packet->Ttl < 1) {
                        return false;
                    }

                    frame->Ttl = ttl;
                    packet->Ttl = ttl;

#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_other dst=%s ttl=%d", Ipep::ToAddress(packet->Destination).to_string().c_str(), ttl);
#endif
                    return EchoOtherServer(exchanger, packet, allocator);
                }
            }

            /** @brief Forwards ICMP packet to non-gateway destination through exchanger. */
            bool ClientPacketDispatchHandler::EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                if (NULLPTR == exchanger) {
                    return false;
                }

                if (owner_->IsDisposed()) {
                    return false;
                }

                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet.get());
                if (NULLPTR == messages) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "icmp_other to_array failed dst=%s",
                        Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return false;
                }

                auto& static_ = owner_->configuration_->udp.static_;
                if ((owner_->static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                    bool se_ok = exchanger->StaticEchoPacketToRemoteExchanger(packet.get());
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_other static_echo dst=%s ok=%d",
                        Ipep::ToAddress(packet->Destination).to_string().c_str(), (int)se_ok);
#endif
                    if (se_ok) {
                        return true;
                    }
                }

                bool ok = exchanger->Echo(messages->Buffer.get(), messages->Length);
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_other echo dst=%s ok=%d",
                    Ipep::ToAddress(packet->Destination).to_string().c_str(), (int)ok);
#endif
                return ok;
            }

            /** @brief Tracks ICMP packet by ACK ID and triggers remote gateway echo flow. */
            bool ClientPacketDispatchHandler::EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                static constexpr int max_icmp_packets_aid = (1 << 24) - 1;

                if (NULLPTR == exchanger) {
                    return false;
                }

                int ack_id = 0;
                /** @brief Allocates a unique ACK ID and stores packet until callback/timeout. */
                for (ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->GetSynchronizedObject());;) {
                    if (owner_->IsDisposed()) {
                        return false;
                    }

                    VEthernetNetworkSwitcher::VEthernetIcmpPacket e = { Executors::GetTickCount() + ppp::net::asio::InternetControlMessageProtocol::MAX_ICMP_TIMEOUT, packet };
                    bool static_exchange = false;

                    for (int i = 0; i < UINT16_MAX; i++) {
                        ack_id = ++owner_->icmppackets_aid_;
                        if (ack_id < 1) {
                            owner_->icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ack_id > max_icmp_packets_aid) {
                            owner_->icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ppp::collections::Dictionary::ContainsKey(owner_->icmppackets_, ack_id)) {
                            continue;
                        }

                        if (!ppp::collections::Dictionary::TryAdd(owner_->icmppackets_, ack_id, e)) {
                            return false;
                        }

                        auto& static_ = owner_->configuration_->udp.static_;
                        if ((owner_->static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                            static_exchange = true;
                            break;
                        }
                        elif(exchanger->Echo(ack_id)) {
#if defined(_ANDROID)
        ANDROID_DNS_REDIRECT_TRACE( "icmp_gateway echo ack_id=%d ok=1", ack_id);
#endif
                            return true;
                        }

                        ppp::collections::Dictionary::TryRemove(owner_->icmppackets_, ack_id);
                        return false;
                    }

                    if (static_exchange) {
                        break;
                    }

                    return false;
                }

                bool ok = exchanger->StaticEchoGatewayServer(ack_id);
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_gateway static_echo ack_id=%d ok=%d", ack_id, (int)ok);
#endif
                if (ok) {
                    return true;
                }
                else {
                    ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->GetSynchronizedObject());
                    ppp::collections::Dictionary::TryRemove(owner_->icmppackets_, ack_id);
                    return false;
                }
            }

        }
    }
}
