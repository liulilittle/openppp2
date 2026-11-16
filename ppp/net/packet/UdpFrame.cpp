#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/Socket.h>
#include <ppp/tap/ITap.h>

/**
 * @file UdpFrame.cpp
 * @brief Implements UDP frame parsing and IPv4 encapsulation.
 */

using namespace ppp::net::native;

namespace ppp {
    namespace net {
        namespace packet {
            /**
             * @brief Encapsulates this UDP frame into an IPv4 packet.
             * @param allocator Buffer allocator for temporary and payload storage.
             * @return Generated IPv4 frame, or null on validation/allocation failure.
             * @throws std::runtime_error When address family is unsupported.
             */
            std::shared_ptr<IPFrame> UdpFrame::ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) {
                if (this->AddressesFamily != AddressFamily::InterNetwork) {
                    throw std::runtime_error("UDP frames of this address family type are not supported.");
                }

                std::shared_ptr<BufferSegment> payload = this->Payload;
                if (NULLPTR == payload || NULLPTR == payload->Buffer) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                int payload_size = payload->Length;
                if (payload_size <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                int payload_offset = sizeof(udp_hdr);
                int message_size_ = payload_offset + payload_size;

                std::shared_ptr<Byte> message_ = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_size_);
                if (NULLPTR == message_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }
                else {
                    memcpy(message_.get() + payload_offset, payload->Buffer.get(), payload_size);
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)message_.get();
                udphdr->src = ntohs(this->Source.Port);
                udphdr->dest = ntohs(this->Destination.Port);
                udphdr->len = ntohs(message_size_);
                udphdr->chksum = 0;

                UInt16 pseudo_checksum = inet_chksum_pseudo(message_.get(),
                    ip_hdr::IP_PROTO_UDP,
                    message_size_,
                    this->Source.GetAddress(),
                    this->Destination.GetAddress());
                /** @note UDP checksum of zero is represented as 0xFFFF on the wire. */
                if (pseudo_checksum == 0) {
                    pseudo_checksum = 0xffff;
                }

                udphdr->chksum = pseudo_checksum;

                std::shared_ptr<IPFrame> packet = make_shared_object<IPFrame>();
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                packet->ProtocolType = ip_hdr::IP_PROTO_UDP;
                packet->Source = this->Source.GetAddress();
                packet->Destination = this->Destination.GetAddress();
                packet->Ttl = this->Ttl;
                packet->Flags = (IPFlags)0x00;
                packet->Tos = ppp::net::Socket::IsDefaultFlashTypeOfService() ? IPFrame::DefaultFlashTypeOfService() : 0x04;

                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(message_, message_size_);
                if (NULLPTR == packet_payload) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }
                
                packet->Payload = packet_payload;
                return packet;
            }

            /**
             * @brief Builds the IPv4 datagram that ToIp() followed by IPFrame::ToArray()
             *        would emit, directly into one buffer.
             * @details The two-step path costs about six allocations and two full payload
             *          copies per datagram; this writes the IPv4 and UDP headers in front
             *          of a single payload copy. Header fields match ToIp()/ToArray():
             *          Id 0, DF set, no options, same TOS policy and checksum fallbacks.
             * @return Null when the datagram would need IPv4 fragmentation (callers then
             *         fall back to ToIp() + IPFrame::Subpackages) or on invalid input or
             *         allocation failure.
             */
            std::shared_ptr<Byte> UdpFrame::ToIPv4Packet(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator,
                const IPEndPoint&                                           source,
                const IPEndPoint&                                           destination,
                Byte                                                        ttl,
                const void*                                                 payload,
                int                                                         payload_size,
                int&                                                        packet_length) noexcept {
                packet_length = 0;
                if (NULLPTR == payload || payload_size <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                // Same limit IPFrame::Subpackages() applies before it starts fragmenting.
                const int udp_size = static_cast<int>(sizeof(udp_hdr)) + payload_size;
                const int max = ((ppp::tap::ITap::Mtu - static_cast<int>(sizeof(ip_hdr))) >> 3) << 3;
                if (udp_size > max) {
                    return NULLPTR;
                }

                const int total = static_cast<int>(sizeof(ip_hdr)) + udp_size;
                std::shared_ptr<Byte> buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, total);
                if (NULLPTR == buffer) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                Byte* message = buffer.get();
                Byte* segment = message + sizeof(ip_hdr);
                memcpy(segment + sizeof(udp_hdr), payload, payload_size);

                struct udp_hdr* udphdr = (struct udp_hdr*)segment;
                udphdr->src = ntohs(source.Port);
                udphdr->dest = ntohs(destination.Port);
                udphdr->len = ntohs(udp_size);
                udphdr->chksum = 0;

                UInt16 pseudo_checksum = inet_chksum_pseudo(segment,
                    ip_hdr::IP_PROTO_UDP,
                    udp_size,
                    source.GetAddress(),
                    destination.GetAddress());
                /** @note UDP checksum of zero is represented as 0xFFFF on the wire. */
                if (pseudo_checksum == 0) {
                    pseudo_checksum = 0xffff;
                }

                udphdr->chksum = pseudo_checksum;

                struct ip_hdr* iphdr = (struct ip_hdr*)message;
                iphdr->dest = destination.GetAddress();
                iphdr->src = source.GetAddress();
                iphdr->ttl = ttl;
                iphdr->proto = ip_hdr::IP_PROTO_UDP;
                iphdr->v_hl = 4 << 4 | static_cast<int>(sizeof(ip_hdr)) >> 2;
                iphdr->tos = ppp::net::Socket::IsDefaultFlashTypeOfService() ? IPFrame::DefaultFlashTypeOfService() : 0x04;
                iphdr->len = htons(total);
                iphdr->id = 0;
                iphdr->flags = htons((UInt16)IPFlags::IP_DF);
                iphdr->chksum = 0;
                iphdr->chksum = inet_chksum(message, sizeof(ip_hdr));
                /** @note RFC-compatible fallback when checksum computes to zero. */
                if (iphdr->chksum == 0) {
                    iphdr->chksum = 0xffff;
                }

                packet_length = total;
                return buffer;
            }

            /**
             * @brief Parses a UDP datagram from an IPv4 payload.
             * @param frame Source IPv4 frame.
             * @return Parsed UDP frame or null if validation fails.
             */
            std::shared_ptr<UdpFrame> UdpFrame::Parse(const IPFrame* frame) noexcept {
                if (NULLPTR == frame) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                std::shared_ptr<BufferSegment> messages = frame->Payload;
                if (NULLPTR == messages || messages->Length <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                if (messages->Length < sizeof(struct udp_hdr)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)messages->Buffer.get();
                if (NULLPTR == udphdr) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                if (messages->Length != ntohs(udphdr->len)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                int offset = sizeof(struct udp_hdr);
                int payload_len = messages->Length - offset;
                if (payload_len <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

#if defined(PACKET_CHECKSUM)
                /** @details Validate checksum only when checksum checks are enabled. */
                if (udphdr->chksum != 0) {
                    UInt32 pseudo_checksum = inet_chksum_pseudo((unsigned char*)udphdr,
                        ip_hdr::IP_PROTO_UDP,
                        messages->Length,
                        frame->Source,
                        frame->Destination);
                    if (pseudo_checksum != 0) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                        return NULLPTR;
                    }
                }
#endif

                std::shared_ptr<UdpFrame> packet = make_shared_object<UdpFrame>();
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }
                
                packet->AddressesFamily = AddressFamily::InterNetwork;
                packet->Ttl = frame->Ttl;
                packet->Source = IPEndPoint(frame->Source, ntohs(udphdr->src));
                packet->Destination = IPEndPoint(frame->Destination, ntohs(udphdr->dest));

                std::shared_ptr<Byte> buffer = messages->Buffer;
                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(
                    wrap_shared_pointer(buffer.get() + offset, buffer), payload_len);

                if (NULLPTR == packet_payload) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                packet->Payload = packet_payload;
                return packet;
            }
        }
    }
}
