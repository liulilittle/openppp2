#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>

using namespace ppp::net::native;

namespace ppp {
    namespace net {
        namespace packet {
            std::shared_ptr<IPFrame> UdpFrame::ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) {
                if (this->AddressesFamily != AddressFamily::InterNetwork) {
                    throw std::runtime_error("UDP frames of this address family type are not supported.");
                }

                std::shared_ptr<BufferSegment> payload = this->Payload;
                if (NULL == payload || NULL == payload->Buffer) {
                    return NULL;
                }

                int payload_size = payload->Length;
                if (payload_size <= 0) {
                    return NULL;
                }

                int payload_offset = sizeof(udp_hdr);
                int message_size_ = payload_offset + payload_size;

                std::shared_ptr<Byte> message_ = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_size_);
                if (NULL == message_) {
                    return NULL;
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
                if (pseudo_checksum == 0) {
                    pseudo_checksum = 0xffff;
                }

                udphdr->chksum = pseudo_checksum;

                std::shared_ptr<IPFrame> packet = make_shared_object<IPFrame>();
                if (NULL == packet) {
                    return NULL;
                }

                packet->ProtocolType = ip_hdr::IP_PROTO_UDP;
                packet->Source = this->Source.GetAddress();
                packet->Destination = this->Destination.GetAddress();
                packet->Ttl = this->Ttl;
                packet->Tos = 0x04;
                packet->Flags = (IPFlags)0x00;

                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(message_, message_size_);
                if (NULL == packet_payload) {
                    return NULL;
                }
                
                packet->Payload = packet_payload;
                return packet;
            }

            std::shared_ptr<UdpFrame> UdpFrame::Parse(const IPFrame* frame) noexcept {
                if (NULL == frame) {
                    return NULL;
                }

                std::shared_ptr<BufferSegment> messages = frame->Payload;
                if (NULL == messages || messages->Length <= 0) {
                    return NULL;
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)messages->Buffer.get();
                if (NULL == udphdr) {
                    return NULL;
                }

                if (messages->Length != ntohs(udphdr->len)) {
                    return NULL;
                }

                int offset = sizeof(struct udp_hdr);
                int payload_len = messages->Length - offset;
                if (payload_len <= 0) {
                    return NULL;
                }

#if defined(PACKET_CHECKSUM)
                if (udphdr->chksum != 0) {
                    UInt32 pseudo_checksum = inet_chksum_pseudo((unsigned char*)udphdr,
                        ip_hdr::IP_PROTO_UDP,
                        messages->Length,
                        frame->Source,
                        frame->Destination);
                    if (pseudo_checksum != 0) {
                        return NULL;
                    }
                }
#endif

                std::shared_ptr<UdpFrame> packet = make_shared_object<UdpFrame>();
                if (NULL == packet) {
                    return NULL;
                }
                
                packet->AddressesFamily = AddressFamily::InterNetwork;
                packet->Ttl = frame->Ttl;
                packet->Source = IPEndPoint(frame->Source, ntohs(udphdr->src));
                packet->Destination = IPEndPoint(frame->Destination, ntohs(udphdr->dest));

                std::shared_ptr<Byte> buffer = messages->Buffer;
                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(
                    std::shared_ptr<Byte>(buffer.get() + offset, [buffer](const Byte*) {}), payload_len);

                if (NULL == packet_payload) {
                    return NULL;
                }

                packet->Payload = packet_payload;
                return packet;
            }
        }
    }
}