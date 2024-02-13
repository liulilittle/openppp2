#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>

using namespace ppp::net::native;

namespace ppp {
    namespace net {
        namespace packet {
            std::shared_ptr<IPFrame> IcmpFrame::ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) {
                if (this->AddressesFamily != AddressFamily::InterNetwork) {
                    throw std::runtime_error("ICMP frames of this address family type are not supported.");
                }

                int payload_size = 0;
                std::shared_ptr<BufferSegment> payload = this->Payload;
                if (NULL != payload) {
                    if (payload->Length < 0 || (payload->Length > 0 && NULL == payload->Buffer)) {
                        return NULL;
                    }

                    payload_size += payload->Length;
                }

                int hdr_bytes_len = sizeof(struct icmp_hdr);
                int packet_size = hdr_bytes_len + payload_size;
                std::shared_ptr<Byte> packet_data = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_size);
                if (NULL == packet_data) {
                    return NULL;
                }

                struct icmp_hdr* icmphdr = (struct icmp_hdr*)packet_data.get();
                icmphdr->icmp_type = this->Type;
                icmphdr->icmp_code = this->Code;
                icmphdr->icmp_id = ntohs(this->Identification);
                icmphdr->icmp_seq = ntohs(this->Sequence);
                icmphdr->icmp_chksum = 0;

                if (payload_size > 0) {
                    memcpy((char*)icmphdr + hdr_bytes_len, payload->Buffer.get(), payload_size);
                }

                icmphdr->icmp_chksum = inet_chksum(icmphdr, packet_size);
                if (icmphdr->icmp_chksum == 0) {
                    icmphdr->icmp_chksum = 0xffff;
                }

                std::shared_ptr<IPFrame> packet = make_shared_object<IPFrame>();
                if (NULL == packet) {
                    return NULL;
                }

                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(packet_data, packet_size);
                if (NULL == packet_payload) {
                    return NULL;
                }
                
                packet->ProtocolType = ip_hdr::IP_PROTO_ICMP;
                packet->Source = this->Source;
                packet->Destination = this->Destination;
                packet->Ttl = this->Ttl;
                packet->Payload = packet_payload;
                return packet;
            }

            std::shared_ptr<IcmpFrame> IcmpFrame::Parse(const IPFrame* frame) noexcept {
                if (NULL == frame || frame->ProtocolType != ip_hdr::IP_PROTO_ICMP) {
                    return NULL;
                }

                std::shared_ptr<BufferSegment> messages = frame->Payload;
                if (NULL == messages || messages->Length <= 0) {
                    return NULL;
                }

                struct icmp_hdr* icmphdr = (struct icmp_hdr*)messages->Buffer.get();
                if (NULL == icmphdr) {
                    return NULL;
                }

#if defined(PACKET_CHECKSUM)
                if (icmphdr->icmp_chksum != 0) {
                    UInt16 cksum = inet_chksum(icmphdr, messages->Length);
                    if (cksum != 0) {
                        return NULL;
                    }
                }
#endif

                int hdr_bytes_len = sizeof(struct icmp_hdr);
                int payload_size = messages->Length - hdr_bytes_len;
                if (payload_size < 0) {
                    return NULL;
                }

                std::shared_ptr<IcmpFrame> packet = make_shared_object<IcmpFrame>();
                if (NULL == packet) {
                    return NULL;
                }
                
                packet->Type = (IcmpType)icmphdr->icmp_type;
                packet->Code = icmphdr->icmp_code;
                packet->Identification = ntohs(icmphdr->icmp_id);
                packet->Sequence = ntohs(icmphdr->icmp_seq);
                packet->Ttl = frame->Ttl;
                packet->Destination = frame->Destination;
                packet->Source = frame->Source;
                packet->AddressesFamily = frame->AddressesFamily;

                std::shared_ptr<Byte> buffer = messages->Buffer;
                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(
                    std::shared_ptr<Byte>(buffer.get() + hdr_bytes_len, [buffer](const Byte*) {}), payload_size);
                if (NULL == packet_payload) {
                    return NULL;
                }

                packet->Payload = packet_payload;
                return packet;
            }
        }
    }
}