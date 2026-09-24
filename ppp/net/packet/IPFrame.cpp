#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/tap/ITap.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file IPFrame.cpp
 * @brief Implements IPv4 frame serialization, parsing, and fragmentation.
 */

using namespace ppp::net::native;

namespace ppp {
    namespace net {
        namespace packet {
            const unsigned char& IPFrame::DefaultTtl = ppp::net::native::ip_hdr::IP_DFT_TTL;

            /**
             * @brief Computes the serialized IPv4 frame length.
             * @return Total packet length including header/options/payload.
             */
            int IPFrame::SizeOf() noexcept {
                std::shared_ptr<BufferSegment> payload_segment = this->Payload;
                std::shared_ptr<BufferSegment> options_segment = this->Options;
                int options_size = 0;
                if (NULLPTR != options_segment) {
                    options_size = options_segment->Length;
                }

                int payload_offset = sizeof(struct ip_hdr) + options_size;
                int payload_size = 0;
                if (NULLPTR != payload_segment) {
                    payload_size = payload_segment->Length;
                }

                int message_data_size = payload_offset + payload_size;
                return message_data_size;
            }

            /**
             * @brief Serializes the current frame into wire-format bytes.
             * @param allocator Buffer allocator used to allocate output storage.
             * @return Serialized packet segment or null on failure.
             */
            std::shared_ptr<BufferSegment> IPFrame::ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<BufferSegment> payload_segment = this->Payload;
                std::shared_ptr<BufferSegment> options_segment = this->Options;
                int options_size = 0;
                if (NULLPTR != options_segment) {
                    options_size = options_segment->Length;
                }

                int payload_offset = sizeof(struct ip_hdr) + options_size;
                int payload_size = 0;
                if (NULLPTR != payload_segment) {
                    payload_size = payload_segment->Length;
                }

                int message_data_size = payload_offset + payload_size;
                std::shared_ptr<Byte> message_data = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_data_size);
                if (NULLPTR == message_data) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameSerializeBufferAllocFailed);
                    return NULLPTR;
                }

                struct ip_hdr* iphdr = (struct ip_hdr*)message_data.get();
                iphdr->dest = this->Destination;
                iphdr->src = this->Source;
                iphdr->ttl = this->Ttl;
                iphdr->proto = this->ProtocolType;
                iphdr->v_hl = 4 << 4 | payload_offset >> 2;
                iphdr->tos = this->Tos; // Routine Mode
                iphdr->len = htons(message_data_size);
                iphdr->id = htons(this->Id);
                iphdr->flags = htons((UInt16)(this->Flags == 0 ? IPFlags::IP_DF : this->Flags));
                iphdr->chksum = 0;

                if (options_size > 0) {
                    Byte* destination_options = message_data.get() + sizeof(struct ip_hdr);
                    memcpy(destination_options, options_segment->Buffer.get(), options_size);
                }

                if (payload_size > 0) {
                    memcpy(message_data.get() + payload_offset, payload_segment->Buffer.get(), payload_size);
                }

                iphdr->chksum = inet_chksum(message_data.get(), payload_offset);
                /** @note RFC-compatible fallback when checksum computes to zero. */
                if (iphdr->chksum == 0) {
                    iphdr->chksum = 0xffff;
                }

                return make_shared_object<BufferSegment>(message_data, message_data_size);
            }

            /**
             * @brief Parses raw bytes into an @ref IPFrame instance.
             * @param allocator Buffer allocator for option/payload copies.
             * @param packet Raw packet bytes.
             * @param size Raw packet size.
             * @return Parsed frame or null when validation/allocation fails.
             */
            std::shared_ptr<IPFrame> IPFrame::Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* packet, int size) noexcept {
                struct ip_hdr* iphdr = ip_hdr::Parse(packet, size);
                if (NULLPTR == iphdr) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    }
                    return NULLPTR;
                }

                std::shared_ptr<IPFrame> frame = make_shared_object<IPFrame>();
                if (NULLPTR == frame) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParseFrameAllocFailed);
                    return NULLPTR;
                }

                frame->Destination = iphdr->dest;
                frame->Source = iphdr->src;
                frame->Tos = ppp::net::Socket::IsDefaultFlashTypeOfService() ? std::max<Byte>(iphdr->tos, DefaultFlashTypeOfService()) : iphdr->tos;
                frame->Ttl = iphdr->ttl;
                frame->AddressesFamily = AddressFamily::InterNetwork;
                frame->ProtocolType = iphdr->proto;
                frame->Id = ntohs(iphdr->id);
                frame->Flags = (IPFlags)ntohs(iphdr->flags);

                int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
                int options_size = (iphdr_hlen - sizeof(struct ip_hdr));
                if (options_size > 0) {
                    std::shared_ptr<BufferSegment> options_ = make_shared_object<BufferSegment>();
                    if (NULLPTR == options_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParseOptionsSegmentAllocFailed);
                        return NULLPTR;
                    }

                    options_->Length = options_size;
                    options_->Buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, options_size);
                    if (NULLPTR == options_->Buffer) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParseOptionsBufferAllocFailed);
                        return NULLPTR;
                    }

                    frame->Options = options_;
                    memcpy(options_->Buffer.get(), (char*)iphdr + sizeof(struct ip_hdr), options_size);
                }

                int message_size_ = size - iphdr_hlen;
                if (message_size_ > 0) {
                    std::shared_ptr<BufferSegment> messages_ = make_shared_object<BufferSegment>();
                    if (NULLPTR == messages_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParsePayloadSegmentAllocFailed);
                        return NULLPTR;
                    }

                    messages_->Length = message_size_;
                    messages_->Buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_size_);
                    if (NULLPTR == messages_->Buffer) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParsePayloadBufferAllocFailed);
                        return NULLPTR;
                    }

                    frame->Payload = messages_;
                    memcpy(messages_->Buffer.get(), (char*)iphdr + iphdr_hlen, message_size_);
                }

                return frame;
            }

            std::shared_ptr<IPFrame> IPFrame::Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<ppp::Byte>& owner, const void* packet, int size) noexcept {
                // If no owning shared_ptr, fall back to the copy-based Parse.
                if (NULLPTR == owner) {
                    return IPFrame::Parse(allocator, packet, size);
                }

                struct ip_hdr* iphdr = ip_hdr::Parse(packet, size);
                if (NULLPTR == iphdr) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    }
                    return NULLPTR;
                }

                std::shared_ptr<IPFrame> frame = make_shared_object<IPFrame>();
                if (NULLPTR == frame) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParseFrameAllocFailed);
                    return NULLPTR;
                }

                frame->Destination = iphdr->dest;
                frame->Source = iphdr->src;
                frame->Tos = ppp::net::Socket::IsDefaultFlashTypeOfService() ? std::max<Byte>(iphdr->tos, DefaultFlashTypeOfService()) : iphdr->tos;
                frame->Ttl = iphdr->ttl;
                frame->AddressesFamily = AddressFamily::InterNetwork;
                frame->ProtocolType = iphdr->proto;
                frame->Id = ntohs(iphdr->id);
                frame->Flags = (IPFlags)ntohs(iphdr->flags);

                int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
                int options_size = (iphdr_hlen - sizeof(struct ip_hdr));
                if (options_size > 0) {
                    std::shared_ptr<BufferSegment> options_ = make_shared_object<BufferSegment>();
                    if (NULLPTR == options_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParseOptionsSegmentAllocFailed);
                        return NULLPTR;
                    }

                    // Zero-copy: wrap the options region into a shared_ptr slice backed by owner.
                    options_->Length = options_size;
                    options_->Buffer = ppp::wrap_shared_pointer(reinterpret_cast<ppp::Byte*>(const_cast<void*>(packet)) + sizeof(struct ip_hdr), owner);
                    if (NULLPTR == options_->Buffer) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParseOptionsBufferAllocFailed);
                        return NULLPTR;
                    }

                    frame->Options = options_;
                }

                int message_size_ = size - iphdr_hlen;
                if (message_size_ > 0) {
                    std::shared_ptr<BufferSegment> messages_ = make_shared_object<BufferSegment>();
                    if (NULLPTR == messages_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParsePayloadSegmentAllocFailed);
                        return NULLPTR;
                    }

                    // Zero-copy: wrap the payload region into a shared_ptr slice backed by owner.
                    messages_->Length = message_size_;
                    messages_->Buffer = ppp::wrap_shared_pointer(reinterpret_cast<ppp::Byte*>(const_cast<void*>(packet)) + iphdr_hlen, owner);
                    if (NULLPTR == messages_->Buffer) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameParsePayloadBufferAllocFailed);
                        return NULLPTR;
                    }

                    frame->Payload = messages_;
                }

                return frame;
            }

            /**
             * @brief Splits an IPv4 packet into MTU-constrained fragments.
             * @param out Receives generated fragments.
             * @param packet Input packet.
             * @return Number of fragments generated, or zero on failure.
             */
            int IPFrame::Subpackages(ppp::vector<IPFramePtr>& out, const IPFramePtr& packet) noexcept {
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameSubpackagesNullPacket);
                    return 0;
                }

                if (packet->Flags & IPFlags::IP_MF) {
                    out.emplace_back(packet);
                    return 1;
                }

                std::shared_ptr<BufferSegment> messages = packet->Payload;
                std::shared_ptr<BufferSegment> options = packet->Options;
                if (NULLPTR == messages) {
                    out.emplace_back(packet);
                    return 1;
                }

                int max = /*ip_hdr::MTU*/ppp::tap::ITap::Mtu - sizeof(struct ip_hdr);
                if (NULLPTR != options) {
                    max -= options->Length;
                }

                int szz = messages->Length;
                max = (max >> 3) << 3;
                if (szz <= max) {
                    out.emplace_back(packet);
                    return 1;
                }

                int ofs = 0;
                int fragmentl = 0;
                std::shared_ptr<Byte> buffer = messages->Buffer;

                std::shared_ptr<IPFrame> fragment;
                /**
                 * @details Emit fixed-size middle fragments with MF set, then
                 * emit a final fragment carrying the remaining bytes.
                 */
                while (szz > max) {
                    fragment = make_shared_object<IPFrame>();
                    if (NULLPTR == fragment) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameSubpackagesFragmentAllocFailed);
                        return 0; 
                    }

                    std::shared_ptr<BufferSegment> packet_payload = 
                        make_shared_object<BufferSegment>(wrap_shared_pointer(buffer.get() + ofs, buffer), max);
                    if (NULLPTR == packet_payload) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameSubpackagesFragmentPayloadAllocFailed);
                        return 0;
                    }

                    fragment->ProtocolType = packet->ProtocolType;
                    fragment->Source = packet->Source;
                    fragment->Destination = packet->Destination;
                    fragment->Flags = IPFlags::IP_MF;
                    fragment->Id = packet->Id;
                    fragment->Options = options;
                    fragment->Ttl = packet->Ttl;
                    fragment->Tos = packet->Tos;
                    fragment->Payload = packet_payload;
                    fragment->SetFragmentOffset(ofs);

                    options = NULLPTR;
                    ofs += max;
                    szz -= max;
                    fragmentl++;
                    out.emplace_back(fragment);
                }

                if (szz > 0) {
                    fragment = make_shared_object<IPFrame>();
                    if (NULLPTR == fragment) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameSubpackagesTailFragmentAllocFailed);
                        return 0; 
                    }

                    std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(
                        wrap_shared_pointer(buffer.get() + ofs, buffer), szz);
                    if (NULLPTR == packet_payload) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpFrameSubpackagesTailPayloadAllocFailed);
                        return 0;
                    }

                    fragment->ProtocolType = packet->ProtocolType;
                    fragment->Source = packet->Source;
                    fragment->Destination = packet->Destination;
                    fragment->Flags = ofs <= 0 ? packet->Flags : (IPFlags)0;
                    fragment->Id = packet->Id;
                    fragment->Options = options;
                    fragment->Ttl = packet->Ttl;
                    fragment->Tos = packet->Tos;
                    fragment->Payload = packet_payload;
                    fragment->SetFragmentOffset(ofs);
                    out.emplace_back(fragment);
                }
                return ++fragmentl;
            }
        }
    }
}
