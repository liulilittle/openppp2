#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/checksum.h>
#include <ppp/cryptography/ssea.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualEthernetPacket.cpp
 * @brief Implements virtual Ethernet packet encoding/decoding and helpers.
 * @author ("OPENPPP2 Team")
 * @license ("GPL-3.0")
 */

namespace ppp
{
    namespace app
    {
        namespace protocol
        {
#pragma pack(push, 1)
            /**
             * @brief Pseudo IP tuple persisted in packet headers.
             */
            typedef struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed))
#endif
            {
                uint32_t    source_ip;          // Source IPv4 address (network order)
                uint16_t    source_port;        // Source port (network order)
                uint32_t    destination_ip;     // Destination IPv4 address (network order)
                uint16_t    destination_port;   // Destination port (network order)
            } PACKET_IP_PACKET_POSEDO;

            /**
             * @brief Internal encoded packet header.
             */
            typedef struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed))
#endif
            {
                uint32_t                mask_id;            // Random mask ID for obfuscation
                uint8_t                 header_length;      // Obfuscated header length (actual length derived via mapping)
                int32_t                 session_id;         // Session ID (positive for UDP, negative for IP)
                uint16_t                checksum;           // Checksum covering header + encrypted payload
                PACKET_IP_PACKET_POSEDO posedo;             // Posedo IP header fields
            } PACKET_HEADER;
#pragma pack(pop)

            typedef ppp::net::IPEndPoint                                        IPEndPoint;
            typedef ppp::net::Socket                                            Socket;

            /**
             * @brief Restores real header length from obfuscated value.
             * @param configuration Runtime configuration.
             * @param N Stored obfuscated header length.
             * @param kf Per-packet random key factor.
             * @return Real header length value.
             * @note This is the inverse mapping used by pack side header length obfuscation.
             */
            static int STATIC_header_length(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                                            int N, int kf) noexcept {
                // Obtain the modulus value from configuration (expected to be between 128 and 256).
                const int VEP_HEADER_MSS_MOD = configuration->Lcgmod(ppp::configurations::AppConfiguration::LCGMOD_TYPE_STATIC);

                // Protect against division by zero (should not happen in production).
                if (VEP_HEADER_MSS_MOD == 0) {
                    return sizeof(PACKET_HEADER); // Fallback to safe value.
                }

                const int KF_MOD = abs(kf % VEP_HEADER_MSS_MOD);

                // Mapping: (N - KF_MOD + MOD) % MOD  (inverse of packing mapping)
                return (N - KF_MOD + VEP_HEADER_MSS_MOD) % VEP_HEADER_MSS_MOD;
            }

            /**
             * @brief Final unpack stage after outer decode/deobfuscation.
             * @param allocator Buffer allocator used for payload output.
             * @param transport Transport ciphertext or null.
             * @param h Decoded packet header pointer.
             * @param proto Protocol id inferred from session sign.
             * @param session_id Positive session identifier.
             * @param packet_length Total packet length.
             * @param out Receives unpacked packet fields.
             * @return True on checksum/decrypt/validation success.
             * @note For UDP packets, source/destination endpoint fields are strictly validated.
             */
            static bool STATIC_Unpack(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                const std::shared_ptr<ppp::Byte>&                               buffer,
                PACKET_HEADER*                                                  h,
                int                                                             proto,
                int                                                             session_id,
                int                                                             packet_length,
                VirtualEthernetPacket&                                          out) noexcept
            {
                // Session ID must be non-zero.
                if (session_id == 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                    return false;
                }

                if (packet_length < static_cast<int>(sizeof(PACKET_HEADER))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return false;
                }

                // Validate checksum: store original, zero it, compute, compare.
                uint16_t x_checksum = h->checksum;
                h->checksum = 0;

                uint16_t y_checksum = ppp::net::native::inet_chksum(h, packet_length);
                h->checksum = x_checksum;
                
                if (x_checksum != y_checksum) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                // Decrypt payload if transport ciphertext is provided.
                std::shared_ptr<ppp::Byte> payload;
                int payload_length = packet_length - sizeof(PACKET_HEADER);
                if (NULLPTR != transport) {
                    payload = transport->Decrypt(allocator, (ppp::Byte*)(h + 1), payload_length, payload_length);
                    if (NULLPTR == payload) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                        return false;
                    }
                } else {
                    // No encryption: zero-copy slice of the decoded buffer.
                    payload = ppp::wrap_shared_pointer(reinterpret_cast<ppp::Byte*>(h + 1), buffer);
                    if (NULLPTR == payload) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }
                }

                // Fill output structure.
                out.Id              = session_id;
                out.Payload         = payload;
                out.Length          = payload_length;
                out.Protocol        = proto;
                out.SourceIP        = h->posedo.source_ip;
                out.SourcePort      = ntohs(h->posedo.source_port);
                out.DestinationIP   = h->posedo.destination_ip;
                out.DestinationPort = ntohs(h->posedo.destination_port);

                // For non-UDP protocols, accept any IP/port.
                if (proto != ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    return true;
                }

                // UDP specific validation: destination and source must be valid.
                if (out.DestinationIP == IPEndPoint::NoneAddress || out.DestinationIP == IPEndPoint::AnyAddress) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return false;
                }

                if (out.DestinationPort <= IPEndPoint::MinPort || out.DestinationPort > IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return false;
                }

                if (out.SourceIP == IPEndPoint::NoneAddress || out.SourceIP == IPEndPoint::AnyAddress) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return false;
                }

                if (out.SourcePort <= IPEndPoint::MinPort || out.SourcePort > IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return false;
                }

                return true;
            }

            /**
             * @brief Decodes a raw virtual Ethernet packet into output object.
             * @param configuration Runtime configuration.
             * @param allocator Buffer allocator.
             * @param protocol Protocol ciphertext resolver.
             * @param transport Transport ciphertext resolver.
             * @param packet Raw encoded packet.
             * @param packet_length Packet byte length.
             * @param out Receives decoded packet fields.
             * @return True on success; otherwise false.
             * @note This routine applies delta decode, unmasking, unshuffle, optional header decrypt and payload decode.
             */
            bool VirtualEthernetPacket::UnpackBy(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                const void*                                                     packet,
                int                                                             packet_length,
                VirtualEthernetPacket&                                          out) noexcept
            {
                // Basic length validation.
                if (NULLPTR == packet || packet_length <= sizeof(PACKET_HEADER)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return false;
                }

                // First layer: delta decoding (decompression / obfuscation removal).
                std::shared_ptr<ppp::Byte> output;
                packet_length = ppp::cryptography::ssea::delta_decode(allocator, packet, packet_length,
                                                                      configuration->key.kf, output);
                if (NULLPTR == output || packet_length <= sizeof(PACKET_HEADER)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                packet = output.get();

                // Access header.
                ppp::Byte* p = (ppp::Byte*)packet;
                PACKET_HEADER* h = (PACKET_HEADER*)p;
                if (h->mask_id == 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                // Compute per-packet key factor from mask_id and global key.
                int kf = ppp::cryptography::ssea::random_next(configuration->key.kf * h->mask_id);

                // Derive actual header length from stored obfuscated value.
                int header_length = (ppp::Byte)STATIC_header_length(configuration, h->header_length, kf);
                if (header_length < sizeof(PACKET_HEADER)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                // Reverse XOR masking on the session_id field and following bytes.
                ppp::Byte* x = p + offsetof(PACKET_HEADER, session_id);
                ppp::Byte* y = p + packet_length;
                ppp::cryptography::ssea::masked_xor_random_next(x, y, kf);

                // Reverse shuffle on the session_id field and following bytes.
                ppp::cryptography::ssea::unshuffle_data(reinterpret_cast<char*>(&h->session_id),
                                                        packet_length - offsetof(PACKET_HEADER, session_id), kf);

                // Determine protocol type based on sign of session_id.
                int32_t session_id = htonl(h->session_id) ^ kf;
                int proto = ppp::net::native::ip_hdr::IP_PROTO_UDP;
                if (session_id < 0) {
                    session_id = ~session_id;   // Absolute value for IP packets.
                    proto = ppp::net::native::ip_hdr::IP_PROTO_IP;
                }

                // Obtain ciphertext instances for the session.
                std::shared_ptr<ppp::cryptography::Ciphertext> transport_ciphertext = transport ? transport(session_id) : NULLPTR;
                std::shared_ptr<ppp::cryptography::Ciphertext> protocol_ciphertext = protocol ? protocol(session_id) : NULLPTR;

                // If both protocol and transport ciphertexts are available, decrypt the header section.
                if (NULLPTR != protocol_ciphertext && NULLPTR != transport_ciphertext) {
                    int header_length_raw = sizeof(PACKET_HEADER) - offsetof(PACKET_HEADER, checksum);
                    int header_length_new;
                    std::shared_ptr<Byte> header_body = protocol_ciphertext->Decrypt(allocator,
                                        reinterpret_cast<ppp::Byte*>(&h->checksum), header_length_raw, header_length_new);
                    if (NULLPTR == header_body) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                        return false;
                    }

                    // If decrypted length matches original, replace in-place.
                    if (header_length_new == header_length_raw) {
                        memcpy(reinterpret_cast<ppp::Byte*>(&h->checksum), header_body.get(), header_length_new);
                    } else {
                        // Otherwise rebuild the entire packet with new header layout.
                        ppp::io::MemoryStream ms;
                        ms.Write(h, 0, offsetof(PACKET_HEADER, checksum));
                        ms.Write(header_body.get(), 0, header_length_new);
                        ms.Write((Byte*)h + header_length, 0, packet_length - header_length);

                        std::shared_ptr<ppp::Byte> buf = ms.GetBuffer();
                        packet_length = ms.GetPosition();

                        h = (PACKET_HEADER*)buf.get();

                        // Recompute obfuscated header length for consistency.
                        h->header_length = (ppp::Byte)STATIC_header_length(configuration, sizeof(PACKET_HEADER), kf);

                        // Continue unpack with reconstructed packet.
                        return STATIC_Unpack(allocator, transport_ciphertext, buf, h, proto, session_id, packet_length, out);
                    }
                } else {
                    // No protocol encryption; fall through.
                    protocol_ciphertext  = NULLPTR;
                    transport_ciphertext = NULLPTR;
                }

                // Final unpack with possibly modified header.
                return STATIC_Unpack(allocator, transport_ciphertext, output, h, proto, session_id, packet_length, out);
            }

            /**
             * @brief Core pack routine after header field preparation.
             * @param configuration Runtime configuration.
             * @param allocator Buffer allocator.
             * @param protocol Protocol ciphertext or null.
             * @param h Mutable packet header.
             * @param payload Payload bytes to embed.
             * @param payload_length Payload size.
             * @param message_length Header+payload size before optional header transform.
             * @param out Receives final encoded packet length.
             * @return Encoded packet buffer, or null on failure.
             * @note Applies checksum, optional protocol-header encryption, shuffle/xor masking and final delta encode.
             */
            static std::shared_ptr<ppp::Byte> STATIC_Pack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                PACKET_HEADER*                                                  h,
                const void*                                                     payload,
                int                                                             payload_length,
                int                                                             message_length,
                int&                                                            out) noexcept
            {
                // Compute per-packet key factor.
                const int kf = ppp::cryptography::ssea::random_next(configuration->key.kf * h->mask_id);
                const int VEP_HEADER_MSS_MOD = configuration->Lcgmod(ppp::configurations::AppConfiguration::LCGMOD_TYPE_STATIC);

                // Defensive check: modulus should not be zero.
                if (VEP_HEADER_MSS_MOD == 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    out = 0;
                    return NULLPTR;
                }
                const int KF_MOD = abs(kf % VEP_HEADER_MSS_MOD);

                // Set obfuscated header length.
                h->header_length = (Byte)((sizeof(PACKET_HEADER) + KF_MOD) % VEP_HEADER_MSS_MOD);

                // Obfuscate session_id.
                h->session_id = htonl(h->session_id ^ kf);

                // Copy payload after header.
                memcpy(h + 1, payload, payload_length);

                // Compute checksum over header + payload (payload may be transport-encrypted).
                h->checksum = ppp::net::native::inet_chksum(h, message_length);

                std::shared_ptr<ppp::Byte> buf;
                std::shared_ptr<ppp::Byte> output;

                // If protocol encryption is enabled, encrypt the trailing part of the header.
                if (NULLPTR != protocol) {
                    int header_length_raw = sizeof(PACKET_HEADER) - offsetof(PACKET_HEADER, checksum);
                    int header_length_new = 0;
                    std::shared_ptr<Byte> header_body = protocol->Encrypt(allocator,
                                        reinterpret_cast<ppp::Byte*>(&h->checksum), header_length_raw, header_length_new);
                    if (NULLPTR == header_body) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                        out = 0;
                        return NULLPTR;
                    }

                    if (header_length_raw == header_length_new) {
                        // Replace in-place.
                        memcpy(reinterpret_cast<ppp::Byte*>(&h->checksum), header_body.get(), header_length_new);
                    } else {
                        // Rebuild packet with new header layout.
                        ppp::io::MemoryStream ms;
                        ms.Write(h, 0, offsetof(PACKET_HEADER, checksum));
                        ms.Write(header_body.get(), 0, header_length_new);
                        ms.Write(h + 1, 0, payload_length);

                        message_length = ms.GetPosition();
                        buf = ms.GetBuffer();

                        h = (PACKET_HEADER*)buf.get();

                        // Recompute obfuscated header length.
                        h->header_length = (Byte)((header_length_new + offsetof(PACKET_HEADER, checksum) + KF_MOD) % VEP_HEADER_MSS_MOD);
                    }
                }

                // Apply shuffle and XOR masking to the session_id and following data.
                ppp::cryptography::ssea::shuffle_data(reinterpret_cast<char*>(&h->session_id),
                                                      message_length - offsetof(PACKET_HEADER, session_id), kf);
                Byte* p = reinterpret_cast<Byte*>(h);
                Byte* x = p + offsetof(PACKET_HEADER, session_id);
                Byte* y = p + message_length;
                ppp::cryptography::ssea::masked_xor_random_next(x, y, kf);

                // Final delta encoding before transmission.
                out = ppp::cryptography::ssea::delta_encode(allocator, h, message_length, configuration->key.kf, output);
                if (NULLPTR == output || out <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    out = 0;
                    return NULLPTR;
                }
                return output;
            }

            /**
             * @brief Packs payload with explicit origin/session id parameters.
             * @param configuration Runtime configuration.
             * @param allocator Buffer allocator.
             * @param protocol Protocol ciphertext resolver.
             * @param transport Transport ciphertext resolver.
             * @param origin_id Id used for cipher selection.
             * @param session_id Id encoded in packet header.
             * @param source_ip Source IPv4 (host order).
             * @param source_port Source port (host order).
             * @param destination_ip Destination IPv4 (host order).
             * @param destination_port Destination port (host order).
             * @param payload Payload bytes.
             * @param payload_length Payload length.
             * @param out Receives final encoded packet length.
             * @return Encoded packet buffer, or null on failure.
             * @note If either protocol/transport cipher is unavailable, both are disabled for this packet.
             */
            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::PackBy(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                int                                                             origin_id,
                int                                                             session_id,
                uint32_t                                                        source_ip,
                int                                                             source_port,
                uint32_t                                                        destination_ip,
                int                                                             destination_port,
                const void*                                                     payload,
                int                                                             payload_length,
                int&                                                            out) noexcept
            {
                out = 0;
                
                // Validate inputs.
                if (origin_id == 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                    return NULLPTR;
                }

                if (NULLPTR == payload || payload_length < 1) {
                    return NULLPTR;
                }

                // Obtain ciphertext instances for the given origin_id.
                std::shared_ptr<ppp::cryptography::Ciphertext> protocol_ciphertext = protocol ? protocol(origin_id) : NULLPTR;
                std::shared_ptr<ppp::cryptography::Ciphertext> transport_ciphertext = transport ? transport(origin_id) : NULLPTR;
                if (NULLPTR == protocol_ciphertext || NULLPTR == transport_ciphertext) {
                    protocol_ciphertext  = NULLPTR;
                    transport_ciphertext = NULLPTR;
                }

                // Encrypt payload with transport ciphertext if available.
                std::shared_ptr<ppp::Byte> payload_managed;
                if (NULLPTR != transport_ciphertext) {
                    payload_managed = transport_ciphertext->Encrypt(allocator, (ppp::Byte*)payload, payload_length, payload_length);
                    if (NULLPTR == payload_managed) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                        return NULLPTR;
                    }
                    payload = payload_managed.get();
                }

                // Allocate buffer for full packet (header + payload).
                int message_length = sizeof(PACKET_HEADER) + payload_length;
                std::shared_ptr<ppp::Byte> messages = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_length);
                if (NULLPTR == messages) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                // Fill header fields.
                PACKET_HEADER* h = reinterpret_cast<PACKET_HEADER*>(messages.get());
                h->checksum                = 0;
                h->header_length           = 0;
                h->session_id              = session_id;
                h->posedo.source_ip        = source_ip;
                h->posedo.source_port      = htons(source_port);
                h->posedo.destination_ip   = destination_ip;
                h->posedo.destination_port = htons(destination_port);

                // Generate a non-zero random mask_id.
                do {
                    h->mask_id = ppp::RandomNext(0, UINT8_MAX) << 24 |
                                 ppp::RandomNext(0, UINT8_MAX) << 16 |
                                 ppp::RandomNext(0, UINT8_MAX) << 8  |
                                 ppp::RandomNext(0, UINT8_MAX);
                } while (h->mask_id == 0);

                // Call static pack routine.
                return STATIC_Pack(configuration, allocator, protocol_ciphertext, h, payload, payload_length, message_length, out);
            }

            /**
             * @brief Allocates and unpacks a packet object.
             * @param configuration Runtime configuration.
             * @param allocator Buffer allocator.
             * @param protocol Protocol ciphertext resolver.
             * @param transport Transport ciphertext resolver.
             * @param packet Raw encoded packet bytes.
             * @param packet_length Raw encoded packet length.
             * @return Parsed packet object on success; otherwise null.
             * @note Thin wrapper around `UnpackBy`.
             */
            std::shared_ptr<VirtualEthernetPacket> VirtualEthernetPacket::Unpack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                const void*                                                     packet,
                int                                                             packet_length) noexcept
            {
                std::shared_ptr<VirtualEthernetPacket> result = ppp::make_shared_object<VirtualEthernetPacket>();
                if (NULLPTR == result) {
                    return NULLPTR;
                }

                return UnpackBy(configuration, allocator, protocol, transport, packet, packet_length, *result) ? result : NULLPTR;
            }

            /**
             * @brief Rebuilds an IPFrame view from this packet.
             * @param allocator Buffer allocator.
             * @return Parsed IP frame or null.
             * @note Works only for packets tagged as `IP_PROTO_IP`.
             */
            std::shared_ptr<ppp::net::packet::IPFrame> VirtualEthernetPacket::GetIPPacket(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator) noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    return NULLPTR;
                }

                // Reconstruct posedo header and payload.
                PACKET_IP_PACKET_POSEDO posedo;
                posedo.source_ip        = SourceIP;
                posedo.source_port      = SourcePort;
                posedo.destination_ip   = DestinationIP;
                posedo.destination_port = DestinationPort;

                ppp::io::MemoryStream ms;
                ms.Write(&posedo, 0, sizeof(posedo));
                ms.Write(Payload.get(), 0, Length);

                std::shared_ptr<ppp::Byte> buffer = ms.GetBuffer();
                return ppp::net::packet::IPFrame::Parse(allocator, buffer, buffer.get(), ms.GetPosition());
            }

            /**
             * @brief Extracts ICMP frame from this packet.
             * @param allocator Buffer allocator.
             * @param packet Receives parsed IP frame.
             * @return Parsed ICMP frame or null.
             * @note Returns null when inner protocol is not ICMP.
             */
            std::shared_ptr<ppp::net::packet::IcmpFrame> VirtualEthernetPacket::GetIcmpPacket(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                std::shared_ptr<ppp::net::packet::IPFrame>&                     packet) noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    return NULLPTR;
                }

                packet = GetIPPacket(allocator);
                if (NULLPTR == packet) {
                    return NULLPTR;
                }

                if (packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return NULLPTR;
                }

                return ppp::net::packet::IcmpFrame::Parse(packet.get());
            }

            /**
             * @brief Extracts UDP frame from this packet.
             * @return Parsed UDP frame or null.
             * @note Works only for packets tagged as `IP_PROTO_UDP`.
             */
            std::shared_ptr<ppp::net::packet::UdpFrame> VirtualEthernetPacket::GetUdpPacket() noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::net::packet::UdpFrame> packet = ppp::make_shared_object<ppp::net::packet::UdpFrame>();
                if (NULLPTR == packet) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::net::packet::BufferSegment> payload = ppp::make_shared_object<ppp::net::packet::BufferSegment>(Payload, Length);
                if (NULLPTR == payload) {
                    return NULLPTR;
                }

                packet->AddressesFamily = ppp::net::AddressFamily::InterNetwork;
                packet->Source          = IPEndPoint(SourceIP, SourcePort);
                packet->Destination     = IPEndPoint(DestinationIP, DestinationPort);
                packet->Payload         = payload;
                return packet;
            }

            /**
             * @brief Packs UDP tuple and payload into transport packet.
             * @param configuration Runtime configuration.
             * @param allocator Buffer allocator.
             * @param protocol Protocol ciphertext resolver.
             * @param transport Transport ciphertext resolver.
             * @param session_id Positive UDP session id.
             * @param source_ip Source IPv4 (host order).
             * @param source_port Source port.
             * @param destination_ip Destination IPv4 (host order).
             * @param destination_port Destination port.
             * @param payload Payload bytes.
             * @param payload_length Payload length.
             * @param out Receives encoded packet length.
             * @return Encoded packet buffer, or null on validation/encoding failure.
             * @note Enforces valid endpoint/port ranges for UDP mode.
             */
            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::Pack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                int                                                             session_id,
                uint32_t                                                        source_ip,
                int                                                             source_port,
                uint32_t                                                        destination_ip,
                int                                                             destination_port,
                const void*                                                     payload,
                int                                                             payload_length,
                int&                                                            out) noexcept
            {
                // Session ID must be positive for UDP.
                if (session_id < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                    return NULLPTR;
                }

                // Validate destination.
                if (destination_ip == IPEndPoint::NoneAddress || destination_ip == IPEndPoint::AnyAddress) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                if (destination_port <= IPEndPoint::MinPort || destination_port > IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }

                if (source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return NULLPTR;
                }
                
                return PackBy(configuration, allocator, protocol, transport, session_id, session_id,
                             source_ip, source_port, destination_ip, destination_port,
                             payload, payload_length, out);
            }

            /**
             * @brief Packs an IP frame into transport packet.
             * @param configuration Runtime configuration.
             * @param allocator Buffer allocator.
             * @param protocol Protocol ciphertext resolver.
             * @param transport Transport ciphertext resolver.
             * @param session_id Positive session id.
             * @param packet Source IP frame.
             * @param out Receives encoded packet length.
             * @return Encoded packet buffer, or null on validation/encoding failure.
             * @note Session id is bitwise-negated for inner IP mode tagging.
             */
            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::Pack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                int                                                             session_id,
                const ppp::net::packet::IPFrame*                                packet,
                int&                                                            out) noexcept
            {
                // Validate inputs.
                if (NULLPTR == packet) {
                    return NULLPTR;
                }

                if (session_id < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                    return NULLPTR;
                }

                // Only ICMP, UDP, TCP are allowed.
                if (packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP &&
                    packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_UDP &&
                    packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_TCP) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return NULLPTR;
                }

                // Convert IP frame to raw buffer.
                std::shared_ptr<ppp::net::packet::BufferSegment> packet_buffers = constantof(packet)->ToArray(allocator);
                if (NULLPTR == packet_buffers) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                // The buffer starts with PACKET_IP_PACKET_POSEDO followed by payload.
                PACKET_IP_PACKET_POSEDO* posedo = (PACKET_IP_PACKET_POSEDO*)packet_buffers->Buffer.get();
                return PackBy(configuration, allocator, protocol, transport, session_id, ~session_id,
                              posedo->source_ip, posedo->source_port,
                              posedo->destination_ip, posedo->destination_port,
                              posedo + 1, packet_buffers->Length - sizeof(PACKET_IP_PACKET_POSEDO), out);
            }

            /**
             * @brief Opens UDP socket with preferred address then protocol fallback.
             * @param socket UDP socket object.
             * @param address Preferred bind address.
             * @param port Bind port.
             * @param sourceEP Endpoint used to infer fallback protocol family.
             * @return True on success; otherwise false.
             * @note If preferred bind fails, socket is closed and retried on v4/v6 ANY.
             */
            bool VirtualEthernetPacket::OpenDatagramSocket(boost::asio::ip::udp::socket&            socket,
                                                           const boost::asio::ip::address&          address,
                                                           int                                      port,
                                                           const boost::asio::ip::udp::endpoint&    sourceEP) noexcept
            {
                bool ok = false;
                if (address.is_v4() || address.is_v6()) {
                    ok = Socket::OpenSocket(socket, address, port);
                    if (ok) {
                        return true;
                    }

                    ok = Socket::Closesocket(socket);
                    if (!ok) {
                        return false;
                    }

                    goto opensocket_by_protocol;
                }

            opensocket_by_protocol:
                if (sourceEP.protocol() == boost::asio::ip::udp::v4()) {
                    ok = Socket::OpenSocket(socket, boost::asio::ip::address_v4::any(), port);
                } else {
                    ok = Socket::OpenSocket(socket, boost::asio::ip::address_v6::any(), port);
                }
                
                return ok;
            }

            /**
             * @brief Fills IP payload with random printable ASCII bytes.
             * @param frame Target IP frame.
             * @param min Minimum random payload length.
             * @param max Maximum random payload length.
             * @return True on success; otherwise false.
             * @note Generated bytes range from `0x20` to `0x7e`.
             */
            bool VirtualEthernetPacket::FillBytesToPayload(ppp::net::packet::IPFrame* frame, int min, int max) noexcept
            {
                if (NULLPTR == frame) {
                    return false;
                }

                if (min < 1 || max < 1 || min > max) {
                    return false;
                }

                int payload_length = RandomNext(min, max);
                if (payload_length < 1) {
                    return false;
                }

                auto payload = make_shared_object<ppp::net::packet::BufferSegment>();
                if (NULLPTR == payload) {
                    return false;
                }

                std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(payload_length);
                if (NULLPTR == buffer) {
                    return false;
                }

                Byte* p = buffer.get();
                for (int i = 0; i < payload_length; i++) {
                    *p++ = RandomNext(0x20, 0x7e); // Printable ASCII range
                }

                frame->Payload  = payload;
                payload->Buffer = buffer;
                payload->Length = payload_length;
                return true;
            }

            /**
             * @brief Creates protocol and transport ciphertext objects.
             * @param configuration Runtime configuration.
             * @param guid Device/session guid.
             * @param fsid Forward-session id.
             * @param id Session id.
             * @param protocol Receives protocol-layer ciphertext.
             * @param transport Receives transport-layer ciphertext.
             * @return void.
             * @note Output pointers are reset to null when encryption is disabled or construction fails.
             */
            void VirtualEthernetPacket::Ciphertext(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const Int128&                                                   guid,
                const Int128&                                                   fsid,
                int                                                             id,
                std::shared_ptr<ppp::cryptography::Ciphertext>&                 protocol,
                std::shared_ptr<ppp::cryptography::Ciphertext>&                 transport) noexcept
            {
                protocol  = NULLPTR;
                transport = NULLPTR;
                if (ppp::configurations::extensions::IsHaveCiphertext(configuration.get())) {
                    ppp::string ivv_string = stl::to_string<ppp::string>(guid, 32) + "/" +
                                             stl::to_string<ppp::string>(fsid, 32) + "\\" +
                                             stl::to_string<ppp::string>(id, 32) + ";";
                    protocol  = make_shared_object<ppp::cryptography::Ciphertext>(configuration->key.protocol,
                                                                                   configuration->key.protocol_key + ivv_string);
                    transport = make_shared_object<ppp::cryptography::Ciphertext>(configuration->key.transport,
                                                                                   configuration->key.transport_key + ivv_string);
                    if (NULLPTR == protocol || NULLPTR == transport) {
                        protocol  = NULLPTR;
                        transport = NULLPTR;
                    }
                }
            }
        }
    }
}
