#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/checksum.h>
#include <ppp/cryptography/ssea.h>

namespace ppp
{
    namespace app
    {
        namespace protocol
        {
#pragma pack(push, 1)
            typedef struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            {
                uint32_t                                                        source_ip;
                uint16_t                                                        source_port;
                uint32_t                                                        destination_ip;
                uint16_t                                                        destination_port;
            } PACKET_IP_PACKET_POSEDO;

            typedef struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            {
                uint32_t                                                        mask_id;
                uint8_t                                                         header_length;
                int32_t                                                         session_id;
                uint16_t                                                        checksum;
                PACKET_IP_PACKET_POSEDO                                         posedo;
            } PACKET_HEADER;
#pragma pack(pop)

            typedef ppp::net::IPEndPoint                                        IPEndPoint;
            typedef ppp::net::Socket                                            Socket;

            static int STATIC_header_length(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, int N, int kf) noexcept {
                const int VEP_HEADER_MSS_MOD = configuration->Lcgmod(ppp::configurations::AppConfiguration::LCGMOD_TYPE_STATIC);
                const int KF_MOD = abs(kf % VEP_HEADER_MSS_MOD);

                return (N - KF_MOD + VEP_HEADER_MSS_MOD) % VEP_HEADER_MSS_MOD;
            }

            static bool STATIC_Unpack(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                PACKET_HEADER*                                                  h,
                int                                                             proto,
                int                                                             session_id,
                int                                                             packet_length,
                VirtualEthernetPacket&                                          out) noexcept
            {
                if (session_id == 0)
                {
                    return false;
                }
                else
                {
                    uint16_t x_checksum = h->checksum;
                    h->checksum = 0;

                    uint16_t y_checksum = ppp::net::native::inet_chksum(h, packet_length);
                    h->checksum = x_checksum;

                    if (x_checksum != y_checksum)
                    {
                        return false;
                    }
                }

                std::shared_ptr<ppp::Byte> payload;
                int payload_length = packet_length - sizeof(PACKET_HEADER);
                if (NULL != transport)
                {
                    payload = transport->Decrypt(allocator, (ppp::Byte*)(h + 1), payload_length, payload_length);
                    if (NULL == payload)
                    {
                        return false;
                    }
                }
                else
                {
                    payload = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, payload_length);
                    if (NULL == payload)
                    {
                        return false;
                    }
                    else
                    {
                        memcpy(payload.get(), h + 1, payload_length);
                    }
                }

                out.Id              = session_id;
                out.Payload         = payload;
                out.Length          = payload_length;
                out.Protocol        = proto;
                out.SourceIP        = h->posedo.source_ip;
                out.SourcePort      = ntohs(h->posedo.source_port);
                out.DestinationIP   = h->posedo.destination_ip;
                out.DestinationPort = ntohs(h->posedo.destination_port);
                   
                if (proto != ppp::net::native::ip_hdr::IP_PROTO_UDP)
                {
                    return true;
                }
                elif(out.DestinationIP == IPEndPoint::NoneAddress || out.DestinationIP == IPEndPoint::AnyAddress)
                {
                    return false;
                }
                elif(out.DestinationPort <= IPEndPoint::MinPort || out.DestinationPort > IPEndPoint::MaxPort)
                {
                    return false;
                }
                elif(out.SourceIP == IPEndPoint::NoneAddress || out.SourceIP == IPEndPoint::AnyAddress)
                {
                    return false;
                }
                elif(out.SourcePort <= IPEndPoint::MinPort || out.SourcePort > IPEndPoint::MaxPort)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }

            bool VirtualEthernetPacket::UnpackBy(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                const void*                                                     packet,
                int                                                             packet_length,
                VirtualEthernetPacket&                                          out) noexcept
            {
                if (NULL == packet || packet_length <= sizeof(PACKET_HEADER))
                {
                    return false;
                }

                std::shared_ptr<ppp::Byte> output;
                packet_length = ppp::cryptography::ssea::delta_decode(allocator, packet, packet_length, configuration->key.kf, output);
                
                if (NULL == output || packet_length <= sizeof(PACKET_HEADER))
                {
                    return false;
                }
                else
                {
                    packet = output.get();
                }

                ppp::Byte* p = (ppp::Byte*)packet;
                PACKET_HEADER* h = (PACKET_HEADER*)p;
                if (h->mask_id == 0)
                {
                    return false;
                }

                int kf = ppp::cryptography::ssea::random_next(configuration->key.kf * h->mask_id);
                int header_length = (ppp::Byte)STATIC_header_length(configuration, h->header_length, kf);

                if (header_length < sizeof(PACKET_HEADER))
                {
                    return false;
                }
                else
                {
                    ppp::Byte* x = p + offset_of(PACKET_HEADER, session_id);
                    ppp::Byte* y = p + packet_length;

                    ppp::cryptography::ssea::masked_xor_random_next(x, y, kf);
                    ppp::cryptography::ssea::unshuffle_data(reinterpret_cast<char*>(&h->session_id), packet_length - offset_of(PACKET_HEADER, session_id), kf);
                }

                int32_t session_id = htonl(h->session_id) ^ kf;
                int proto = ppp::net::native::ip_hdr::IP_PROTO_UDP;
                if (session_id < 0)
                {
                    session_id = ~session_id; /* abs(result->Id) */;
                    proto = ppp::net::native::ip_hdr::IP_PROTO_IP;
                }

                std::shared_ptr<ppp::cryptography::Ciphertext> transport_ciphertext = transport ? transport(session_id) : NULL;
                std::shared_ptr<ppp::cryptography::Ciphertext> protocol_ciphertext = protocol ? protocol(session_id) : NULL;

                if (NULL != protocol_ciphertext && NULL != transport_ciphertext)
                {
                    int header_length_raw = sizeof(PACKET_HEADER) - offset_of(PACKET_HEADER, checksum);
                    int header_length_new;

                    std::shared_ptr<Byte> header_body = protocol_ciphertext->Decrypt(allocator, reinterpret_cast<ppp::Byte*>(&h->checksum), header_length_raw, header_length_new);
                    if (NULL == header_body) 
                    {
                        return false;
                    }

                    if (header_length_new == header_length_raw)
                    {
                        memcpy(reinterpret_cast<ppp::Byte*>(&h->checksum), header_body.get(), header_length_new);
                    }
                    else
                    {
                        ppp::io::MemoryStream ms;
                        ms.Write(h, 0, offset_of(PACKET_HEADER, checksum));
                        ms.Write(header_body.get(), 0, header_length_new);
                        ms.Write((Byte*)h + header_length, 0, packet_length - header_length);

                        std::shared_ptr<ppp::Byte> buf = ms.GetBuffer();
                        packet_length = ms.GetPosition();

                        h = (PACKET_HEADER*)buf.get();
                        h->header_length = (ppp::Byte)STATIC_header_length(configuration, sizeof(PACKET_HEADER), kf);

                        return STATIC_Unpack(allocator, transport_ciphertext, h, proto, session_id, packet_length, out);
                    }
                }
                else 
                {
                    protocol_ciphertext  = NULL;
                    transport_ciphertext = NULL;
                }

                return STATIC_Unpack(allocator, transport_ciphertext, h, proto, session_id, packet_length, out);
            }

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
                const int kf = ppp::cryptography::ssea::random_next(configuration->key.kf * h->mask_id);
                const int VEP_HEADER_MSS_MOD = configuration->Lcgmod(ppp::configurations::AppConfiguration::LCGMOD_TYPE_STATIC);

                const int KF_MOD = abs(kf % VEP_HEADER_MSS_MOD);
                h->header_length = (Byte)((sizeof(PACKET_HEADER) + KF_MOD) % VEP_HEADER_MSS_MOD);

                h->session_id = htonl(h->session_id ^ kf);
                memcpy(h + 1, payload, payload_length);

                ppp::io::MemoryStream ms;
                h->checksum = ppp::net::native::inet_chksum(h, message_length);

                std::shared_ptr<ppp::Byte> buf;
                std::shared_ptr<ppp::Byte> output;
                if (NULL != protocol)
                {
                    int header_length_raw = sizeof(PACKET_HEADER) - offset_of(PACKET_HEADER, checksum);
                    int header_length_new = 0;

                    std::shared_ptr<Byte> header_body = protocol->Encrypt(allocator,
                        reinterpret_cast<ppp::Byte*>(&h->checksum), header_length_raw, header_length_new);
                    if (NULL == header_body)
                    {
                        return NULL;
                    }

                    if (header_length_raw == header_length_new)
                    {
                        memcpy(reinterpret_cast<ppp::Byte*>(&h->checksum), header_body.get(), header_length_new);
                    }
                    else
                    {
                        ms.Write(h, 0, offset_of(PACKET_HEADER, checksum));
                        ms.Write(header_body.get(), 0, header_length_new);
                        ms.Write(h + 1, 0, payload_length);

                        message_length = ms.GetPosition();
                        buf = ms.GetBuffer();
 
                        h = (PACKET_HEADER*)buf.get();
                        h->header_length = (Byte)((header_length_new + offset_of(PACKET_HEADER, checksum) + KF_MOD) % VEP_HEADER_MSS_MOD);
                    }
                }

                ppp::cryptography::ssea::shuffle_data(reinterpret_cast<char*>(&h->session_id), message_length - offset_of(PACKET_HEADER, session_id), kf);
                for (;;)
                {
                    Byte* p = reinterpret_cast<Byte*>(h);
                    ppp::Byte* x = p + offset_of(PACKET_HEADER, session_id);
                    ppp::Byte* y = p + message_length;

                    ppp::cryptography::ssea::masked_xor_random_next(x, y, kf);
                    break;
                }

                out = ppp::cryptography::ssea::delta_encode(allocator, h, message_length, configuration->key.kf, output);
                return output;
            }

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
                if (NULL == payload || payload_length < 1 || origin_id == 0)
                {
                    return NULL;
                }
        
                std::shared_ptr<ppp::cryptography::Ciphertext> protocol_ciphertext = protocol ? protocol(origin_id) : NULL;
                std::shared_ptr<ppp::cryptography::Ciphertext> transport_ciphertext = transport ? transport(origin_id) : NULL;
                if (NULL == protocol_ciphertext || NULL == transport_ciphertext)
                {
                    protocol_ciphertext  = NULL;
                    transport_ciphertext = NULL;
                }

                std::shared_ptr<ppp::Byte> payload_managed;
                if (NULL != transport_ciphertext)
                {
                    payload_managed = transport_ciphertext->Encrypt(allocator, (ppp::Byte*)payload, payload_length, payload_length);
                    if (NULL == payload_managed)
                    {
                        return NULL;
                    }
                    else
                    {
                        payload = payload_managed.get();
                    }
                }
            
                int message_length = sizeof(PACKET_HEADER) + payload_length;
                std::shared_ptr<ppp::Byte> messages = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_length);
                if (NULL == messages)
                {
                    return NULL;
                }
            
                PACKET_HEADER* h           = reinterpret_cast<PACKET_HEADER*>(messages.get());
                h->checksum                = 0;
                h->header_length           = 0;
                h->session_id              = session_id;
                h->posedo.source_ip        = source_ip;
                h->posedo.source_port      = htons(source_port);
                h->posedo.destination_ip   = destination_ip;
                h->posedo.destination_port = htons(destination_port);

                do 
                {
                    h->mask_id = ppp::RandomNext(0, UINT8_MAX) << 24 | 
                        ppp::RandomNext(0, UINT8_MAX) << 16 |
                        ppp::RandomNext(0, UINT8_MAX) << 8 | 
                        ppp::RandomNext(0, UINT8_MAX);
                } while (h->mask_id == 0);

                return STATIC_Pack(configuration, allocator, protocol_ciphertext, h, payload, payload_length, message_length, out);
            }

            std::shared_ptr<VirtualEthernetPacket> VirtualEthernetPacket::Unpack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration, 
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                const void*                                                     packet, 
                int                                                             packet_length) noexcept
            {
                std::shared_ptr<VirtualEthernetPacket> result = ppp::make_shared_object<VirtualEthernetPacket>();
                if (NULL == result)
                {
                    return NULL;
                }

                return UnpackBy(configuration, allocator, protocol, transport, packet, packet_length, *result) ? result : NULL;
            }

            std::shared_ptr<ppp::net::packet::IPFrame> VirtualEthernetPacket::GetIPPacket(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_IP)
                {
                    return NULL;
                }

                PACKET_IP_PACKET_POSEDO posedo;
                posedo.source_ip        = SourceIP;
                posedo.source_port      = SourcePort;
                posedo.destination_ip   = DestinationIP;
                posedo.destination_port = DestinationPort;

                ppp::io::MemoryStream ms;
                ms.Write(&posedo, 0, sizeof(posedo));
                ms.Write(Payload.get(), 0, Length);

                std::shared_ptr<ppp::Byte> buffer = ms.GetBuffer();
                return ppp::net::packet::IPFrame::Parse(allocator, buffer.get(), ms.GetPosition());
            }

            std::shared_ptr<ppp::net::packet::IcmpFrame> VirtualEthernetPacket::GetIcmpPacket(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator, 
                std::shared_ptr<ppp::net::packet::IPFrame>&                     packet) noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_IP)
                {
                    return NULL;
                }

                packet = GetIPPacket(allocator);
                if (NULL == packet)
                {
                    return NULL;
                }

                if (packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP)
                {
                    return NULL;
                }

                return ppp::net::packet::IcmpFrame::Parse(packet.get());
            }

            std::shared_ptr<ppp::net::packet::UdpFrame> VirtualEthernetPacket::GetUdpPacket() noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_UDP)
                {
                    return NULL;
                }

                std::shared_ptr<ppp::net::packet::UdpFrame> packet = ppp::make_shared_object<ppp::net::packet::UdpFrame>();
                if (NULL == packet)
                {
                    return NULL;
                }

                std::shared_ptr<ppp::net::packet::BufferSegment> payload = ppp::make_shared_object<ppp::net::packet::BufferSegment>(Payload, Length);
                if (NULL == payload)
                {
                    return NULL;
                }

                packet->AddressesFamily = ppp::net::AddressFamily::InterNetwork;
                packet->Source          = IPEndPoint(SourceIP, SourcePort);
                packet->Destination     = IPEndPoint(DestinationIP, DestinationPort);
                packet->Payload         = payload;
                return packet;
            }

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
                if (session_id < 1)
                {
                    return NULL;
                }

                if (destination_ip == IPEndPoint::NoneAddress || destination_ip == IPEndPoint::AnyAddress)
                {
                    return NULL;
                }
            
                if (destination_port <= IPEndPoint::MinPort || destination_port > IPEndPoint::MaxPort)
                {
                    return NULL;
                }

                if (source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort)
                {
                    return NULL;
                }

                return PackBy(configuration, allocator, protocol, transport, session_id, session_id, source_ip,
                    source_port, destination_ip, destination_port, payload, payload_length, out);
            }

            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::Pack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                int                                                             session_id,
                const ppp::net::packet::IPFrame*                                packet,
                int&                                                            out) noexcept
            {
                if (NULL == packet || session_id < 1)
                {
                    return NULL;
                }

                if (packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP &&
                    packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_UDP &&
                    packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_TCP)
                {
                    return NULL;
                }

                std::shared_ptr<ppp::net::packet::BufferSegment> packet_buffers = constantof(packet)->ToArray(allocator);
                if (NULL == packet_buffers)
                { 
                    return NULL;
                }

                PACKET_IP_PACKET_POSEDO* posedo = (PACKET_IP_PACKET_POSEDO*)packet_buffers->Buffer.get();
                return PackBy(configuration, allocator, protocol, transport, session_id, ~session_id, posedo->source_ip,
                    posedo->source_port, posedo->destination_ip, posedo->destination_port, posedo + 1, packet_buffers->Length - sizeof(PACKET_IP_PACKET_POSEDO), out);
            }

            bool VirtualEthernetPacket::OpenDatagramSocket(boost::asio::ip::udp::socket& socket, const boost::asio::ip::address& address, int port, const boost::asio::ip::udp::endpoint& sourceEP) noexcept 
            {
                bool ok = false;
                if (address.is_v4() || address.is_v6()) 
                {
                    ok = Socket::OpenSocket(socket, address, port);
                    if (ok) 
                    {
                        return true;
                    }

                    ok = Socket::Closesocket(socket);
                    if (!ok) 
                    {
                        return false;
                    }

                    goto opensocket_by_protocol;
                }

            opensocket_by_protocol: /* Label.s */
                if (sourceEP.protocol() == boost::asio::ip::udp::v4()) 
                {
                    ok = Socket::OpenSocket(socket, boost::asio::ip::address_v4::any(), port);
                }
                else 
                {
                    ok = Socket::OpenSocket(socket, boost::asio::ip::address_v6::any(), port);
                }

                return ok;
            }

            bool VirtualEthernetPacket::FillBytesToPayload(ppp::net::packet::IPFrame* frame, int min, int max) noexcept
            {
                if (NULL == frame)
                {
                    return false;
                }

                if (min < 1) 
                {
                    return false;
                }

                if (max < 1)
                {
                    return false;
                }

                int payload_length = RandomNext(min, max);
                if (payload_length < 1) 
                {
                    return false;
                }

                auto payload = make_shared_object<ppp::net::packet::BufferSegment>();
                if (NULL == payload) 
                {
                    return false;
                }

                std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(payload_length);
                if (NULL == buffer) 
                {
                    return false;
                }

                Byte* p = buffer.get();
                for (int i = 0; i < payload_length; i++) 
                {
                    *p++ = RandomNext(0x20, 0x7e);
                }

                frame->Payload  = payload;
                payload->Buffer = buffer;
                payload->Length = payload_length;

                return true;
            }
        
            void VirtualEthernetPacket::Ciphertext( 
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const Int128&                                                   guid,
                const Int128&                                                   fsid,
                int                                                             id,
                std::shared_ptr<ppp::cryptography::Ciphertext>&                 protocol,
                std::shared_ptr<ppp::cryptography::Ciphertext>&                 transport) noexcept 
            {
                protocol  = NULL;
                transport = NULL;

                if (ppp::configurations::extensions::IsHaveCiphertext(configuration.get())) 
                {
                    ppp::string ivv_string = 
                        stl::to_string<ppp::string>(guid, 32) + "/" + 
                        stl::to_string<ppp::string>(fsid, 32) + "\\" +
                        stl::to_string<ppp::string>(id, 32) + ";";

                    protocol  = make_shared_object<ppp::cryptography::Ciphertext>(configuration->key.protocol, configuration->key.protocol_key + ivv_string);
                    transport = make_shared_object<ppp::cryptography::Ciphertext>(configuration->key.transport, configuration->key.transport_key + ivv_string);

                    if (NULL == protocol || NULL == transport) 
                    {
                        protocol  = NULL;
                        transport = NULL;
                    }
                }
            }
        }
    }
}