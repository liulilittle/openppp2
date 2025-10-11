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
                uint16_t                                                        checksum;
                int32_t                                                         session_id;
                PACKET_IP_PACKET_POSEDO                                         posedo;
            } PACKET_HEADER;
#pragma pack(pop)

            typedef ppp::net::IPEndPoint                                        IPEndPoint;
            typedef ppp::net::Socket                                            Socket;

            static bool STATIC_Unpack(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                PACKET_HEADER*                                                  h,
                int                                                             packet_length,
                VirtualEthernetPacket&                                          out) noexcept
            {
                if (h->session_id == 0)
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

                out.Id              = ntohl(h->session_id);
                out.Payload         = payload;
                out.Length          = payload_length;
                out.SourceIP        = h->posedo.source_ip;
                out.SourcePort      = ntohs(h->posedo.source_port);
                out.DestinationIP   = h->posedo.destination_ip;
                out.DestinationPort = ntohs(h->posedo.destination_port);
                return true;
            }

            bool VirtualEthernetPacket::UnpackBy(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
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

                int kf = configuration->key.kf ^ h->mask_id;
                int header_length = (ppp::Byte)(h->header_length ^ kf);
                if (header_length < sizeof(PACKET_HEADER))
                {
                    return false;
                }
                else
                {
                    ppp::Byte* x = p + offset_of(PACKET_HEADER, checksum);
                    ppp::Byte* y = p + packet_length;
                    while (x != y)
                    {
                        *x++ ^= kf;
                    }
                }

                ppp::cryptography::ssea::unshuffle_data(reinterpret_cast<char*>(&h->checksum), packet_length - offset_of(PACKET_HEADER, checksum), kf);
                if (NULL != protocol)
                {
                    int header_length_raw = sizeof(PACKET_HEADER) - offset_of(PACKET_HEADER, checksum);
                    int header_length_new;

                    std::shared_ptr<Byte> header_body = protocol->Decrypt(allocator, reinterpret_cast<ppp::Byte*>(&h->checksum), header_length_raw, header_length_new);
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
                        h->header_length = (ppp::Byte)(sizeof(PACKET_HEADER) ^ kf);

                        return STATIC_Unpack(allocator, transport, h, packet_length, out);
                    }
                }

                return STATIC_Unpack(allocator, transport, h, packet_length, out);
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
                int kf = configuration->key.kf ^ h->mask_id;
                h->header_length = (ppp::Byte)(sizeof(PACKET_HEADER) ^ kf);

                memcpy(h + 1, payload, payload_length);
                h->checksum = ppp::net::native::inet_chksum(h, message_length);

                ppp::io::MemoryStream ms;
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
                        h->header_length = (ppp::Byte)((header_length_new + offset_of(PACKET_HEADER, checksum)) ^ kf);
                    }
                }

                ppp::cryptography::ssea::shuffle_data(reinterpret_cast<char*>(&h->checksum), message_length - offset_of(PACKET_HEADER, checksum), kf);

                do
                {
                    Byte* p = reinterpret_cast<Byte*>(h);
                    ppp::Byte* x = p + offset_of(PACKET_HEADER, checksum);
                    ppp::Byte* y = p + message_length;
                    for (; x != y; x++)
                    {
                        *x = (Byte)((int)*x ^ kf);
                    }
                } while (false);

                out = ppp::cryptography::ssea::delta_encode(allocator, h, message_length, configuration->key.kf, output);
                return output;
            }

            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::PackBy(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
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
                if (NULL == payload || payload_length < 1 || session_id == 0)
                {
                    return NULL;
                }
        
                std::shared_ptr<ppp::Byte> payload_managed;
                if (NULL != transport)
                {
                    payload_managed = transport->Encrypt(allocator, (ppp::Byte*)payload, payload_length, payload_length);
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
                h->session_id              = htonl(session_id);
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
                
                return STATIC_Pack(configuration, allocator, protocol, h, payload, payload_length, message_length, out);
            }

            int VirtualEthernetPacket::NewId() noexcept
            {
                static std::atomic<int> aid_ = RandomNext();

                for (;;)
                {
                    int id = ++aid_;
                    if (id < 1)
                    {
                        aid_ = 0;
                        continue;
                    }
                    else
                    {
                        return id;
                    }
                }
            }

            std::shared_ptr<VirtualEthernetPacket> VirtualEthernetPacket::Unpack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration, 
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                const void*                                                     packet, 
                int                                                             packet_length) noexcept
            {
                std::shared_ptr<VirtualEthernetPacket> result = ppp::make_shared_object<VirtualEthernetPacket>();
                if (NULL == result)
                {
                    return NULL;
                }

                bool ok = UnpackBy(configuration, allocator, protocol, transport, packet, packet_length, *result);
                if (!ok)
                {
                    return NULL;
                }

                if (result->Id < 0)
                {
                    result->Id       = ~result->Id; /* abs(result->Id) */;
                    result->Protocol = ppp::net::native::ip_hdr::IP_PROTO_IP;
                    return result;
                }

                if (result->DestinationIP == IPEndPoint::NoneAddress || result->DestinationIP == IPEndPoint::AnyAddress)
                {
                    return NULL;
                }

                if (result->DestinationPort <= IPEndPoint::MinPort || result->DestinationPort > IPEndPoint::MaxPort)
                {
                    return NULL;
                }

                if (result->SourceIP == IPEndPoint::NoneAddress || result->SourceIP == IPEndPoint::AnyAddress)
                {
                    return NULL;
                }

                if (result->SourcePort <= IPEndPoint::MinPort || result->SourcePort > IPEndPoint::MaxPort)
                {
                    return NULL;
                }

                result->Protocol = ppp::net::native::ip_hdr::IP_PROTO_UDP;
                return result;
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
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
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

                return PackBy(configuration, allocator, protocol, transport, session_id, source_ip,
                    source_port, destination_ip, destination_port, payload, payload_length, out);
            }

            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::Pack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
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
                return PackBy(configuration, allocator, protocol, transport, ~session_id, posedo->source_ip,
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
        }
    }
}