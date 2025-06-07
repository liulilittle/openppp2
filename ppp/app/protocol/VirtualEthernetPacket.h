#pragma once

#include <ppp/stdafx.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>

namespace ppp 
{
    namespace app 
    {
        namespace protocol 
        {
            struct VirtualEthernetPacket final
            {
            public:
                std::shared_ptr<ppp::Byte>                                          Payload;
                int32_t                                                             Length          = 0;
                int32_t                                                             Protocol        = 0;
                int32_t                                                             Id              = 0;
                uint32_t                                                            SourceIP        = 0;
                uint16_t                                                            SourcePort      = 0;
                uint32_t                                                            DestinationIP   = 0;
                uint32_t                                                            DestinationPort = 0;

            public:
                std::shared_ptr<ppp::net::packet::IcmpFrame>                        GetIcmpPacket(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, std::shared_ptr<ppp::net::packet::IPFrame>& packet) noexcept;
                std::shared_ptr<ppp::net::packet::IPFrame>                          GetIPPacket(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                std::shared_ptr<ppp::net::packet::UdpFrame>                         GetUdpPacket() noexcept;

            public:
                static int                                                          NewId() noexcept;
                static std::shared_ptr<ppp::Byte>                                   Pack(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                    const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                    int                                                             session_id,
                    const ppp::net::packet::IPFrame*                                packet,
                    int&                                                            out) noexcept;
                static std::shared_ptr<ppp::Byte>                                   Pack(
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
                    int&                                                            out) noexcept;
                static std::shared_ptr<VirtualEthernetPacket>                       Unpack(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration, 
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                    const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                    const void*                                                     packet, 
                    int                                                             packet_length) noexcept;

            public:
                static bool                                                         FillBytesToPayload(ppp::net::packet::IPFrame* frame) noexcept { return FillBytesToPayload(frame, 1, 128); }
                static bool                                                         FillBytesToPayload(ppp::net::packet::IPFrame* frame, int min, int max) noexcept;
                static bool                                                         OpenDatagramSocket(boost::asio::ip::udp::socket& socket, const boost::asio::ip::address& address, int port, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                static bool                                                         UnpackBy(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration, 
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                    const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                    const void*                                                     packet, 
                    int                                                             packet_length, 
                    VirtualEthernetPacket&                                          out) noexcept;
                static std::shared_ptr<ppp::Byte>                                   PackBy(
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
                    int&                                                            out) noexcept;
            };
        }
    }
}