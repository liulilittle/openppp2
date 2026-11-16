#pragma once

/**
 * @file UdpFrame.h
 * @brief UDP packet model and UDP/IPv4 conversion helpers.
 *
 * @ref ppp::net::packet::UdpFrame models the logical view of a UDP datagram
 * within the ppp virtual-NIC stack.  Address fields are stored as
 * @ref ppp::net::IPEndPoint values (which use **network byte order** internally).
 *
 * Typical usage patterns
 * ----------------------
 * Parsing (inbound path — raw TAP frame → UdpFrame):
 * @code
 *   auto ip_frame  = IPFrame::Parse(allocator, raw, raw_len);
 *   auto udp_frame = UdpFrame::Parse(ip_frame.get());
 *   // udp_frame->Source / Destination carry port + address
 * @endcode
 *
 * Generation (outbound path — forward UDP datagram back to VPN client):
 * @code
 *   UdpFrame udp;
 *   udp.Source      = local_ep;       // IPEndPoint (network byte order)
 *   udp.Destination = remote_ep;
 *   udp.Ttl         = 64;
 *   udp.Payload     = make_shared<BufferSegment>(buf, len);
 *   auto ip_frame   = UdpFrame::ToIp(allocator, &udp);
 * @endcode
 *
 * @note  The UDP checksum field is calculated by @ref ToIp using the standard
 *        IPv4 pseudo-header method; callers do not need to set it manually.
 * @note  Payload bytes are in **network byte order** as received from the wire;
 *        no byte-swapping is performed on the datagram body.
 */

#include <ppp/stdafx.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>

namespace ppp {
    namespace net {
        namespace packet {
            class IPFrame;
            class BufferSegment;

            /**
             * @brief Represents a UDP datagram with source/destination endpoint metadata.
             *
             * Structure layout:
             *   Source          = IPEndPoint,                      ///< UDP source endpoint
             *   Destination     = IPEndPoint,                      ///< UDP destination endpoint
             *   AddressesFamily = AddressFamily,                   ///< Address family
             *   Ttl             = Byte,                            ///< IP TTL for generated packet
             *   Payload         = std::shared_ptr<BufferSegment>   ///< UDP payload bytes
             *
             * @note  @ref Source.Port and @ref Destination.Port are in host byte order
             *        as stored by @ref IPEndPoint.  The @ref ToIp method handles the
             *        correct network-byte-order conversion for the wire format.
             */
            class UdpFrame final {
            public:
                /** @brief UDP source endpoint (address in network byte order, port in host order). */
                IPEndPoint                                      Source;
                /** @brief UDP destination endpoint (address in network byte order, port in host order). */
                IPEndPoint                                      Destination;
                /** @brief Address family; typically @ref AddressFamily::InterNetwork. */
                AddressFamily                                   AddressesFamily;
                /**
                 * @brief IP Time-To-Live value placed in the enclosing IPv4 header.
                 *
                 * Initialized to @ref IPFrame::DefaultTtl.  Callers may override this when
                 * propagating the original IP TTL from a received packet.
                 */
                Byte                                            Ttl;
                /**
                 * @brief UDP application payload bytes (everything after the 8-byte UDP header).
                 *
                 * NULLPTR indicates an empty datagram.  The buffer is not modified by @ref ToIp;
                 * bytes are written verbatim into the generated IPv4 packet.
                 */
                std::shared_ptr<BufferSegment>                  Payload;

            public:
                /**
                 * @brief Constructs a UDP frame with default address family and TTL.
                 *
                 * Source and Destination endpoints are default-constructed (none/invalid).
                 * Callers must populate all fields before calling @ref ToIp.
                 */
                UdpFrame() noexcept
                    : AddressesFamily(AddressFamily::InterNetwork)
                    , Ttl(IPFrame::DefaultTtl) {
                }

            public:
                /**
                 * @brief Converts a UDP frame pointer to an enclosing IPv4 packet.
                 *
                 * Static convenience overload that null-checks @p frame before dispatching
                 * to the member @ref ToIp overload.
                 *
                 * @param allocator  Allocator for the generated packet buffer.
                 * @param frame      Source UDP frame pointer; NULLPTR returns NULLPTR.
                 * @return           Shared @ref IPFrame containing the complete UDP datagram;
                 *                   NULLPTR on failure.
                 */
                static std::shared_ptr<IPFrame>                 ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const UdpFrame* frame) {
                    if (NULLPTR == frame) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                        return NULLPTR;
                    }

                    UdpFrame* packet = constantof(frame);
                    return packet->ToIp(allocator);
                }

                /**
                 * @brief Converts this UDP frame to an enclosing IPv4 packet.
                 *
                 * Builds a complete IPv4/UDP wire-format packet from this frame's fields.
                 * Specifically:
                 *  - Sets IPv4 src/dst from @ref Source / @ref Destination addresses.
                 *  - Sets UDP src/dst ports from @ref Source.Port / @ref Destination.Port.
                 *  - Appends @ref Payload bytes after the 8-byte UDP header.
                 *  - Computes and writes the UDP checksum using the IPv4 pseudo-header.
                 *  - Computes and writes the IPv4 header checksum.
                 *
                 * @param allocator  Allocator for the generated buffer.
                 * @return           Shared @ref IPFrame on success; NULLPTR on allocation failure
                 *                   or if @ref Destination is invalid.
                 */
                std::shared_ptr<IPFrame>                        ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator);

                /**
                 * @brief Builds the same IPv4 datagram as ToIp() + IPFrame::ToArray() in one buffer.
                 * @return Null when IPv4 fragmentation would be required or on failure.
                 */
                static std::shared_ptr<Byte>                    ToIPv4Packet(
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator,
                    const IPEndPoint&                                           source,
                    const IPEndPoint&                                           destination,
                    Byte                                                        ttl,
                    const void*                                                 payload,
                    int                                                         payload_size,
                    int&                                                        packet_length) noexcept;

                /**
                 * @brief Parses an IPv4 frame as a UDP datagram.
                 *
                 * Extracts the UDP header from @p frame's payload, validates the length,
                 * and populates a @ref UdpFrame with the source/destination endpoints and
                 * application payload.
                 *
                 * @param frame  Source IPv4 frame whose @ref IPFrame::ProtocolType must be
                 *               IPPROTO_UDP.
                 * @return       Shared @ref UdpFrame on success; NULLPTR if @p frame is null,
                 *               protocol is not UDP, or the header length is invalid.
                 */
                static std::shared_ptr<UdpFrame>                Parse(const IPFrame* frame) noexcept;
            };
        }
    }
}
