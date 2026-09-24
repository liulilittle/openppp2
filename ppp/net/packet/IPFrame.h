#pragma once

/**
 * @file IPFrame.h
 * @brief IPv4 frame model, serialization, parsing, and fragmentation helpers.
 *
 * This header defines the in-memory representation of an IPv4 packet used
 * throughout the ppp virtual-NIC stack.  All multi-byte fields follow
 * **network byte order** (big-endian) unless the field is annotated otherwise.
 *
 * Key types
 * ---------
 * - @ref BufferSegment — a reference-counted byte buffer + length pair used as
 *   both payload and options carriers within @ref IPFrame.
 * - @ref IPFrame — the primary IPv4 packet model; owns header fields and shared
 *   buffer segments for the payload and optional IPv4 options region.
 *
 * Fragmentation
 * -------------
 * @ref IPFrame::Subpackages splits an oversized frame into MTU-sized IPv4
 * fragments.  Each fragment carries a portion of the original payload with the
 * DF bit cleared and the fragment-offset/MF fields set correctly.
 * @ref IPFrame::GetFragmentOffset / @ref IPFrame::SetFragmentOffset provide
 * typed access to the 13-bit fragment-offset field embedded in @ref Flags.
 *
 * Serialization
 * -------------
 * @ref IPFrame::ToArray serializes the logical frame to a contiguous wire-format
 * byte buffer, computing the IPv4 header checksum as required by RFC 791.
 * @ref IPFrame::Parse performs the reverse (wire → object) with field validation.
 *
 * @note  All address fields (@ref IPFrame::Source, @ref IPFrame::Destination) are
 *        stored in **network byte order** (as they appear on the wire).
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            /**
             * @brief Alias for the IPv4 header flags/fragment-offset field type.
             *
             * Bit layout (16 bits, network byte order):
             *   Bits [15:13] = IP flags (Reserved, DF, MF).
             *   Bits [12:0]  = Fragment offset in 8-byte units.
             */
            typedef ppp::net::native::ip_hdr::Flags                     IPFlags;

            /**
             * @brief Owns a shared byte buffer and its valid length.
             *
             * Used to represent the payload and options sections of an @ref IPFrame
             * without copying data.  The @ref Buffer shared pointer keeps the underlying
             * allocation alive as long as any @ref BufferSegment referring to it exists.
             *
             * Structure layout:
             *   Buffer = std::shared_ptr<Byte>,  ///< Shared byte storage
             *   Length = int,                    ///< Number of valid bytes in Buffer (≥ 0)
             */
            class BufferSegment final {
            public:
                /** @brief Shared pointer to the underlying byte storage. */
                std::shared_ptr<Byte>                                   Buffer;
                /** @brief Number of valid bytes in @ref Buffer; always ≥ 0. */
                int                                                     Length = 0;

            public:
                /** @brief Constructs an empty segment with null buffer and zero length. */
                BufferSegment() noexcept : Length(0) {}

                /**
                 * @brief Constructs a segment from an existing shared buffer.
                 * @param buffer  Shared byte buffer (may be NULLPTR for empty segment).
                 * @param length  Number of valid bytes; clamped to 0 when @p buffer is NULLPTR.
                 */
                BufferSegment(const std::shared_ptr<Byte>& buffer, int length) noexcept
                    : Buffer(buffer)
                    , Length(buffer ? std::max<int>(0, length) : 0) {

                }
            };

            /**
             * @brief Represents an IPv4 packet with header fields and payload segments.
             *
             * All multi-byte network fields are in **network byte order** (big-endian)
             * as they appear on the wire.  Host-order conversions must be applied by
             * callers when reading or writing numeric comparisons.
             *
             * Ownership model
             * ---------------
             * @ref Payload and @ref Options are shared with zero-copy semantics; the
             * underlying byte arrays may be shared across multiple @ref IPFrame instances
             * (e.g. when generating fragments from a single source frame).
             *
             * Structure layout:
             *   AddressesFamily = AddressFamily,                      ///< Address family (always InterNetwork)
             *   Destination     = UInt32,                             ///< Dst IPv4 (network byte order)
             *   Source          = UInt32,                             ///< Src IPv4 (network byte order)
             *   Ttl             = Byte,                               ///< Time to live
             *   Id              = UInt16,                             ///< Identification field
             *   Tos             = Byte,                               ///< Type of service / DSCP
             *   ProtocolType    = Byte,                               ///< Encapsulated protocol (IPPROTO_*)
             *   Flags           = IPFlags,                            ///< Flags + fragment offset
             *   Payload         = std::shared_ptr<BufferSegment>,     ///< Transport header + data
             *   Options         = std::shared_ptr<BufferSegment>      ///< Optional IPv4 options
             */
            class IPFrame final {
            public:
                /** @brief Shared pointer alias for convenience in container types. */
                typedef std::shared_ptr<IPFrame>                        IPFramePtr;

            public:
                /** @brief Address family of this packet; always @ref AddressFamily::InterNetwork. */
                AddressFamily                                           AddressesFamily;
                /** @brief Destination IPv4 address in **network byte order**. */
                UInt32                                                  Destination;
                /** @brief Source IPv4 address in **network byte order**. */
                UInt32                                                  Source;
                /** @brief IP Time to Live field; decremented by each router hop. */
                Byte                                                    Ttl;
                /** @brief IPv4 identification field used for fragment reassembly matching. */
                UInt16                                                  Id;
                /** @brief Type of service / DSCP byte; 0x68 indicates flash precedence. */
                Byte                                                    Tos;
                /** @brief Encapsulated protocol identifier (e.g. IPPROTO_TCP, IPPROTO_UDP). */
                Byte                                                    ProtocolType;
                /**
                 * @brief Fragmentation flags and 13-bit fragment offset packed into 16 bits.
                 *
                 * Stored in network byte order.  Use @ref GetFragmentOffset /
                 * @ref SetFragmentOffset for typed access to the offset sub-field.
                 */
                IPFlags                                                 Flags;
                /** @brief Payload segment containing the transport-layer header and data. */
                std::shared_ptr<BufferSegment>                          Payload;
                /** @brief Optional IPv4 options segment; NULLPTR when no options are present. */
                std::shared_ptr<BufferSegment>                          Options;

            public:
                /**
                 * @brief Constructs a default IPv4 frame with sensible initial values.
                 *
                 * - DF (don't-fragment) flag is set by default.
                 * - TOS is initialized to the project flash precedence value when the
                 *   global flash-TOS flag is enabled; otherwise 0.
                 * - TTL is initialized to @ref DefaultTtl.
                 */
                IPFrame() noexcept
                    : AddressesFamily(AddressFamily::InterNetwork)
                    , Destination(0)
                    , Source(0)
                    , Ttl(IPFrame::DefaultTtl)
                    , Id(0)
                    , Tos(ppp::net::Socket::IsDefaultFlashTypeOfService() ? DefaultFlashTypeOfService() : 0)
                    , ProtocolType(0)
                    , Flags(IPFlags::IP_DF) {

                }

            public:
                /**
                 * @brief Gets the fragment byte offset extracted from @ref Flags.
                 *
                 * The 13-bit fragment-offset field encodes the byte offset of this fragment's
                 * data within the original datagram in units of 8 bytes; this method returns
                 * the actual byte offset.
                 *
                 * @return  Fragment byte offset; 0 for non-fragmented or first-fragment packets.
                 */
                int                                                     GetFragmentOffset() noexcept {
                    int offset = (UInt16)this->Flags;
                    offset = ((UInt16)(offset << 3)) >> 3;
                    offset <<= 3;
                    return offset;
                }

                /**
                 * @brief Sets the fragment byte offset into @ref Flags.
                 *
                 * Preserves the upper 3 flag bits (Reserved, DF, MF) while writing the
                 * 13-bit fragment offset field in units of 8 bytes.
                 *
                 * @param value  Fragment byte offset; must be a multiple of 8.
                 */
                void                                                    SetFragmentOffset(int value) noexcept {
                    int flags = (int)this->Flags >> 13;
                    flags = flags << 13 | value >> 3;
                    this->Flags = (IPFlags)flags;
                }

                /**
                 * @brief Checks whether the payload content is absent or empty.
                 * @return  true when @ref Payload is NULLPTR, its @ref BufferSegment::Buffer
                 *          is NULLPTR, or its @ref BufferSegment::Length is less than 1.
                 */
                bool                                                    IsEmpty() noexcept {
                    std::shared_ptr<BufferSegment> payload = Payload;
                    if (NULLPTR == payload) {
                        return true;
                    }

                    std::shared_ptr<Byte> buffer = payload->Buffer;
                    return NULLPTR == buffer || payload->Length < 1;
                }

                /**
                 * @brief Returns the default flash TOS value used by this project.
                 * @return  0x68 (DSCP Precedence: Flash, throughput/reliability bits set).
                 */
                static int                                              DefaultFlashTypeOfService() noexcept { return 0x68; }

                /**
                 * @brief Applies the default flash TOS to a frame when the pointer is valid.
                 * @param packet  Target frame pointer; no-op when NULLPTR.
                 */
                static void                                             DefaultFlashTypeOfService(const IPFrame* packet) noexcept { 
                    if (NULLPTR != packet) {
                        IPFrame* frame = constantof(packet);
                        frame->Tos = DefaultFlashTypeOfService();
                    }
                }
                
            public:
                /**
                 * @brief Serializes this frame into a contiguous wire-format byte buffer.
                 *
                 * Computes and writes the IPv4 header checksum.  The output buffer contains
                 * the full IP header (with options) followed by the payload bytes.
                 *
                 * @param allocator  Allocator used for the output buffer; may be NULLPTR to
                 *                   fall back to the global allocator.
                 * @return           Shared @ref BufferSegment containing the serialized packet;
                 *                   NULLPTR on allocation failure or if the frame is empty.
                 */
                std::shared_ptr<BufferSegment>                          ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

                /**
                 * @brief Serializes a frame pointer into a contiguous wire-format byte buffer.
                 * @param allocator  Allocator for the output buffer.
                 * @param packet     Source frame pointer; NULLPTR returns NULLPTR immediately.
                 * @return           Shared @ref BufferSegment with serialized packet, or NULLPTR.
                 */
                static std::shared_ptr<BufferSegment>                   ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const IPFrame* packet) noexcept {
                    if (NULLPTR == packet) {
                        return NULLPTR;
                    }

                    IPFrame* frame = constantof(packet);
                    return frame->ToArray(allocator);
                }

            public:
                /**
                 * @brief Calculates the total serialized frame size in bytes.
                 *
                 * Returns the sum of the IPv4 header length, options length (if any),
                 * and payload length.  Does not allocate any buffer.
                 *
                 * @return  Total packet size in bytes.
                 */
                int                                                     SizeOf() noexcept;

                /**
                 * @brief Calculates the serialized size for a frame pointer.
                 * @param packet  Source frame pointer.
                 * @return        Packet size in bytes; bitwise-not-zero (~0) when @p packet
                 *                is NULLPTR (use as an error sentinel).
                 */
                static int                                              SizeOf(const IPFrame* packet) noexcept {
                    if (NULLPTR == packet) {
                        return ~0;
                    }

                    IPFrame* frame = constantof(packet);
                    return frame->SizeOf();
                }

            public:
                /**
                 * @brief Parses a raw byte buffer into an IPv4 frame object.
                 *
                 * Validates the IP version, header length, total length, and checksum
                 * fields.  Shared buffer segments are allocated via @p allocator to
                 * hold the payload and options without extra copying.
                 *
                 * @param allocator  Allocator for parsed segment buffers; may be NULLPTR.
                 * @param packet     Pointer to the first byte of the wire-format IPv4 packet.
                 * @param size       Total packet size in bytes.
                 * @return           Shared @ref IPFrame on success; NULLPTR on validation failure.
                 * @note             The raw @p packet buffer is not retained; all data is copied
                 *                   into allocator-managed storage.
                 */
                static std::shared_ptr<IPFrame>                         Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* packet, int size) noexcept;

                /**
                 * @brief Parses a raw byte buffer into an IPv4 frame using zero-copy slices.
                 *
                 * When @p owner is a valid shared_ptr, the parsed payload and options segments
                 * are backed by zero-copy views into @p owner (via wrap_shared_pointer) instead
                 * of allocating and copying into new storage.  When @p owner is NULLPTR the
                 * function falls back to the copy-based behaviour of the primary overload.
                 *
                 * @param allocator  Allocator for parsed segment buffers (used only on fallback).
                 * @param owner       Shared buffer that owns the lifetime of @p packet.
                 * @param packet      Pointer to the first byte of the wire-format IPv4 packet.
                 * @param size        Total packet size in bytes.
                 * @return           Shared @ref IPFrame on success; NULLPTR on validation failure.
                 */
                static std::shared_ptr<IPFrame>                         Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<ppp::Byte>& owner, const void* packet, int size) noexcept;
                
            public:
                /**
                 * @brief Generates a new IPv4 identification value.
                 * @return  Monotonically increasing 16-bit ID value (wraps at UINT16_MAX).
                 */
                static UInt16                                           NewId() noexcept { return ppp::net::native::ip_hdr::NewId(); }

                /**
                 * @brief Splits a frame into MTU-compatible IPv4 fragments.
                 *
                 * When @p packet's payload exceeds the MTU, this function produces a series
                 * of fragments with correct fragment offsets and the MF (more fragments) bit
                 * set on all but the last fragment.  If no fragmentation is needed, @p out
                 * receives the original packet unmodified.
                 *
                 * @param out     Vector that receives the output fragment frames (appended).
                 * @param packet  Source frame to fragment.
                 * @return        Number of fragments appended to @p out; 0 on failure.
                 */
                static int                                              Subpackages(ppp::vector<IPFramePtr>& out, const IPFramePtr& packet) noexcept;

            public:
                /**
                 * @brief Default TTL value used for newly created frames.
                 *
                 * References a process-global variable so that a single configuration
                 * point controls the TTL for all synthesised packets.
                 */
                static const unsigned char&                             DefaultTtl;
            };
        }
    }
}
