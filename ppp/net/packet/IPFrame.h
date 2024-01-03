#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            typedef ppp::net::native::ip_hdr::Flags                     IPFlags;

            class BufferSegment final {
            public:
                std::shared_ptr<Byte>                                   Buffer;
                int                                                     Length;

            public:
                BufferSegment() noexcept : Length(0) {}
                BufferSegment(const std::shared_ptr<Byte>& buffer, int length) noexcept
                    : Buffer(buffer)
                    , Length(buffer ? std::max<int>(0, length) : 0) {

                }
            };

            class IPFrame final {
            public:
                typedef std::shared_ptr<IPFrame>                        IPFramePtr;

            public:
                AddressFamily                                           AddressesFamily;
                UInt32                                                  Destination;
                UInt32                                                  Source;
                Byte                                                    Ttl;
                UInt16                                                  Id;
                Byte                                                    Tos;
                Byte                                                    ProtocolType;
                IPFlags                                                 Flags;
                std::shared_ptr<BufferSegment>                          Payload;
                std::shared_ptr<BufferSegment>                          Options;

            public:
                IPFrame() noexcept
                    : AddressesFamily(AddressFamily::InterNetwork)
                    , Destination(0)
                    , Source(IPFrame::DefaultTtl)
                    , Ttl(64)
                    , Id(0)
                    , Tos(0)
                    , ProtocolType(0)
                    , Flags(IPFlags::IP_DF) {

                }
                int                                                     GetFragmentOffset() noexcept {
                    int offset = (UInt16)this->Flags;
                    offset = ((UInt16)(offset << 3)) >> 3;
                    offset <<= 3;
                    return offset;
                }
                void                                                    SetFragmentOffset(int value) noexcept {
                    int flags = (int)this->Flags >> 13;
                    flags = flags << 13 | value >> 3;
                    this->Flags = (IPFlags)flags;
                }
        
            public:     
                static std::shared_ptr<BufferSegment>                   ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const IPFrame* packet) noexcept {
                    if (NULL == packet) {
                        return NULL;
                    }
                    return const_cast<IPFrame*>(packet)->ToArray(allocator);
                }
                static UInt16                                           NewId() noexcept {
                    return ppp::net::native::ip_hdr::NewId();
                }
                static int                                              SizeOf(const IPFrame* packet) noexcept {
                    if (NULL == packet) {
                        return ~0;
                    }
                    return const_cast<IPFrame*>(packet)->SizeOf();
                }
                std::shared_ptr<BufferSegment>                          ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                int                                                     SizeOf() noexcept;
                static std::shared_ptr<IPFrame>                         Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* packet, int size) noexcept {
                    return IPFrame::Parse(allocator, packet, size, true);
                }
                static std::shared_ptr<IPFrame>                         Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* packet, int size, bool checksum) noexcept;
                static int                                              Subpackages(ppp::vector<IPFramePtr>& out, const IPFramePtr& packet) noexcept;

            public:
                static const Byte                                       DefaultTtl = ppp::net::native::ip_hdr::IP_DFT_TTL;
            };
        }
    }
}