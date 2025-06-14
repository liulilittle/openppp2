#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            typedef ppp::net::native::ip_hdr::Flags                     IPFlags;

            class BufferSegment final {
            public:
                std::shared_ptr<Byte>                                   Buffer;
                int                                                     Length = 0;

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
                    , Tos(ppp::net::Socket::IsDefaultFlashTypeOfService() ? DefaultFlashTypeOfService() : 0)
                    , ProtocolType(0)
                    , Flags(IPFlags::IP_DF) {

                }

            public:
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
                bool                                                    IsEmpty() noexcept {
                    std::shared_ptr<BufferSegment> payload = Payload;
                    if (NULL == payload) {
                        return true;
                    }

                    std::shared_ptr<Byte> buffer = payload->Buffer;
                    return NULL == buffer || payload->Length < 1;
                }
                static int                                              DefaultFlashTypeOfService() noexcept { return 0x68; }
                static void                                             DefaultFlashTypeOfService(const IPFrame* packet) noexcept { 
                    if (NULL != packet) {
                        IPFrame* frame = constantof(packet);
                        frame->Tos = DefaultFlashTypeOfService();
                    }
                }
                
            public:     
                std::shared_ptr<BufferSegment>                          ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                static std::shared_ptr<BufferSegment>                   ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const IPFrame* packet) noexcept {
                    if (NULL == packet) {
                        return NULL;
                    }

                    IPFrame* frame = constantof(packet);
                    return frame->ToArray(allocator);
                }

            public:
                int                                                     SizeOf() noexcept;
                static int                                              SizeOf(const IPFrame* packet) noexcept {
                    if (NULL == packet) {
                        return ~0;
                    }

                    IPFrame* frame = constantof(packet);
                    return frame->SizeOf();
                }

            public:
                static std::shared_ptr<IPFrame>                         Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* packet, int size) noexcept;
                
            public:
                static UInt16                                           NewId() noexcept { return ppp::net::native::ip_hdr::NewId(); }
                static int                                              Subpackages(ppp::vector<IPFramePtr>& out, const IPFramePtr& packet) noexcept;

            public:
                static const unsigned char&                             DefaultTtl;
            };
        }
    }
}