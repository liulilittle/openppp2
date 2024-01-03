#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            typedef ppp::net::native::IcmpType                  IcmpType;

            class IPFrame;
            class BufferSegment;

            class IcmpFrame final {
            public:
                IcmpType                                        Type;
                Byte                                            Code;
                UInt16                                          Identification;
                UInt16                                          Sequence;
                UInt32                                          Source;
                UInt32                                          Destination;
                Byte                                            Ttl;
                AddressFamily                                   AddressesFamily;
                std::shared_ptr<BufferSegment>                  Payload;

            public:
                IcmpFrame() noexcept
                    : Type(IcmpType::ICMP_ECHO)
                    , Code(0)
                    , Identification(0)
                    , Sequence(0)
                    , Source(0)
                    , Destination(0)
                    , Ttl(IPFrame::DefaultTtl)
                    , AddressesFamily(AddressFamily::InterNetwork) {
                }

            public:
                static std::shared_ptr<IPFrame>                 ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const IcmpFrame* frame) {
                    if (NULL == frame) {
                        return NULL;
                    }
                    return const_cast<IcmpFrame*>(frame)->ToIp(allocator);
                }
                std::shared_ptr<IPFrame>                        ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator);
                static std::shared_ptr<IcmpFrame>               Parse(const IPFrame* frame) noexcept;
            };
        }
    }
}