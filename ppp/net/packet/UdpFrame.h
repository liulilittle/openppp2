#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>

namespace ppp {
    namespace net {
        namespace packet {
            class IPFrame;
            class BufferSegment;

            class UdpFrame final {
            public:
                IPEndPoint                                      Source;
                IPEndPoint                                      Destination;
                AddressFamily                                   AddressesFamily;
                Byte                                            Ttl;
                std::shared_ptr<BufferSegment>                  Payload;

            public:
                UdpFrame() noexcept
                    : AddressesFamily(AddressFamily::InterNetwork)
                    , Ttl(IPFrame::DefaultTtl) {
                }

            public:
                static std::shared_ptr<IPFrame>                 ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const UdpFrame* frame) {
                    if (NULL == frame) {
                        return NULL;
                    }

                    UdpFrame* packet = constantof(frame);
                    return packet->ToIp(allocator);
                }
                std::shared_ptr<IPFrame>                        ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator);
                static std::shared_ptr<UdpFrame>                Parse(const IPFrame* frame) noexcept;
            };
        }
    }
}